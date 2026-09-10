"""
The host tells the device which output index to derive. The device never checks
that this index matches where the output really sits in the transaction.

INS_GEN_TXOUT_KEYS reads `output_index` from the wire. It uses that value for
the amount key, for the one-time output key, and for the view tag. It never
compares it to the output's position in vout.

Two checks look like they would catch this. Neither does.

  OUT_EPH        hashes each key in the order the keys were made. It sees the
                 key, not the index that made it.
  prefix parser  walks the vout the host streamed and compares each key to that
                 chain. This compares one order to another order. Neither side
                 stores an index.

So the host can ask for the first output with output_index=1 and put the
returned key at vout[0]. Every destination, commitment and prefix check passes.
The device shows the address the user expects, and signs.

This destroys the output. The recipient reads position i and computes
Hs(a.R || i).G + B. At vout[0] it computes index 0. The key there was made with
index 1. The two never match, so the recipient cannot find the output and cannot
derive its secret key. The money is gone. The screen looks normal.

The test proves both parts without trusting the device:

  - Python recomputes the derivation from the test seed's secret view key. It
    does 8.a.R, then Hs(D || varint(i)).G + B. The reference is independent.
  - The key at vout[0] matches the index-1 reference. It differs from the
    index-0 reference, which is what a real recipient computes.

Classes, in file order:

  TestIndexChangesDerivation   Checks the premise. Index 0 and index 1 give
                               different keys, and both match Python. It uses
                               indices 0 and 1 in order, so it stays valid after
                               the index is bound.
  TestOutputIndexUnbound       The old behaviour. One output made at index 1,
                               streamed at vout[0], accepted by the prefix
                               check, reviewed and signed. Skipped now, because
                               the device refuses the first step.
  TestSequentialIndexAccepted  The control. Index 0 at vout[0] is accepted and
                               matches the index-0 reference. It must stay
                               green.
  TestWrongIndexRefused        The fix. The first output must say index 0.
  TestRepeatedIndexRefused     The fix. An index cannot be used twice.
  TestSkippedIndexRefused      The fix. An index cannot be skipped.

The three refusal classes come last. A refusal exits the app, so each one needs
its own transaction and must end on the refusal.

Run: pytest tests/test_vuln_output_index_unbound.py -v --device flex
     (DEBUG=1 build. Add --golden_run once to record the snapshots.)

Snapshot directories take the name of the test function. Method names must stay
unique across the whole suite.

Every test here asks for the `monero` fixture, even the parts that only read
state captured earlier. pytest reorders tests to save fixture setup. A test that
omits the fixture leaves its class, runs after the others, and gets a new
class-scoped `state` full of None. Keep the signatures the same, or move such a
check into the test that produced the value.
"""

import pytest
import nacl.bindings as nb

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import Keys, SigType
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys
from monero_client.status_words import (
    SW_WRONG_DATA)
from monero_client.crypto.monero_math import (
    derivation_to_scalar,
    key_derivation)


ZERO_COMMITMENT = bytes(32)
FEE = 30660000            # 0.00003066 XMR
AMOUNT = 907880000        # 0.00090788 XMR


# The test seed "abandon ... about". This is the address shown on screen. The
# secret view key is here so the test can compute the recipient's own scan.
_USER = Keys(
    public_view_key=bytes.fromhex(
        "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"),
    public_spend_key=bytes.fromhex(
        "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d"),
    secret_view_key=bytes.fromhex(
        "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201"),
    secret_spend_key=bytes.fromhex(
        "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109"),
    addr="",
)


def _recipient_scan(tx_pub_key: bytes, index: int) -> bytes:
    """The one-time key a real recipient computes for position `index`.

    It is Hs(8.a.R || varint(index)).G + B. Computed here, from the seed keys.
    The device is not asked."""
    d = key_derivation(tx_pub_key, _USER.secret_view_key)
    s = derivation_to_scalar(d, index)
    return nb.crypto_core_ed25519_add(
        nb.crypto_scalarmult_ed25519_base_noclamp(s), _USER.public_spend_key)


def _open_real(monero: MoneroCmd, state):
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["R"] = tx_pub_key
    state["r"] = tx_priv_key


def _gen(monero: MoneroCmd, state, output_index: int):
    """Send one INS_GEN_TXOUT_KEYS for the on-screen address, at this index.

    Returns (amount_key, one_time_key)."""
    ak, eph, _ = monero.gen_txout_keys(
        _tx_priv_key=state["r"], tx_pub_key=state["R"],
        dst_pub_view_key=_USER.public_view_key,
        dst_pub_spend_key=_USER.public_spend_key,
        output_index=output_index, is_change_addr=False, is_subaddress=False)
    return ak, eph


def _expect_refused(monero: MoneroCmd, state, output_index: int):
    """Ask for an output at a wrong index and require 0x6984."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _gen(monero, state, output_index)
    assert exc.value.status == SW_WRONG_DATA, (
        "expected %#06x for index %d, got %#06x"
        % (SW_WRONG_DATA, output_index, exc.value.status))


def _tx_state():
    return {"R": None, "r": None, "ak": None, "eph": None}


@pytest.mark.incremental
class TestIndexChangesDerivation:
    """The index changes the keys, and Python agrees with the device.

    Both must hold before the attack below proves anything."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_idx_open(monero: MoneroCmd, state):
        _open_real(monero, state)

    @staticmethod
    def test_idx_reference_matches_device(monero: MoneroCmd, state):
        """Two outputs to one address, at positions 0 and 1.

        This is a normal, in-order pair. The keys differ, and each matches what
        a recipient reading that position computes."""
        ak0, eph0 = _gen(monero, state, 0)
        ak1, eph1 = _gen(monero, state, 1)

        assert eph0 != eph1, "the output index does not affect the one-time key"
        assert ak0 != ak1, "the output index does not affect the amount key"
        assert eph0 == _recipient_scan(state["R"], 0), (
            "index 0: device key != client reference -- the reference is wrong, "
            "so nothing below can be trusted")
        assert eph1 == _recipient_scan(state["R"], 1), (
            "index 1: device key != client reference")

    @staticmethod
    def test_idx_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.skip(reason="Shows the old behaviour, before the index was bound. It passes only "
                         "on a build without the check. Use --run-skipped to see it again.")
@pytest.mark.incremental
class TestOutputIndexUnbound:
    """One output. Made at index 1. Streamed and signed at vout[0]."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_unbound_gen_at_wrong_index(monero: MoneroCmd, state):
        """Ask for the only output of the transaction with output_index=1.

        The device accepts it. The key it returns is one that a recipient
        reading position 0 will never derive.

        The proof sits in this test on purpose. See the note on fixture
        ordering at the top of the file."""
        _open_real(monero, state)
        state["ak"], state["eph"] = _gen(monero, state, 1)

        at_vout0 = state["eph"]
        assert at_vout0 == _recipient_scan(state["R"], 1), (
            "not reproduced: the device did not use the host's index")
        assert at_vout0 != _recipient_scan(state["R"], 0), (
            "index 0 and 1 collide -- impossible, check the reference")
        print("\n[impact] vout[0] will carry %s\n"
              "         recipient derives   %s  -> undetectable, unspendable"
              % (at_vout0.hex(), _recipient_scan(state["R"], 0).hex()))

    @staticmethod
    def test_unbound_prefix_binding_accepts_it(monero: MoneroCmd, device,
                                               test_name: str, state):
        """The prefix check compares vout to the order the keys were made in.

        A key built with the wrong index therefore passes."""
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)
        prefix = build_tx_prefix_outkeys(vout_keys=[state["eph"]],
                                         tx_pubkey=state["R"])
        assert len(monero.prefix_hash_update(index=1, payload=prefix,
                                             is_last=True)) == 32

    @staticmethod
    def test_unbound_reviewed_and_signed(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator, device,
                                         test_name: str, state):
        """The user reviews the expected address. The device then returns the
        pre-MLSAG hash. That hash is what INS_MLSAG and INS_CLSAG sign."""
        mask = monero.gen_commitment_mask(state["ak"])
        blinded_mask, blinded_amount = monero.blind(
            _ak_amount=state["ak"], mask=mask, amount=AMOUNT, is_short=True)

        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            _ak_amount=state["ak"], commitment=ZERO_COMMITMENT,
            blinded_amount=blinded_amount, blinded_mask=blinded_mask,
            is_last=True, swipe_count=2)
        monero.validate_prehash_finalize(
            index=1, is_short=False, is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            _ak_amount=state["ak"], commitment=ZERO_COMMITMENT,
            blinded_amount=blinded_amount, blinded_mask=blinded_mask,
            is_last=True)
        monero.close_tx()


@pytest.mark.incremental
class TestSequentialIndexAccepted:
    """The control. A normal transaction must still work after the fix."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_seq_gen_at_position_zero(monero: MoneroCmd, state):
        _open_real(monero, state)
        state["ak"], state["eph"] = _gen(monero, state, 0)
        assert state["eph"] == _recipient_scan(state["R"], 0), (
            "the honest output is not scannable at its own position")

    @staticmethod
    def test_seq_prefix_accepted(monero: MoneroCmd, device, test_name: str, state):
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)
        prefix = build_tx_prefix_outkeys(vout_keys=[state["eph"]],
                                         tx_pubkey=state["R"])
        assert len(monero.prefix_hash_update(index=1, payload=prefix,
                                             is_last=True)) == 32
        monero.close_tx()


@pytest.mark.incremental
class TestWrongIndexRefused:
    """The fix. The first output must declare index 0.

    A refusal exits the app, so each of the three refusal classes below gets a
    transaction of its own and ends on the refusal."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_refused_first_output_at_index_one(monero: MoneroCmd, state):
        _open_real(monero, state)
        _expect_refused(monero, state, 1)


@pytest.mark.incremental
class TestRepeatedIndexRefused:
    """Index 0 twice. The second output sits at position 1, so it must say 1."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_refused_repeated_index(monero: MoneroCmd, state):
        _open_real(monero, state)
        _gen(monero, state, 0)
        _expect_refused(monero, state, 0)


@pytest.mark.incremental
class TestSkippedIndexRefused:
    """Index 0 then index 2. Skipping a position is refused too."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_refused_skipped_index(monero: MoneroCmd, state):
        _open_real(monero, state)
        _gen(monero, state, 0)
        _expect_refused(monero, state, 2)
