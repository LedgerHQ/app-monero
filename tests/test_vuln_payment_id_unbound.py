"""
The device encrypts a payment ID and then forgets it. Nothing checks that the
payment ID in the signed transaction is the one the device produced.

An integrated address is a normal address plus an 8-byte payment ID. Every
customer of one exchange gets the same view and spend keys and a payment ID of
their own, so the payment ID is the only thing that says who is being paid.

`INS_STEALTH` takes a plaintext payment ID, encrypts it with a secret only the
recipient can rebuild, and returns the 8 bytes. It stores nothing. Later the
host streams the transaction prefix, and the prefix parser treats the whole
TX_EXTRA_NONCE payload as bytes to skip. So the host can send the user's payment
ID to the device, put a different one in the prefix, and the device signs it.

Nothing on screen changes. The destination keys are untouched, so every key and
commitment check passes, and the review draws the address built from those keys.
The exchange then credits somebody else.

The review never shows a payment ID at all, because INS_VALIDATE renders the
destination with monero_base58_public_key(..., NULL). That is a second problem
and this file does not cover it. Binding the value comes first.

One thing the wallet does that shapes the fix: most transactions carry a payment
ID even when the user did not ask for one. If a transaction has no payment ID
and at most two destinations, the wallet encrypts a null value and puts that in
the prefix, so transactions look alike on chain
(cryptonote_tx_utils.cpp, near line 313). With more than two destinations it
adds nothing. So a fix must accept a dummy value, and must accept no nonce at
all. Both shapes are tested here.

Classes, in file order:

  TestEncryptedIdDependsOnPlaintext  The premise. Two plaintext payment IDs give
                                     two different ciphertexts in one
                                     transaction, so swapping one for the other
                                     is a real change.
  TestPaymentIdSubstitutionAccepted  The old behaviour. The device encrypts one
                                     payment ID, the prefix carries another, and
                                     the prefix is accepted. Skipped now: it
                                     needs two INS_STEALTH calls in one real
                                     transaction, which the fix refuses.
  TestHonestPaymentIdAccepted        Control. The prefix carries the ciphertext
                                     the device returned.
  TestOrdinaryTransactionShapes      Control. A dummy payment ID is accepted,
                                     and so is a transaction with no nonce.
  TestSubstitutedPaymentIdRefused    The fix. A swapped payment ID gives 0x6921.
  TestInventedPaymentIdRefused       The fix. A payment ID the device never made
                                     gives 0x6921.
  TestSecondStealthRefused           The fix. One payment ID per transaction.

The three refusal classes come last. A refusal exits the app, so each needs its
own transaction and must end on the refusal.

Run: pytest tests/test_vuln_payment_id_unbound.py -v --device flex
     (DEBUG=1 build. No screens are drawn, so there are no snapshots.)

Snapshot directories take the name of the test function. Method names must stay
unique across the whole suite.

Every test asks for the `monero` fixture, even where it is unused. pytest
reorders tests to save fixture setup, and a test that omits it leaves its class
and runs against a fresh class-scoped `state`.
"""

import struct

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import InsType, Type, SigType
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.varint import encode_varint
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

# What the user means to pay, and what the attacker swaps in.
PAY_ID_USER = bytes.fromhex("1122334455667788")
PAY_ID_ATTACKER = bytes.fromhex("99aabbccddeeff00")
PAY_ID_DUMMY = bytes(8)          # what the wallet sends when there is none

# Eight bytes the device never produced. Any value that differs will do: the
# check is a comparison, so the attacker does not need a valid ciphertext.
ENC_FOREIGN = bytes.fromhex("dead beef dead beef".replace(" ", ""))

SW_SECURITY_PAYMENT_ID = 0x6921


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int,
              payload: bytes = b"") -> bytes:
    """One APDU in the app's framing. The option byte is the first data byte."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _hmac(value: bytes) -> bytes:
    """A scalar as the device wants it: the value then its HMAC."""
    return value + hmac_sha256(value, MoneroCryptoCmd.HMAC_KEY, Type.SCALAR)


def _stealth(backend: BackendInterface, view_pub: bytes, tx_priv_key: bytes,
             payment_id: bytes) -> bytes:
    """INS_STEALTH. Returns the 8 encrypted bytes the device hands back.

    It derives 8.r.A from the destination view key and the tx secret, keccaks
    that with a tail byte into a mask, and XORs the payment ID with it."""
    payload = view_pub + _hmac(tx_priv_key) + payment_id
    out = backend.exchange_raw(
        _raw_apdu(InsType.INS_STEALTH, 0, 0, 0x00, payload)).data
    assert len(out) == 8, "expected 8 encrypted bytes, got %d" % len(out)
    return out


def _nonce(encrypted_id: bytes) -> bytes:
    """A TX_EXTRA_NONCE field holding an encrypted payment ID.

    Tag 0x02, length 9, subtype 0x01, then the 8 bytes."""
    body = b"\x01" + encrypted_id
    return b"\x02" + encode_varint(len(body)) + body


def _long_nonce(payment_id32: bytes) -> bytes:
    """A TX_EXTRA_NONCE holding a legacy *unencrypted* long payment ID.

    Tag 0x02, length 33, subtype 0x00, then 32 plaintext bytes. The device
    never makes one of these, so it has nothing to compare it against."""
    assert len(payment_id32) == 32
    body = b"\x00" + payment_id32
    return b"\x02" + encode_varint(len(body)) + body


def _open(monero: MoneroCmd, state, sig_type=SigType.REAL):
    """reset, set the mode, open_tx, and record the device's keys as the payee."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, _ = monero.get_public_keys()
    state["A"] = view
    state["B"] = spend
    assert monero.set_signature_mode(sig_type=sig_type) == sig_type
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["R"] = tx_pub_key
    state["r"] = tx_priv_key


def _open_real(monero: MoneroCmd, state):
    _open(monero, state, SigType.REAL)


def _gen_one_output(monero: MoneroCmd, state) -> bytes:
    """One output to the payee, at index 0. Returns its one-time key."""
    ak, eph, _ = monero.gen_txout_keys(
        _tx_priv_key=state["r"], tx_pub_key=state["R"],
        dst_pub_view_key=state["A"], dst_pub_spend_key=state["B"],
        output_index=0, is_change_addr=False, is_subaddress=False)
    state["ak"] = ak
    return eph


def _stream_prefix(monero: MoneroCmd, device, test_name: str, state,
                   eph: bytes, extra_suffix: bytes = b"") -> bytes:
    """Send the prefix and return the hash the device computes."""
    monero.prefix_hash_init(test_name, device, navigator=None,
                            version=0, timelock=0)
    prefix = build_tx_prefix_outkeys(vout_keys=[eph], tx_pubkey=state["R"],
                                     extra_suffix=extra_suffix)
    return monero.prefix_hash_update(index=1, payload=prefix, is_last=True)


def _expect_prefix_refused(monero: MoneroCmd, backend: BackendInterface,
                           device, test_name: str, state, eph: bytes,
                           extra_suffix: bytes):
    """Stream the prefix and require 0x6921. Sent raw, because the client helper
    turns a refusal into its own error type."""
    monero.prefix_hash_init(test_name, device, navigator=None,
                            version=0, timelock=0)
    prefix = build_tx_prefix_outkeys(vout_keys=[eph], tx_pubkey=state["R"],
                                     extra_suffix=extra_suffix)
    try:
        sw = backend.exchange_raw(
            _raw_apdu(InsType.INS_PREFIX_HASH, 2, 1, 0x00, prefix)).status
    except ExceptionRAPDU as exc:
        sw = exc.status
    assert sw == SW_SECURITY_PAYMENT_ID, (
        "expected %#06x for a payment ID the device did not make, got %#06x"
        % (SW_SECURITY_PAYMENT_ID, sw))


def _tx_state():
    return {"A": None, "B": None, "R": None, "r": None, "ak": None}


@pytest.mark.incremental
class TestEncryptedIdDependsOnPlaintext:
    """Swapping the payment ID is a real change, not a no-op."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_two_plaintexts_two_ciphertexts(monero: MoneroCmd,
                                                backend: BackendInterface,
                                                state):
        """Same transaction, same payee, two payment IDs.

        Fake mode, because a real transaction now keeps only one payment ID and
        refuses a second INS_STEALTH. Nothing is retained for a fake one, so the
        repeated calls are allowed and the tx key stays the same, which is what
        makes the two ciphertexts comparable."""
        _open(monero, state, SigType.FAKE)
        enc_user = _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        enc_attacker = _stealth(backend, state["A"], state["r"], PAY_ID_ATTACKER)
        enc_dummy = _stealth(backend, state["A"], state["r"], PAY_ID_DUMMY)

        assert enc_user != enc_attacker, (
            "the ciphertext does not follow the payment ID -- the premise of "
            "this file no longer holds")
        assert enc_dummy != enc_user, "a dummy payment ID must also differ"
        print("\n[premise] user     %s -> %s\n"
              "          attacker %s -> %s"
              % (PAY_ID_USER.hex(), enc_user.hex(),
                 PAY_ID_ATTACKER.hex(), enc_attacker.hex()))
        monero.close_tx()


@pytest.mark.skip(reason="Shows the old behaviour, before the payment ID was bound. It needs "
                         "two INS_STEALTH calls in one real transaction, which is now refused. "
                         "Use --run-skipped on a build without the check.")
@pytest.mark.incremental
class TestPaymentIdSubstitutionAccepted:
    """The device encrypts one payment ID. The prefix carries another."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_prefix_carries_a_different_id(monero: MoneroCmd,
                                               backend: BackendInterface,
                                               device, test_name: str, state):
        """The device is asked to encrypt the user's payment ID. The prefix then
        carries the attacker's. The device hashes it and returns a prefix hash,
        so the substituted value is now part of what gets signed."""
        _open_real(monero, state)
        enc_user = _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        enc_attacker = _stealth(backend, state["A"], state["r"], PAY_ID_ATTACKER)
        assert enc_user != enc_attacker

        eph = _gen_one_output(monero, state)
        prefix_hash = _stream_prefix(monero, device, test_name, state, eph,
                                     extra_suffix=_nonce(enc_attacker))
        assert len(prefix_hash) == 32, (
            "not reproduced: the device refused the swapped payment ID")
        print("\n[impact] device encrypted %s\n"
              "         prefix carries    %s  -> signed anyway"
              % (enc_user.hex(), enc_attacker.hex()))
        monero.close_tx()


@pytest.mark.incremental
class TestHonestPaymentIdAccepted:
    """Control. The prefix carries the ciphertext the device returned."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_honest_id_accepted(monero: MoneroCmd,
                                    backend: BackendInterface,
                                    device, test_name: str, state):
        _open_real(monero, state)
        enc_user = _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(monero, device, test_name, state, eph,
                                  extra_suffix=_nonce(enc_user))) == 32
        monero.close_tx()


@pytest.mark.incremental
class TestOrdinaryTransactionShapes:
    """Control. The two shapes an ordinary send takes must keep working."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_dummy_id_accepted(monero: MoneroCmd,
                                   backend: BackendInterface,
                                   device, test_name: str, state):
        """What the wallet sends when the user gave no payment ID: a null value,
        encrypted, in the prefix."""
        _open_real(monero, state)
        enc_dummy = _stealth(backend, state["A"], state["r"], PAY_ID_DUMMY)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(monero, device, test_name, state, eph,
                                  extra_suffix=_nonce(enc_dummy))) == 32
        monero.close_tx()

    @staticmethod
    def test_pid_no_nonce_accepted(monero: MoneroCmd, device,
                                   test_name: str, state):
        """What a send with more than two destinations looks like: no nonce, and
        no INS_STEALTH call either."""
        _open_real(monero, state)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(monero, device, test_name, state, eph)) == 32
        monero.close_tx()


@pytest.mark.incremental
class TestSubstitutedPaymentIdRefused:
    """The fix. The prefix must carry the payment ID the device produced.

    Each refusal exits the app, so the three classes below get a transaction of
    their own and end on the refusal."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_swapped_id_refused(monero: MoneroCmd,
                                    backend: BackendInterface,
                                    device, test_name: str, state):
        _open_real(monero, state)
        _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        _expect_prefix_refused(monero, backend, device, test_name, state, eph,
                               _nonce(ENC_FOREIGN))


@pytest.mark.incremental
class TestInventedPaymentIdRefused:
    """The fix. A payment ID the device was never asked to make is refused."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_invented_id_refused(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     device, test_name: str, state):
        """No INS_STEALTH at all, but the prefix carries a payment ID. This is
        how an attacker labels a payment that the user never labelled."""
        _open_real(monero, state)
        eph = _gen_one_output(monero, state)
        _expect_prefix_refused(monero, backend, device, test_name, state, eph,
                               _nonce(ENC_FOREIGN))


@pytest.mark.incremental
class TestSecondStealthRefused:
    """The fix. One payment ID per real transaction.

    Without this the host could ask for two ciphertexts and the check would
    compare against whichever one the device chose to keep, which the host
    controls by ordering the calls."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_second_stealth_refused(monero: MoneroCmd,
                                        backend: BackendInterface, state):
        _open_real(monero, state)
        _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        try:
            sw = backend.exchange_raw(_raw_apdu(
                InsType.INS_STEALTH, 0, 0, 0x00,
                state["A"] + _hmac(state["r"]) + PAY_ID_ATTACKER)).status
        except ExceptionRAPDU as exc:
            sw = exc.status
        assert sw == SW_SECURITY_PAYMENT_ID, (
            "expected %#06x for a second payment ID, got %#06x"
            % (SW_SECURITY_PAYMENT_ID, sw))


# ---------------------------------------------------------------------------
# The residual, found by the 2026-09-11 re-scan of this branch.
#
# Comparing the 9-byte nonce was not enough: nothing required it to be present,
# nothing looked at a nonce of any other length, and nothing stopped a second
# one. So a host that had the device produce payment ID A -- and show the
# integrated address carrying A at review -- could still get other payment-ID
# bytes into the signed prefix. Now a transaction that made a payment ID must
# carry exactly one nonce, in the encrypted shape, matching the retained value.
#
# That is the wallet's own invariant: cryptonote_tx_utils.cpp:265-333 rewrites
# the nonce in place around the INS_STEALTH call, and adds a dummy one only
# when there is neither a long nor a short payment ID.
#
# 32 plaintext bytes the attacker wants a service to read as its own account.
PAY_ID_LONG_ATTACKER = bytes.fromhex("aa" * 32)


@pytest.mark.incremental
class TestRetainedPaymentIdMustAppear:
    """
    The device made payment ID A and the review showed the integrated address
    for it, so a prefix with no nonce at all no longer finalizes.

    Distinct from TestOrdinaryTransactionShapes.test_pid_no_nonce_accepted,
    which is the legitimate shape: no INS_STEALTH call, so nothing was retained
    and there is nothing to leave out. That test is this one's control -- a fix
    that simply demanded a nonce would break it.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_omitted_refused(monero: MoneroCmd,
                                 backend: BackendInterface,
                                 device, test_name: str, state):
        _open_real(monero, state)
        _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        _expect_prefix_refused(monero, backend, device, test_name, state, eph,
                               extra_suffix=b"")


@pytest.mark.incremental
class TestLongNonceRefusedWhenIdRetained:
    """
    A 33-byte legacy nonce used to slip through, because only a 9-byte one was
    compared. With a payment ID retained, any other nonce shape is refused.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_long_nonce_refused(monero: MoneroCmd,
                                    backend: BackendInterface,
                                    device, test_name: str, state):
        _open_real(monero, state)
        _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        _expect_prefix_refused(monero, backend, device, test_name, state, eph,
                               extra_suffix=_long_nonce(PAY_ID_LONG_ATTACKER))


@pytest.mark.incremental
class TestDuplicateNonceRefused:
    """
    The strongest of the three: the honest nonce is streamed first and satisfies
    the comparison, then a second one carrying the attacker's bytes follows. It
    met every check the first fix added, so it is the one worth keeping pinned.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_second_nonce_refused(monero: MoneroCmd,
                                      backend: BackendInterface,
                                      device, test_name: str, state):
        _open_real(monero, state)
        enc_user = _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        _expect_prefix_refused(
            monero, backend, device, test_name, state, eph,
            extra_suffix=_nonce(enc_user) + _long_nonce(PAY_ID_LONG_ATTACKER))


@pytest.mark.skip(reason="Shows the old behaviour, before the nonce had to be "
                         "present, unique and of the encrypted shape. Needs a "
                         "build without those checks.")
@pytest.mark.incremental
class TestResidualNonceHolesAccepted:
    """
    The three shapes the first V-071 fix let through, kept reproducible. Each
    one signed payment-ID bytes the device never made while the review showed
    the integrated address for the one it did.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_pid_residual_omitted(monero: MoneroCmd,
                                  backend: BackendInterface,
                                  device, test_name: str, state):
        _open_real(monero, state)
        _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(monero, device, test_name, state, eph)) == 32
        monero.close_tx()

    @staticmethod
    def test_pid_residual_long_nonce(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     device, test_name: str, state):
        _open_real(monero, state)
        _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(
            monero, device, test_name, state, eph,
            extra_suffix=_long_nonce(PAY_ID_LONG_ATTACKER))) == 32
        monero.close_tx()

    @staticmethod
    def test_pid_residual_duplicate(monero: MoneroCmd,
                                    backend: BackendInterface,
                                    device, test_name: str, state):
        _open_real(monero, state)
        enc_user = _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(
            monero, device, test_name, state, eph,
            extra_suffix=_nonce(enc_user)
            + _long_nonce(PAY_ID_LONG_ATTACKER))) == 32
        monero.close_tx()
