"""
Encrypted scalar handles carry no integrity outside a transaction.

monero_io_insert_encrypt and monero_io_fetch_decrypt append and verify an HMAC
only when tx_in_progress is set (src/monero_io.c:165, :282). Outside a
transaction the device decrypts whatever 32 bytes the host sent and feeds the
result straight to the scalar range check and then to an elliptic-curve
operation. INS_SECRET_SCAL_MUL_BASE returns that point in clear, so the host
gets a decryption oracle for any handle-shaped input it can construct.

What this file can and cannot show
----------------------------------
The build these tests run against defines IODUMMYCRYPT (Makefile:89, only under
DEBUG=1), so a handle here is the plaintext XORed with 0x55, not AES-CBC. The
release build takes the #else branch and uses cx_aes_no_throw, which forwards a
NULL IV (lib_cxng/src/cx_aes.c), i.e. CBC with a zero IV.

So the *confidentiality* half of the finding, recovering a handle's plaintext
by splicing CBC blocks and differencing the points that come back, cannot be
reproduced on any build the functional suite can drive. It is covered in
unit-tests/test_monero_io.c, where monero_io.c compiles with the real AES path,
and that is where the fix is verified too: outside a transaction a handle now
takes two passes with its halves swapped between them, so a splice no longer
hands back a half of either source.

The *integrity* half is not fixed. A handle is 32 bytes and the wallet carries
no tag beside one: send_secret appends an HMAC only while tx_in_progress, so
demanding integrity outside a transaction would break every existing wallet.
The two classes that state that requirement are therefore skipped rather than
inverted, so they can be un-skipped by whoever closes it instead of standing in
the way.

The handle chain, all outside a transaction and all without an HMAC:

    INS_GEN_KEY_DERIVATION    fake view-key sentinel + [m]G  ->  E(8.a.[m]G)
    INS_DERIVATION_TO_SCALAR  index i                        ->  E(h), h known
    INS_DERIVE_SECRET_KEY     fake spend-key sentinel        ->  E(h + b)

h follows from the test seed, so the last handle minus h is the master private
spend key. On this build that is three APDUs; on a release build it is the same
three plus the CBC oracle to read E(h + b).

Classes:
  TestHandleTransformPremise  - the handle is deterministic and carries no tag
  TestHandleStillRoundTrips   - control: the format change broke nothing
  TestSpendKeyChainIsReachable - E(h + b) needs no HMAC and no transaction
  TestForgedHandleRefused     - skipped: what a fixed build must do
  TestSplicedHandleRefused    - skipped: what a fixed build must do
"""

import pytest
import nacl.bindings as nb

from monero_client.exception.device_error import DeviceError
from monero_client.monero_cmd import MoneroCmd
from monero_client.crypto.monero_math import (L, base, derivation_to_scalar,
                                              key_derivation, num, red)

# The test seed "abandon ... about". Present so the tests can assert against
# the truth rather than against the device's own answer.
VIEW_SECRET = bytes.fromhex(
    "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201")
SECRET_SPEND_KEY = bytes.fromhex(
    "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109")
PUBLIC_SPEND_KEY = bytes.fromhex(
    "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d")

# The sentinels monero_io_fetch_decrypt_key swaps for the real keys.
# src/monero_init.c:30-38.
FAKE_VIEW_KEY = bytes(32)
FAKE_SPEND_KEY = b"\xff" * 32

# IODUMMYCRYPT: src/monero_io.c:149 and :295 XOR each byte with this.
DUMMY_CRYPT_BYTE = 0x55

# Any scalar; [KNOWN_SCALAR]G starts the derivation chain.
KNOWN_SCALAR = 12345


def _unwrap(handle: bytes) -> bytes:
    """The plaintext of a handle on an IODUMMYCRYPT build."""
    return bytes(b ^ DUMMY_CRYPT_BYTE for b in handle)


def _wrap(scalar: bytes) -> bytes:
    """A handle the device will accept, built entirely host-side."""
    return bytes(b ^ DUMMY_CRYPT_BYTE for b in scalar)


def _known_derivation() -> bytes:
    """8.a.[m]G, which the host can compute because it knows the seed."""
    return key_derivation(base(red(KNOWN_SCALAR)), VIEW_SECRET)


def _mint_scalar_handle(monero: MoneroCmd, index: int) -> bytes:
    """E(h) for h = Hs(8.a.[m]G || index), a scalar the host knows."""
    enc_drv = monero.gen_key_derivation(pub_key=base(red(KNOWN_SCALAR)),
                                        _priv_key=FAKE_VIEW_KEY)
    return monero.derivation_to_scalar(enc_drv, index)


@pytest.mark.incremental
class TestHandleTransformPremise:
    """
    A handle has no nonce and no tag. Both follow from one exchange: mint the
    same handle twice and it is byte-identical, and it is 32 bytes long with
    nothing appended.
    """

    @staticmethod
    def test_handle_is_deterministic_and_untagged(monero: MoneroCmd):
        first = _mint_scalar_handle(monero, 0)
        second = _mint_scalar_handle(monero, 0)

        assert len(first) == 32, \
            "a handle with integrity would carry a tag, so be longer than 32"
        assert first == second, \
            "the same scalar gives the same handle, so there is no nonce"

    @staticmethod
    def test_the_host_can_read_the_handle_on_this_build(monero: MoneroCmd):
        """IODUMMYCRYPT, so the plaintext is one XOR away. Stated explicitly
        because every assertion below depends on it, and because it is what
        makes this build unable to test the CBC half."""
        handle = _mint_scalar_handle(monero, 0)
        want = derivation_to_scalar(_known_derivation(), 0)
        assert _unwrap(handle) == want, (
            "expected the IODUMMYCRYPT transform\n"
            "  handle    %s\n  plaintext %s\n  want      %s"
            % (handle.hex(), _unwrap(handle).hex(), want.hex()))


@pytest.mark.incremental
class TestHandleStillRoundTrips:
    """
    The control. Splitting the handle format by instruction is the part of the
    fix that can break a wallet, so this asserts the ordinary path end to end:
    a handle the device minted, handed straight back, yields the scalar the
    harness predicted.
    """

    @staticmethod
    def test_a_minted_handle_redeems_to_its_own_scalar(monero: MoneroCmd):
        handle = _mint_scalar_handle(monero, 0)
        want = derivation_to_scalar(_known_derivation(), 0)

        got = monero.secret_scalar_mul_base(_scalar=handle)
        assert got == base(want), (
            "a handle the device minted must still redeem\n"
            "  got  %s\n  want %s" % (got.hex(), base(want).hex()))


SKIP_NO_INTEGRITY = (
    "Not fixed: a 32-byte handle has no room for a tag and send_secret carries "
    "one only while tx_in_progress, so authenticated handles need a wallet "
    "change first. Un-skip when that lands.")


@pytest.mark.skip(reason=SKIP_NO_INTEGRITY)
@pytest.mark.incremental
class TestForgedHandleRefused:
    """
    A handle the device never minted must be refused, not multiplied. The
    status word is left unpinned because the fix that makes this pass does not
    exist yet and will choose one.
    """

    @staticmethod
    def test_a_host_built_handle_is_refused(monero: MoneroCmd):
        scalar = red(0xdeadbeef)
        with pytest.raises(DeviceError):
            monero.secret_scalar_mul_base(_scalar=_wrap(scalar))


@pytest.mark.skip(reason=SKIP_NO_INTEGRITY)
@pytest.mark.incremental
class TestSplicedHandleRefused:
    """
    Both halves come from handles the device minted, so the host needs no
    knowledge of the wrapper key to build this. It must still be refused: the
    device did not mint this pairing.
    """

    @staticmethod
    def test_two_device_handles_spliced_are_refused(monero: MoneroCmd):
        low = _mint_scalar_handle(monero, 0)
        high = _mint_scalar_handle(monero, 1)
        with pytest.raises(DeviceError):
            monero.secret_scalar_mul_base(_scalar=low[:16] + high[16:])


@pytest.mark.incremental
class TestSpendKeyChainIsReachable:
    """
    What the missing integrity is worth. Three APDUs, no HMAC on any of them
    and no transaction, put E(h + b) in the host's hands; on a release build
    the CBC oracle was what read it. Nothing here is forged, so this keeps
    holding whatever integrity is added later - what it pins is the reach of
    the chain, and that reading it needs only a build whose handle transform
    the host knows.
    """

    @staticmethod
    def test_the_spend_key_handle_is_obtainable(monero: MoneroCmd):
        index = 0
        enc_drv = monero.gen_key_derivation(pub_key=base(red(KNOWN_SCALAR)),
                                            _priv_key=FAKE_VIEW_KEY)
        enc_y = monero.derive_secret_key(derivation=enc_drv,
                                         output_index=index,
                                         _priv_key=FAKE_SPEND_KEY)

        h = derivation_to_scalar(_known_derivation(), index)
        recovered = red(num(_unwrap(enc_y)) - num(h))

        assert nb.crypto_scalarmult_ed25519_base_noclamp(recovered) \
            == PUBLIC_SPEND_KEY, \
            "recovered scalar is not the private spend key"
        assert recovered == SECRET_SPEND_KEY, (
            "and it is the seed's spend key\n  got  %s\n  want %s"
            % (recovered.hex(), SECRET_SPEND_KEY.hex()))
