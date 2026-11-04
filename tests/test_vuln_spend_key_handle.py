"""
A handle holding the private spend key is refused.

Outside a transaction a handle carries no type, so a handle whose value is the
spend key b used to be accepted by any command. Long-format INS_UNBLIND returns
k - Hs(handle) in clear, and Hs(b) is the private view key. The device now
refuses a handle holding b wherever a handle is decrypted. b still reaches a
command through its placeholder, which only INS_VERIFY_KEY and
INS_DERIVE_SECRET_KEY accept, and the wallet only ever holds the placeholder.

The build these tests run against defines IODUMMYCRYPT, so a handle is the
plaintext XORed with 0x55 and the test builds the handle of b from the test
seed. It stands for a handle of b however one is come by.

Classes:
  TestSpendKeyHandleRefusedByUnblind - long-format unblind refuses it
  TestSpendKeyHandleRefusedElsewhere - another command refuses it too
  TestHonestUnblindStillWorks        - control: device amount keys still unblind
  TestSpendKeyHandleWasAccepted      - skipped: the behaviour before the fix
"""

import struct

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_crypto_cmd import PROTOCOL_VERSION
from monero_client.monero_types import InsType
from monero_client.crypto.monero_math import (base, derivation_to_scalar,
                                              hash_to_scalar, key_derivation,
                                              num, red)

# The test seed "abandon ... about".
VIEW_SECRET = bytes.fromhex(
    "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201")
SECRET_SPEND_KEY = bytes.fromhex(
    "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109")

FAKE_VIEW_KEY = bytes(32)
DUMMY_CRYPT_BYTE = 0x55
KNOWN_SCALAR = 12345

SW_OK = 0x9000
SW_WRONG_DATA = 0x6984

LONG_AMOUNT = 0
SHORT_AMOUNT = 2


def _wrap(scalar: bytes) -> bytes:
    return bytes(b ^ DUMMY_CRYPT_BYTE for b in scalar)


def _status(backend: BackendInterface, ins: InsType, option: int,
            payload: bytes) -> tuple:
    """Send one APDU and return (status word, response).

    Blocking exchange: a refusal exits the app, and a streamed response then
    dies mid-read instead of giving the status word.
    """
    apdu = struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, 0, 0,
                       1 + len(payload), option) + payload
    try:
        rapdu = backend.exchange_raw(apdu)
        return rapdu.status, rapdu.data
    except ExceptionRAPDU as exc:
        return exc.status, b""


def _unblind(backend: BackendInterface, handle: bytes, option: int) -> tuple:
    """Unblind with a zero mask and value, outside a transaction (no HMAC)."""
    return _status(backend, InsType.INS_UNBLIND, option,
                   handle + bytes(32) + bytes(32))


def _amount_key_handle(monero: MoneroCmd) -> tuple:
    """A device-made amount key, as the wallet gets one while scanning."""
    pub = base(red(KNOWN_SCALAR))
    enc_drv = monero.gen_key_derivation(pub_key=pub, _priv_key=FAKE_VIEW_KEY)
    handle = monero.derivation_to_scalar(enc_drv, 0)
    return handle, derivation_to_scalar(key_derivation(pub, VIEW_SECRET), 0)


@pytest.mark.incremental
class TestSpendKeyHandleRefusedByUnblind:
    """Long-format unblind of a handle holding b would return -a."""

    @staticmethod
    def test_unblind_refuses_a_spend_key_handle(monero: MoneroCmd,
                                                backend: BackendInterface):
        sw, _ = _unblind(backend, _wrap(SECRET_SPEND_KEY), LONG_AMOUNT)
        assert sw == SW_WRONG_DATA, (
            f"a handle holding the spend key must be refused with "
            f"SW_WRONG_DATA, got {hex(sw)}")


@pytest.mark.incremental
class TestSpendKeyHandleRefusedElsewhere:
    """The refusal is where every handle is decrypted, not only in unblind."""

    @staticmethod
    def test_scal_mul_base_refuses_a_spend_key_handle(
            monero: MoneroCmd, backend: BackendInterface):
        sw, _ = _status(backend, InsType.INS_SECRET_SCAL_MUL_BASE, 0,
                        _wrap(SECRET_SPEND_KEY))
        assert sw == SW_WRONG_DATA, (
            f"a handle holding the spend key must be refused with "
            f"SW_WRONG_DATA, got {hex(sw)}")


@pytest.mark.incremental
class TestHonestUnblindStillWorks:
    """
    The wallet unblinds old outputs (RingCT Full, Simple and Bulletproof v1)
    with the long format while it scans, and newer ones with the short format.
    Both must still work for an amount key the device made.
    """

    @staticmethod
    def test_long_unblind_of_an_amount_key(monero: MoneroCmd,
                                           backend: BackendInterface):
        handle, ak = _amount_key_handle(monero)
        sw, resp = _unblind(backend, handle, LONG_AMOUNT)
        assert sw == SW_OK, f"long unblind of an amount key failed: {hex(sw)}"

        # v is returned first, then k; both start from zero.
        mask_scalar = hash_to_scalar(ak)
        want_k = red(-num(mask_scalar))
        want_v = red(-num(hash_to_scalar(mask_scalar)))
        assert resp[32:] == want_k and resp[:32] == want_v, (
            "long unblind returned the wrong values\n"
            f"  got  v={resp[:32].hex()} k={resp[32:].hex()}\n"
            f"  want v={want_v.hex()} k={want_k.hex()}")

    @staticmethod
    def test_short_unblind_of_an_amount_key(monero: MoneroCmd,
                                            backend: BackendInterface):
        handle, _ = _amount_key_handle(monero)
        sw, _ = _unblind(backend, handle, SHORT_AMOUNT)
        assert sw == SW_OK, f"short unblind of an amount key failed: {hex(sw)}"


@pytest.mark.skip(reason="the behaviour before the fix; run with "
                         "--run-skipped against an unfixed build")
@pytest.mark.incremental
class TestSpendKeyHandleWasAccepted:
    """On an unfixed build, long-format unblind accepts a handle holding b."""

    @staticmethod
    def test_unblind_accepted_a_spend_key_handle(monero: MoneroCmd,
                                                 backend: BackendInterface):
        sw, _ = _unblind(backend, _wrap(SECRET_SPEND_KEY), LONG_AMOUNT)
        assert sw == SW_OK, f"expected the unfixed build to accept, got {hex(sw)}"
