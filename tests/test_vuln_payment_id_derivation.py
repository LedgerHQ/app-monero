"""
The payment-ID nonce is not bound to what the user reviewed.

V-071 made the prefix carry the exact encrypted payment ID the device produced.
This is the gap that left: INS_STEALTH takes *both* derivation operands from the
host and never checks either of them.

    monero_io_fetch(pub, KEY_SIZE);                 <- host picks the point
    err = monero_io_fetch_decrypt_key(sec, ...);    <- host picks the scalar
    monero_generate_key_derivation(drv, pub, sec, ...);

So nothing requires that `sec` is the transaction secret behind the on-chain R,
or that `pub` is the view key of the destination the device is about to show.
The prefix check proves the bytes came from the device; it does not prove the
reviewed recipient can decrypt them.

The result is a deposit that arrives at the right address carrying a payment ID
nobody can read: the service credits no one, and the money is effectively lost.
The user saw the integrated address they intended, and every other check passed.

Two independent bindings are missing, so there are two ways in:
  * the wrong scalar, with the right destination view key
  * the wrong view key, with the right transaction secret

Both are exercised below. The HMAC is not the obstacle: under DEBUG the wrapper
key is pinned, so the harness can wrap any scalar the way the device would.

The fix ties both operands down: INS_STEALTH takes only this transaction's
secret, keeps the point it was given, and the output review requires the Aout
it is about to display to be that same point.

Classes (one INS_STEALTH per transaction, so one per class):
  TestHonestDerivationAccepted   - control, the shape the wallet sends
  TestForeignSecretRefused       - wrong scalar, refused at INS_STEALTH
  TestForeignViewKeyRefused      - wrong point, refused at the output review
  TestDerivationHolesAccepted    - skipped; the behaviour before the fix
"""

import pytest
import nacl.bindings as nb
from ragger.backend.interface import BackendInterface

from ragger.error import ExceptionRAPDU

from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import InsType, Type
from monero_client.crypto.hmac import hmac_sha256
from monero_client.crypto.monero_math import sc_reduce32
from monero_client.status_words import SW_SECURITY_PAYMENT_ID

from test_vuln_payment_id_unbound import (
    PAY_ID_USER, _stealth, _nonce, _open_real, _gen_one_output,
    _stream_prefix, _tx_state)
from test_vuln_payment_id_unreviewed import _setup, FEE, ZERO_COMMITMENT

# A valid view key that is not the destination's: the point for scalar 0x44*32.
FOREIGN_A_PUB = nb.crypto_scalarmult_ed25519_base_noclamp(
    sc_reduce32(bytes([0x44] * 32)))


def _foreign_secret(wrapped_r: bytes) -> bytes:
    """A wrapped scalar the device will accept that is not the tx secret.

    The device XORs to decrypt under DEBUG, so flipping a byte of the wrapper
    yields a different plaintext scalar; _stealth re-computes the HMAC over
    whatever it is given, so provenance still checks out."""
    return bytes([wrapped_r[0] ^ 0xFF]) + wrapped_r[1:]


# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestHonestDerivationAccepted:
    """The shape monero-core sends: the destination view key and the tx secret
    the device handed out at open_tx. Must keep working."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_honest_derivation(monero: MoneroCmd, backend: BackendInterface,
                               device, test_name: str, state):
        _open_real(monero, state)
        enc = _stealth(backend, state["A"], state["r"], PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(monero, device, test_name, state, eph,
                                  extra_suffix=_nonce(enc))) == 32
        monero.close_tx()


@pytest.mark.incremental
class TestForeignSecretRefused:
    """
    Right destination, wrong scalar. Refused at INS_STEALTH itself, so the
    nonce is never produced and nothing reaches the review.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_foreign_secret_refused(monero: MoneroCmd,
                                    backend: BackendInterface, state):
        _open_real(monero, state)
        with pytest.raises(ExceptionRAPDU) as exc:
            _stealth(backend, state["A"], _foreign_secret(state["r"]),
                     PAY_ID_USER)
        assert exc.value.status == SW_SECURITY_PAYMENT_ID, (
            "expected %#06x for a payment ID derived from a foreign scalar, "
            "got %#06x" % (SW_SECURITY_PAYMENT_ID, exc.value.status))


@pytest.mark.incremental
class TestForeignViewKeyRefused:
    """
    Right scalar, wrong point.

    This one is refused at INS_VALIDATE, not at INS_STEALTH: when the mask is
    built the device does not yet know which destination the host will review,
    so the point is only checkable once Aout arrives. The prefix still accepts
    the nonce -- those bytes really are the device's -- which is exactly why
    the second binding has to exist.

    Nothing is drawn: the refusal comes before the address is built, so the
    send is synchronous.
    """

    @staticmethod
    def test_foreign_view_key_refused(monero: MoneroCmd,
                                      backend: BackendInterface,
                                      navigator: Navigator, device,
                                      test_name: str):
        (_addr, view, spend, ak, _enc,
         blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                                test_name, PAY_ID_USER,
                                                stealth_view=FOREIGN_A_PUB)

        monero.validate_prehash_init(test_name, device, navigator,
                                     index=1, txntype=0, txnfee=FEE)
        payload = b"".join((
            b"\x00",  # is_subaddress
            b"\x00",  # is_change_addr
            view, spend, ak,
            hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
            ZERO_COMMITMENT, blinded_mask, blinded_amount,
        ))
        try:
            monero.transport.send(cla=PROTOCOL_VERSION,
                                  ins=InsType.INS_VALIDATE,
                                  p1=2, p2=1, option=0x02, payload=payload)
            sw, _response = monero.transport.recv()
        except ExceptionRAPDU as exc:
            sw = exc.status
        assert sw == SW_SECURITY_PAYMENT_ID, (
            "expected %#06x for a payment ID derived against a foreign view "
            "key, got %#06x" % (SW_SECURITY_PAYMENT_ID, sw))


@pytest.mark.skip(reason="Shows the behaviour before the derivation operands "
                         "were bound. Needs a build without those checks.")
@pytest.mark.incremental
class TestDerivationHolesAccepted:
    """
    Both attacks as they stood: the device produced the nonce, the prefix check
    matched its own bytes, and the integrated address on screen was the one the
    user intended. Kept reproducible on an unfixed build.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_foreign_secret_was_accepted(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         device, test_name: str, state):
        _open_real(monero, state)
        enc = _stealth(backend, state["A"], _foreign_secret(state["r"]),
                       PAY_ID_USER)
        eph = _gen_one_output(monero, state)
        assert len(_stream_prefix(monero, device, test_name, state, eph,
                                  extra_suffix=_nonce(enc))) == 32
        monero.close_tx()

    @staticmethod
    def test_foreign_view_key_was_accepted(monero: MoneroCmd,
                                           backend: BackendInterface,
                                           navigator: Navigator, device,
                                           test_name: str):
        """Has to reach INS_VALIDATE to mean anything: the prefix accepted this
        nonce before the fix and still does, because those bytes are the
        device's. The review is where the binding lives."""
        (_addr, view, spend, ak, _enc,
         blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                                test_name, PAY_ID_USER,
                                                stealth_view=FOREIGN_A_PUB)

        monero.validate_prehash_init(test_name, device, navigator,
                                     index=1, txntype=0, txnfee=FEE)
        payload = b"".join((
            b"\x00", b"\x00", view, spend, ak,
            hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
            ZERO_COMMITMENT, blinded_mask, blinded_amount,
        ))
        monero.transport.send(cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE,
                              p1=2, p2=1, option=0x02, payload=payload)
        sw, _response = monero.transport.recv()
        assert sw == 0x9000, (
            "before the fix the review accepted a payment ID derived against "
            "a foreign view key, got %#06x" % sw)
