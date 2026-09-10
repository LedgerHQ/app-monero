"""GET_TX_PROOF signs with whatever scalar it is handed.

The sink at src/monero_proof.c:53 decrypts an `r` out of any wrapper the device
ever produced and never checks that the public fields it was also given are
consistent with it: not R == r.G, not D == r.A. The response is Schnorr-linear,
`sig_r = k - sig_c*r`, so a wrapper whose offset from the master spend key is
known to the host converts into a signature under the master spend key itself.

DERIVE_SECRET_KEY supplies exactly such a wrapper. It is on the fake-spend-key
allowlist (src/monero_io.c:345), so it will compute `x = Hs(derivation||index) + b`
with `b` the master spend scalar, and hand it back as a generic TYPE_SCALAR
blob. The host knows the hash term because it knows the derivation: the wallet
holds the private view key by design, to scan the chain without the device
(device_ledger.cpp:611-628, "View key is retrievied, if allowed, to speed up
blockchain parsing").

So: ask for a proof with R = B, A = G, D = B and that wrapper as r. The device
returns (c, s = k - c*(h+b)). Add c*h and you hold (c, k - c*b), a TXPROOF_V2
signature under the wallet's spend key over a message of the attacker's choice.
Nothing is displayed and no transaction is open.

The premise is pure algebra and is proved here first, with no device at all. If
that fails, the rest means nothing.

Outside a transaction the device applies no HMAC to its wrappers and binds no
type to them, so a blob minted by one instruction is accepted by another. The
test never encrypts anything: every wrapper it submits came from the device.
"""

import os

import pytest
import nacl.bindings as nb
from Crypto.Hash import keccak

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_crypto_cmd import MoneroCryptoCmd

_L = 2 ** 252 + 27742317777372353535851937790883648493

# The sentinels the wallet substitutes for the real keys. src/monero_init.c:30.
FAKE_VIEW_KEY = bytes(32)
FAKE_SPEND_KEY = b"\xff" * 32

# The test seed "abandon ... about". Present so the test can assert the forged
# response really is k - c*b, rather than just that a verifier accepts it.
SECRET_SPEND_KEY = bytes.fromhex(
    "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109")
PUBLIC_SPEND_KEY = bytes.fromhex(
    "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d")

G = nb.crypto_scalarmult_ed25519_base_noclamp((1).to_bytes(32, "little"))
SEP = keccak.new(digest_bits=256, data=b"TXPROOF_V2").digest()


def _num(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _red(n: int) -> bytes:
    return (n % _L).to_bytes(32, "little")


def _hs(data: bytes) -> bytes:
    return _red(_num(keccak.new(digest_bits=256, data=data).digest()))


def _mul(scalar: bytes, point: bytes) -> bytes:
    return nb.crypto_scalarmult_ed25519_noclamp(scalar, point)


def _base(scalar: bytes) -> bytes:
    return nb.crypto_scalarmult_ed25519_base_noclamp(scalar)


def _add(p: bytes, q: bytes) -> bytes:
    return nb.crypto_core_ed25519_add(p, q)


def _key_derivation(pub: bytes, priv: bytes) -> bytes:
    """8 * priv * pub, Monero's ECDH derivation. No clamping."""
    return _mul(_red(_num(priv) * 8), pub)


def _derivation_to_scalar(derivation: bytes, index: int) -> bytes:
    """Hs(derivation || varint(index)). Indices below 128 are one byte."""
    assert index < 128
    return _hs(derivation + bytes([index]))


def _challenge(msg, D, X, Y, R, A, B) -> bytes:
    """Hs(msg || D || X || Y || sep || R || A || B), s_comm_2 in crypto.cpp."""
    return _hs(msg + D + X + Y + SEP + R + A + B)


def _verify_txproof_v2(msg, R, A, B, D, sig_c, sig_r) -> bool:
    """crypto_ops::check_tx_proof for TXPROOF_V2, independent of the device.

    X = c.R + s.B if B is present else c.R + s.G;  Y = c.D + s.A.
    """
    X = _add(_mul(sig_c, R), _mul(sig_r, B) if B else _base(sig_r))
    Y = _add(_mul(sig_c, D), _mul(sig_r, A))
    return _challenge(msg, D, X, Y, R, A, B or bytes(32)) == sig_c


def _device_side(msg, R, A, B_field, D, x, k):
    """What src/monero_proof.c computes, standard mode. For the premise only."""
    X, Y = _base(k), _mul(k, A)
    sig_c = _challenge(msg, D, X, Y, R, A, B_field)
    return sig_c, _red(_num(k) - _num(sig_c) * _num(x))


class TestForgeryAlgebra:
    """No device. If these do not hold, nothing below them is interesting."""

    def test_seed_keys_are_consistent(self):
        assert _base(SECRET_SPEND_KEY) == PUBLIC_SPEND_KEY

    def test_offset_wrapper_converts_to_a_spend_key_signature(self):
        b = SECRET_SPEND_KEY
        B = PUBLIC_SPEND_KEY
        msg = os.urandom(32)
        h = _hs(b"a derivation the host can compute")
        x = _red(_num(h) + _num(b))          # what DERIVE_SECRET_KEY wraps
        k = _red(_num(os.urandom(32)))       # the device's nonce

        # the host presents the victim's spend key as the transaction key
        R, A, D = B, G, B
        sig_c, sig_r = _device_side(msg, R, A, bytes(32), D, x, k)

        # what the device returned is not itself a valid proof
        assert not _verify_txproof_v2(msg, R, A, None, D, sig_c, sig_r)

        adjusted = _red(_num(sig_r) + _num(sig_c) * _num(h))

        assert adjusted == _red(_num(k) - _num(sig_c) * _num(b)), \
            "the adjusted response is not k - c*b"
        assert _verify_txproof_v2(msg, R, A, None, D, sig_c, adjusted), \
            "the adjusted signature does not verify under the spend key"

    def test_a_legitimate_proof_verifies(self):
        """Controls the verifier itself: it must accept an honest proof."""
        msg = os.urandom(32)
        r = _red(_num(os.urandom(32)))
        A = _base(_red(_num(os.urandom(32))))   # some recipient view key
        R, D = _base(r), _mul(r, A)
        k = _red(_num(os.urandom(32)))
        sig_c, sig_r = _device_side(msg, R, A, bytes(32), D, r, k)

        assert _verify_txproof_v2(msg, R, A, None, D, sig_c, sig_r)


SW_WRONG_DATA = 0x6984

OUTPUT_INDEX = 7


def _spend_key_offset_wrapper(client, navigator, device, test_name):
    """Drive the device to hand back a wrapper for Hs(derivation||i) + b.

    Returns (h, wrapped_x, A, B). Nothing here is encrypted by the test: every
    wrapper submitted came out of the device.
    """
    A, B, _addr = client.get_public_keys()
    assert B == PUBLIC_SPEND_KEY, "unexpected seed on the device"

    # The view key, as the wallet itself obtains it. One approval.
    a = client.get_private_view_key(test_name, device, navigator)

    # A derivation whose plaintext the host can compute: it chose the point and
    # it holds the view key, so it does not need the device's answer.
    wrapped_d = client.gen_key_derivation(G, FAKE_VIEW_KEY)
    d = _key_derivation(G, a)
    assert MoneroCryptoCmd.xor_cipher(wrapped_d, b"\x55") == d, \
        "the derivation the host computed is not the one the device used"

    h = _derivation_to_scalar(d, OUTPUT_INDEX)

    # x = h + b, under the fake spend sentinel. A generic scalar wrapper with
    # nothing tying it to the instruction that made it.
    wrapped_x = client.derive_secret_key(wrapped_d, OUTPUT_INDEX,
                                         FAKE_SPEND_KEY)

    # h.G + B == x.G shows what the wrapper holds without needing b
    assert _add(_base(h), B) == _base(
        MoneroCryptoCmd.xor_cipher(wrapped_x, b"\x55")), \
        "the wrapper is not Hs(derivation||index) + b"

    return h, wrapped_x, A, B


class TestHonestProofsStillWork:
    """Both shapes the fix must keep accepting.

    Every field comes from the device, so these are real proofs satisfying
    R == r.G (or r.B) and D == r.A - exactly what the added check recomputes.
    A fix that merely banned wrappers at this sink would fail these.
    """

    def test_standard_mode_proof_is_accepted(self, backend: BackendInterface):
        client = MoneroCryptoCmd(backend)

        A, _B, _addr = client.get_public_keys()
        R, wrapped_r = client.generate_keypair()        # R = r.G
        D = client.secret_scalar_mul_key(A, wrapped_r)  # D = r.A

        msg = bytes.fromhex("a1" * 32)
        sig_c, sig_r = client.get_tx_proof(msg, R, A, bytes(32), D, wrapped_r)

        assert _verify_txproof_v2(msg, R, A, None, D, sig_c, sig_r), \
            "an honest standard-mode proof did not verify"

    def test_subaddress_mode_proof_is_accepted(self,
                                               backend: BackendInterface):
        """The other branch of the check: R is r.B, not r.G."""
        client = MoneroCryptoCmd(backend)

        A, B, _addr = client.get_public_keys()
        _R0, wrapped_r = client.generate_keypair()
        R = client.secret_scalar_mul_key(B, wrapped_r)  # R = r.B
        D = client.secret_scalar_mul_key(A, wrapped_r)  # D = r.A

        msg = bytes.fromhex("b2" * 32)
        sig_c, sig_r = client.get_tx_proof(msg, R, A, B, D, wrapped_r,
                                           subaddress=True)

        assert _verify_txproof_v2(msg, R, A, B, D, sig_c, sig_r), \
            "an honest subaddress-mode proof did not verify"


class TestForgedProofIsRefused:
    """The finding, inverted. One refusal, last in its class: a non-OK status
    reaches send_error_and_kill_app and the app exits."""

    def test_spend_key_offset_wrapper_is_refused(
            self, backend: BackendInterface, navigator: Navigator, device,
            test_name):
        client = MoneroCryptoCmd(backend)
        _h, wrapped_x, _A, B = _spend_key_offset_wrapper(
            client, navigator, device, test_name)

        # Claim the victim's spend key is the transaction key. R == x.G is
        # false, since x is h + b and R is b.G.
        with pytest.raises(ExceptionRAPDU) as exc_info:
            client.get_tx_proof(bytes.fromhex("5c" * 32), B, G, bytes(32), B,
                                wrapped_x)
        assert exc_info.value.status == SW_WRONG_DATA, (
            f"Expected SW_WRONG_DATA (0x6984), "
            f"got {hex(exc_info.value.status)}")


@pytest.mark.skip(reason="the behaviour before the fix; needs a build without "
                         "the R and D relation checks")
class TestSinkWasUnbound:
    """Kept so the finding stays reproducible on an unfixed build.

    Run with --run-skipped against a build lacking the checks: the device signs
    with a scalar it never related to the fields it was given, and adding c*h
    to the response yields a TXPROOF_V2 signature under the master spend key
    over a message the host chose, with no transaction open and nothing shown.
    """

    def test_the_sink_signs_under_the_master_spend_key(
            self, backend: BackendInterface, navigator: Navigator, device,
            test_name):
        client = MoneroCryptoCmd(backend)
        h, wrapped_x, _A, B = _spend_key_offset_wrapper(
            client, navigator, device, test_name)

        msg = bytes.fromhex("5c" * 32)   # any 32 bytes; hashed straight in
        R, A_arg, D = B, G, B
        sig_c, sig_r = client.get_tx_proof(msg, R, A_arg, bytes(32), D,
                                           wrapped_x)

        # What the device returned is not itself a forgery.
        assert not _verify_txproof_v2(msg, R, A_arg, None, D, sig_c, sig_r)

        adjusted = _red(_num(sig_r) + _num(sig_c) * _num(h))

        assert _verify_txproof_v2(msg, R, A_arg, None, D, sig_c, adjusted), \
            "the adjusted signature does not verify under the spend key"
