"""
monero_ecmul_8k clears the Ed25519 cofactor on the *scalar* instead of on the
point:

    error = monero_multm_8(s8, scalar32, sizeof(s8), scalar32_len);
    error = monero_ecmul_point(W, P, s8, W_len, P_len, sizeof(s8));

monero_multm_8 computes s8 = 8x mod l, and l is odd, so the reduction is the
whole problem. Write q = floor(8x/l), so s8 = 8x - q*l as integers. On a point
T of order 8 that gives

    [s8]T = [8x]T - [q*l]T = [-q*(l mod 8)]T = [-5q]T     (l mod 8 == 5)

and q -> -5q mod 8 is a bijection, so the answer names q exactly. Monero's own
generate_key_derivation multiplies by 8 on the point, [8]([x]P), which lands in
the prime-order subgroup whatever P was; the device's [8x mod l]P does not.

The identity rejection that follows the multiply only catches q == 0, which is
the one case where no reduction happened and the old arithmetic was right.

Observable: INS_STEALTH. It derives 8.x.P, keccaks the point with a tail byte
and XORs the low 8 bytes into the payment ID it returns in clear, so a zero
payment ID hands back the mask itself. With a torsion point there are only
eight possible derivations, so eight offline keccaks name the one the device
used.

The scalar has to be one the device protects but the harness can predict, or
there is nothing to demonstrate: q = floor(8x/l) is 0 for the test seed's
private view key, and at q = 0 the defect is inert. The chain is

    INS_GEN_KEY_DERIVATION   fake view-key sentinel, [m]G  ->  8.a.[m]G
    INS_DERIVATION_TO_SCALAR                              ->  Hs(that || 0)

both returned as wrappers the host cannot read, while the plaintexts follow
from the test seed. That scalar's q is 1, so the defect is live on it.

Unlike V-005's mixed-order case this is not a residual of a missing check: a
plain torsion point defeats the cofactor clearing the code claims to do, and
the description's doubling ladder over INS_SECRET_KEY_ADD turns the three bits
into the whole scalar.

The fix computes [x]([8]P) in one decompress, which is what monero-core does
(crypto.cpp:198-199, ge_scalarmult then ge_mul8), and keeps the identity test
on the result. Legitimate answers are unchanged, and it is no slower than the
scalar-side version it replaces, which matters for app-monero#181.

Classes:
  TestCofactorPremise        - no device: the reduction moves the torsion part
  TestHonestDerivation       - control: a real point derives the real value
  TestMixedOrderStillCleared - control: torsion is cleared, not refused
  TestTorsionPointRefused    - the finding, now refused
  TestQuotientLeakVuln       - skipped; the leak before the fix
"""

import struct

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from Crypto.Hash import keccak

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_crypto_cmd import PROTOCOL_VERSION
from monero_client.monero_types import InsType
from monero_client.status_words import SW_WRONG_DATA
from monero_client.crypto import ed25519_raw as ed
from monero_client.crypto.monero_math import (L, base, derivation_to_scalar,
                                              key_derivation, num, red)

# The test seed's private view key, from the client docstring. Known here so
# the leak can be checked against the truth rather than against itself.
VIEW_SECRET = bytes.fromhex(
    "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201")

# 32 zero bytes: the sentinel monero_io_fetch_decrypt_key swaps for the
# device's private view key.
FAKE_VIEW_KEY = bytes(32)

# Any scalar; [KNOWN_SCALAR]G is the point the derivation chain starts from.
KNOWN_SCALAR = 12345

# Index 0 already gives a scalar with q == 1. Nothing else about it matters.
OUTPUT_INDEX = 0

# monero_apdu_stealth appends this to the derivation before the keccak.
PAYMENT_ID_TAIL = b"\x8d"

# A zero payment ID, so the reply is the mask itself and not a ciphertext.
ZERO_PAYMENT_ID = bytes(8)

TORSION = ed.decompress(ed.ORDER_8_POINT)


def _raw_apdu(ins: InsType, payload: bytes) -> bytes:
    """One APDU in the app's framing. The option byte is the first data byte."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, 0, 0,
                       1 + len(payload), 0) + payload


def _stealth(backend: BackendInterface, pub: bytes, sec: bytes,
             payment_id: bytes) -> bytes:
    """INS_STEALTH with no HMAC after the scalar.

    Outside a transaction the device consumes none, so an interleaved one
    would be read as the payment ID."""
    out = backend.exchange_raw(
        _raw_apdu(InsType.INS_STEALTH, pub + sec + payment_id)).data
    assert len(out) == 8, "expected 8 bytes, got %d" % len(out)
    return out


def _mask(derivation: bytes) -> bytes:
    """The 8 bytes INS_STEALTH XORs into the payment ID."""
    return keccak.new(digest_bits=256,
                      data=derivation + PAYMENT_ID_TAIL).digest()[:8]


def _target_scalar() -> bytes:
    """The plaintext of the scalar the device will be asked to multiply by."""
    drv = key_derivation(base(red(KNOWN_SCALAR)), VIEW_SECRET)
    return derivation_to_scalar(drv, OUTPUT_INDEX)


def _target_wrapper(monero: MoneroCmd) -> bytes:
    """The same scalar as a wrapper, which is all the host ever holds."""
    pub = base(red(KNOWN_SCALAR))
    enc_drv = monero.gen_key_derivation(pub_key=pub, _priv_key=FAKE_VIEW_KEY)
    return monero.derivation_to_scalar(enc_drv, OUTPUT_INDEX)


def _quotient(scalar: bytes) -> int:
    """q = floor(8x/l): what the reduction leaks."""
    return (8 * num(scalar)) // L


@pytest.mark.incremental
class TestCofactorPremise:
    """No device. If this fails the rest is noise."""

    @staticmethod
    def test_l_is_five_mod_eight(monero: MoneroCmd):
        assert L % 8 == 5
        assert sorted((-5 * q) % 8 for q in range(8)) == list(range(8)), \
            "q -> -5q mod 8 has to be a bijection, or q is not recoverable"

    @staticmethod
    def test_the_reduction_moves_the_torsion_component(monero: MoneroCmd):
        """[8x mod l]T is a live torsion point where [8]([x]T) is the identity."""
        x = num(_target_scalar())
        q = (8 * x) // L
        assert q, "the chosen scalar must have q != 0 or the defect is inert"

        reduced = ed.smul((8 * x) % L, TORSION)
        assert not ed.is_identity(reduced), \
            "the identity rejection would have caught it"
        assert ed.compress(reduced) == ed.compress(ed.smul((-5 * q) % 8,
                                                           TORSION))
        assert ed.is_identity(ed.smul(8, ed.smul(x, TORSION))), \
            "point-first cofactor clearing gives the identity, so a correct " \
            "device refuses instead of answering"

    @staticmethod
    def test_the_eight_answers_are_distinguishable(monero: MoneroCmd):
        """Eight offline keccaks are enough to read q off the reply."""
        masks = [_mask(ed.compress(ed.smul(j, TORSION))) for j in range(8)]
        assert len(set(masks)) == 8


@pytest.mark.incremental
class TestHonestDerivation:
    """
    The control that matters. A guard that refused everything, or one that
    changed the arithmetic, would still satisfy the refusal class below, so
    this asserts the *value*: 8.a.[m]G, computed independently.
    """

    @staticmethod
    def test_prime_order_point_derives_the_reference_value(
            monero: MoneroCmd, backend: BackendInterface):
        pub = base(red(KNOWN_SCALAR))
        got = _stealth(backend, pub, FAKE_VIEW_KEY, ZERO_PAYMENT_ID)
        want = _mask(key_derivation(pub, VIEW_SECRET))
        assert got == want, (
            "a legitimate point must still derive the same mask\n"
            "  got  %s\n  want %s" % (got.hex(), want.hex()))


@pytest.mark.incremental
class TestMixedOrderStillCleared:
    """
    A point with a torsion part must be cleared, not refused. monero-core's
    generate_key_derivation accepts one and mul8s it, and the transaction
    public key it passes comes off the chain, so refusing would stop the
    wallet scanning an output any software wallet handles.

    [8](Q + T) = [8]Q, so the answer is the prime-order one.
    """

    @staticmethod
    def test_mixed_order_point_gives_the_prime_order_answer(
            monero: MoneroCmd, backend: BackendInterface):
        point = ed.compress(ed.mixed_order_point(KNOWN_SCALAR))
        got = _stealth(backend, point, FAKE_VIEW_KEY, ZERO_PAYMENT_ID)
        want = _mask(key_derivation(base(red(KNOWN_SCALAR)), VIEW_SECRET))
        assert got == want, (
            "torsion has to be cleared, leaving 8.a.Q\n"
            "  got  %s\n  want %s" % (got.hex(), want.hex()))


@pytest.mark.incremental
class TestTorsionPointRefused:
    """
    The finding. A pure torsion point reached a secret multiply and the answer
    named floor(8x/l); [8]P is the identity, so it is now refused before the
    scalar is used. The refusal ends the app, so it is the last test here.
    """

    @staticmethod
    def test_wrapper_chain_hides_the_scalar(monero: MoneroCmd):
        """The device returns it encrypted; only the harness knows the value."""
        wrapper = _target_wrapper(monero)
        assert wrapper != _target_scalar(), \
            "the scalar must reach the device as a wrapper, not in clear"

    @staticmethod
    def test_torsion_point_refused(monero: MoneroCmd,
                                   backend: BackendInterface):
        wrapper = _target_wrapper(monero)
        with pytest.raises(ExceptionRAPDU) as exc:
            _stealth(backend, ed.ORDER_8_POINT, wrapper, ZERO_PAYMENT_ID)
        assert exc.value.status == SW_WRONG_DATA, (
            "expected %#06x for a point of order dividing eight, got %#06x"
            % (SW_WRONG_DATA, exc.value.status))


@pytest.mark.skip(reason="Shows the leak before the cofactor clearing moved "
                         "to the point; passes only on a build that still "
                         "multiplies the scalar by eight.")
@pytest.mark.incremental
class TestQuotientLeakVuln:
    """
    What the device used to answer: one of eight torsion masks, from which
    floor(8x/l) falls out. Kept reproducible on an unfixed build.
    """

    @staticmethod
    def test_reply_names_the_quotient(monero: MoneroCmd,
                                      backend: BackendInterface):
        q = _quotient(_target_scalar())
        wrapper = _target_wrapper(monero)

        got = _stealth(backend, ed.ORDER_8_POINT, wrapper, ZERO_PAYMENT_ID)

        candidates = {_mask(ed.compress(ed.smul(j, TORSION))): j
                      for j in range(8)}
        assert got in candidates, (
            "the reply should be one of the eight torsion masks, got %s"
            % got.hex())
        j = candidates[got]
        assert j == (-5 * q) % 8
        assert (-5 * j) % 8 == q, \
            "the host reads q = %d back out of the reply" % q
