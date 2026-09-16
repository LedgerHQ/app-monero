"""
monero_ecmul_k multiplies a host-supplied point by a device secret, and only
rejects points whose order divides 8.

    error = monero_ecmul_8(eightP, P, sizeof(eightP), P_len);
    if (memcmp(eightP, ED25519_IDENTITY, 32) == 0) {
        return SW_WRONG_DATA;          /* pure torsion: rejected */
    }

That catches a *pure* torsion point. It does not catch a **mixed-order** one.
For P = Q + T with Q in the prime-order subgroup and T of order 8, [8]P = [8]Q
is not the identity, so P sails through -- and

    [x]P = [x]Q + [x mod 8]T

still carries the low three bits of the secret. Q is prime-order, so the host
recovers them by finding the one j in 0..7 for which [x]P - [j]T lands back in
the prime subgroup.

INS_SECRET_SCAL_MUL_KEY reaches this with the device's own private view key:
monero_io_fetch_decrypt_key() substitutes G_monero_vstate.a for the fake
view-key sentinel on any instruction, and outside a transaction the wrapper
carries no HMAC (src/monero_io.c:345-359).

The finding's own remediation -- "multiplying it by 8 and verifying it is not
the identity" -- is what the device already did, so the literal report was
closed. What these tests cover is the residual it left.

The fix replaces the [8]P test with the exact one, [l]P == identity, which
rejects torsion of any order and so subsumes the old check. monero-core makes
the same test itself in multisig key exchange (multisig_kex_msg.cpp:87), and
every point it sends the device is a sum of [scalar]G, so nothing legitimate
is refused.

nacl cannot build the input: it validates subgroup membership. The arithmetic
lives in monero_client/crypto/ed25519_raw.py, cross-checked against nacl on
prime-order points by the premise class below.

Classes:
  TestMixedOrderPremise       - no device: the point defeats an [8]P guard
  TestLegitimatePointAccepted - control: a real point still gives a real answer
  TestPureTorsionRefused      - the old guard's case, still refused
  TestMixedOrderRefused       - the finding, now refused
  TestViewKeyBitsLeakVuln     - skipped; the leak before the fix
"""

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd
from monero_client.status_words import SW_WRONG_DATA
from monero_client.crypto import ed25519_raw as ed

# The test seed's private view key, from the client docstring. Known here only
# so the leak can be asserted against the truth rather than against itself.
VIEW_SECRET = bytes.fromhex(
    "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201")
VIEW_SECRET_MOD8 = int.from_bytes(VIEW_SECRET, "little") % 8

# 32 zero bytes: the sentinel monero_io_fetch_decrypt_key swaps for the
# device's private view key.
FAKE_VIEW_KEY = bytes(32)

# Any prime-order scalar; the point is [KNOWN_SCALAR]G + T.
KNOWN_SCALAR = 12345


@pytest.mark.incremental
class TestMixedOrderPremise:
    """No device. If this fails the rest is noise."""

    @staticmethod
    def test_raw_arithmetic_agrees_with_nacl(monero: MoneroCmd):
        import nacl.bindings as nb
        from monero_client.crypto.monero_math import sc_reduce32
        for seed in (b"\x01" + bytes(31), b"\x02" + bytes(31), b"\xab" * 32):
            s = sc_reduce32(seed)
            mine = ed.compress(ed.smul(int.from_bytes(s, "little"),
                                       ed.basepoint()))
            assert mine == nb.crypto_scalarmult_ed25519_base_noclamp(s)

    @staticmethod
    def test_mixed_point_defeats_an_eight_p_guard(monero: MoneroCmd):
        p = ed.mixed_order_point(KNOWN_SCALAR)
        assert not ed.is_low_order(p), \
            "a mixed-order point must not look low-order, or the guard catches it"
        assert not ed.in_prime_subgroup(p), \
            "and it must not be prime-order, or there is nothing to leak"

    @staticmethod
    def test_the_low_bits_are_recoverable(monero: MoneroCmd):
        """Done locally first: given [x]P, recover x mod 8."""
        p = ed.mixed_order_point(KNOWN_SCALAR)
        x = int.from_bytes(VIEW_SECRET, "little") % ed.L
        assert ed.recover_mod8(ed.smul(x, p)) == VIEW_SECRET_MOD8


@pytest.mark.incremental
class TestLegitimatePointAccepted:
    """
    The control that matters. A subgroup check that refused everything would
    satisfy both refusal classes below, so this asserts the *value*, not just
    that the call succeeded: [a]([k]G) has to equal [a*k mod l]G, which the
    harness computes independently.
    """

    @staticmethod
    def test_prime_order_point_gives_the_right_answer(monero: MoneroCmd):
        import nacl.bindings as nb
        from monero_client.crypto.monero_math import red

        point = ed.compress(ed.smul(KNOWN_SCALAR, ed.basepoint()))
        got = monero.secret_scalar_mul_key(pub_key=point,
                                           _scalar=FAKE_VIEW_KEY)

        a = int.from_bytes(VIEW_SECRET, "little")
        want = nb.crypto_scalarmult_ed25519_base_noclamp(
            red(a * KNOWN_SCALAR % ed.L))
        assert got == want, (
            "a legitimate point must still multiply correctly\n"
            "  got  %s\n  want %s" % (got.hex(), want.hex()))


@pytest.mark.incremental
class TestPureTorsionRefused:
    """The case the old [8]P guard caught. The subgroup check subsumes it, so
    this must keep refusing -- it is how we know the new test did not narrow
    what the old one covered."""

    @staticmethod
    def test_pure_torsion_refused(monero: MoneroCmd):
        with pytest.raises(ExceptionRAPDU) as exc:
            monero.secret_scalar_mul_key(pub_key=ed.ORDER_8_POINT,
                                         _scalar=FAKE_VIEW_KEY)
        assert exc.value.status == SW_WRONG_DATA, (
            "expected %#06x for a low-order point, got %#06x"
            % (SW_WRONG_DATA, exc.value.status))


@pytest.mark.incremental
class TestMixedOrderRefused:
    """
    The finding. A point with a prime-order part and a torsion part passes an
    [8]P guard; the device now rejects it before the secret is used.
    """

    @staticmethod
    def test_mixed_order_refused(monero: MoneroCmd):
        point = ed.compress(ed.mixed_order_point(KNOWN_SCALAR))
        with pytest.raises(ExceptionRAPDU) as exc:
            monero.secret_scalar_mul_key(pub_key=point,
                                         _scalar=FAKE_VIEW_KEY)
        assert exc.value.status == SW_WRONG_DATA, (
            "expected %#06x for a mixed-order point, got %#06x"
            % (SW_WRONG_DATA, exc.value.status))


@pytest.mark.skip(reason="Shows the leak before the subgroup check; passes "
                         "only on a build that still guards with [8]P alone.")
@pytest.mark.incremental
class TestViewKeyBitsLeakVuln:
    """
    What the device used to answer: [a]P for a mixed-order P, from which the
    low three bits of the private view key fall out. Kept reproducible.
    """

    @staticmethod
    def test_response_revealed_the_view_key_mod_8(monero: MoneroCmd,
                                                  backend: BackendInterface):
        point = ed.compress(ed.mixed_order_point(KNOWN_SCALAR))
        result = monero.secret_scalar_mul_key(pub_key=point,
                                              _scalar=FAKE_VIEW_KEY)
        assert ed.recover_mod8(ed.decompress(result)) == VIEW_SECRET_MOD8
