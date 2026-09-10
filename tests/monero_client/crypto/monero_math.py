"""Monero's ed25519 scalar and point arithmetic, for test-side references.

These mirror what the device computes, so a test can predict an answer instead
of trusting the device to check itself. They were hand-rolled in four separate
test files before, in four spellings of the same maths; the helpers here are
the union of those.

`nacl.bindings` rejects points outside the prime-order subgroup, so anything
needing torsion points has to do its own arithmetic.
"""

import nacl.bindings as nb
from Crypto.Hash import keccak

from ..utils.varint import encode_varint

#: order of the ed25519 prime-order subgroup
L = 2 ** 252 + 27742317777372353535851937790883648493


def num(s: bytes) -> int:
    """Little-endian bytes to int, the encoding Monero scalars use."""
    return int.from_bytes(s, "little")


def red(n: int) -> bytes:
    """int to a reduced 32-byte little-endian scalar."""
    return (n % L).to_bytes(32, "little")


def sc_reduce32(b: bytes) -> bytes:
    """Reduce a 32-byte little-endian scalar mod L."""
    return red(num(b))


def hash_to_scalar(data: bytes) -> bytes:
    """Hs(data) - keccak-256 then reduce. Monero's Hs, not SHA3."""
    return red(num(keccak.new(digest_bits=256, data=data).digest()))


def key_derivation(pub: bytes, priv: bytes) -> bytes:
    """8 * priv * pub, Monero's ECDH derivation. No clamping."""
    return nb.crypto_scalarmult_ed25519_noclamp(red(num(priv) * 8), pub)


def derivation_to_scalar(derivation: bytes, index: int) -> bytes:
    """Hs(derivation || varint(index)), the per-output scalar."""
    return hash_to_scalar(derivation + encode_varint(index))


def mul(scalar: bytes, point: bytes) -> bytes:
    """scalar * point."""
    return nb.crypto_scalarmult_ed25519_noclamp(scalar, point)


def base(scalar: bytes) -> bytes:
    """scalar * G."""
    return nb.crypto_scalarmult_ed25519_base_noclamp(scalar)


def add(p: bytes, q: bytes) -> bytes:
    """p + q."""
    return nb.crypto_core_ed25519_add(p, q)


def one_time_key(derivation: bytes, index: int, spend_pub: bytes) -> bytes:
    """Hs(derivation || varint(index)).G + B - the key that lands in vout."""
    return add(base(derivation_to_scalar(derivation, index)), spend_pub)


def recipient_scan(tx_pub_key: bytes, index: int, view_sec: bytes,
                   spend_pub: bytes) -> bytes:
    """The one-time key a recipient computes for `index`, from their own keys."""
    return one_time_key(key_derivation(tx_pub_key, view_sec), index, spend_pub)
