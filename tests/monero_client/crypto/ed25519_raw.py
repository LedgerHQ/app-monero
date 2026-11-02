"""Unvalidated Ed25519 point arithmetic, for building points nacl refuses.

`nacl.bindings` rejects anything outside the prime-order subgroup, which is
exactly what a subgroup-check test needs to send. These routines do the group
law directly and validate nothing, so they can produce a torsion point or a
mixed-order one. Correctness is checked against nacl for prime-order points in
the tests that use them.

Affine coordinates and Python ints: slow, and only ever used to build a handful
of points in a test.
"""

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P

IDENTITY = (0, 1)

# One of the canonical order-8 points. Any generator of the 8-torsion subgroup
# works; this encoding appears in the usual Ed25519 small-order test vectors.
ORDER_8_POINT = bytes.fromhex(
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")


def _inv(x):
    return pow(x, P - 2, P)


def add(p, q):
    """The twisted Edwards addition law. No subgroup or validity check."""
    x1, y1 = p
    x2, y2 = q
    k = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k) % P
    return (x3, y3)


def smul(n, p):
    """[n]p by double-and-add."""
    r = IDENTITY
    while n > 0:
        if n & 1:
            r = add(r, p)
        p = add(p, p)
        n >>= 1
    return r


def compress(p):
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decompress(b):
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x % 2 != sign:
        x = P - x
    return (x, y)


def basepoint():
    y = 4 * _inv(5) % P
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x % 2:
        x = P - x
    return (x, y)


def is_identity(p):
    return compress(p) == compress(IDENTITY)


def in_prime_subgroup(p):
    """What a real subgroup check tests: [l]P == identity."""
    return is_identity(smul(L, p))


def is_low_order(p):
    """What the device checks today: [8]P == identity. True only for a point
    whose order divides 8, so a mixed-order point passes."""
    return is_identity(smul(8, p))


def mixed_order_point(scalar):
    """[scalar]G + T, with T of order 8.

    Not in the prime-order subgroup, and not low order either, so it is
    accepted by an [8]P guard and still leaks the multiplier modulo 8."""
    return add(smul(scalar, basepoint()), decompress(ORDER_8_POINT))


def recover_mod8(result, torsion=None):
    """Given [x]P for P built by mixed_order_point, return x mod 8.

    [x]P = [x]Q + [x mod 8]T, and Q is prime-order, so subtracting the right
    multiple of T lands the whole thing back in the prime subgroup. Exactly one
    of the eight candidates does."""
    t = decompress(ORDER_8_POINT) if torsion is None else torsion
    hits = [j for j in range(8)
            if in_prime_subgroup(add(result, smul((8 - j) % 8, t)))]
    if len(hits) != 1:
        raise AssertionError("expected exactly one candidate, got %r" % hits)
    return hits[0]
