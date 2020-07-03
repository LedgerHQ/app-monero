"""MoneroPy - A python toolbox for Monero
Copyright (C) 2016 The MoneroPy Developers.

MoneroPy is released under the BSD 3-Clause license. Use and redistribution of
this software is subject to the license terms in the LICENSE file found in the
top-level directory of this distribution.

Modified by emesik and rooterkyberian:
 + optimized
 + proper exceptions instead of returning errors as results

"""

from typing import List

ALPHABET: List[int] = [
    ord(s) for s in ("123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
                     "abcdefghijkmnopqrstuvwxyz")
]
B58_BASE: int = 58
UINT64_MAX: int = 2 ** 64
ENCODED_BLOCK_SIZES: List[int] = [0, 2, 3, 5, 6, 7, 9, 10, 11]
FULL_BLOCK_SIZE: int = 8
FULL_ENCODED_BLOCK_SIZE: int = 11


def hex_to_bin(h: str) -> List[int]:
    if len(h) % 2 != 0:
        raise ValueError(f"Hex string has invalid length: {len(h)}")

    return [int(h[i:i + 2], 16) for i in range(0, len(h), 2)]


def bin_to_hex(b: bytes) -> str:
    return "".join("%02x" % int(b) for b in b)


def uint8be_to_64(data: bytes) -> int:
    if not (1 <= len(data) <= 8):
        raise ValueError(f"Invalid input length: {len(data)}")

    res: int = 0

    for b in data:  # type: int
        res = res << 8 | b

    return res


def uint64_to_8be(num: int, size: int) -> List[int]:
    if size < 1 or size > 8:
        raise ValueError(f"Invalid input length: {size}")

    res: List[int] = [0] * size

    two_pow8: int = 2 ** 8

    for i in range(size - 1, -1, -1):  # type: int
        res[i] = num % two_pow8
        num = num // two_pow8

    return res


def encode_block(data: bytes, buf: bytearray, index: int) -> bytearray:
    l_data: int = len(data)

    if l_data < 1 or l_data > FULL_ENCODED_BLOCK_SIZE:
        raise ValueError(f"Invalid block length: {l_data}")

    remainder: int
    num: int = uint8be_to_64(data)
    i: int = ENCODED_BLOCK_SIZES[l_data] - 1

    while num > 0:
        remainder = num % B58_BASE
        num = num // B58_BASE
        buf[index + i] = ALPHABET[remainder]
        i -= 1

    return buf


def encode(data: bytes) -> str:
    """Encode data bytes as base58 (ex: encoding a Monero address)."""
    l_data: int = len(data)

    if l_data == 0:
        return ""

    full_block_count: int = l_data // FULL_BLOCK_SIZE
    last_block_size: int = l_data % FULL_BLOCK_SIZE
    res_size: int = (full_block_count *
                     FULL_ENCODED_BLOCK_SIZE +
                     ENCODED_BLOCK_SIZES[last_block_size])

    res: bytearray = bytearray([ALPHABET[0]] * res_size)

    for i in range(full_block_count):  # type: int
        res = encode_block(
            data[(i * FULL_BLOCK_SIZE):(i * FULL_BLOCK_SIZE + FULL_BLOCK_SIZE)],
            res,
            i * FULL_ENCODED_BLOCK_SIZE
        )

    if last_block_size > 0:
        begin: int = full_block_count * FULL_BLOCK_SIZE
        end: int = full_block_count * FULL_BLOCK_SIZE + last_block_size
        res = encode_block(data[begin:end],
                           res,
                           full_block_count * FULL_ENCODED_BLOCK_SIZE)

    return bytes(res).decode("ascii")


def decode_block(data: bytes, buf: bytearray, index: int) -> bytearray:
    l_data: int = len(data)

    if l_data < 1 or l_data > FULL_ENCODED_BLOCK_SIZE:
        raise ValueError(f"Invalid block length: {l_data}")

    res_size: int = ENCODED_BLOCK_SIZES.index(l_data)

    if res_size <= 0:
        raise ValueError(f"Invalid block size: {res_size}")

    res_num: int = 0
    order: int = 1

    for i in range(l_data - 1, -1, -1):  # type: int
        digit: int = ALPHABET.index(data[i])
        if digit < 0:
            raise ValueError(f"Invalid symbol: {data[i]}")

        product: int = order * digit + res_num
        if product > UINT64_MAX:
            raise ValueError(
                f"Overflow: {order} * {digit} + {res_num} = {product}"
            )

        res_num: int = product
        order: int = order * B58_BASE

    if res_size < FULL_BLOCK_SIZE and 2 ** (8 * res_size) <= res_num:
        raise ValueError(f"Overflow: {res_num} doesn't fit in {res_size} bit(s)")

    tmp_buf: List[int] = uint64_to_8be(res_num, res_size)
    buf[index:index + len(tmp_buf)] = tmp_buf

    return buf


def decode(data_encoded: str) -> str:
    """Decode a base58 string (ex: a Monero address) into hexidecimal form."""
    data_encoded: bytearray = bytearray(data_encoded, encoding="ascii")
    l_enc: int = len(data_encoded)

    if l_enc == 0:
        return ""

    full_block_count: int = l_enc // FULL_ENCODED_BLOCK_SIZE
    last_block_size: int = l_enc % FULL_ENCODED_BLOCK_SIZE

    try:
        last_block_decoded_size: int = ENCODED_BLOCK_SIZES.index(last_block_size)
    except ValueError:
        raise ValueError(f"Invalid encoded length: {l_enc}")

    data_size: int = (full_block_count *
                      FULL_BLOCK_SIZE +
                      last_block_decoded_size)

    data: bytearray = bytearray(data_size)
    begin: int
    end: int

    for i in range(full_block_count):  # type: int
        begin = i * FULL_ENCODED_BLOCK_SIZE
        end = i * FULL_ENCODED_BLOCK_SIZE + FULL_ENCODED_BLOCK_SIZE
        data = decode_block(data_encoded[begin:end],
                            data,
                            i * FULL_BLOCK_SIZE)

    if last_block_size > 0:
        begin = full_block_count * FULL_ENCODED_BLOCK_SIZE
        end = full_block_count * FULL_ENCODED_BLOCK_SIZE + last_block_size
        data = decode_block(data_encoded[begin:end],
                            data,
                            full_block_count * FULL_BLOCK_SIZE)

    return bin_to_hex(data)
