from typing import List


def encode_varint(value: int) -> bytes:
    if value == 0:
        return b"\x00"

    result: List[int] = []

    while value:
        result.append(0b10000000 | (value & 0b01111111))
        value >>= 7

    result[-1] &= 0x7f

    return bytes(result)


def decode_varint(value_encoded: bytes) -> int:
    result: int = 0
    shift: int = 0

    for byte in value_encoded:
        result |= (byte & 0b01111111) << shift
        shift += 7

        if byte & 0b10000000 == 0:
            return result

    return result
