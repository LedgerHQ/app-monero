import hashlib
import hmac
import struct

from monero_client.monero_types import Type


def encode_msg_for_hmac(msg: bytes, msg_type: Type) -> bytes:
    """See monero_io_insert_hmac_for() in `monero_io.c`."""
    if msg_type == Type.ALPHA:
        raise Exception("Can't compute HMAC with type ALPHA.")

    return msg + struct.pack("B", msg_type) + (b"\x00" * 4)


def hmac_sha256(msg: bytes, key: bytes, monero_type: Type) -> bytes:
    return hmac.new(key,
                    msg=encode_msg_for_hmac(msg, monero_type),
                    digestmod=hashlib.sha256).digest()
