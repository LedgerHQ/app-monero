import struct
from typing import Tuple

from monero_client.crypto.hmac import hmac_sha256
from monero_client.exception.device_error import DeviceError
from monero_client.monero_types import InsType
from monero_client.monero_types import Type
from monero_client.io.transport import Transport

PROTOCOL_VERSION: int = 3


class MoneroCryptoCmd:
    HMAC_KEY: bytes = b"\xab" * 32

    def __init__(self, debug: bool = False, speculos: bool = False) -> None:
        self.device = Transport(debug=debug, speculos=speculos)
        self.is_in_tx_mode = False

    @staticmethod
    def xor_cipher(value: bytes, key: bytes) -> bytes:
        assert len(key) == 1

        return bytes([byte ^ int.from_bytes(key, byteorder="big")
                      for byte in value])

    def secret_scalar_mul_key(self,
                              pub_key: bytes,
                              _scalar: bytes) -> bytes:
        ins: InsType = InsType.INS_SECRET_SCAL_MUL_KEY

        payload: bytes = b"".join([
            pub_key,
            _scalar,  # encrypted scalar
            hmac_sha256(_scalar,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),  # hmac
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 32

        return response  # scalar * pub_key

    def secret_scalar_mul_base(self,
                               _priv_key: bytes):
        ins: InsType = InsType.INS_SECRET_SCAL_MUL_BASE

        payload: bytes = b"".join([
            _priv_key,  # encrypted priv_key
            hmac_sha256(_priv_key,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),  # hmac
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 32

        return response  # priv_key * G

    def get_public_keys(self) -> Tuple[bytes, bytes, str]:
        ins: InsType = InsType.INS_GET_KEY

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=1,
                         p2=0,
                         option=0)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=1")

        assert len(response) == 159

        view_pub_key = response[:32]
        spend_pub_key = response[32:64]
        base58_address = response[64:159].decode("ascii")

        return view_pub_key, spend_pub_key, base58_address

    def get_private_view_key(self, button) -> bytes:
        ins: InsType = InsType.INS_GET_KEY

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=2,
                         p2=0,
                         option=0)

        # "Export View Key"
        button.right_click()

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=2")

        assert len(response) == 32

        return response  # priv_view_key

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        ins: InsType = InsType.INS_GENERATE_KEYPAIR

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        if self.is_in_tx_mode:
            assert len(response) == 96  # The secret is encrypted and a MAC is used
        else:
            assert len(response) == 64  # The secret is only encrypted

        return response[:32], response[32:]  # pub_key, _priv_key

    def verify_key(self, _priv_key: bytes, pub_key: bytes) -> bool:
        ins: InsType = InsType.INS_VERIFY_KEY

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=_priv_key + pub_key)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 4

        # 32 bits integer (should be 0 or 1)
        verified, *_ = struct.unpack(">I", response)

        return True if verified else False

    def generate_key_image(self, _priv_key: bytes, pub_key: bytes) -> bytes:
        ins: InsType = InsType.INS_GEN_KEY_IMAGE

        payload: bytes = b"".join([
            pub_key,
            _priv_key,
            hmac_sha256(_priv_key,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),  # hmac
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 32

        return response  # key image

    def put_key(self,
                priv_view_key: bytes,
                pub_view_key: bytes,
                priv_spend_key: bytes,
                pub_spend_key: bytes,
                address: str) -> None:
        ins: InsType = InsType.INS_PUT_KEY

        payload: bytes = b"".join([
            priv_view_key,
            pub_view_key,
            priv_spend_key,
            pub_spend_key,
            address.encode("ascii")
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 0

    def gen_key_derivation(self, pub_key: bytes, _priv_key: bytes) -> bytes:
        ins: InsType = InsType.INS_GEN_KEY_DERIVATION

        payload: bytes = b"".join([
            pub_key,
            _priv_key,
            hmac_sha256(_priv_key,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        _d_in: bytes = response[:32]  # encrypted derivation

        if self.is_in_tx_mode:
            assert len(response) == 64
            hmac_d_in: bytes = response[32:64]

            assert (hmac_d_in == hmac_sha256(_d_in,
                                             MoneroCryptoCmd.HMAC_KEY,
                                             Type.DERIVATION))
        else:
            assert len(response) == 32

        return _d_in
