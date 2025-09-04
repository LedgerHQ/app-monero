import struct
from typing import Tuple

from .crypto.hmac import hmac_sha256
from .exception.device_error import DeviceError
from .monero_types import InsType
from .monero_types import Type
from .io.transport import Transport
from pathlib import Path
from ledgered.devices import Device, DeviceType

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID, NavIns
from .utils.utils import get_nano_review_instructions

PROTOCOL_VERSION: int = 3
TESTS_ROOT_DIR = Path(__file__).parent.parent


class MoneroCryptoCmd:
    HMAC_KEY: bytes = b"\xab" * 32

    def __init__(self, backend: BackendInterface, debug: bool = False) -> None:
        self.transport = Transport(backend, debug=debug)
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

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins)

        assert len(response) == 32

        return response  # scalar * pub_key

    def secret_scalar_mul_base(self, _priv_key: bytes):
        ins: InsType = InsType.INS_SECRET_SCAL_MUL_BASE

        payload: bytes = b"".join([
            _priv_key,  # encrypted priv_key
            hmac_sha256(_priv_key,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),  # hmac
        ])

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins)

        assert len(response) == 32

        return response  # priv_key * G

    def get_public_keys(self) -> Tuple[bytes, bytes, str]:
        ins: InsType = InsType.INS_GET_KEY

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=1,
                         p2=0,
                         option=0)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins, "P1=1")

        assert len(response) == 159

        view_pub_key = response[:32]
        spend_pub_key = response[32:64]
        base58_address = response[64:159].decode("ascii")

        return view_pub_key, spend_pub_key, base58_address

    def display_address(self,
                        test_name: str,
                        device: Device,
                        navigator: Navigator,
                        derivation: bytes,
                        output_index: bytes,
                        screen_num: int = 3) -> bytes:
        ins: InsType = InsType.INS_DISPLAY_ADDRESS

        payload: bytes = b"".join([
            derivation,
            output_index,
        ])

        if device.type == DeviceType.NANOS:
            instructions = get_nano_review_instructions(8)
        elif device.is_nano:
            instructions = get_nano_review_instructions(4)
        elif device.type == DeviceType.APEX_P:
            instructions = [
                NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
                NavIns(NavInsID.TOUCH, (150, 250)),
                NavIns(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR),
                NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
                NavIns(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM),
                NavIns(NavInsID.USE_CASE_STATUS_DISMISS)
            ]
        elif device.type == DeviceType.FLEX or screen_num == 3:
            instructions = [
                NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
                NavIns(NavInsID.TOUCH, (200, 350 if device.type == DeviceType.FLEX else 375)),
                NavIns(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR),
                NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
                NavIns(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM),
                NavIns(NavInsID.USE_CASE_STATUS_DISMISS)
            ]
        elif device.type == DeviceType.STAX:
            instructions = [
                NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
                NavIns(NavInsID.TOUCH, (63, 519)),
                NavIns(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR),
                NavIns(NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM),
                NavIns(NavInsID.USE_CASE_STATUS_DISMISS)
            ]
        with self.transport.send_async(cla=PROTOCOL_VERSION,
                                    ins=ins,
                                    p1=0,
                                    p2=0,
                                    option=0,
                                    payload=payload):

            navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                           test_name,
                                           instructions)

        sw, response = self.transport.async_response()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins, "P1=2")

        return response  # priv_view_key

    def get_private_view_key(self,
                             test_name: str,
                             device: Device,
                             navigator: Navigator,
                             refuse: bool = False) -> bytes:
        ins: InsType = InsType.INS_GET_KEY

        if not refuse:
            if device.is_nano:
                instructions = get_nano_review_instructions(1)
            else:
                instructions = [
                    NavIns(NavInsID.USE_CASE_CHOICE_CONFIRM)
                ]
        else:
            if device.is_nano:
                instructions = get_nano_review_instructions(2)
            else:
                instructions = [
                    NavIns(NavInsID.USE_CASE_CHOICE_REJECT)
                ]
        try:

            with self.transport.send_async(cla=PROTOCOL_VERSION,
                                        ins=ins,
                                        p1=2,
                                        p2=0,
                                        option=0):

                navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                               test_name,
                                               instructions)

            sw, response = self.transport.async_response()  # type: int, bytes
        except ExceptionRAPDU as e:
            # Looking for Deny value
            if e.status == 0x6982 and refuse and not e.data:
                return None
            else:
                raise ValueError(e)

        if not sw & 0x9000:
            raise DeviceError(sw, ins, "P1=2")

        assert len(response) == 32

        return response  # priv_view_key

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        ins: InsType = InsType.INS_GENERATE_KEYPAIR

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins)

        if self.is_in_tx_mode:
            assert len(response) == 96  # The secret is encrypted and a MAC is used
        else:
            assert len(response) == 64  # The secret is only encrypted

        return response[:32], response[32:]  # pub_key, _priv_key

    def verify_key(self, _priv_key: bytes, pub_key: bytes) -> bool:
        ins: InsType = InsType.INS_VERIFY_KEY

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=_priv_key + pub_key)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins)

        assert len(response) == 4

        # 32 bits integer (should be 0 or 1)
        verified, *_ = struct.unpack(">I", response)

        return bool(verified)

    def generate_key_image(self, _priv_key: bytes, pub_key: bytes) -> bytes:
        ins: InsType = InsType.INS_GEN_KEY_IMAGE

        payload: bytes = b"".join([
            pub_key,
            _priv_key,
            hmac_sha256(_priv_key,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),  # hmac
        ])

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
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

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
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

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
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

    def derive_view_tag(self, derivation: bytes, output_index: bytes) -> int:
        ins: InsType = InsType.INS_DERIVE_VIEW_TAG

        payload: bytes = b"".join([
            derivation,
            output_index,
        ])

        self.transport.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.transport.recv()  # type: int, bytes

        if not sw & 0x9000:
            raise DeviceError(sw, ins)

        assert len(response) == 1

        return int.from_bytes(response, "big")
