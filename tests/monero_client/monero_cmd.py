"""Simple client for Monero application

From test seed of 12 words:
"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

* view public: A = 865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa
* spend public: B = dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d
* view secret: a = 0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201
* spend secret: b = 3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109
* Stage net address: 5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE

"""

import struct
from typing import Tuple

from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import InsType, Type, SigType
from monero_client.crypto.hmac import hmac_sha256
from monero_client.exception.device_error import DeviceError
from monero_client.io.button import Button
from monero_client.utils.varint import encode_varint

PROTOCOL_VERSION: int = 3


class MoneroCmd(MoneroCryptoCmd):
    def __init__(self, debug: bool = False, speculos: bool = False) -> None:
        MoneroCryptoCmd.__init__(self, debug, speculos)

    def reset_and_get_version(self,
                              monero_client_version: bytes
                              ) -> Tuple[int, int, int]:
        ins: InsType = InsType.INS_RESET

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=monero_client_version)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 3

        major, minor, patch = struct.unpack(
            "BBB",
            response
        )  # type: int, int, int

        self.is_in_tx_mode = False

        return major, minor, patch

    def set_signature_mode(self, sig_type: SigType) -> int:
        ins: InsType = InsType.INS_SET_SIGNATURE_MODE

        payload: bytes = struct.pack("B", sig_type)

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=1,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 4

        sig_mode, *_ = struct.unpack(">I", response)

        if sig_mode not in (1, 2):
            raise Exception(f"Signature mode should be 1 (real) or 2 (fake).")

        return SigType.REAL if sig_mode else SigType.FAKE

    def open_tx(self) -> Tuple[bytes, bytes, bytes, bytes]:
        ins: InsType = InsType.INS_OPEN_TX

        # 4 bytes
        account: bytes = struct.pack(">I", 0)

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=1,
                         p2=0,
                         option=0,
                         payload=account)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        self.is_in_tx_mode = True

        assert len(response) == 224

        tx_pub_key: bytes = response[:32]  # R = r.G
        _tx_priv_key: bytes = response[32:64]  # r (encrypted)
        hmac_tx_priv_key: bytes = response[64:96]
        fake_view_key: bytes = response[96:128]
        hmac_fake_view_key: bytes = response[128:160]
        fake_spend_key: bytes = response[160:192]
        hmac_fake_spend_key: bytes = response[192:]

        assert (hmac_tx_priv_key == hmac_sha256(_tx_priv_key,
                                                MoneroCryptoCmd.HMAC_KEY,
                                                Type.SCALAR))
        assert (hmac_fake_view_key == hmac_sha256(fake_view_key,
                                                  MoneroCryptoCmd.HMAC_KEY,
                                                  Type.SCALAR))
        assert (hmac_fake_spend_key == hmac_sha256(fake_spend_key,
                                                   MoneroCryptoCmd.HMAC_KEY,
                                                   Type.SCALAR))

        return (tx_pub_key,
                _tx_priv_key,
                fake_view_key,
                fake_spend_key)

    def close_tx(self) -> None:
        ins: InsType = InsType.INS_CLOSE_TX

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        self.is_in_tx_mode = False

        assert len(response) == 0

    def gen_txout_keys(self,
                       _tx_priv_key: bytes,
                       tx_pub_key: bytes,
                       dst_pub_view_key: bytes,
                       dst_pub_spend_key: bytes,
                       output_index: int,
                       is_change_addr: bool,
                       is_subaddress: bool) -> Tuple[bytes, bytes]:
        ins: InsType = InsType.INS_GEN_TXOUT_KEYS

        payload: bytes = b"".join((
            struct.pack('>I', 0),  # tx_version
            _tx_priv_key,  # r (encrypted)
            hmac_sha256(_tx_priv_key,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.SCALAR),  # hmac
            tx_pub_key,  # R
            dst_pub_view_key,  # A_out
            dst_pub_spend_key,  # B_out
            struct.pack('>I', output_index),
            b"\x01" if is_change_addr else b"\x00",
            b"\x01" if is_subaddress else b"\x00",
            b"\x00" * 33,  # additional_txkeys
        ))

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 96

        _ak_amount = response[:32]
        hmac_ak_amount = response[32:64]
        out_ephemeral_pub_key = response[64:96]

        assert (hmac_ak_amount == hmac_sha256(_ak_amount,
                                              MoneroCryptoCmd.HMAC_KEY,
                                              Type.AMOUNT_KEY))

        return _ak_amount, out_ephemeral_pub_key

    def prefix_hash_init(self, button: Button, version: int, timelock: int) -> None:
        ins: InsType = InsType.INS_PREFIX_HASH

        payload: bytes = b"".join([
            encode_varint(version),
            encode_varint(timelock)
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=1,
                         p2=0,
                         option=0,
                         payload=payload)

        # "Timelock" -> go down
        button.right_click()
        # "Reject Timelock" -> go down
        button.right_click()
        # "Accept Timelock" -> accept
        button.both_click()

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=1 (init)")

        assert len(response) == 0

    def prefix_hash_update(self, index: int, payload: bytes, is_last: bool) -> bytes:
        ins: InsType = InsType.INS_PREFIX_HASH

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=InsType.INS_PREFIX_HASH,
                         p1=2,
                         p2=index,
                         option=0 if is_last else 0x80,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=2 (update)")

        if is_last:
            assert len(response) == 32
        else:
            assert len(response) == 0

        return response

    def gen_commitment_mask(self, _ak_amount: bytes) -> bytes:
        ins: InsType = InsType.INS_GEN_COMMITMENT_MASK

        payload: bytes = b"".join([
            _ak_amount,
            hmac_sha256(_ak_amount,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.AMOUNT_KEY)
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

        return response  # mask

    def blind(self,
              _ak_amount: bytes,
              mask: bytes,
              amount: int,
              is_short: bool) -> Tuple[bytes, bytes]:
        ins: InsType = InsType.INS_BLIND

        payload: bytes = b"".join([
            _ak_amount,
            hmac_sha256(_ak_amount,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.AMOUNT_KEY),
            mask,
            amount.to_bytes(32, byteorder="big")
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=2 if is_short else 0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 64

        blinded_amount, blinded_mask = response[:32], response[32:]

        return blinded_mask, blinded_amount

    def unblind(self,
                _ak_amount: bytes,
                blinded_mask: bytes,
                blinded_amount: bytes,
                is_short: bool) -> Tuple[bytes, bytes]:
        ins: InsType = InsType.INS_UNBLIND

        payload: bytes = b"".join([
            _ak_amount,
            hmac_sha256(_ak_amount,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.AMOUNT_KEY),
            blinded_mask,
            blinded_amount
        ])

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=0,
                         p2=0,
                         option=2 if is_short else 0,
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins)

        assert len(response) == 64

        amount, mask = response[:32], response[32:]

        return mask, amount

    def validate_prehash_init(self,
                              button: Button,
                              index: int,
                              txntype: int,
                              txnfee: int) -> None:
        ins: InsType = InsType.INS_VALIDATE

        # txntype is skipped in the app
        payload: bytes = struct.pack("B", txntype) + encode_varint(txnfee)

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=1,
                         p2=index,
                         option=0,
                         payload=payload)

        # "Fee" -> go down
        button.right_click()
        # "Reject Fee" -> go down
        button.right_click()
        # "Accept Fee" -> accept
        button.both_click()

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=1 (init)")

        assert len(response) == 0

    def validate_prehash_update(self,
                                index: int,
                                is_short: bool,
                                is_change_addr: bool,
                                is_subaddress: bool,
                                dst_pub_view_key: bytes,
                                dst_pub_spend_key: bytes,
                                _ak_amount: bytes,
                                commitment: bytes,
                                blinded_mask: bytes,
                                blinded_amount: bytes,
                                is_last: bool) -> None:
        ins: InsType = InsType.INS_VALIDATE

        payload: bytes = b"".join((
            b"\x01" if is_subaddress else b"\x00",
            b"\x01" if is_change_addr else b"\x00",
            dst_pub_view_key,
            dst_pub_spend_key,
            _ak_amount,
            hmac_sha256(_ak_amount,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.AMOUNT_KEY),
            commitment,
            blinded_mask,
            blinded_amount
        ))

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=2,
                         p2=index,
                         option=(0 if is_last else 0x80) | (0x02 if is_short else 0),
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=2 (update)")

        assert len(response) == 0

    def validate_prehash_finalize(self,
                                  index: int,
                                  is_short: bool,
                                  is_change_addr: bool,
                                  is_subaddress: bool,
                                  dst_pub_view_key: bytes,
                                  dst_pub_spend_key: bytes,
                                  _ak_amount: bytes,
                                  commitment: bytes,
                                  blinded_mask: bytes,
                                  blinded_amount: bytes,
                                  is_last: bool) -> None:
        ins: InsType = InsType.INS_VALIDATE

        payload: bytes = b"".join((
            b"\x01" if is_subaddress else b"\x00",
            b"\x01" if is_change_addr else b"\x00",
            dst_pub_view_key,
            dst_pub_spend_key,
            _ak_amount,
            hmac_sha256(_ak_amount,
                        MoneroCryptoCmd.HMAC_KEY,
                        Type.AMOUNT_KEY),
            commitment,
            blinded_mask,
            blinded_amount
        ))

        self.device.send(cla=PROTOCOL_VERSION,
                         ins=ins,
                         p1=3,
                         p2=index,
                         option=(0 if is_last else 0x80) | (0x02 if is_short else 0),
                         payload=payload)

        sw, response = self.device.recv()  # type: int, bytes

        if not (sw & 0x9000):
            raise DeviceError(sw, ins, "P1=3 (finalize)")

        assert len(response) == 0
