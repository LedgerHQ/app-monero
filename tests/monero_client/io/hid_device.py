import logging
from typing import List, Tuple

try:
    import hid
except ImportError:
    hid = None

from .comm import Comm


LEDGER_VENDOR_ID: int = 0x2C97


class HID(Comm):
    def __init__(self) -> None:
        if hid is None:
            raise ImportError("hidapi is not installed!")

        self.device = hid.device()
        self.path = HID.enumerate_devices()[0]
        self.device.open_path(self.path)
        self.device.set_nonblocking(True)
        self.__opened: bool = True

    @staticmethod
    def enumerate_devices() -> List[bytes]:
        devices: List[bytes] = []

        for hid_device in hid.enumerate(LEDGER_VENDOR_ID, 0):
            if (hid_device.get("interface_number") == 0 or
                    hid_device.get("usage_page") == 0xffa0):
                devices.append(hid_device["path"])

        assert (len(devices) != 0,
                f"Can't find HID device with vendor id {LEDGER_VENDOR_ID}")

        return devices

    def send(self, apdus: bytes) -> None:
        data: bytes = int.to_bytes(len(apdus), 2, byteorder="big") + apdus
        offset: int = 0
        seq_idx: int = 0

        while offset < len(data):
            # Header: channel (0x101), tag (0x05), sequence index
            header: bytes = (b"\x01\x01\x05" +
                             seq_idx.to_bytes(2, byteorder="big"))
            data_chunk: bytes = (header +
                                 data[offset:offset + 64 - len(header)])

            self.device.write(b"\x00" + data_chunk)
            logging.debug("=> %s", data_chunk.hex())
            offset += 64 - len(header)
            seq_idx += 1

    def recv(self, timeout: int = 1000) -> Tuple[int, bytes]:
        seq_idx: int = 0
        self.device.set_nonblocking(False)
        data_chunk: bytes = bytes(self.device.read(64 + 1))
        self.device.set_nonblocking(True)

        assert data_chunk[:2] == b"\x01\x01"
        assert data_chunk[2] == 5
        assert data_chunk[3:5] == seq_idx.to_bytes(2, byteorder="big")

        data_len: int = int.from_bytes(data_chunk[5:7], byteorder="big")
        data: bytes = data_chunk[7:]

        while len(data) < data_len:
            read_bytes = bytes(self.device.read(64 + 1, timeout_ms=timeout))
            data += read_bytes[5:]

        logging.debug("<= %s", data[:data_len].hex())

        sw: int = int.from_bytes(data[data_len-2:data_len], byteorder="big")
        data: bytes = data[:data_len-2]

        return sw, data

    def exchange(self, data: bytes, timeout=1000) -> Tuple[int, bytes]:
        self.send(data)

        return self.recv(timeout)

    def close(self):
        if self.__opened:
            self.device.close()
            self.__opened = False
