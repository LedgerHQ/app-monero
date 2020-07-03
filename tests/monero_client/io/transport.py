import enum
import logging
import struct
from typing import Union, Tuple

from monero_client.io.tcp_client import TCPClient
from monero_client.io.hid_device import HID


class Transport:
    def __init__(self, debug: bool = False, speculos: bool = False) -> None:
        if debug:
            logging.basicConfig(format="%(message)s", level=logging.DEBUG)

        self.com: Union[TCPClient, HID] = (TCPClient(server="127.0.0.1", port=9999)
                                           if speculos else HID())

    def exchange(self,
                 cla: int,
                 ins: enum.IntEnum,
                 p1: int = 0,
                 p2: int = 0,
                 option: int = 0,
                 payload: bytes = b"") -> Tuple[int, bytes]:
        header: bytes = struct.pack("BBBBBB",
                                    cla,
                                    ins.value,
                                    p1,
                                    p2,
                                    1 + len(payload),
                                    option)

        return self.com.exchange(header + payload)

    def send(self,
             cla: int,
             ins: enum.IntEnum,
             p1: int = 0,
             p2: int = 0,
             option: int = 0,
             payload: bytes = b"") -> None:
        header: bytes = struct.pack("BBBBBB",
                                    cla,
                                    ins.value,
                                    p1,
                                    p2,
                                    1 + len(payload),
                                    option)
        self.com.send(header + payload)

    def recv(self) -> Tuple[int, bytes]:
        return self.com.recv()

    def close(self) -> None:
        self.com.close()
