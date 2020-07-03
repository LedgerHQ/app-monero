import logging
import socket
from typing import Tuple

from .comm import Comm


class TCPClient(Comm):
    def __init__(self, server: str, port: int) -> None:
        self.server: str = server
        self.port: int = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server, self.port))
        self.__opened: bool = True

    def send(self, apdus: bytes) -> None:
        logging.debug("=> %s", apdus.hex())
        length: bytes = int.to_bytes(len(apdus), 4, byteorder="big")
        self.socket.send(length + apdus)

    def recv(self) -> Tuple[int, bytes]:
        length: int = int.from_bytes(self.socket.recv(4), byteorder="big")
        data: bytes = self.socket.recv(length)
        sw: int = int.from_bytes(self.socket.recv(2), byteorder="big")

        logging.debug("<= %s %s", data.hex(), hex(sw)[2:])

        return sw, data

    def exchange(self, apdus: bytes) -> Tuple[int, bytes]:
        self.send(apdus)
        sw, response = self.recv()  # type: int, bytes

        return sw, response

    def close(self):
        if self.__opened:
            self.socket.close()
            self.__opened = False
