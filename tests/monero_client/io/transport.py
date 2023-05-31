import enum
import logging
import struct
from typing import Union, Tuple
from ragger.backend.interface import BackendInterface, RAPDU
from contextlib import contextmanager


class Transport:
    backend: BackendInterface

    def __init__(self, backend, debug) -> None:
        if debug:
            logging.basicConfig(format="%(message)s", level=logging.DEBUG)

        self._client = backend

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

        return self._client.exchange(header + payload)

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
        self._client.send_raw(header + payload)

    @contextmanager
    def send_async(self,
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
        with self._client.exchange_async_raw(header + payload):
            yield

    def recv(self) -> Tuple[int, bytes]:
        response = self._client.receive()
        return (response.status, response.data)

    def async_response(self) -> Tuple[int, bytes]:
        response = self._client.last_async_response
        return (response.status, response.data)
