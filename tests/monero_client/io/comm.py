from abc import ABCMeta, abstractmethod
from typing import Tuple


class Comm(metaclass=ABCMeta):
    @abstractmethod
    def send(self, apdus: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def recv(self) -> Tuple[int, bytes]:
        raise NotImplementedError

    @abstractmethod
    def exchange(self, apdus: bytes) -> Tuple[int, bytes]:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError
