import json
import queue
import socket
from typing import Optional


class FakeDisplay:
    def listen(self):
        pass

    def close(self):
        pass


class Display:
    def __init__(self, server: str, port: int) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server, port))
        self.q = queue.Queue()

    def listen(self):
        while True:
            text: Optional[bytes] = json.loads(
                self.socket.recv(1000)
            ).get("text")

            if text:
                self.q.put(text)

    def close(self):
        self.socket.close()


"""
class DisplayClientProtocol(asyncio.Protocol):
    def __init__(self, q, on_con_lost):
        self.on_con_lost = on_con_lost
        self.q = q
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        text: Optional[bytes] = json.loads(data).get("text")
        if text:
            logging.debug("+ %s", text)
            self.q.put(text)

    def connection_lost(self, exc):
        print('The server closed the connection')
        self.on_con_lost.set_result(True)


async def main():
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()
    q = queue.Queue()

    transport, protocol = await loop.create_connection(
        lambda: DisplayClientProtocol(q, on_con_lost),
        "127.0.0.1",
        43000
    )

    try:
        await on_con_lost
    finally:
        transport.close()


asyncio.run(main())
"""
