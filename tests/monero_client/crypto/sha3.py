"""Helpers for Monero adresses.

mainnet address prefix:
    - address: 18
    - integrated address: 19
    - subaddress: 42

stagenet address prefix:
    - address: 24
    - integrated address: 25
    - subaddress: 36

testnet address prefix:
    - address: 53
    - integrated address: 54
    - subaddress: 63


SOFTWALLET
------------
integrated_address 0102030405060708
5KpvhQBFNXYe3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELipMNxnGr3Wv1zf7dWq

HWWALLET
--------
integrated_address 0102030405060708
5DhUnJjS31jgAQDY6qKUP6TeBy5JqXSJzhG4i7447yMXS7wdt4hKh6gQCTTa9FiYNpEjBoHZ9iTww3vL96P1hcmTbnu8Nst8WHC21KaMVc


>>> addr_prefix: bytes = b"\x19"
>>> pub_spend_key: bytes = bytes.fromhex("dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d")
>>> pub_view_key: bytes = bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa")
>>> payment_id: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08"
>>> concat: bytes = addr_prefix + pub_spend_key + pub_view_key + payment_id
>>> addr: str = base58.encode(concat + sha3(concat)[:4])

"""

import hashlib


def sc_reduce32(value: bytes) -> bytes:
    n: int = int.from_bytes(value, byteorder="little")
    l: int = 2**252 + 27742317777372353535851937790883648493

    return (n % l).to_bytes(32, "little")


def sha3(value: bytes) -> bytes:
    return hashlib.sha3_256(value).digest()
