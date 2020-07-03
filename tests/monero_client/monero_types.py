from dataclasses import dataclass
import enum
from typing import Optional


@dataclass
class Keys:
    public_view_key: bytes
    secret_view_key: bytes
    public_spend_key: bytes
    secret_spend_key: Optional[bytes]
    addr: str


@enum.unique
class SigType(enum.IntEnum):
    REAL = 1
    FAKE = 2


@enum.unique
class Type(enum.IntEnum):
    SCALAR = 1
    DERIVATION = 2
    AMOUNT_KEY = 3
    ALPHA = 4


@enum.unique
class InsType(enum.IntEnum):
    INS_NONE = 0x00
    INS_RESET = 0x02
    INS_LOCK_DISPLAY = 0x04

    INS_GET_KEY = 0x20
    INS_DISPLAY_ADDRESS = 0x21
    INS_PUT_KEY = 0x22
    INS_GET_CHACHA8_PREKEY = 0x24
    INS_VERIFY_KEY = 0x26
    INS_MANAGE_SEEDWORDS = 0x28

    INS_SECRET_KEY_TO_PUBLIC_KEY = 0x30
    INS_GEN_KEY_DERIVATION = 0x32
    INS_DERIVATION_TO_SCALAR = 0x34
    INS_DERIVE_PUBLIC_KEY = 0x36
    INS_DERIVE_SECRET_KEY = 0x38
    INS_GEN_KEY_IMAGE = 0x3A
    INS_SECRET_KEY_ADD = 0x3C
    INS_GENERATE_KEYPAIR = 0x40
    INS_SECRET_SCAL_MUL_KEY = 0x42
    INS_SECRET_SCAL_MUL_BASE = 0x44

    INS_DERIVE_SUBADDRESS_PUBLIC_KEY = 0x46
    INS_GET_SUBADDRESS = 0x48
    INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY = 0x4A
    INS_GET_SUBADDRESS_SECRET_KEY = 0x4C

    INS_OPEN_TX = 0x70
    INS_SET_SIGNATURE_MODE = 0x72
    INS_GET_ADDITIONAL_KEY = 0x74
    INS_STEALTH = 0x76
    INS_GEN_COMMITMENT_MASK = 0x77
    INS_BLIND = 0x78
    INS_UNBLIND = 0x7A
    INS_GEN_TXOUT_KEYS = 0x7B
    INS_PREFIX_HASH = 0x7D
    INS_VALIDATE = 0x7C
    INS_MLSAG = 0x7E
    INS_CLOSE_TX = 0x80

    INS_GET_TX_PROOF = 0xA0
    INS_GEN_SIGNATURE = 0xA2
    INS_GEN_RING_SIGNATURE = 0xA4

    INS_GET_RESPONSE = 0xc0

    def __repr__(self):
        return f"{self.name}[{hex(self.value)}]"
