from bip32 import HARDENED_INDEX

from ragger.backend import SpeculosBackend
from ragger.navigator import NavInsID, NavIns
from ragger.backend.interface import RAPDU


def get_nano_review_instructions(num_screen_skip):
    instructions = [NavIns(NavInsID.RIGHT_CLICK)] * num_screen_skip
    instructions.append(NavIns(NavInsID.BOTH_CLICK))
    return instructions


def get_stax_review_instructions(num_screen_skip):
    instructions = [NavIns(NavInsID.USE_CASE_CHOICE_CONFIRM)]

    for i in range(num_screen_skip):
        instructions.append(NavIns(NavInsID.USE_CASE_REVIEW_TAP))

    instructions.append(NavIns(NavInsID.USE_CASE_REVIEW_CONFIRM))
    instructions.append(NavIns(NavInsID.USE_CASE_STATUS_DISMISS))
    return instructions


def get_stax_review_instructions_with_warning(num_screen_skip):
    instructions = [NavIns(NavInsID.USE_CASE_CHOICE_CONFIRM)]
    instructions.append(NavIns(NavInsID.USE_CASE_CHOICE_CONFIRM))

    for i in range(num_screen_skip):
        instructions.append(NavIns(NavInsID.USE_CASE_REVIEW_TAP))

    instructions.append(NavIns(NavInsID.USE_CASE_REVIEW_CONFIRM))
    instructions.append(NavIns(NavInsID.USE_CASE_STATUS_DISMISS))
    return instructions


def get_async_response(backend: SpeculosBackend) -> RAPDU:
    return backend.last_async_response


def pack_derivation_path(derivation_path: str) -> bytes:
    split = derivation_path.split("/")
    assert split.pop(0) == "m", "master expected"
    derivation_path: bytes = (len(split)).to_bytes(1, byteorder='big')
    for i in split:
        if (i[-1] == "'"):
            derivation_path += (int(i[:-1]) | HARDENED_INDEX).to_bytes(4, byteorder='big')
        else:
            derivation_path += int(i).to_bytes(4, byteorder='big')
    return derivation_path
