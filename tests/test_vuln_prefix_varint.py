"""
Streaming varint overflow in the tx-prefix parser.

`pfx_varint_byte` (src/monero_prefix.c) accumulates one byte at a time and used
to guard only the shift count: `prefix_vi_shift >= 64`. A uint64 varint is at
most ten bytes, and on the tenth the shift is 63, so only bit 63 still fits.
Any larger payload was still shifted, its high bits dropped, and the varint
reported complete.

That is a parser differential, not just a lost value. The ten bytes
`0x80 * 9 + 0x02` encode 2**64, which no canonical decoder accepts -- and the
device read **0**. The same accumulator supplies the vin count, the vout count,
the extra length, the additional-key count and the TLV lengths, so the device
could walk different field boundaries from the host that built the transaction.

The fix applies the rule the repository's own non-streaming decoder already
used (`monero_decode_varint`, src/monero_crypto.c): on the tenth byte the value
must be 0x00 or 0x01 -- payload 0 or 1, continuation clear.

Observability: every varint state turns a decoder error into SW_WRONG_DATA
(0x6984), and a non-last prefix chunk that parses cleanly answers SW_OK with no
data. So "accepted" and "refused" are directly distinguishable, which is what
lets the control below prove the fix did not simply ban ten-byte varints.

Classes:
  TestTenthBytePayloadOneAccepted  - control: 2**63 is legal and still parses
  TestVinCountTenthByteRefused     - the finding, in the first varint state
  TestExtraLengthTenthByteRefused  - and in a later one, after real parsing

The vout count, additional-key count and TLV length states are not covered
separately: they call the same `pfx_varint_byte` and handle `r < 0` with the
same `return SW_WRONG_DATA` (src/monero_prefix.c:413-435, 542-566, 614-630), so
a test there would exercise these same three lines through a longer setup.
"""

import struct

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_types import InsType, SigType
from monero_client.utils.varint import encode_varint
from monero_client.status_words import SW_WRONG_DATA

TXIN_TO_KEY_TAG = 0x02
TXOUT_TO_KEY_TAG = 0x02

# Ten bytes whose tenth carries a payload above 1. The host encodes 2**64; the
# unfixed decoder shifts the 2 clean out of the word and reports 0.
VARINT_2_POW_64 = b"\x80" * 9 + b"\x02"
# The same shape with payload 1: exactly 2**63, which is representable and which
# monero_decode_varint accepts. The fix must too.
VARINT_2_POW_63 = b"\x80" * 9 + b"\x01"


def _vin(n_inputs: int = 1, ring: int = 11) -> bytes:
    """A well-formed vin section the parser skips over."""
    out = encode_varint(n_inputs)
    for _ in range(n_inputs):
        out += bytes([TXIN_TO_KEY_TAG])
        out += encode_varint(0)          # amount
        out += encode_varint(ring)
        out += encode_varint(7) * ring   # offset deltas
        out += bytes(32)                 # key image
    return out


def _vout(key: bytes) -> bytes:
    return encode_varint(1) + encode_varint(0) + bytes([TXOUT_TO_KEY_TAG]) + key


def _open_real(monero: MoneroCmd, state):
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    view, spend, _ = monero.get_public_keys()
    _ak, eph, _ = monero.gen_txout_keys(
        _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
        dst_pub_view_key=view, dst_pub_spend_key=spend,
        output_index=0, is_change_addr=False, is_subaddress=False)
    state["eph"] = eph
    state["R"] = tx_pub_key


def _stream(backend: BackendInterface, payload: bytes) -> int:
    """One MORE chunk of vin||vout||extra. Returns the status word.

    Raw, and blocking: a refusal exits the app, and the client helper asserts a
    response length this path does not always reach."""
    apdu = struct.pack("BBBBBB", PROTOCOL_VERSION,
                       InsType.INS_PREFIX_HASH.value, 2, 1,
                       1 + len(payload), 0x80) + payload
    try:
        return backend.exchange_raw(apdu).status
    except ExceptionRAPDU as exc:
        return exc.status


def _state():
    return {"eph": None, "R": None}


# ---------------------------------------------------------------------------
# Control: the fix must not ban ten-byte varints outright
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestTenthBytePayloadOneAccepted:
    """
    `0x80 * 9 + 0x01` is 2**63: ten bytes, tenth payload 1, the largest a uint64
    varint can hold. monero_decode_varint accepts it and so must this decoder,
    or the two disagree in the other direction. Read as a vin count it is
    absurd, but the parser simply waits for that many inputs -- a MORE chunk
    with nothing left to do answers SW_OK.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_setup(monero: MoneroCmd, device, test_name: str, state):
        _open_real(monero, state)
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)

    @staticmethod
    def test_two_pow_63_vin_count_parses(monero: MoneroCmd,
                                         backend: BackendInterface, state):
        sw = _stream(backend, VARINT_2_POW_63)
        assert sw == 0x9000, (
            f"2**63 is a representable uint64 varint and must still decode, "
            f"got {hex(sw)}")


# ---------------------------------------------------------------------------
# The finding: first varint state
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestVinCountTenthByteRefused:
    """
    The vin count is the prefix's first varint. Before the fix the device read
    these ten bytes as 0 and carried on parsing a zero-input transaction, so
    the whole chunk was accepted; now the decoder refuses.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_setup(monero: MoneroCmd, device, test_name: str, state):
        _open_real(monero, state)
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)

    @staticmethod
    def test_vin_count_2_pow_64_refused(monero: MoneroCmd,
                                        backend: BackendInterface, state):
        sw = _stream(backend, VARINT_2_POW_64)
        assert sw == SW_WRONG_DATA, (
            f"a tenth varint byte above 1 must be refused, got {hex(sw)}")


# ---------------------------------------------------------------------------
# The finding: a later varint state, reached through real parsing
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestExtraLengthTenthByteRefused:
    """
    Same bytes in the extra-length varint, after a valid vin and vout have been
    walked. Proves the guard holds once the parser carries state, not only on
    the first byte it sees.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_setup(monero: MoneroCmd, device, test_name: str, state):
        _open_real(monero, state)
        monero.prefix_hash_init(test_name, device, navigator=None,
                                version=0, timelock=0)

    @staticmethod
    def test_extra_length_2_pow_64_refused(monero: MoneroCmd,
                                           backend: BackendInterface, state):
        payload = _vin() + _vout(state["eph"]) + VARINT_2_POW_64
        sw = _stream(backend, payload)
        assert sw == SW_WRONG_DATA, (
            f"a tenth varint byte above 1 must be refused in the extra length "
            f"too, got {hex(sw)}")
