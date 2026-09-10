"""
The device must not believe the host about how many bytes it sent.

monero_io_do() used to throw away the length io_exchange returns and trust the
Lc byte instead, so a short APDU that declared a long one made the app copy
bytes nobody transmitted:

    io_lc = G_io_apdu_buffer[4];
    memcpy(io_buffer, G_io_apdu_buffer + 5, io_lc);

Those bytes were not random. G_io_apdu_buffer is G_io_tx_buffer, the same array
the app writes its replies into, and nothing clears the tail, so what the
parser picked up was the previous answer.

Nothing downstream caught it either: io_length was set to the declared Lc, and
monero_io_assert_available() compares against io_length, so every fetch in the
handler believed the data was there.

monero_io_do() now compares the declared Lc against what the transport says
arrived and refuses the mismatch with 0x6700. The refusal ends the app, so it
is the last test of its class.

INS_GET_SUBADDRESS is the probe. It reads an 8-byte index in the clear, has no
HMAC, no range check and no UI, and returns 64 bytes that are a pure function
of that index, so what the device read back is visible in what it answers.

  TestHonestTrafficIsUnaffected  Well-formed APDUs still work, down to the
                                 shortest legal one.
  TestTruncatedApduIsRefused     A 5-byte APDU claiming 9 gets 0x6700.
  TestTruncatedApduWasAccepted   Skipped: what it did before the fix.
  TestPredecessorDecidedAnswer   Skipped: and that the host chose those bytes.

Sending this needs care: Transport and every _raw_apdu in tests/ compute
Lc = 1 + len(payload), and backend.exchange_async_raw re-packs the APDU and
recomputes Lc. Only exchange_raw and send_raw pass the bytes through.

Run: pytest tests/test_vuln_apdu_length_unchecked.py -v --device flex

The backend is class-scoped, so one app instance spans a class and the buffer
carries between its tests. Every test asks for the `monero` fixture, even where
unused: pytest reorders tests to save fixture setup, and one that omits it
leaves its class and gets a fresh class-scoped `state`.
"""

import struct

import pytest

from ragger.backend.interface import BackendInterface, RaisePolicy

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_types import InsType

SW_WRONG_LENGTH = 0x6700

# Option byte plus the 8-byte index: what an honest caller declares.
HONEST_LC = 9

# Where the index lands in the previous reply. monero_io_do copies from
# G_io_apdu_buffer + 5, the dispatcher eats one byte as `options`
# (monero_dispatch.c:139), then the handler fetches 8.
STALE_INDEX = slice(6, 14)


def _honest(backend: BackendInterface, index: bytes) -> bytes:
    """A well-formed INS_GET_SUBADDRESS, framed the way the app expects."""
    apdu = struct.pack("BBBBBB", PROTOCOL_VERSION,
                       InsType.INS_GET_SUBADDRESS.value, 0, 0,
                       1 + len(index), 0x00) + index
    rapdu = backend.exchange_raw(apdu)
    assert rapdu.status == 0x9000, "honest query refused: %#06x" % rapdu.status
    return rapdu.data


def _truncated(backend: BackendInterface, lc: int = HONEST_LC):
    """Header only. Lc says `lc` payload bytes follow; none are sent."""
    apdu = struct.pack("BBBBB", PROTOCOL_VERSION,
                       InsType.INS_GET_SUBADDRESS.value, 0, 0, lc)
    return backend.exchange_raw(apdu)


def _start(monero: MoneroCmd, backend: BackendInterface):
    monero.reset_and_get_version(monero_client_version=b"0.18")
    # The refusal has to arrive as a status, not an exception.
    backend.raise_policy = RaisePolicy.RAISE_NOTHING


@pytest.mark.incremental
class TestHonestTrafficIsUnaffected:
    """The guard must pass everything a real host sends.

    monero-gui builds every APDU as `buffer_send[4] = offset - 5` with
    `length_send = offset` (device_ledger.cpp:404-409), so Lc always equals the
    transmitted length minus the header. A guard that rejected a legal shape
    would pass the refusal test below and fail here."""

    @staticmethod
    def test_a_full_length_query_is_answered(monero: MoneroCmd,
                                             backend: BackendInterface):
        _start(monero, backend)
        assert len(_honest(backend, struct.pack("<II", 0, 1))) == 64

    @staticmethod
    def test_the_shortest_legal_apdu_is_answered(monero: MoneroCmd,
                                                 backend: BackendInterface):
        # Lc = 1, the option byte and nothing else: the smallest thing the app
        # ever receives, and the closest legal shape to the malformed one.
        apdu = struct.pack("BBBBBB", PROTOCOL_VERSION,
                           InsType.INS_GET_CHACHA8_PREKEY.value, 0, 0, 1, 0x00)
        rapdu = backend.exchange_raw(apdu)

        assert rapdu.status == 0x9000, (
            "the guard rejected a well-formed 6-byte APDU: %#06x"
            % rapdu.status)


@pytest.mark.incremental
class TestTruncatedApduIsRefused:
    """An APDU that declares more data than it carries is refused."""

    @staticmethod
    def test_the_baseline_query_works(monero: MoneroCmd,
                                      backend: BackendInterface):
        _start(monero, backend)
        # Leaves a reply in the shared buffer, which is what the truncated APDU
        # below would have been parsed out of.
        assert len(_honest(backend, struct.pack("<II", 0, 1))) == 64

    @staticmethod
    def test_a_truncated_apdu_is_refused(monero: MoneroCmd,
                                         backend: BackendInterface):
        # Last in its class: the refusal ends the app.
        rapdu = _truncated(backend)

        assert rapdu.status == SW_WRONG_LENGTH, (
            "expected %#06x for an APDU declaring %d payload bytes and "
            "carrying none, got %#06x with %d bytes of data"
            % (SW_WRONG_LENGTH, HONEST_LC, rapdu.status, len(rapdu.data)))
        assert len(rapdu.data) == 0, (
            "refused but still answered data: %s" % rapdu.data.hex())


@pytest.mark.skip(reason="behaviour before the fix; kept to reproduce "
                         "it on an unfixed build")
@pytest.mark.incremental
class TestTruncatedApduWasAccepted:
    """The truncated APDU used to be answered from the previous reply."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"first": None, "truncated": None}

    @staticmethod
    def test_an_honest_query_is_answered(monero: MoneroCmd,
                                         backend: BackendInterface, state):
        _start(monero, backend)
        state["first"] = _honest(backend, struct.pack("<II", 0, 1))
        assert len(state["first"]) == 64

    @staticmethod
    def test_a_truncated_apdu_is_answered(monero: MoneroCmd,
                                          backend: BackendInterface, state):
        rapdu = _truncated(backend)
        state["truncated"] = rapdu.data

        assert rapdu.status == 0x9000
        assert len(rapdu.data) == 64

    @staticmethod
    def test_the_answer_came_from_the_previous_reply(
            monero: MoneroCmd, backend: BackendInterface, state):
        stale = state["first"][STALE_INDEX]
        assert _honest(backend, stale) == state["truncated"]


@pytest.mark.skip(reason="behaviour before the fix; kept to reproduce "
                         "it on an unfixed build")
@pytest.mark.incremental
class TestPredecessorDecidedAnswer:
    """And the host picked those bytes by picking the command before them,
    which is what made this more than uninitialised memory."""

    @staticmethod
    def test_two_predecessors_gave_two_answers(monero: MoneroCmd,
                                               backend: BackendInterface):
        _start(monero, backend)

        seen = []
        for major in (3, 7):
            first = _honest(backend, struct.pack("<II", major, 0))
            rapdu = _truncated(backend)
            assert rapdu.status == 0x9000
            seen.append((first[STALE_INDEX], rapdu.data))

        assert seen[0][1] != seen[1][1]
        for stale, answer in seen:
            assert _honest(backend, stale) == answer
