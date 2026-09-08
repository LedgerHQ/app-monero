"""
The output-key transcript is a bare concatenation, so a view-tag byte can move
across a key boundary without changing it.

OUT_EPH binds the keys the device derived to the keys it signs. Both sides write
the same receipt with no punctuation: 32 key bytes, then one tag byte only if
this output has a tag. No index, no type, no length. And the host chooses which
outputs have tags -- use_view_tags per call on the build side, the 0x02/0x03
target variant per output in the prefix.

Two outputs are enough. Derive the first tagged and the second untagged:

    device hashes   K0 || tag0 || K1                   65 bytes
    prefix says     K0 || (tag0 || K1[0:31]) || K1[31]  65 bytes

Same bytes, so the receipts match and the prefix is accepted. But vout[1] now
holds tag0 || K1[0:31], shifted one byte from the key the device derived. The
recipient looks for K1, finds nothing, and the amount is lost. The screen shows
nothing wrong: the address is checked by a different chain, untouched here.

  TestTranscriptIsAmbiguous     The premise, Python only: the two framings are
                                the same bytes, and the shift changes vout[1].
  TestBoundaryShiftWasAccepted  The old behaviour, skipped: the device took the
                                shifted prefix. Needs a build without framing.
  TestHonestMixedFormsWork      Control: a mix streamed truthfully must still be
                                accepted, so the fix binds the form rather than
                                banning one.
  TestBoundaryShiftRefused      The fix: the shifted prefix gives 0x6915.

The premise comes first. If it fails, read the rest as broken rather than as a
finding. The refusal comes last: it exits the app.

The shifted 32 bytes are probably not a valid Ed25519 point, so a real network
would reject the transaction rather than lose the output. The device's own check
is still bypassed, which is the point. Getting a valid substituted point means
regenerating until the shifted value decompresses -- slower, and not needed.

Run: pytest tests/test_vuln_out_eph_ambiguous.py -v --device flex
     (DEBUG=1 build. No screens are drawn, so there are no snapshots.)

Every test asks for the `monero` fixture, even where unused: pytest reorders
tests to save fixture setup, and one that omits it leaves its class and gets a
fresh class-scoped `state`.
"""

import hashlib

import pytest

from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import Keys, SigType
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

# The OUT_EPH mismatch the framing now produces. Not a new status word: this is
# the check that was always there, finally reached.
SW_SECURITY_OUTKEYS_CHAIN_CONTROL = 0x6915

# The test seed "abandon ... about", the address the review would show.
_USER = Keys(
    public_view_key=bytes.fromhex(
        "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"),
    public_spend_key=bytes.fromhex(
        "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d"),
    secret_view_key=None,
    secret_spend_key=None,
    addr="",
)


def _transcript(keys, tags):
    """The receipt both sides write: each key, then its tag if it has one.

    tags[i] is None for an untagged output. Same rule read from either side,
    which is the bug."""
    out = b""
    for key, tag in zip(keys, tags):
        out += key
        if tag is not None:
            out += tag
    return out


def _shift(keys, tags):
    """Move the first output's tag into the second output's key.

    Returns (keys, tags) for the prefix: vout[0] loses its tag, vout[1] gains
    one, and vout[1]'s key becomes the old tag plus all but the last byte of
    the real key."""
    k0, k1 = keys
    tag0 = tags[0]
    assert tag0 is not None, "the first output must be the tagged one"
    assert tags[1] is None, "the second output must be untagged"

    return [k0, tag0 + k1[:31]], [None, k1[31:32]]


def _open_real(monero: MoneroCmd, state):
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["R"] = tx_pub_key
    state["r"] = tx_priv_key


def _gen(monero: MoneroCmd, state, index: int, tagged: bool):
    """One output to the on-screen address. Returns (key, tag or None)."""
    if tagged:
        _ak, eph, _add, tag = monero.gen_txout_keys_view_tagged(
            _tx_priv_key=state["r"], tx_pub_key=state["R"],
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            output_index=index, is_change_addr=False, is_subaddress=False)
        return eph, tag

    _ak, eph, _add = monero.gen_txout_keys(
        _tx_priv_key=state["r"], tx_pub_key=state["R"],
        dst_pub_view_key=_USER.public_view_key,
        dst_pub_spend_key=_USER.public_spend_key,
        output_index=index, is_change_addr=False, is_subaddress=False)
    return eph, None


def _stream_prefix(monero: MoneroCmd, device, test_name: str, state,
                   keys, tags) -> bytes:
    """Send a two-output prefix and return the hash the device computes.

    Tags are bytes here, because that is what the device returns and what key
    slicing produces; the prefix builder wants ints."""
    monero.prefix_hash_init(test_name, device, navigator=None,
                            version=0, timelock=0)
    prefix = build_tx_prefix_outkeys(
        vout_keys=keys, tx_pubkey=state["R"],
        view_tags=[None if t is None else t[0] for t in tags])
    return monero.prefix_hash_update(index=1, payload=prefix, is_last=True)


def _state():
    return {"R": None, "r": None, "keys": None, "tags": None}


@pytest.mark.incremental
class TestTranscriptIsAmbiguous:
    """The premise, in Python. Stand-in keys: the claim is about the framing."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_shift_preserves_the_transcript(monero: MoneroCmd, state):
        """Tagged-then-untagged hashes the same as untagged-then-tagged."""
        k0 = bytes(range(32))
        k1 = bytes(range(32, 64))
        tag0 = b"\xa5"

        built = _transcript([k0, k1], [tag0, None])
        signed = _transcript(*_shift([k0, k1], [tag0, None]))

        assert built == signed, (
            "the two framings differ, so there is nothing to exploit:\n"
            "  built  %s\n  signed %s" % (built.hex(), signed.hex()))
        assert len(built) == 65
        assert (hashlib.sha256(built).digest()
                == hashlib.sha256(signed).digest())

    @staticmethod
    def test_shift_changes_the_second_key(monero: MoneroCmd, state):
        """And vout[1] ends up holding something else entirely."""
        k0 = bytes(range(32))
        k1 = bytes(range(32, 64))
        tag0 = b"\xa5"

        keys, _tags = _shift([k0, k1], [tag0, None])

        assert keys[0] == k0, "the first key must be untouched"
        assert keys[1] != k1, "the second key is unchanged, no attack"
        assert keys[1] == tag0 + k1[:31]
        assert len(keys[1]) == 32


@pytest.mark.skip(reason="The old behaviour: the shifted prefix was accepted. "
                         "Passes only on a build that hashes the keys without "
                         "framing. Use --run-skipped to see it again.")
@pytest.mark.incremental
class TestBoundaryShiftWasAccepted:
    """A prefix carrying a key the device never derived, and it went through.

    Everything the device checked passed -- the digest matched because the bytes
    were the same, the output count was unchanged, and R was untouched."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_shift_derive_two_outputs(monero: MoneroCmd, state):
        """Output 0 tagged, output 1 not, both to the same address.

        A wallet would not mix the forms, but use_view_tags is a host byte per
        call and nothing pins it for the transaction."""
        _open_real(monero, state)

        k0, tag0 = _gen(monero, state, 0, tagged=True)
        k1, tag1 = _gen(monero, state, 1, tagged=False)

        assert tag0 is not None and len(tag0) == 1, "no view tag came back"
        assert tag1 is None
        state["keys"], state["tags"] = [k0, k1], [tag0, None]

        print("\n[derived] K0=%s tag0=%s\n          K1=%s"
              % (k0.hex(), tag0.hex(), k1.hex()))

    @staticmethod
    def test_shift_prefix_is_accepted(monero: MoneroCmd, device,
                                      test_name: str, state):
        """The device accepts the shifted prefix and returns its hash.

        That hash covers a transaction whose second output key was never
        derived, and it is what INS_MLSAG and INS_CLSAG go on to sign."""
        keys, tags = _shift(state["keys"], state["tags"])
        assert keys[1] != state["keys"][1], "not shifted"

        prefix_hash = _stream_prefix(monero, device, test_name, state,
                                     keys, tags)

        assert len(prefix_hash) == 32, (
            "the device refused the shifted prefix -- the transcript is framed "
            "after all, so this finding is fixed")

        print("\n[impact] device derived vout[1] = %s\n"
              "         prefix carries vout[1] = %s\n"
              "         accepted, prefixH = %s"
              % (state["keys"][1].hex(), keys[1].hex(), prefix_hash.hex()))
        monero.close_tx()


@pytest.mark.incremental
class TestHonestMixedFormsWork:
    """Control. The fix must make the two sides agree, not ban an output type.

    A mixed transaction is not something a wallet builds -- use_view_tags is one
    per-transaction value -- and consensus rejects it outside one grace-period
    hard fork (check_output_types). So this is not "mixing is legal"; it is that
    the device should refuse a mismatched form because the framing caught it, not
    because it forbids the shape."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_mixed_derive_two_outputs(monero: MoneroCmd, state):
        _open_real(monero, state)
        k0, tag0 = _gen(monero, state, 0, tagged=True)
        k1, tag1 = _gen(monero, state, 1, tagged=False)
        state["keys"], state["tags"] = [k0, k1], [tag0, tag1]

    @staticmethod
    def test_mixed_honest_prefix_is_accepted(monero: MoneroCmd, device,
                                             test_name: str, state):
        """The same two outputs, streamed as they were derived."""
        prefix_hash = _stream_prefix(monero, device, test_name, state,
                                     state["keys"], state["tags"])
        assert len(prefix_hash) == 32, (
            "an honest mix of tagged and untagged outputs was refused")
        monero.close_tx()


@pytest.mark.incremental
class TestBoundaryShiftRefused:
    """The fix. The framing makes the two transcripts differ, so the shift is
    caught by the OUT_EPH compare that was already there.

    Last in the file: a refusal exits the app."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_refused_derive_two_outputs(monero: MoneroCmd, state):
        """Output 0 tagged, output 1 not, as before."""
        _open_real(monero, state)
        k0, tag0 = _gen(monero, state, 0, tagged=True)
        k1, _tag1 = _gen(monero, state, 1, tagged=False)
        state["keys"], state["tags"] = [k0, k1], [tag0, None]

    @staticmethod
    def test_refused_shifted_prefix(monero: MoneroCmd, device,
                                    test_name: str, state):
        """The shifted prefix now gives 0x6915."""
        keys, tags = _shift(state["keys"], state["tags"])

        try:
            _stream_prefix(monero, device, test_name, state, keys, tags)
            sw = 0x9000
        except ExceptionRAPDU as exc:
            sw = exc.status

        assert sw == SW_SECURITY_OUTKEYS_CHAIN_CONTROL, (
            "expected %#06x for a shifted view-tag boundary, got %#06x"
            % (SW_SECURITY_OUTKEYS_CHAIN_CONTROL, sw))
