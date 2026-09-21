"""
tx_extra parser stress.

2.2.0 added a streaming tx-prefix parser (src/monero_prefix.c) that walks
vin/vout/extra during INS_PREFIX_HASH to bind the output keys (OUT_EPH), the main
tx pubkey (EXTRA_R) and any additional keys (ADDK). The device hashes the raw
streamed bytes into prefixH, so prefixH can't diverge from what the host signs --
the only failure mode is the parser erroring on a valid tx_extra shape
(SW_SECURITY_OUTKEYS_CHAIN_CONTROL / SW_WRONG_DATA), which app_main turns into
app_exit -> a crash to dashboard.

These tests stream tx_extra shapes real wallets emit but the real-sign vectors
don't cover, and assert the parser handles them. The parser runs entirely within
INS_PREFIX_HASH, before any UI, so no navigation is needed.

Covered:
  * integrated (encrypted) payment ID nonce  -> tag 0x02, 9-byte, accepted
  * long (unencrypted) payment ID nonce      -> tag 0x02, 33-byte, refused
  * tx_extra padding                         -> tag 0x00 + trailing zeros
  * padding whose run is not all zeros       -> refused
  * an unknown tx_extra tag                  -> refused
  * multi-destination (3 outputs)            -> larger vout walk
  * subaddress additional tx pubkeys         -> tag 0x04 (checked vs ADDK)

The long payment ID is the one refusal: a real transaction takes only the
encrypted payment ID the device made itself, because the device cannot vouch for
any other and no wallet has read a long one since hardfork 12.
"""

import pytest

from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import SigType
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys
from monero_client.status_words import (SW_SECURITY_PAYMENT_ID,
                                        SW_WRONG_DATA)

# The device now requires the prefix to carry the encrypted payment ID it made
# itself, so a test that streams one has to ask for it first.
from test_vuln_payment_id_unbound import _stealth


def _open_and_genkeys(monero: MoneroCmd, n_outputs: int, backend=None,
                      payment_id: bytes = None):
    """Reset, enter REAL mode, open a tx and derive n one-time output keys to
    the primary address. Returns (tx_pub_key, [eph_keys], enc_payment_id).

    Pass a payment_id to have the device encrypt one, as a wallet does before it
    puts the value in the prefix. INS_STEALTH has to follow INS_OPEN_TX, so the
    call goes here rather than in the test. enc_payment_id is None otherwise."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, fvk, fsk = monero.open_tx()
    assert fvk == b"\x00" * 32 and fsk == b"\xff" * 32

    pub_view, pub_spend, _ = monero.get_public_keys()
    enc_pid = (None if payment_id is None
               else _stealth(backend, pub_view, _tx_priv_key, payment_id))
    eph_keys = []
    for index in range(n_outputs):
        _ak, eph, _ = monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key,
            tx_pub_key=tx_pub_key,
            dst_pub_view_key=pub_view,
            dst_pub_spend_key=pub_spend,
            output_index=index,
            is_change_addr=False,
            is_subaddress=False,
        )
        eph_keys.append(eph)
    return tx_pub_key, eph_keys, enc_pid


def _stream_prefix(monero: MoneroCmd, device, test_name: str,
                   tx_pub_key: bytes, eph_keys, extra_suffix: bytes = b""):
    """Stream version/timelock then vin||vout||extra. Raises if the device's
    tx_extra parser rejects the shape. Returns the device's prefix hash."""
    prefix = build_tx_prefix_outkeys(
        vout_keys=eph_keys, tx_pubkey=tx_pub_key, extra_suffix=extra_suffix,
    )
    monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
    return monero.prefix_hash_update(index=1, payload=prefix, is_last=True)


def _stream_prefix_chunked(monero: MoneroCmd, device, test_name: str,
                           tx_pub_key: bytes, eph_keys,
                           extra_suffix: bytes, chunk: int = 200):
    """_stream_prefix for a prefix too long for one APDU.

    The dispatcher wants p2 to run 1, 2, 3 (monero_dispatch.c:316-328), and the
    parser is resumable, which is what makes splitting legal."""
    prefix = build_tx_prefix_outkeys(
        vout_keys=eph_keys, tx_pubkey=tx_pub_key, extra_suffix=extra_suffix,
    )
    monero.prefix_hash_init(test_name, device, navigator=None, version=0,
                            timelock=0)
    parts = [prefix[o:o + chunk] for o in range(0, len(prefix), chunk)]
    out = b""
    for index, part in enumerate(parts, start=1):
        out = monero.prefix_hash_update(index=index, payload=part,
                                        is_last=(index == len(parts)))
    return out


# tx_extra nonce sub-tags (cryptonote_basic/tx_extra.h)
_NONCE_ENCRYPTED_PAYMENT_ID = b"\x01"   # + 8 bytes
_NONCE_PAYMENT_ID = b"\x00"             # + 32 bytes


def _nonce_field(content: bytes) -> bytes:
    """TX_EXTRA_NONCE (0x02) || varint(len) || content. len < 128 -> 1 byte."""
    assert len(content) < 128
    return b"\x02" + bytes([len(content)]) + content


# --- V-078: what monero-core's own parser accepts -------------------------
#
# tx_extra.h:55-72 deserializes padding by reading to the end of extra and
# failing on the first non-zero byte, with at most TX_EXTRA_PADDING_MAX_COUNT
# (255) bytes counting the tag. An unknown tag has no variant entry, so
# do_serialize fails. cryptonote_format_utils.cpp:580 stops at the first bad
# field and returns false.
#
# Only the shapes these tests send are covered; it is a differential oracle,
# not a second implementation of the wallet.

_PADDING_MAX_COUNT = 255


def _reference_parse_extra(extra: bytes) -> bool:
    """True when monero-core would parse the whole blob."""
    i = 0
    while i < len(extra):
        tag = extra[i]
        i += 1
        if tag == 0x00:                                 # padding, to the end
            run = 1
            while i < len(extra):
                if extra[i] != 0:
                    return False
                i += 1
                run += 1
                if run > _PADDING_MAX_COUNT:
                    return False
            return True
        if tag == 0x01:                                 # main tx public key
            if len(extra) - i < 32:
                return False
            i += 32
        elif tag == 0x02:                               # nonce
            if i >= len(extra) or extra[i] >= 128:
                return False
            length = extra[i]
            i += 1
            if len(extra) - i < length:
                return False
            i += length
        elif tag == 0x04:                               # additional pub keys
            if i >= len(extra) or extra[i] >= 128:
                return False
            count = extra[i]
            i += 1
            if len(extra) - i < count * 32:
                return False
            i += count * 32
        else:                                           # no variant entry
            return False
    return True


def _extra_blob(tx_pub_key: bytes, suffix: bytes) -> bytes:
    """The extra build_tx_prefix_outkeys emits for these tests: 0x01 || R."""
    return b"\x01" + tx_pub_key + suffix


# A padding tag whose run is not all zeros, and a tag no wallet defines.
_PADDING_WITH_GARBAGE = b"\x00\x00\x00\x00\xff\x00\x00\x00"
_UNKNOWN_TAG_FIELD = b"\x7f" + b"\xde\xad\xbe\xef\xde\xad\xbe\xef"


@pytest.mark.incremental
class TestExtraCanonicalDifferential:
    """No device. The reference rules these two shapes break, and the legal
    padding they are compared against."""

    @staticmethod
    def test_reference_refuses_what_the_device_takes(monero: MoneroCmd):
        r = b"\x11" * 32
        assert _reference_parse_extra(_extra_blob(r, b"\x00" * 8)), \
            "all-zero padding is legal and must stay accepted"
        assert not _reference_parse_extra(_extra_blob(r, _PADDING_WITH_GARBAGE)), \
            "a non-zero byte in the padding run fails tx_extra.h:67"
        assert not _reference_parse_extra(_extra_blob(r, _UNKNOWN_TAG_FIELD)), \
            "an unknown tag has no variant entry"
        assert not _reference_parse_extra(_extra_blob(r, b"\x00" * 300)), \
            "a padding run over 255 bytes fails tx_extra.h:71"


@pytest.mark.incremental
class TestExtraNonZeroPadding:
    """
    The padding case used to consume the rest of extra without looking at it.
    A run that is not all zeros is what the wallet parser refuses first, so the
    device has to refuse it too rather than sign past it.
    """

    @staticmethod
    def test_non_zero_padding_refused(monero: MoneroCmd, device,
                                      test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        with pytest.raises(ExceptionRAPDU) as exc:
            _stream_prefix(monero, device, test_name, tx_pub_key, eph,
                           _PADDING_WITH_GARBAGE)
        assert exc.value.status == SW_WRONG_DATA, (
            "expected %#06x for a non-zero padding byte, got %#06x"
            % (SW_WRONG_DATA, exc.value.status))


@pytest.mark.incremental
class TestExtraOverlongPadding:
    """
    tx_extra.h:71 caps a padding field at 255 bytes including the tag, so 254
    zeros is the most that parses. One more has to be refused.
    """

    @staticmethod
    def test_overlong_padding_refused(monero: MoneroCmd, device,
                                      test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        with pytest.raises(ExceptionRAPDU) as exc:
            _stream_prefix_chunked(monero, device, test_name, tx_pub_key, eph,
                                   b"\x00" * 256)
        assert exc.value.status == SW_WRONG_DATA, (
            "expected %#06x for an over-long padding run, got %#06x"
            % (SW_WRONG_DATA, exc.value.status))


@pytest.mark.incremental
class TestExtraUnknownTag:
    """
    An unrecognised tag took the same path as padding, so the rest of extra was
    skipped rather than refused. The wallet parser has no variant for it and
    stops there, so a real signature must not reach past it.
    """

    @staticmethod
    def test_unknown_tag_refused(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        with pytest.raises(ExceptionRAPDU) as exc:
            _stream_prefix(monero, device, test_name, tx_pub_key, eph,
                           _UNKNOWN_TAG_FIELD)
        assert exc.value.status == SW_WRONG_DATA, (
            "expected %#06x for an unknown tx_extra tag, got %#06x"
            % (SW_WRONG_DATA, exc.value.status))


@pytest.mark.skip(reason="Shows what the parser took before the canonical "
                         "padding and unknown-tag rules; passes only on a "
                         "build without them.")
@pytest.mark.incremental
class TestExtraCanonicalVuln:
    """Both shapes reaching prefixH, kept reproducible on an unfixed build."""

    @staticmethod
    def test_non_zero_padding_was_accepted(monero: MoneroCmd, device,
                                           test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph,
                           _PADDING_WITH_GARBAGE)
        assert len(h) == 32
        assert not _reference_parse_extra(
            _extra_blob(tx_pub_key, _PADDING_WITH_GARBAGE)), \
            "the device signed an extra the wallet parser rejects"

    @staticmethod
    def test_unknown_tag_was_accepted(monero: MoneroCmd, device,
                                      test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph,
                           _UNKNOWN_TAG_FIELD)
        assert len(h) == 32
        assert not _reference_parse_extra(
            _extra_blob(tx_pub_key, _UNKNOWN_TAG_FIELD)), \
            "the device signed an extra the wallet parser rejects"


@pytest.mark.incremental
class TestExtraIntegratedPaymentId:
    """Integrated address send: an 8-byte encrypted payment ID in a nonce."""

    @staticmethod
    def test_integrated_payment_id_accepted(monero: MoneroCmd, backend,
                                            device, test_name: str):
        tx_pub_key, eph, enc_pid = _open_and_genkeys(
            monero, n_outputs=2, backend=backend, payment_id=bytes.fromhex("1122334455667788"))
        suffix = _nonce_field(_NONCE_ENCRYPTED_PAYMENT_ID + enc_pid)
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraLongPaymentId:
    """
    Legacy long (unencrypted) 32-byte payment ID in a nonce, now refused.

    The device never makes one, so it has nothing to compare it against and
    nothing to show at review, and wallet2 has discarded them on receive since
    hardfork 12 (IGNORE_LONG_PAYMENT_ID_FROM_BLOCK_VERSION), so there is no
    reader either. Signing 32 unreviewed bytes for no one is the worse trade,
    so a real transaction takes only the encrypted payment ID the device made.

    This is a deliberate compatibility break: Monero GUI can still put a long
    payment ID in a transaction, though only from a scanned QR code or a
    monero: URI -- its input field is readOnly.
    """

    @staticmethod
    def test_long_payment_id_refused(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        suffix = _nonce_field(_NONCE_PAYMENT_ID + bytes(32))
        with pytest.raises(ExceptionRAPDU) as exc_info:
            _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert exc_info.value.status == SW_SECURITY_PAYMENT_ID, (
            "expected %#06x for a payment ID the device did not make, got %#06x"
            % (SW_SECURITY_PAYMENT_ID, exc_info.value.status))


@pytest.mark.incremental
class TestExtraPadding:
    """tx_extra padding: tag 0x00 followed by trailing zero bytes."""

    @staticmethod
    def test_padding_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=2)
        suffix = b"\x00" * 8  # first 0x00 = padding tag, rest consumed as padding
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraMultiDestination:
    """Three real outputs: exercises a longer vout walk in the parser."""

    @staticmethod
    def test_three_outputs_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph, _ = _open_and_genkeys(monero, n_outputs=3)
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraPaymentIdMultiDestination:
    """Combined: 3 outputs plus an integrated payment ID nonce."""

    @staticmethod
    def test_combined_accepted(monero: MoneroCmd, backend, device,
                               test_name: str):
        tx_pub_key, eph, enc_pid = _open_and_genkeys(
            monero, n_outputs=3, backend=backend, payment_id=bytes.fromhex("1122334455667788"))
        suffix = _nonce_field(_NONCE_ENCRYPTED_PAYMENT_ID + enc_pid)
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


def _open_and_genkeys_additional(monero: MoneroCmd, n_outputs: int,
                                 backend=None, payment_id: bytes = None):
    """Like _open_and_genkeys, but each output requests an additional tx key
    (the subaddress path).

    Returns (tx_pub_key, [eph_keys], [additional_pubs], enc_payment_id)."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, fvk, fsk = monero.open_tx()
    assert fvk == b"\x00" * 32 and fsk == b"\xff" * 32

    pub_view, pub_spend, _ = monero.get_public_keys()
    enc_pid = (None if payment_id is None
               else _stealth(backend, pub_view, _tx_priv_key, payment_id))
    eph_keys, add_pubs = [], []
    for index in range(n_outputs):
        _ak, eph, add_pub = monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key,
            tx_pub_key=tx_pub_key,
            dst_pub_view_key=pub_view,
            dst_pub_spend_key=pub_spend,
            output_index=index,
            is_change_addr=False,
            is_subaddress=True,
            need_additional_txkeys=True,
        )
        eph_keys.append(eph)
        add_pubs.append(add_pub)
    return tx_pub_key, eph_keys, add_pubs, enc_pid


@pytest.mark.incremental
class TestExtraAdditionalKeys:
    """
    Subaddress send (tag 0x04 additional public keys). Each output carries one
    device-derived additional tx public key, streamed in `extra` as
    0x04 || varint(count) || count*32. The parser binds them against ADDK and
    enforces count == tx_output_cnt (monero_prefix.c PFX_EXTRA_ADDK*).
    """

    @staticmethod
    def test_additional_keys_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph, add_pubs, _ = _open_and_genkeys_additional(monero, n_outputs=2)
        prefix = build_tx_prefix_outkeys(
            vout_keys=eph, tx_pubkey=tx_pub_key, additional_pubkeys=add_pubs,
        )
        monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
        h = monero.prefix_hash_update(index=1, payload=prefix, is_last=True)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraAdditionalKeysWithPaymentId:
    """Subaddress send + integrated payment ID: tag 0x04 followed by a nonce."""

    @staticmethod
    def test_additional_keys_and_payment_id_accepted(
        monero: MoneroCmd, backend, device, test_name: str
    ):
        tx_pub_key, eph, add_pubs, enc_pid = _open_and_genkeys_additional(
            monero, n_outputs=2, backend=backend, payment_id=bytes.fromhex("1122334455667788"))
        suffix = _nonce_field(_NONCE_ENCRYPTED_PAYMENT_ID + enc_pid)
        prefix = build_tx_prefix_outkeys(
            vout_keys=eph, tx_pubkey=tx_pub_key,
            additional_pubkeys=add_pubs, extra_suffix=suffix,
        )
        monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
        h = monero.prefix_hash_update(index=1, payload=prefix, is_last=True)
        assert len(h) == 32
