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
don't cover, and assert the parser accepts them. The parser runs entirely within
INS_PREFIX_HASH, before any UI, so no navigation is needed.

Covered:
  * integrated (encrypted) payment ID nonce  -> tag 0x02, 9-byte content
  * long (unencrypted) payment ID nonce      -> tag 0x02, 33-byte content
  * tx_extra padding                         -> tag 0x00 + trailing zeros
  * multi-destination (3 outputs)            -> larger vout walk
  * subaddress additional tx pubkeys         -> tag 0x04 (checked vs ADDK)
"""

import pytest

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import SigType
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys


def _open_and_genkeys(monero: MoneroCmd, n_outputs: int):
    """Reset, enter REAL mode, open a tx and derive n one-time output keys to
    the primary address. Returns (tx_pub_key, [eph_keys])."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, fvk, fsk = monero.open_tx()
    assert fvk == b"\x00" * 32 and fsk == b"\xff" * 32

    pub_view, pub_spend, _ = monero.get_public_keys()
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
    return tx_pub_key, eph_keys


def _stream_prefix(monero: MoneroCmd, device, test_name: str,
                   tx_pub_key: bytes, eph_keys, extra_suffix: bytes = b""):
    """Stream version/timelock then vin||vout||extra. Raises if the device's
    tx_extra parser rejects the shape. Returns the device's prefix hash."""
    prefix = build_tx_prefix_outkeys(
        vout_keys=eph_keys, tx_pubkey=tx_pub_key, extra_suffix=extra_suffix,
    )
    monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
    return monero.prefix_hash_update(index=1, payload=prefix, is_last=True)


# tx_extra nonce sub-tags (cryptonote_basic/tx_extra.h)
_NONCE_ENCRYPTED_PAYMENT_ID = b"\x01"   # + 8 bytes
_NONCE_PAYMENT_ID = b"\x00"             # + 32 bytes


def _nonce_field(content: bytes) -> bytes:
    """TX_EXTRA_NONCE (0x02) || varint(len) || content. len < 128 -> 1 byte."""
    assert len(content) < 128
    return b"\x02" + bytes([len(content)]) + content


@pytest.mark.incremental
class TestExtraIntegratedPaymentId:
    """Integrated address send: an 8-byte encrypted payment ID in a nonce."""

    @staticmethod
    def test_integrated_payment_id_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph = _open_and_genkeys(monero, n_outputs=2)
        suffix = _nonce_field(_NONCE_ENCRYPTED_PAYMENT_ID + bytes(8))
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraLongPaymentId:
    """Legacy long (unencrypted) 32-byte payment ID in a nonce."""

    @staticmethod
    def test_long_payment_id_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph = _open_and_genkeys(monero, n_outputs=2)
        suffix = _nonce_field(_NONCE_PAYMENT_ID + bytes(32))
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraPadding:
    """tx_extra padding: tag 0x00 followed by trailing zero bytes."""

    @staticmethod
    def test_padding_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph = _open_and_genkeys(monero, n_outputs=2)
        suffix = b"\x00" * 8  # first 0x00 = padding tag, rest consumed as padding
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraMultiDestination:
    """Three real outputs: exercises a longer vout walk in the parser."""

    @staticmethod
    def test_three_outputs_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph = _open_and_genkeys(monero, n_outputs=3)
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph)
        assert len(h) == 32


@pytest.mark.incremental
class TestExtraPaymentIdMultiDestination:
    """Combined: 3 outputs plus an integrated payment ID nonce."""

    @staticmethod
    def test_combined_accepted(monero: MoneroCmd, device, test_name: str):
        tx_pub_key, eph = _open_and_genkeys(monero, n_outputs=3)
        suffix = _nonce_field(_NONCE_ENCRYPTED_PAYMENT_ID + bytes(8))
        h = _stream_prefix(monero, device, test_name, tx_pub_key, eph, suffix)
        assert len(h) == 32


def _open_and_genkeys_additional(monero: MoneroCmd, n_outputs: int):
    """Like _open_and_genkeys, but each output requests an additional tx key
    (the subaddress path). Returns (tx_pub_key, [eph_keys], [additional_pubs])."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, fvk, fsk = monero.open_tx()
    assert fvk == b"\x00" * 32 and fsk == b"\xff" * 32

    pub_view, pub_spend, _ = monero.get_public_keys()
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
    return tx_pub_key, eph_keys, add_pubs


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
        tx_pub_key, eph, add_pubs = _open_and_genkeys_additional(monero, n_outputs=2)
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
        monero: MoneroCmd, device, test_name: str
    ):
        tx_pub_key, eph, add_pubs = _open_and_genkeys_additional(monero, n_outputs=2)
        suffix = _nonce_field(_NONCE_ENCRYPTED_PAYMENT_ID + bytes(8))
        prefix = build_tx_prefix_outkeys(
            vout_keys=eph, tx_pubkey=tx_pub_key,
            additional_pubkeys=add_pubs, extra_suffix=suffix,
        )
        monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
        h = monero.prefix_hash_update(index=1, payload=prefix, is_last=True)
        assert len(h) == 32
