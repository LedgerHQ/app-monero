"""
A single-subaddress-destination send must not be rejected at the change output.

monero-core's construct_tx_with_tx_key computes the main tx public key as r*D_dest
(not r*G) when there's exactly one subaddress destination and no standard ones --
and the change address is excluded from that count. So a normal "send to one
subaddress, plus change" carries txkey_pub == r*D_dest for every output, change
included. An earlier change-binding check pinned the change's txkey_pub to r.G and
rejected this with 0x6984 -> app_exit -> "Preparing TX" crash (matches the
monero-wallet log: INS 0x7b, output 1 is_change=1, RESP 6984). It hit any send to a
single subaddress, regardless of the sender's account.

These tests reproduce the legitimate flow by computing r*D_dest the way the wallet
does, via the device's INS_SECRET_SCAL_MUL_KEY (it can't see r), and assert the
change output is accepted.
"""

import pytest

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import SigType

# established offline subaddress-key helper + test-seed keys
from test_vuln_change_address import _compute_subaddress_keys, _USER


def _open_real(monero: MoneroCmd):
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, fvk, fsk = monero.open_tx()
    assert fvk == b"\x00" * 32 and fsk == b"\xff" * 32
    return tx_pub_key, _tx_priv_key


def _txkey_pub_for_single_subaddr(monero: MoneroCmd, _tx_priv_key: bytes,
                                  dest_spend_key: bytes) -> bytes:
    """The wallet's main tx pubkey for a single subaddress destination:
    r * D_dest, computed on-device (the host never sees r)."""
    return monero.secret_scalar_mul_key(pub_key=dest_spend_key, _scalar=_tx_priv_key)


@pytest.mark.incremental
class TestSubaddrDestChangeToPrimary:
    """
    Send to ONE subaddress destination (3, 7), change back to the PRIMARY
    account (account 0). Even here txkey_pub = r*D_dest, so the change output
    must still be accepted. Shows account-0 users are hit too.
    """

    @staticmethod
    def test_subaddr_dest_change_primary(monero: MoneroCmd):
        tx_pub_key, _tx_priv_key = _open_real(monero)
        A_dest, B_dest = _compute_subaddress_keys(major=3, minor=7)
        txkey_pub = _txkey_pub_for_single_subaddr(monero, _tx_priv_key, B_dest)
        assert txkey_pub != tx_pub_key  # r*D_dest != r*G (the whole point)

        # output 0: the subaddress destination (no change check, no R pin)
        monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key, tx_pub_key=txkey_pub,
            dst_pub_view_key=A_dest, dst_pub_spend_key=B_dest,
            output_index=0, is_change_addr=False, is_subaddress=True,
        )

        # output 1: legitimate change to the primary address. MUST be accepted;
        # the old r.G pin rejected it with 0x6984 (the reproduced crash).
        monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key, tx_pub_key=txkey_pub,
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            output_index=1, is_change_addr=True, is_subaddress=False,
        )


@pytest.mark.incremental
class TestSubaddrDestChangeToSubaddr:
    """
    The exact monero-wallet log case: send to ONE subaddress destination (3, 7),
    change to a non-primary account root (1, 0). Both outputs carry r*D_dest.
    """

    @staticmethod
    def test_subaddr_dest_change_subaddr(monero: MoneroCmd):
        tx_pub_key, _tx_priv_key = _open_real(monero)
        A_dest, B_dest = _compute_subaddress_keys(major=3, minor=7)
        A_chg, B_chg = _compute_subaddress_keys(major=1, minor=0)
        txkey_pub = _txkey_pub_for_single_subaddr(monero, _tx_priv_key, B_dest)
        assert txkey_pub != tx_pub_key

        # output 0: subaddress destination
        monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key, tx_pub_key=txkey_pub,
            dst_pub_view_key=A_dest, dst_pub_spend_key=B_dest,
            output_index=0, is_change_addr=False, is_subaddress=True,
        )

        # output 1: change to account 1 root. MUST be accepted (today: 0x6984).
        monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key, tx_pub_key=txkey_pub,
            dst_pub_view_key=A_chg, dst_pub_spend_key=B_chg,
            output_index=1, is_change_addr=True, is_subaddress=True,
        )
