"""
Every legitimate (is_subaddress, need_additional_txkeys, txkey_pub) combination must
keep working.

monero-core couples the three, in construct_tx_with_tx_key and identically in the
multisig builder. classify_addresses() counts the non-change destinations, de-duped
by address, and then:

  num_std  num_sub   txkey_pub   need_additional_txkeys
  >=1      0         r*G         false
  0        1         r*D_dest    false
  >=1      >=1       r*G         true
  0        >=2       r*G         true

INS_GEN_TXOUT_KEYS today accepts txkey_pub == R or == tx_key*Bout for any
non-change output, without correlating it to those two flags -- which is what lets
a host derive an unrecoverable output while the review stays honest
(tests/test_vuln_need_additional_unbound.py). Correlating them is a stateless check,
but only if every row above still passes, so this file pins them down.

Rows 1 and 2 already had coverage -- test_sig_real_* and
test_vuln_subaddr_dest_change.py respectively, the latter explicitly asserting
txkey_pub != r*G. Rows 3 and 4 had none: nothing in the suite sent
need_additional_txkeys = 1. They are the reason this file exists.

Everything here stops at INS_GEN_TXOUT_KEYS, which is where the check lives and
where a wrong one would reject. No prefix, no review, no snapshots. Each row opens
its own transaction, because tx_main_txkey pins txkey_pub across the outputs of one
transaction; the class is deliberately not `incremental` so one broken row does not
mask the others.

Run: pytest tests/test_multi_dest_additional_keys.py -v --device flex   (DEBUG=1)
"""

import pytest

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import SigType

# established offline subaddress-key helper + test-seed keys
from test_vuln_change_address import _compute_subaddress_keys, _USER


def _open_real(monero: MoneroCmd):
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    return tx_pub_key, tx_priv_key


def _rD(monero: MoneroCmd, tx_priv_key: bytes, dest_spend_key: bytes) -> bytes:
    """r * D_dest, computed on-device the way the wallet does -- the host never
    sees r."""
    return monero.secret_scalar_mul_key(pub_key=dest_spend_key, _scalar=tx_priv_key)


def _gen(monero: MoneroCmd, txkey_pub: bytes, tx_priv_key: bytes, dest,
         index: int, is_change: bool, is_subaddress: bool, need_additional: bool):
    """One INS_GEN_TXOUT_KEYS. `dest` is an (Aout, Bout) pair."""
    return monero.gen_txout_keys(
        _tx_priv_key=tx_priv_key, tx_pub_key=txkey_pub,
        dst_pub_view_key=dest[0], dst_pub_spend_key=dest[1],
        output_index=index, is_change_addr=is_change,
        is_subaddress=is_subaddress, need_additional_txkeys=need_additional)


_STD = (_USER.public_view_key, _USER.public_spend_key)


class TestLegitimateTxKeyCombinations:
    """Each row of the table, asserted accepted at derivation time."""

    @staticmethod
    def test_row1_all_standard(monero: MoneroCmd):
        """num_std>=1, num_sub=0 -> txkey_pub = r*G, no additional keys."""
        R, r = _open_real(monero)
        _gen(monero, R, r, _STD, 0, is_change=False, is_subaddress=False,
             need_additional=False)
        _gen(monero, R, r, _STD, 1, is_change=True, is_subaddress=False,
             need_additional=False)
        monero.close_tx()

    @staticmethod
    def test_row2_single_subaddress_dest(monero: MoneroCmd):
        """num_std=0, num_sub=1 -> txkey_pub = r*D_dest, no additional keys.

        The row a naive check would break: txkey_pub is deliberately NOT r*G."""
        R, r = _open_real(monero)
        sub = _compute_subaddress_keys(3, 7)
        txkey_pub = _rD(monero, r, sub[1])
        assert txkey_pub != R, "r*D_dest must differ from r*G, or the row is untested"
        _gen(monero, txkey_pub, r, sub, 0, is_change=False, is_subaddress=True,
             need_additional=False)
        _gen(monero, txkey_pub, r, _STD, 1, is_change=True, is_subaddress=False,
             need_additional=False)
        monero.close_tx()

    @staticmethod
    def test_row3_standard_plus_subaddress(monero: MoneroCmd):
        """num_std>=1, num_sub>=1 -> txkey_pub = r*G AND additional keys for every
        output. Previously untested."""
        R, r = _open_real(monero)
        sub = _compute_subaddress_keys(3, 7)
        _, _, add0 = _gen(monero, R, r, _STD, 0, is_change=False,
                          is_subaddress=False, need_additional=True)
        _, _, add1 = _gen(monero, R, r, sub, 1, is_change=False,
                          is_subaddress=True, need_additional=True)
        _, _, add2 = _gen(monero, R, r, _STD, 2, is_change=True,
                          is_subaddress=False, need_additional=True)
        assert add0 and add1 and add2, "every output should carry an additional key"
        # The standard destination publishes s*G, the subaddress one s*Bout.
        assert add0 != add1, "the two forms of additional pubkey must differ"
        monero.close_tx()

    @staticmethod
    def test_row4_two_subaddresses(monero: MoneroCmd):
        """num_std=0, num_sub>=2 -> txkey_pub = r*G AND additional keys.
        Previously untested."""
        R, r = _open_real(monero)
        sub_a = _compute_subaddress_keys(3, 7)
        sub_b = _compute_subaddress_keys(4, 9)
        assert sub_a != sub_b
        _gen(monero, R, r, sub_a, 0, is_change=False, is_subaddress=True,
             need_additional=True)
        _gen(monero, R, r, sub_b, 1, is_change=False, is_subaddress=True,
             need_additional=True)
        _gen(monero, R, r, _STD, 2, is_change=True, is_subaddress=False,
             need_additional=True)
        monero.close_tx()

    @staticmethod
    def test_change_to_subaddress_with_additional_keys(monero: MoneroCmd):
        """A change output may itself be a subaddress, and is excluded from the
        classification either way, so it must be accepted alongside row 3."""
        R, r = _open_real(monero)
        sub = _compute_subaddress_keys(3, 7)
        chg = _compute_subaddress_keys(5, 2)
        _gen(monero, R, r, _STD, 0, is_change=False, is_subaddress=False,
             need_additional=True)
        _gen(monero, R, r, sub, 1, is_change=False, is_subaddress=True,
             need_additional=True)
        _gen(monero, R, r, chg, 2, is_change=True, is_subaddress=True,
             need_additional=True)
        monero.close_tx()
