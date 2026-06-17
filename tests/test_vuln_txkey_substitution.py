"""
The main tx public key (txkey_pub) the host supplies to INS_GEN_TXOUT_KEYS must
be one the device can vouch for -- derived from its own ephemeral secret r:
either r*G (standard / multi-destination, known on-device as G_monero_vstate.R)
or r*Bout for the single subaddress-destination case (monero-core uses r*D_dest
there).

A host that substitutes an unvouched key would have it land on-chain as the tx
public key R while the device derives the *destination* outputs under the real r.
The recipient scans with a_dst * R, which no longer matches, so the output is
undetectable and unspendable -- the funds are burned (a griefing / fund-loss
attack from an untrusted host). The device rejects such a key on any real
(non-change) output with SW_WRONG_DATA (0x6984).

The legitimate cases are covered elsewhere:
  * r*G (standard send)                  -> every real-sign test
  * r*D_dest (single subaddress dest)    -> test_vuln_subaddr_dest_change.py
The change output is not validated here (its Bout is the change address, not the
destination); it shares the same key via the tx_main_txkey pin.
"""

import pytest

from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import SigType

from test_vuln_change_address import _USER

SW_WRONG_DATA = 0x6984


@pytest.mark.incremental
class TestTxKeyMustBeDeviceDerived:
    """A substituted main tx pubkey on a real destination is rejected."""

    @staticmethod
    def test_substituted_txkey_rejected(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
        tx_pub_key, _tx_priv_key, _, _ = monero.open_tx()

        # A txkey the device cannot vouch for: neither r*G (== tx_pub_key, the R
        # the device returned) nor r*Bout. Flip one byte of the genuine R so it
        # stays 32 bytes but differs from both.
        bogus_txkey = tx_pub_key[:-1] + bytes([tx_pub_key[-1] ^ 0x01])

        with pytest.raises(ExceptionRAPDU) as exc:
            monero.gen_txout_keys(
                _tx_priv_key=_tx_priv_key,
                tx_pub_key=bogus_txkey,           # substituted main tx pubkey
                dst_pub_view_key=_USER.public_view_key,
                dst_pub_spend_key=_USER.public_spend_key,
                output_index=0,
                is_change_addr=False,             # a real destination -> validated
                is_subaddress=False,
            )
        assert exc.value.status == SW_WRONG_DATA, (
            f"a substituted main tx pubkey on a destination must be rejected with "
            f"SW_WRONG_DATA (0x6984), got {hex(exc.value.status)}")
