"""
PoC for the change-output tx-public-key binding.

INS_GEN_TXOUT_KEYS derives a change/self output from a host-supplied `txkey_pub`
and binds the on-chain main tx public key to it via EXTRA_R. Nothing pinned that
`txkey_pub` to the device's open-tx key R (= r.G), so a malicious host could
derive the change from one key while a different R lands on-chain (bound through
a later output), making the user's change undiscoverable/unspendable -> burned.

The fix pins every output of a real tx to a single main tx public key: the
device records txkey_pub from the first output and requires every later output
to match it. The wallet computes one txkey_pub per tx and reuses it for all
outputs (r.G, or r.D for a single subaddress destination -- see
cryptonote_tx_utils.cpp), so a legitimate tx always passes; the burn attack
(change derived under a different key than the one bound on-chain via another
output) is a multi-output txkey_pub mismatch, rejected with 0x6984.

NB: a single lone change output is self-consistent (its txkey_pub is the one
that lands in extra), so it is not a burn and is accepted. The honest path is
covered by test_sig_real_* and test_vuln_subaddr_dest_change.
"""

import pytest

from monero_client.monero_types import SigType, Keys
from monero_client.monero_cmd import MoneroCmd


@pytest.mark.incremental
class TestChangeTxkeyBinding:

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"sender": None}

    @staticmethod
    def test_reset(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_get_keys(monero: MoneroCmd, state):
        public_view_key, public_spend_key, base58_address = monero.get_public_keys()
        state["sender"] = Keys(public_view_key=public_view_key,
                               public_spend_key=public_spend_key,
                               secret_view_key=None,
                               secret_spend_key=None,
                               addr=base58_address)

    @staticmethod
    def test_change_with_mismatched_txkey_pub_is_rejected(monero: MoneroCmd, state):
        """
        Burn attack: output 0 (destination) sets the tx's main key; output 1
        (change) is then derived under a DIFFERENT txkey_pub. The consistency
        pin rejects the mismatched change output with 0x6984.
        """
        monero.set_signature_mode(sig_type=SigType.REAL)
        tx_pub_key, _tx_priv_key, _fake_v, _fake_s = monero.open_tx()
        sender = state["sender"]

        # output 0: a legitimate destination fixes the tx main key (= R here).
        monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key,
            tx_pub_key=tx_pub_key,
            dst_pub_view_key=sender.public_view_key,
            dst_pub_spend_key=sender.public_spend_key,
            output_index=0,
            is_change_addr=False,
            is_subaddress=False,
        )

        # output 1: change derived under a different key (one flipped byte) -> the
        # key that would land on-chain (output 0's) differs from the change's,
        # which is exactly the burn the binding must prevent.
        wrong_pub = bytes([tx_pub_key[0] ^ 0x01]) + tx_pub_key[1:]
        with pytest.raises(Exception) as exc_info:
            monero.gen_txout_keys(
                _tx_priv_key=_tx_priv_key,
                tx_pub_key=wrong_pub,                          # <-- != output 0's key
                dst_pub_view_key=sender.public_view_key,       # valid change addr
                dst_pub_spend_key=sender.public_spend_key,
                output_index=1,
                is_change_addr=True,
                is_subaddress=False,
            )
        # SW_WRONG_DATA (0x6984): the consistency pin rejected the output.
        assert "0x6984" in str(exc_info.value), exc_info.value

    # Positive path (all outputs sharing one txkey_pub, incl. the r.D single-
    # subaddress case) is covered by test_sig_real_* and
    # test_vuln_subaddr_dest_change.
