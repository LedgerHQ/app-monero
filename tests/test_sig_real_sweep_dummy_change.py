"""
sweep_all / sweep_single carry a zero-amount dummy change output (the 2nd output
Monero adds to meet the 2-output minimum), whose address need not be wallet-owned.

The change-address check is gated on a non-zero unblinded amount, so:
  * a zero-amount change to a non-wallet address is ACCEPTED (the dummy), and
  * a non-zero change to that same non-wallet address is REJECTED (0x691C).

The accept path runs through the on-device review, which auto-confirms a non-last
output on NBGL but blocks on BAGL, so the accept test is NBGL-only. The reject
path fails synchronously (before any UI) and runs everywhere.

Needs a DEBUG=1 build: the commitment is sent as zeros and relies on
BYPASS_COMMITMENT_FOR_TESTS (the helper drives the change check, not the
commitment check).
"""

import pytest
import nacl.bindings as nb

from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import SigType
from monero_client.crypto.monero_math import sc_reduce32
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

# Reuse the REAL-tx prehash driver and the non-wallet "attacker" address.
from test_vuln_change_address import (
    _drive_change_through_prehash,
    _record_index,
    _ATTACKER_A_PUB,
    _ATTACKER_B_PUB,
    _AMOUNT_CHANGE,
)

# A high account, as in GitHub issue #190 where the wallet has 267 accounts.
_HIGH_ACCOUNT = 267

# Stands in for the random address wallet2 generates for zero change
# (dummy.generate()); fixed so the run is reproducible.
_DUMMY_A_PUB = nb.crypto_scalarmult_ed25519_base_noclamp(sc_reduce32(bytes([0x5A] * 32)))
_DUMMY_B_PUB = nb.crypto_scalarmult_ed25519_base_noclamp(sc_reduce32(bytes([0x5B] * 32)))


class TestSweepDummyChangeAccepted:
    """A zero-amount dummy change to a non-wallet address is accepted (sweep)."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nbgl_only(device):
        if device.is_nano:
            pytest.skip("zero-change accept goes through the review; BAGL blocks, "
                        "so it is asserted on NBGL")

    @staticmethod
    def test_zero_amount_change_to_nonwallet_accepted(
        monero: MoneroCmd, backend: BackendInterface, navigator: Navigator,
        test_name: str):
        # Non-last (MORE) zero-amount change to an attacker address: the amount
        # gate skips the address check, so NBGL auto-confirms with SW_OK. If the
        # gate were missing, the check would fire and return 0x691C.
        sw = _drive_change_through_prehash(
            monero, backend, navigator, test_name,
            chg_view=_ATTACKER_A_PUB, chg_spend=_ATTACKER_B_PUB,
            is_subaddress=False, amount=0, is_last=False)
        assert sw == 0x9000, (
            f"a zero-amount dummy change to a non-wallet address must be accepted "
            f"(sweep_all/sweep_single), got {hex(sw)}")


class TestSweepNonZeroChangeStillRejected:
    """Control: the SAME non-wallet address with a non-zero amount is rejected."""

    @staticmethod
    def test_nonzero_change_to_nonwallet_rejected(
        monero: MoneroCmd, backend: BackendInterface, navigator: Navigator,
        test_name: str):
        sw = _drive_change_through_prehash(
            monero, backend, navigator, test_name,
            chg_view=_ATTACKER_A_PUB, chg_spend=_ATTACKER_B_PUB,
            is_subaddress=False, amount=_AMOUNT_CHANGE, is_last=False)
        assert sw == 0x691C, (
            f"a non-zero change to a non-wallet address must be rejected, "
            f"got {hex(sw)}")


@pytest.mark.incremental
class TestSweepFromHighAccount:
    """
    Workaround for issue #190: sweeping an account >= 50 still signs.

    sweep_all from account 267 with one destination leaves no change, so
    wallet2 adds a zero-amount change output to a random address. The change
    check skips zero amounts, so the review goes through to the end, on Nano
    and NBGL alike. The destination is the primary address, which is where a
    user would move the funds.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {
            "receiver_view": [None, _DUMMY_A_PUB],
            "receiver_spend": [None, _DUMMY_B_PUB],
            "is_change_addr": [False, True],
            "amount": [907880000, 0],
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "fvk": None,
            "_ak_amount": [None, None],
            "eph_keys": [],
            "blinded_mask": [None, None],
            "blinded_amount": [None, None],
        }

    @staticmethod
    def test_reset_hi(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_get_keys_hi(monero: MoneroCmd, state):
        view, spend, _ = monero.get_public_keys()
        state["receiver_view"][0] = view
        state["receiver_spend"][0] = spend

    @staticmethod
    def test_set_sig_hi(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_hi(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, fvk, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key
        state["fvk"] = fvk

    @staticmethod
    def test_input_from_high_account_hi(monero: MoneroCmd, state):
        # The wallet derives each input's key from its subaddress, here one in
        # account 267, as the device sees on a real sweep. The zero change
        # below skips the change check, so this does not decide the result.
        _record_index(monero, state["fvk"], major=_HIGH_ACCOUNT, minor=5)

    @staticmethod
    def test_gen_txout_keys_hi(monero: MoneroCmd, state):
        for i in range(2):
            _ak, eph, _ = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=state["receiver_view"][i],
                dst_pub_spend_key=state["receiver_spend"][i],
                output_index=i,
                is_change_addr=state["is_change_addr"][i],
                is_subaddress=False,
            )
            state["_ak_amount"][i] = _ak
            state["eph_keys"].append(eph)

    @staticmethod
    def test_prefix_hash_hi(monero: MoneroCmd, navigator: Navigator, device,
                            test_name: str, state):
        prefix = build_tx_prefix_outkeys(vout_keys=state["eph_keys"],
                                         tx_pubkey=state["tx_pub_key"])
        monero.prefix_hash_init(test_name, device, navigator=navigator,
                                version=0, timelock=0)
        monero.prefix_hash_update(index=1, payload=prefix, is_last=True)

    @staticmethod
    def test_blind_hi(monero: MoneroCmd, state):
        masks = [monero.gen_commitment_mask(state["_ak_amount"][i]) for i in range(2)]
        for i in range(2):
            bm, ba = monero.blind(_ak_amount=state["_ak_amount"][i], mask=masks[i],
                                  amount=state["amount"][i], is_short=True)
            state["blinded_mask"][i] = bm
            state["blinded_amount"][i] = ba

    @staticmethod
    def test_validate_hi(monero: MoneroCmd, backend: BackendInterface,
                         navigator: Navigator, test_name: str, state):
        monero.validate_prehash_init(test_name, backend.device, navigator, 1, 0,
                                     30660000)
        # Same screens as test_sig_real_simple: fee, destination (amount and
        # address), change.
        for i in range(2):
            monero.validate_prehash_update(
                backend, test_name, navigator,
                index=i + 1, is_short=True,
                is_change_addr=state["is_change_addr"][i], is_subaddress=False,
                dst_pub_view_key=state["receiver_view"][i],
                dst_pub_spend_key=state["receiver_spend"][i],
                _ak_amount=state["_ak_amount"][i],
                commitment=bytes(32),
                blinded_amount=state["blinded_amount"][i],
                blinded_mask=state["blinded_mask"][i],
                is_last=(i == 1), swipe_count=3)
        for i in range(2):
            monero.validate_prehash_finalize(
                index=i + 1, is_short=False, is_change_addr=False,
                is_subaddress=False,
                dst_pub_view_key=state["receiver_view"][i],
                dst_pub_spend_key=state["receiver_spend"][i],
                _ak_amount=state["_ak_amount"][i],
                commitment=bytes(32),
                blinded_amount=state["blinded_amount"][i],
                blinded_mask=state["blinded_mask"][i],
                is_last=(i == 1))

    @staticmethod
    def test_close_tx_hi(monero: MoneroCmd):
        monero.close_tx()


class TestHighAccountChangeRejected:
    """
    Control for issue #190: non-zero change to account 267 is refused when no
    input comes from that account.
    """

    @staticmethod
    def test_high_account_change_rejected(
        monero: MoneroCmd, backend: BackendInterface, navigator: Navigator,
        test_name: str):
        sw = _drive_change_through_prehash(
            monero, backend, navigator, test_name,
            chg_view=None, chg_spend=None, is_subaddress=True,
            amount=_AMOUNT_CHANGE, is_last=False,
            subaddr=(_HIGH_ACCOUNT, 0))
        assert sw == 0x691C, (
            f"non-zero change to account {_HIGH_ACCOUNT} with no input from it "
            f"must be refused, got {hex(sw)}")
