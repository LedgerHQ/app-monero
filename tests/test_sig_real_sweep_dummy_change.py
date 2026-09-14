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

from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd

# Reuse the REAL-tx prehash driver and the non-wallet "attacker" address.
from test_vuln_change_address import (
    _drive_change_through_prehash,
    _ATTACKER_A_PUB,
    _ATTACKER_B_PUB,
    _AMOUNT_CHANGE,
)


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
