"""
A short-amount output must be canonically encoded.

In the modern RCT types (CLSAG / BulletproofPlus) the amount is carried as 8
masked bytes; the device displays the value from those low 8 bytes, while the
commitment binds the full 32-byte value. A non-canonical encoding (any byte past
the low 8 set) could show one amount and commit to another, so the device rejects
it with SW_SECURITY_AMOUNT_CHAIN_CONTROL (0x6913), synchronously, right after the
unblind and before any review.

Honest wallets never produce this: ecdhEncode (v2) xor8()s only the low 8 bytes
of an amount that started as d2h(value) (high 24 bytes zero), and the device's
short unblind only XORs v[0:8] -- so v[8:32] is always zero for legit traffic.
This test crafts a non-canonical amount (a high byte set) to exercise the guard.

Needs a DEBUG=1 build: the commitment is sent as zeros, and the canonical check
runs before the commitment check.
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd

# Reuse the REAL-tx prehash driver; the canonical check is independent of the
# change-address logic, so a (valid) primary change address is used and never
# reached -- the amount check fires first.
from test_vuln_change_address import _drive_change_through_prehash, _USER, _AMOUNT_CHANGE


class TestNonCanonicalShortAmountRejected:
    """A short amount with a non-zero high byte is rejected before any review."""

    @staticmethod
    def test_high_byte_set_rejected(
        monero: MoneroCmd, backend: BackendInterface, navigator: Navigator,
        test_name: str):
        sw = _drive_change_through_prehash(
            monero, backend, navigator, test_name,
            chg_view=_USER.public_view_key, chg_spend=_USER.public_spend_key,
            is_subaddress=False, amount=_AMOUNT_CHANGE, is_last=False,
            corrupt_amount_high_byte=True)
        assert sw == 0x6913, (
            f"a non-canonical short amount (high byte set) must be rejected with "
            f"SW_SECURITY_AMOUNT_CHAIN_CONTROL (0x6913), got {hex(sw)}")
