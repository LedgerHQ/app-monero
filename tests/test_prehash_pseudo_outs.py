"""
INS_VALIDATE P1=1 beyond the fee step.

The fee arrives as P2=1 and is reviewed. For RCTTypeSimple the wallet then
streams one 32-byte pseudoOut per input as P2=2, 3, ... and the device draws
nothing for them (device_ledger.cpp:1915). Those bytes go into the transaction
prehash, so they are signed.

`io_p2` used to be read exactly once in monero_prehash.c, by the guard on the
fee step, and every other P2 fell through to hashing `io_length - io_offset`
bytes unparsed. Nothing checked the payload was 32 bytes or that the sequence
stopped where the wallet said it did, so a host could put whatever it liked
into the signed prehash without it appearing anywhere on screen.

This is hardening rather than a scan finding: the network verifier recomputes
the prehash from the transaction it receives, so bytes the device hashed but the
transaction does not contain break the signature instead of buying anything.
Recorded as app-monero-dev#40. The reason it is worth closing anyway is that it
was the last unparsed region reaching the prehash, the same tidy-up V-093 and
V-078 were about.

The control is the point of this file. No other test sends a pseudoOut at all,
so a wrong guess about the shape the wallet sends would have shipped silently.

On BAGL the fee step draws a screen, which these tests approve without
comparing it to a golden set: nothing here is about what is drawn, and a golden
directory per test name would be churn. NBGL does not draw at all for the fee,
so it needs nothing either way.

Classes:
  TestPseudoOutsAccepted - control: the wallet's own shape, then a wrong length
  TestPseudoOutAfterLast - a step past the one the wallet marked last
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd
from monero_client.status_words import (SW_SUBCOMMAND_NOT_ALLOWED,
                                        SW_WRONG_LENGTH)

# One whole real transaction up to just before the review, which is exactly the
# state INS_VALIDATE needs. Shared rather than copied: it is 25 lines of setup
# and nothing here is about how the transaction is built.
from test_vuln_payment_id_unreviewed import _setup, FEE

# Any 32 bytes; the device hashes a pseudoOut without interpreting it.
PSEUDO_OUT = bytes.fromhex(
    "1111111111111111111111111111111111111111111111111111111111111111")


@pytest.mark.incremental
class TestPseudoOutsAccepted:
    """
    The honest shape first, then the refusal. A fix that simply banned P2>=2
    would pass the refusal and fail the control.
    """

    @staticmethod
    def test_a_single_thirty_two_byte_pseudo_out_is_accepted(
            monero: MoneroCmd, backend: BackendInterface,
            navigator: Navigator, device, test_name: str):
        _setup(monero, backend, device, test_name, payment_id=None)
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE,
                                     more=True,
                                     compare_snapshots=False)
        monero.validate_prehash_pseudo_out(index=2, pseudo_out=PSEUDO_OUT,
                                           is_last=True)

    @staticmethod
    def test_a_pseudo_out_of_the_wrong_length_is_refused(
            monero: MoneroCmd, backend: BackendInterface,
            navigator: Navigator, device, test_name: str):
        _setup(monero, backend, device, test_name, payment_id=None)
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE,
                                     more=True,
                                     compare_snapshots=False)
        with pytest.raises(ExceptionRAPDU) as exc:
            monero.validate_prehash_pseudo_out(index=2,
                                               pseudo_out=PSEUDO_OUT + b"\x99",
                                               is_last=True)
        assert exc.value.status == SW_WRONG_LENGTH, (
            "expected %#06x for a 33-byte pseudoOut, got %#06x"
            % (SW_WRONG_LENGTH, exc.value.status))


@pytest.mark.incremental
class TestPseudoOutAfterLast:
    """
    The fee step carries the wallet's "pseudoOuts follow" bit, and the last
    pseudoOut clears it. A further step after that is the host extending a
    sequence the wallet had ended.
    """

    @staticmethod
    def test_a_step_after_the_last_is_refused(
            monero: MoneroCmd, backend: BackendInterface,
            navigator: Navigator, device, test_name: str):
        _setup(monero, backend, device, test_name, payment_id=None)
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE,
                                     more=True,
                                     compare_snapshots=False)
        monero.validate_prehash_pseudo_out(index=2, pseudo_out=PSEUDO_OUT,
                                           is_last=True)
        with pytest.raises(ExceptionRAPDU) as exc:
            monero.validate_prehash_pseudo_out(index=3,
                                               pseudo_out=PSEUDO_OUT,
                                               is_last=True)
        assert exc.value.status == SW_SUBCOMMAND_NOT_ALLOWED, (
            "expected %#06x for a step past the last, got %#06x"
            % (SW_SUBCOMMAND_NOT_ALLOWED, exc.value.status))
