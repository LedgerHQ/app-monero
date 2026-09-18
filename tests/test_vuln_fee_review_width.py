"""
The fee at review has to be the fee that was hashed.

INS_VALIDATE P1=1 P2=1 carries [type][varint fee]. The device hashes those
bytes into the transaction prehash and shows the fee for approval. It used to
read the varint twice for that, with different limits:

    monero_decode_varint(io_buffer + fee_off, MIN(10, fee_max), &fee, &fee_len)
    monero_vamount2str(io_buffer + io_offset, ux_amount, 15)
        -> monero_decode_varint(binary, 8, &amount, &out_len)

Ten bytes to accept and hash, eight to display. A fee needing nine bytes was
therefore accepted and committed while the formatter refused it, and its error
was dropped. On that path ux_amount is not written, and nothing clears it
between transactions, so the screen kept the previous amount and " XMR" was
appended to that. The user approved a number they recognised and signed a
different one.

Nine bytes means a fee of 2^56 or more, 72057.594037927936 XMR: monero's own
reader refuses a padded encoding (varint.h:105-107, EVARINT_REPRESENT), so no
smaller fee can reach the nine-byte case and still be relayed. That makes this
an exchange-scale hole rather than a wallet one, but a silent failure in a
review path is worth closing whatever the balance.

The fix formats the fee that was already decoded, before anything is hashed,
and with the real buffer size rather than a hard-coded 15.

Why this test has to read the screen: the fix changes nothing about what is
signed. The same bytes are hashed either way, so there is no status word and no
digest to assert on. The display is the only observable, which also means the
unit tests on monero_amount2str do not guard the fix - they guard the
formatter, and would still pass if the call site went back to re-decoding.

NBGL only. The fee is stored at P1=1 and shown in the terminal review, which
is readable without golden snapshots. BAGL draws it on its own screen while the
APDU is still pending, which needs different plumbing for no extra coverage:
the code under test has no UI in it.

Classes:
  TestFeeReviewWidth - an ordinary fee first, then the nine-byte one
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import InsType, Type
from monero_client.crypto.hmac import hmac_sha256

# One real transaction up to just before the review, plus the page reader and
# the constants. Shared rather than copied: none of it is what this file tests.
from test_vuln_payment_id_unreviewed import (FEE, SIGN_PAGE, ZERO_COMMITMENT,
                                             _page_text, _setup)

# 2^56 atomic units, the smallest fee whose varint needs nine bytes.
NINE_BYTE_FEE = 1 << 56
NINE_BYTE_TEXT = "72057.594037927936"

# What FEE renders as.
ORDINARY_TEXT = "0.00003066"


def _review_text(backend: BackendInterface, navigator: Navigator,
                 max_pages: int = 12) -> str:
    """Walk the review and return every page's text.

    navigate_and_compare would want a golden directory per test name, and the
    assertion here is the text rather than the pixels, so this swipes without
    comparing."""
    backend.wait_for_text_on_screen("Continue")
    navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM],
                       screen_change_before_first_instruction=False)

    backend.wait_for_text_on_screen("Review")
    pages = []
    for _ in range(max_pages):
        page = _page_text(backend)
        pages.append(page)
        if SIGN_PAGE in page:
            return " || ".join(pages)
        navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT],
                           screen_change_before_first_instruction=False)
    raise AssertionError(
        "never reached the '%s' page in %d swipes; saw: %s"
        % (SIGN_PAGE, max_pages, " || ".join(pages)))


def _fee_as_reviewed(monero: MoneroCmd, backend: BackendInterface,
                     navigator: Navigator, device, test_name: str,
                     fee: int) -> str:
    """Stream a real transaction carrying `fee` and return the review text."""
    (_addr, view, spend, ak, _pid,
     blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                            test_name, payment_id=None)

    monero.validate_prehash_init(test_name, device, navigator, 1, 0, fee,
                                 compare_snapshots=False)

    payload = b"".join((
        b"\x00",  # is_subaddress
        b"\x00",  # is_change_addr
        view, spend, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))

    backend.wait_for_text_on_screen("Processing")
    with monero.transport.send_async(cla=PROTOCOL_VERSION,
                                     ins=InsType.INS_VALIDATE,
                                     p1=2, p2=1,
                                     option=0x02,  # terminal + short amount
                                     payload=payload):
        review = _review_text(backend, navigator)
        navigator.navigate([NavInsID.USE_CASE_REVIEW_CONFIRM],
                           screen_change_before_first_instruction=False)

    sw, response = monero.transport.async_response()
    assert sw == 0x9000, "terminal INS_VALIDATE refused: %#06x" % sw
    assert len(response) == 0
    return review


@pytest.mark.incremental
class TestFeeReviewWidth:
    """
    An ordinary fee first as the control, then the nine-byte one.

    On a device that has been signing, the failed format left the *previous*
    amount on screen, which is what made this dangerous. These tests cannot
    reproduce that: _setup resets, and INS_RESET zeroes the whole state
    (monero_init.c:43), so ux_amount starts empty and an unfixed build would
    review a bare " XMR". That still fails the assertion below, which is all a
    non-regression test needs, but the stale-value case is the one to picture
    when judging the finding rather than the test.
    """

    @staticmethod
    def test_an_ordinary_fee_is_shown(monero: MoneroCmd,
                                      backend: BackendInterface,
                                      navigator: Navigator, device,
                                      test_name: str):
        if device.is_nano:
            pytest.skip("BAGL shows the fee at P1=1, not in this review")
        review = _fee_as_reviewed(monero, backend, navigator, device,
                                  test_name, FEE)
        assert ORDINARY_TEXT in review, (
            "expected %s in the review, saw: %s" % (ORDINARY_TEXT, review))

    @staticmethod
    def test_a_nine_byte_fee_is_shown(
            monero: MoneroCmd, backend: BackendInterface,
            navigator: Navigator, device, test_name: str):
        if device.is_nano:
            pytest.skip("BAGL shows the fee at P1=1, not in this review")
        review = _fee_as_reviewed(monero, backend, navigator, device,
                                  test_name, NINE_BYTE_FEE)
        assert NINE_BYTE_TEXT in review, (
            "a nine-byte fee was hashed but not shown; review: %s" % review)
