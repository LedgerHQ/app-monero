"""
The NBGL review is filled across several INS_VALIDATE APDUs and drawn only at
the last one, so each queued row must stay as it was when it was added, and a
row that does not fit must end the transaction there.

Change titles: every change row used to point at one shared title buffer, so
the last change output's "Change account N" relabelled all earlier ones. A
host could send change to an account the wallet never scans and hide it behind
a last change row to an ordinary account.

Overflow: when the review is full, the row helper cancels the transaction and
replies SW_DENY, but its caller used to carry on. Mid-review it then replied
SW_OK as well and put the spinner back over the rejection; on the last output
it drew the review of the aborted transaction. A wallet paying four
destinations reaches it through the address rows, and six change outputs reach
it through the amount rows.

  TestChangeRowsKeepTheirAccount  Two change rows show their own accounts.
  TestOverflowMidReviewStops      A fourth destination is refused, and the
                                  device does not go back to "Processing".
  TestOverflowOnLastOutputStops   The same as the last output: no review is
                                  drawn after the refusal.
  TestAmountOverflowMidReviewStops     A sixth change output is refused, and
                                       the device does not go back to
                                       "Processing".
  TestAmountOverflowOnLastOutputStops  The same as the last output.
  TestChangeRowsWereRelabelled    Skipped: the behaviour before the fix.
  TestOverflowWasFollowedByMore   Skipped: the behaviour before the fix.

NBGL only: Nano reviews and confirms each output on its own.

DEBUG=1 builds run on Stagenet, so a review opens with a shared-keys warning.

Every test asks for the `monero` fixture, even where unused: pytest reorders
tests to save fixture setup, and one that omits it leaves its class.
"""

import struct

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_crypto_cmd import MoneroCryptoCmd, PROTOCOL_VERSION
from monero_client.monero_types import InsType, SigType, Type
from monero_client.crypto.hmac import hmac_sha256
from monero_client.status_words import SW_DENY
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

from test_vuln_change_address import (_USER, _FEE, _compute_subaddress_keys,
                                      _record_index)
from test_vuln_payment_id_unreviewed import _page_text, SIGN_PAGE

XMR = 1_000_000_000_000
NETWORK_WARNING = "Stage network"


@pytest.fixture(autouse=True, scope="module")
def nbgl_only(device):
    if device.is_nano:
        pytest.skip("Nano reviews each output on its own")


def _dest(amount):
    """A plain payment to the user's primary address."""
    return (_USER.public_view_key, _USER.public_spend_key, False, False,
            amount)


def _change(major, amount):
    """Change to the root of account `major`."""
    view, spend = _compute_subaddress_keys(major=major, minor=0)
    return (view, spend, True, True, amount)


def _prepare(monero: MoneroCmd, device, test_name: str, outputs, record=()):
    """Open a REAL transaction and run it up to the first INS_VALIDATE P1=2.

    `record` lists the (major, minor) of inputs whose keys are derived, which
    is what lets change go to those accounts. Returns one APDU payload per
    output."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, fvk, _ = monero.open_tx()
    for major, minor in record:
        _record_index(monero, fvk, major=major, minor=minor)

    aks, ephs = [], []
    for i, (view, spend, is_change, is_sub, _amount) in enumerate(outputs):
        ak, eph, _ = monero.gen_txout_keys(
            _tx_priv_key=_tx_priv_key, tx_pub_key=tx_pub_key,
            dst_pub_view_key=view, dst_pub_spend_key=spend, output_index=i,
            is_change_addr=is_change, is_subaddress=is_sub)
        aks.append(ak)
        ephs.append(eph)

    prefix = build_tx_prefix_outkeys(vout_keys=ephs, tx_pubkey=tx_pub_key)
    monero.prefix_hash_init(test_name, device, navigator=None, version=0,
                            timelock=0)
    # Six or more outputs do not fit one APDU; P2 counts the chunks from 1.
    chunks = [prefix[i:i + 200] for i in range(0, len(prefix), 200)]
    for i, chunk in enumerate(chunks):
        monero.prefix_hash_update(index=i + 1, payload=chunk,
                                  is_last=i == len(chunks) - 1)

    masks = [monero.gen_commitment_mask(ak) for ak in aks]
    payloads = []
    for (view, spend, is_change, is_sub, amount), ak, y in zip(outputs, aks,
                                                              masks):
        bm, ba = monero.blind(_ak_amount=ak, mask=y, amount=amount,
                              is_short=True)
        payloads.append(b"".join((
            b"\x01" if is_sub else b"\x00",
            b"\x01" if is_change else b"\x00",
            view, spend, ak,
            hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
            bytes(32),  # commitment (DEBUG: BYPASS_COMMITMENT_FOR_TESTS)
            bm, ba,
        )))
    return payloads


def _output_apdu(index: int, payload: bytes, is_last: bool) -> bytes:
    option = (0x00 if is_last else 0x80) | 0x02  # | short amount
    return struct.pack("BBBBBB", PROTOCOL_VERSION, InsType.INS_VALIDATE.value,
                       2, index, 1 + len(payload), option) + payload


def _send_output(backend: BackendInterface, index: int, payload: bytes,
                 is_last: bool) -> int:
    """One output whose reply comes without a review: return its status."""
    backend.wait_for_text_on_screen("Processing")
    try:
        return backend.exchange_raw(_output_apdu(index, payload,
                                                 is_last)).status
    except ExceptionRAPDU as exc:
        return exc.status


def _review_pages(backend: BackendInterface, navigator: Navigator,
                  max_pages: int = 8) -> list:
    """Read every page of the final review and stop on the sign page."""
    backend.wait_for_text_on_screen("Continue")
    navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM],
                       screen_change_before_first_instruction=False)
    backend.wait_for_text_on_screen("Review")
    pages = []
    for _ in range(max_pages):
        page = _page_text(backend)
        pages.append(page)
        if SIGN_PAGE in page:
            return pages
        navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT],
                           screen_change_before_first_instruction=False)
    raise AssertionError("never reached the '%s' page; saw: %s"
                         % (SIGN_PAGE, " || ".join(pages)))


def _two_change_review(monero: MoneroCmd, backend: BackendInterface,
                       navigator: Navigator, device, test_name: str) -> str:
    """Change to account 5, then change to account 7 as the last output, both
    spent from. Approve the review and return its text."""
    payloads = _prepare(monero, device, test_name,
                        [_change(5, 1 * XMR), _change(7, 2 * XMR)],
                        record=((5, 0), (7, 0)))
    monero.validate_prehash_init(test_name, device, navigator, 1, 0, _FEE)
    assert _send_output(backend, 1, payloads[0], is_last=False) == 0x9000

    backend.wait_for_text_on_screen("Processing")
    with monero.transport.send_async(cla=PROTOCOL_VERSION,
                                     ins=InsType.INS_VALIDATE, p1=2, p2=2,
                                     option=0x02, payload=payloads[1]):
        review = " || ".join(_review_pages(backend, navigator))
        navigator.navigate([NavInsID.USE_CASE_REVIEW_CONFIRM],
                           screen_change_before_first_instruction=False)
    sw, _ = monero.transport.async_response()
    assert sw == 0x9000, "the last change output was refused: %#06x" % sw
    print("\n[review] %s" % review)
    return review


# Three destinations fill the review's address rows, so the fourth overflows.
_FOUR_DESTINATIONS = [_dest(1 * XMR), _dest(1 * XMR), _dest(1 * XMR),
                      _dest(1 * XMR)]

# The fee and five change outputs fill the six amount rows. Change adds no
# address row, so the sixth change output overflows the amounts alone.
_SIX_CHANGES = [_change(5, 1 * XMR)] * 6


def _overflow(monero: MoneroCmd, backend: BackendInterface,
              navigator: Navigator, device, test_name: str, outputs,
              fits: int, record=()) -> int:
    """Send the `fits` outputs the review has room for, then the next one,
    and return its status."""
    payloads = _prepare(monero, device, test_name, outputs, record)
    monero.validate_prehash_init(test_name, device, navigator, 1, 0, _FEE)
    for i in range(fits):
        assert _send_output(backend, i + 1, payloads[i], is_last=False) == \
            0x9000
    return _send_output(backend, fits + 1, payloads[fits],
                        is_last=fits + 1 == len(outputs))


def _overflow_mid_review(monero: MoneroCmd, backend: BackendInterface,
                         navigator: Navigator, device,
                         test_name: str) -> int:
    """Four destinations then change: the fourth destination overflows."""
    return _overflow(monero, backend, navigator, device, test_name,
                     _FOUR_DESTINATIONS + [_change(0, 1 * XMR)], fits=3)


def _overflow_on_last(monero: MoneroCmd, backend: BackendInterface,
                      navigator: Navigator, device, test_name: str) -> int:
    """Four destinations, the fourth being the last output."""
    return _overflow(monero, backend, navigator, device, test_name,
                     _FOUR_DESTINATIONS, fits=3)


@pytest.mark.incremental
class TestChangeRowsKeepTheirAccount:
    """Each change row names the account its own output goes to."""

    @staticmethod
    def test_each_change_row_shows_its_account(monero: MoneroCmd,
                                               backend: BackendInterface,
                                               navigator: Navigator, device,
                                               test_name: str):
        review = _two_change_review(monero, backend, navigator, device,
                                    test_name)
        assert "Change account 5" in review, (
            "the first change row lost its account: %s" % review)
        assert "Change account 7" in review, (
            "the last change row lost its account: %s" % review)


@pytest.mark.incremental
class TestOverflowMidReviewStops:
    """The refusal is the only reply, and the device stays on it."""

    @staticmethod
    def test_fourth_destination_is_refused(monero: MoneroCmd,
                                           backend: BackendInterface,
                                           navigator: Navigator, device,
                                           test_name: str):
        sw = _overflow_mid_review(monero, backend, navigator, device,
                                  test_name)
        assert sw == SW_DENY, "expected SW_DENY, got %#06x" % sw
        # After a refusal the device shows the rejection and goes home. The
        # spinner coming back means the caller went on as if it had accepted.
        backend.wait_for_text_not_on_screen("Processing", timeout=5)


@pytest.mark.incremental
class TestOverflowOnLastOutputStops:
    """No review of the aborted transaction is drawn after the refusal."""

    @staticmethod
    def test_no_review_after_the_refusal(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator, device,
                                         test_name: str):
        sw = _overflow_on_last(monero, backend, navigator, device, test_name)
        assert sw == SW_DENY, "expected SW_DENY, got %#06x" % sw
        with pytest.raises(TimeoutError):
            backend.wait_for_text_on_screen(NETWORK_WARNING, timeout=5)


@pytest.mark.incremental
class TestAmountOverflowMidReviewStops:
    """A sixth change output, with one more output to come, is refused and
    nothing follows the refusal."""

    @staticmethod
    def test_sixth_change_is_refused(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     navigator: Navigator, device,
                                     test_name: str):
        sw = _overflow(monero, backend, navigator, device, test_name,
                       _SIX_CHANGES + [_change(5, 1 * XMR)], fits=5,
                       record=((5, 0),))
        assert sw == SW_DENY, "expected SW_DENY, got %#06x" % sw
        backend.wait_for_text_not_on_screen("Processing", timeout=5)


@pytest.mark.incremental
class TestAmountOverflowOnLastOutputStops:
    """A sixth change output as the last output is refused, and no review of
    the aborted transaction is drawn."""

    @staticmethod
    def test_no_review_after_the_refusal(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator, device,
                                         test_name: str):
        sw = _overflow(monero, backend, navigator, device, test_name,
                       _SIX_CHANGES, fits=5, record=((5, 0),))
        assert sw == SW_DENY, "expected SW_DENY, got %#06x" % sw
        with pytest.raises(TimeoutError):
            backend.wait_for_text_on_screen(NETWORK_WARNING, timeout=5)


@pytest.mark.skip(reason="the behaviour before the fix; run with "
                         "--run-skipped against an unfixed build")
@pytest.mark.incremental
class TestChangeRowsWereRelabelled:
    """Both change rows read "Change account 7" on an unfixed build."""

    @staticmethod
    def test_first_change_row_took_the_last_account(
            monero: MoneroCmd, backend: BackendInterface,
            navigator: Navigator, device, test_name: str):
        review = _two_change_review(monero, backend, navigator, device,
                                    test_name)
        assert "Change account 5" not in review
        assert review.count("Change account 7") == 2, review


@pytest.mark.skip(reason="the behaviour before the fix; run with "
                         "--run-skipped against an unfixed build")
@pytest.mark.incremental
class TestOverflowWasFollowedByMore:
    """On an unfixed build the refused last output still draws a review."""

    @staticmethod
    def test_review_drawn_after_the_refusal(monero: MoneroCmd,
                                            backend: BackendInterface,
                                            navigator: Navigator, device,
                                            test_name: str):
        sw = _overflow_on_last(monero, backend, navigator, device, test_name)
        assert sw == SW_DENY, "expected SW_DENY, got %#06x" % sw
        backend.wait_for_text_on_screen(NETWORK_WARNING, timeout=5)
