"""
Nothing the device signs says which network it is for.

The BIP32 path is m/44'/128'/0'/0/0 with no network component
(monero_init.c:83-89), so Mainnet, Stagenet and Testnet derive the same keys,
and network_id is read only to pick the base58 prefix and to draw the settings
screens -- never by signing code. A device set to Stagenet will therefore
sign a transaction that spends the same wallet's Mainnet outputs.

Key separation would close this, and was not taken: it strands the Stagenet and
Testnet wallets people already have. A network tag in the transcript is not an
option either, because network verifiers must hash the same bytes. So the
fix is disclosure -- the review now opens with a page naming the network and
saying the keys are shared -- and the finding stays open.

  TestNetworkWarningIsShown       The warning comes before the review and
                                  rejecting on it aborts the transaction.
  TestSigningStillWorks           A payment completes through it.
  TestReviewStartedDirectly       Skipped: the behaviour before the fix.
  TestKeysAreNetworkScoped        Skipped: the requirement that would close the
                                  finding.

Both UIs are covered. Touch draws a page with Continue and Reject; BAGL adds a
step to the front of the review flow, so there it is one more click.

DEBUG=1 forces MONERO_BETA (Makefile:91), so this build is Stagenet.

Run: pytest tests/test_vuln_network_unbound.py -v --device flex

Every test asks for the `monero` fixture, even where unused: pytest reorders
tests to save fixture setup, and one that omits it leaves its class and gets a
fresh class-scoped `state`.
"""

import pytest

from ragger.backend.interface import BackendInterface, RaisePolicy
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_cmd import (MoneroCmd, PROTOCOL_VERSION,
                                      TESTS_ROOT_DIR)
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import InsType, Type
from monero_client.crypto.hmac import hmac_sha256

from monero_client.utils.utils import get_nano_review_instructions
from monero_client.status_words import (
    SW_DENY)

from test_vuln_payment_id_unreviewed import (_setup, _pay, _squash, _page_text,
                                             _prefix_of, FEE, SIGN_PAGE,
                                             ZERO_COMMITMENT)


# What the warning must call the active network, keyed by the address prefix
# the device reports (monero_types.h:37-47). Mainnet is absent on purpose:
# there the keys are the ones the user expects, so nothing is warned about.
NETWORK_NAME = {24: "Stage network", 53: "Test network"}

# Each UI says the shared-keys part in its own words, because a nano line holds
# far less than a touch page.
SHARED_KEYS = "same keys on every network"
SHARED_KEYS_NANO = "Same keys as Main"


def _warning_words(addr: str, device) -> tuple:
    """What this build's warning must say, or skip on a Mainnet one.

    Both UIs name the network the way their own Settings menu does, and nano
    titles every word."""
    prefix = _prefix_of(addr)
    if prefix not in NETWORK_NAME:
        pytest.skip("main network build: no warning by design")
    if device.is_nano:
        return NETWORK_NAME[prefix].title(), SHARED_KEYS_NANO
    return NETWORK_NAME[prefix], SHARED_KEYS


def _terminal_payload(view: bytes, spend: bytes, ak: bytes,
                      blinded_mask: bytes, blinded_amount: bytes,
                      is_change: bool = False) -> bytes:
    """An INS_VALIDATE P1=2 record for one of the wallet's own outputs."""
    return b"".join((
        b"\x00",  # is_subaddress
        b"\x01" if is_change else b"\x00",
        view, spend, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))


@pytest.mark.incremental
class TestNetworkWarningIsShown:
    """The terminal review opens with the shared-keys warning.

    Change as the only output, on both UIs: it draws the shorter review, so
    reaching Reject on nano takes a fixed number of clicks instead of one that
    depends on how the address pages."""

    @staticmethod
    def test_warning_precedes_the_review(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator, device,
                                         test_name: str):
        (addr, view, spend, ak, _enc,
         blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                                test_name, None,
                                                is_change=True)
        net, shared = _warning_words(addr, device)
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        backend.wait_for_text_on_screen("Processing")

        # The reject is an error status, and send_async raises it on leaving
        # its block -- outside any try here. Take it as a status instead.
        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with monero.transport.send_async(
                cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE, p1=2, p2=1,
                option=0x02,  # terminal + short amount
                payload=_terminal_payload(view, spend, ak, blinded_mask,
                                          blinded_amount, is_change=True)):
            backend.wait_for_text_on_screen(net)
            navigator.navigate_and_compare(
                TESTS_ROOT_DIR, test_name, [],
                screen_change_before_first_instruction=False)
            page = _page_text(backend)

            assert net in page, (
                "the warning does not name the network:\n  %s" % page)
            assert shared in page, (
                "the warning does not say the keys are shared:\n  %s" % page)
            assert SIGN_PAGE not in page, (
                "the accept is already on screen, so the warning is not "
                "before the review:\n  %s" % page)

            print("\n[warning] %s" % page)

            # Reject here, not Continue: it ends the transaction, so this stays
            # the last test of its class. On nano that means clicking on to the
            # Reject step, past the warning, the change and the accept.
            if device.is_nano:
                navigator.navigate(
                    get_nano_review_instructions(3),
                    screen_change_before_first_instruction=False,
                    screen_change_after_last_instruction=False)
            else:
                navigator.navigate(
                    [NavInsID.USE_CASE_CHOICE_REJECT],
                    screen_change_before_first_instruction=False)

        sw, _response = monero.transport.async_response()
        assert sw == SW_DENY, (
            "Reject on the warning did not abort: %#06x" % sw)


@pytest.mark.incremental
class TestSigningStillWorks:
    """An honest payment completes with the warning in the way.

    A fix that showed the warning but broke the path past it passes the test
    above and fails here. On nano it also pins the click count monero_cmd
    sends: were the warning step to go, the accept would land on "Reject" and
    the device would answer SW_DENY."""

    @staticmethod
    def test_payment_completes(monero: MoneroCmd, backend: BackendInterface,
                               navigator: Navigator, device, test_name: str):
        if device.is_nano:
            (_addr, view, spend, ak, _enc,
             blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                                    test_name, None,
                                                    is_change=True)
            monero.validate_prehash_init(test_name, device, navigator,
                                         1, 0, FEE)
            monero.validate_prehash_update(
                backend, test_name, navigator, index=1, is_short=True,
                is_change_addr=True, is_subaddress=False,
                dst_pub_view_key=view, dst_pub_spend_key=spend, _ak_amount=ak,
                commitment=ZERO_COMMITMENT, blinded_mask=blinded_mask,
                blinded_amount=blinded_amount, is_last=True)
            monero.validate_prehash_finalize(
                index=1, is_short=False, is_change_addr=True,
                is_subaddress=False, dst_pub_view_key=view,
                dst_pub_spend_key=spend, _ak_amount=ak,
                commitment=ZERO_COMMITMENT, blinded_amount=blinded_amount,
                blinded_mask=blinded_mask, is_last=True)
            monero.close_tx()
            return

        # The NBGL review's page count is what _pay discovers, so let it drive
        # rather than guessing a swipe count here.
        addr, _view, _spend, _enc, review = _pay(monero, backend, navigator,
                                                 device, test_name, None)
        assert _squash(addr) in _squash(review), (
            "the destination is not on the review")


@pytest.mark.skip(reason="behaviour before the fix; kept to reproduce it "
                         "on an unfixed build")
@pytest.mark.incremental
class TestReviewStartedDirectly:
    """The terminal review used to open on its own first page, with nothing
    said about the network."""

    @staticmethod
    def test_first_page_is_the_review(monero: MoneroCmd,
                                      backend: BackendInterface,
                                      navigator: Navigator, device,
                                      test_name: str):
        if device.is_nano:
            pytest.skip("NBGL only")

        (_addr, view, spend, ak, _enc,
         blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                                test_name, None)
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        backend.wait_for_text_on_screen("Processing")
        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with monero.transport.send_async(
                cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE, p1=2, p2=1,
                option=0x02,
                payload=_terminal_payload(view, spend, ak, blinded_mask,
                                          blinded_amount)):
            backend.wait_for_text_on_screen("Review")
            page = _page_text(backend)

            assert SHARED_KEYS not in page
            navigator.navigate([NavInsID.USE_CASE_REVIEW_REJECT],
                               screen_change_before_first_instruction=False)

        sw, _response = monero.transport.async_response()
        assert sw == SW_DENY


@pytest.mark.skip(reason="open: key separation was not implemented, and "
                         "checking it needs the same seed on two networks")
class TestKeysAreNetworkScoped:
    """The requirement that would close the finding.

    The warning tells the user; it does not stop a compromised host. Only
    deriving different keys per network makes a Stagenet signature useless
    against Mainnet outputs."""

    @staticmethod
    def test_stagenet_keys_are_not_the_mainnet_keys(monero: MoneroCmd):
        """Install the seed on a Mainnet build, note get_public_keys, then
        install it on Stagenet: a device that scoped its keys by network gives
        two different pairs. This one gives one pair with two prefixes."""
        pytest.fail("not automated: needs one seed installed on two networks")
