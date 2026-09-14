"""
The review must show the payment ID, or binding it buys nothing.

test_vuln_payment_id_unbound.py pins the other half: the prefix must carry the
payment ID INS_STEALTH produced. That alone stops nothing, because the device
takes the payment ID from the host and never asks about it.

So the host does not need to lie to anyone. It hands INS_STEALTH the attacker's
payment ID, puts the ciphertext it gets back in the prefix, and signs. An honest
wallet does the same, so every check passes.

Only the screen can catch it, and it used to render the destination with
monero_base58_public_key(..., NULL) -- the last argument is the payment ID. That
draws the base address, which every customer of one service shares.

The fix passes the payment ID, so the review draws the integrated address. These
tests pay twice, honestly both times, and read the review off the screen.

Two shapes must keep drawing the base address: an all-zero payment ID, which a
wallet puts in most transactions so they look alike on chain
(cryptonote_tx_utils.cpp, near line 313), and no payment ID at all. Otherwise
every ordinary send would show an address the user never typed.

Classes, in file order:

  TestIntegratedAddressReference  The reference. Python builds the addresses
                                  here, and the plain one must equal what the
                                  device reports.
  TestPaymentIdIsShown            The fix. Two payment IDs, two reviews, each
                                  with its own integrated address.
  TestOrdinaryTransactionShapes   The control. A dummy payment ID and no
                                  payment ID both draw the base address.
  TestReviewIgnoredPaymentId      The old behaviour: one review either way.
                                  Skipped, it needs a build without the fix.
  TestSubaddressClaimRefused      The fix. A subaddress with a payment ID is
                                  refused.

The reference goes first: if Python and the device disagree, read everything
below as broken, not as a finding.

The refusal goes last. It exits the app.

NBGL only wherever a screen is read. BAGL draws the same ux_address, so the
finding is not device specific, but it pages with clicks and one reader cannot
do both.

Run: pytest tests/test_vuln_payment_id_unreviewed.py -v --device flex
     (DEBUG=1 build. Add --golden_run once to record the snapshots.)

Snapshot directories take the name of the test function. Method names must stay
unique across the whole suite.

Every test asks for the `monero` fixture, even where it is unused. pytest
reorders tests to save fixture setup, and a test that omits it leaves its class
and runs against a fresh class-scoped `state`.
"""

import pytest

from Crypto.Hash import keccak

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION, TESTS_ROOT_DIR
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import InsType, SigType, Type
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.base58 import encode as b58_encode, decode as b58_decode
from monero_client.utils.varint import encode_varint
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

from test_vuln_payment_id_unbound import (PAY_ID_USER, PAY_ID_ATTACKER,
                                          PAY_ID_DUMMY,
                                          SW_SECURITY_PAYMENT_ID,
                                          _nonce, _stealth)

ZERO_COMMITMENT = bytes(32)
FEE = 30660000            # 0.00003066 XMR
AMOUNT = 907880000        # 0.00090788 XMR

SIGN_PAGE = "Sign transaction"

# The base58 prefix of an integrated address, by the prefix of the plain address
# on the same network (monero_types.h). The device picks the integrated one as
# soon as monero_base58_public_key gets a payment ID.
_INTEGRATED_PREFIX = {18: 19, 24: 25, 53: 54}


def _address(prefix: int, spend: bytes, view: bytes,
             payment_id: bytes = b"") -> str:
    """A Monero address, built here instead of asked of the device.

    Varint prefix, spend key, view key, payment ID if any, then 4 checksum
    bytes: the first 4 of the keccak of all the rest."""
    body = encode_varint(prefix) + spend + view + payment_id
    k = keccak.new(digest_bits=256)
    k.update(body)
    return b58_encode(body + k.digest()[:4])


def _prefix_of(addr: str) -> int:
    """The network prefix of an address, so the tests do not hardcode a net."""
    return bytes.fromhex(b58_decode(addr))[0]


def _integrated(addr: str, spend: bytes, view: bytes,
                payment_id: bytes) -> str:
    """The integrated address for these keys and this payment ID, on whatever
    network the device is built for."""
    return _address(_INTEGRATED_PREFIX[_prefix_of(addr)], spend, view,
                    payment_id)


def _squash(text: str) -> str:
    """Drop everything that is not a base58 character.

    A page arrives as separate text events, so an address can be split across
    them. Substring checks need the spacing gone."""
    return "".join(c for c in text if c.isalnum())


def _page_text(backend: BackendInterface) -> str:
    """Every text event on the current screen, joined."""
    return " | ".join(event.get("text", "")
                      for event in backend.get_current_screen_content()["events"])


def _read_review(backend: BackendInterface, navigator: Navigator,
                 snapshot_name: str, max_pages: int = 12) -> str:
    """Swipe through the review, snapshot every page, return them all, and stop
    on the hold-to-sign page so the caller can confirm.

    The page count is found, not scripted, because whether the pages differ is
    the question. navigate_and_compare with no instructions just snapshots the
    screen as it stands."""
    # DEBUG builds run on Stagenet, so the review opens with a shared-keys
    # warning. Not snapshotted: this file measures review pages.
    backend.wait_for_text_on_screen("Continue")
    navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM],
                       screen_change_before_first_instruction=False)

    backend.wait_for_text_on_screen("Review")
    pages = []
    for idx in range(max_pages):
        navigator.navigate_and_compare(
            TESTS_ROOT_DIR, snapshot_name, [],
            screen_change_before_first_instruction=False, snap_start_idx=idx)
        page = _page_text(backend)
        pages.append(page)
        if SIGN_PAGE in page:
            return " || ".join(pages)
        navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT],
                           screen_change_before_first_instruction=False)
    raise AssertionError(
        "never reached the '%s' page in %d swipes; saw: %s"
        % (SIGN_PAGE, max_pages, " || ".join(pages)))


def _send_terminal_output(monero: MoneroCmd, backend: BackendInterface,
                          navigator: Navigator, view: bytes, spend: bytes,
                          ak: bytes, blinded_mask: bytes,
                          blinded_amount: bytes, snapshot_name: str) -> str:
    """Terminal INS_VALIDATE P1=2: draws the review, read it, then approve.

    Not monero.validate_prehash_update(): it swipes a fixed number of times,
    and the pages are what this file measures."""
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
        review = _read_review(backend, navigator, snapshot_name)
        navigator.navigate([NavInsID.USE_CASE_REVIEW_CONFIRM],
                           screen_change_before_first_instruction=False)

    sw, response = monero.transport.async_response()
    assert sw == 0x9000, "terminal INS_VALIDATE refused: %#06x" % sw
    assert len(response) == 0
    return review


def _setup(monero: MoneroCmd, backend: BackendInterface, device,
           snapshot_name: str, payment_id, is_change: bool = False,
           stealth_view: bytes = None):
    """A real one-output transaction, up to just before the review.

    Honest: the prefix nonce is the ciphertext the device returned and the keys
    are its own. The only host choice is which payment ID to encrypt.

    payment_id None means no INS_STEALTH and no nonce, which is what the wallet
    sends with more than two destinations.

    is_change makes that output the change, which the caller must then claim in
    the terminal record too. It draws the shorter review, with no address to
    page through.

    stealth_view overrides the point INS_STEALTH derives the mask against. The
    honest value is the destination's own view key; anything else is the
    unbound-operand case.

    Returns (plain address, view, spend, amount key, encrypted payment ID,
    blinded mask, blinded amount)."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, addr = monero.get_public_keys()
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()

    enc_pid = (None if payment_id is None
               else _stealth(backend, stealth_view or view, tx_priv_key,
                             payment_id))

    ak, eph, _ = monero.gen_txout_keys(
        _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
        dst_pub_view_key=view, dst_pub_spend_key=spend,
        output_index=0, is_change_addr=is_change, is_subaddress=False)

    monero.prefix_hash_init(snapshot_name, device, navigator=None,
                            version=0, timelock=0)
    prefix = build_tx_prefix_outkeys(
        vout_keys=[eph], tx_pubkey=tx_pub_key,
        extra_suffix=(b"" if enc_pid is None else _nonce(enc_pid)))
    assert len(monero.prefix_hash_update(index=1, payload=prefix,
                                         is_last=True)) == 32

    mask = monero.gen_commitment_mask(ak)
    blinded_mask, blinded_amount = monero.blind(
        _ak_amount=ak, mask=mask, amount=AMOUNT, is_short=True)

    return addr, view, spend, ak, enc_pid, blinded_mask, blinded_amount


def _pay(monero: MoneroCmd, backend: BackendInterface, navigator: Navigator,
         device, snapshot_name: str, payment_id):
    """One whole honest payment, reviewed and prehashed.

    Returns (plain address, view key, spend key, encrypted payment ID,
    review text)."""
    (addr, view, spend, ak, enc_pid,
     blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                            snapshot_name, payment_id)

    monero.validate_prehash_init(snapshot_name, device, navigator, 1, 0, FEE)
    review = _send_terminal_output(monero, backend, navigator, view, spend, ak,
                                   blinded_mask, blinded_amount, snapshot_name)
    monero.validate_prehash_finalize(
        index=1, is_short=False, is_change_addr=False, is_subaddress=False,
        dst_pub_view_key=view, dst_pub_spend_key=spend, _ak_amount=ak,
        commitment=ZERO_COMMITMENT, blinded_amount=blinded_amount,
        blinded_mask=blinded_mask, is_last=True)
    monero.close_tx()

    return addr, view, spend, enc_pid, review


def _expect_subaddress_claim_refused(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     navigator: Navigator, device,
                                     snapshot_name: str):
    """Set a payment ID, then claim the destination is a subaddress.

    The output is derived as a standard one, so the claim in this APDU is the
    only thing wrong.

    Nothing is drawn -- the refusal comes before the address is built -- so the
    send is synchronous. A refusal arrives as an error type, not a status."""
    (_addr, view, spend, ak, _enc,
     blinded_mask, blinded_amount) = _setup(monero, backend, device,
                                            snapshot_name, PAY_ID_USER)

    monero.validate_prehash_init(snapshot_name, device, navigator,
                                 index=1, txntype=0, txnfee=FEE)
    payload = b"".join((
        b"\x01",  # is_subaddress -- the lie under test
        b"\x00",  # is_change_addr
        view, spend, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))
    try:
        monero.transport.send(cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE,
                              p1=2, p2=1, option=0x02, payload=payload)
        sw, _response = monero.transport.recv()
    except ExceptionRAPDU as exc:
        sw = exc.status
    assert sw == SW_SECURITY_PAYMENT_ID, (
        "expected %#06x for a subaddress carrying a payment ID, got %#06x"
        % (SW_SECURITY_PAYMENT_ID, sw))


def _state():
    return {"addr": None, "view": None, "spend": None,
            "user": None, "attacker": None, "dummy": None, "none": None}


@pytest.mark.incremental
class TestIntegratedAddressReference:
    """Python must agree with the device about addresses first.

    The device is never asked for an integrated address, so it cannot be
    compared. The plain one, built the same way from the same parts, can be. If
    that matches, so does the other: only the prefix and 8 bytes differ."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_ref_standard_address_matches_device(monero: MoneroCmd, state):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        view, spend, addr = monero.get_public_keys()
        state["view"], state["spend"], state["addr"] = view, spend, addr

        prefix = _prefix_of(addr)
        assert prefix in _INTEGRATED_PREFIX, (
            "unknown network prefix %d -- add it to _INTEGRATED_PREFIX" % prefix)
        assert _address(prefix, spend, view) == addr, (
            "the address built here differs from the device's own, so nothing "
            "below can be trusted")

    @staticmethod
    def test_ref_payment_id_changes_the_address(monero: MoneroCmd, state):
        """The two payment IDs give two different integrated addresses.

        This is what a user compares against what they typed."""
        addr, view, spend = state["addr"], state["view"], state["spend"]
        user = _integrated(addr, spend, view, PAY_ID_USER)
        attacker = _integrated(addr, spend, view, PAY_ID_ATTACKER)

        assert user != attacker, "the payment ID does not affect the address"
        assert user != addr and attacker != addr, (
            "an integrated address must differ from the plain one")
        assert len(user) == len(attacker), (
            "two integrated addresses of unequal length -- check the encoder")
        state["user"], state["attacker"] = user, attacker


@pytest.mark.incremental
class TestPaymentIdIsShown:
    """Two honest payments, two payment IDs, two different reviews.

    Nothing is malformed. Both are what monero-gui builds and both reach the
    pre-MLSAG hash. Each review must carry the integrated address Python
    computed for its payment ID -- the right one, not just a different one."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_review_user_payment_id(monero: MoneroCmd,
                                    backend: BackendInterface,
                                    navigator: Navigator, device,
                                    test_name: str, state):
        """Pay with the payment ID the user asked for."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        addr, view, spend, enc, review = _pay(monero, backend, navigator,
                                              device, test_name, PAY_ID_USER)
        state["addr"], state["view"], state["spend"] = addr, view, spend
        state["user"] = (enc, review)

    @staticmethod
    def test_review_attacker_payment_id(monero: MoneroCmd,
                                        backend: BackendInterface,
                                        navigator: Navigator, device,
                                        test_name: str, state):
        """Same transaction, same keys, same amount. Attacker's payment ID."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        _a, _v, _s, enc, review = _pay(monero, backend, navigator, device,
                                       test_name, PAY_ID_ATTACKER)
        state["attacker"] = (enc, review)

    @staticmethod
    def test_review_shows_the_integrated_address(monero: MoneroCmd, device,
                                                 state):
        """Each review carries its own integrated address, and only its own.

        Python builds both, so this checks the encoding, not just that two
        strings differ."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        enc_user, review_user = state["user"]
        enc_attacker, review_attacker = state["attacker"]
        addr, view, spend = state["addr"], state["view"], state["spend"]

        assert enc_user != enc_attacker, (
            "the two payment IDs encrypted to the same bytes, so there is "
            "nothing for the review to distinguish")
        assert review_user != review_attacker, (
            "the reviews are still identical, so the payment ID is not shown")

        want_user = _integrated(addr, spend, view, PAY_ID_USER)
        want_attacker = _integrated(addr, spend, view, PAY_ID_ATTACKER)

        seen_user = _squash(review_user)
        seen_attacker = _squash(review_attacker)

        assert want_user in seen_user, (
            "the user's integrated address is not on screen\n"
            "  want %s\n  saw  %s" % (want_user, review_user))
        assert want_attacker in seen_attacker, (
            "the attacker's integrated address is not on screen\n"
            "  want %s\n  saw  %s" % (want_attacker, review_attacker))

        # Each review shows one address and not the other, so a user comparing
        # against what they typed sees a mismatch rather than a superset.
        assert want_attacker not in seen_user, (
            "the user's review also carries the attacker's address")
        assert want_user not in seen_attacker, (
            "the attacker's review also carries the user's address")

        # The plain address must be gone, or the two would still look alike to
        # anyone matching on the base form.
        assert _squash(addr) not in seen_user, (
            "the plain address is still drawn alongside the integrated one")


@pytest.mark.incremental
class TestOrdinaryTransactionShapes:
    """The control. A wrong fix breaks every ordinary send here.

    A wallet puts an all-zero payment ID in most transactions, and none at all
    with more than two destinations. Neither is a label anybody chose, so both
    must draw the plain address, and must draw the same thing."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_review_dummy_payment_id(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     navigator: Navigator, device,
                                     test_name: str, state):
        """INS_STEALTH is called with eight zero bytes, as the wallet does."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        addr, _v, _s, _enc, review = _pay(monero, backend, navigator, device,
                                          test_name, PAY_ID_DUMMY)
        state["addr"] = addr
        state["dummy"] = review

    @staticmethod
    def test_review_without_payment_id(monero: MoneroCmd,
                                       backend: BackendInterface,
                                       navigator: Navigator, device,
                                       test_name: str, state):
        """No INS_STEALTH and no nonce in the prefix."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        _a, _v, _s, enc, review = _pay(monero, backend, navigator, device,
                                       test_name, None)
        assert enc is None
        state["none"] = review

    @staticmethod
    def test_both_show_the_plain_address(monero: MoneroCmd, device, state):
        """The dummy is invisible: same screen as a transaction without one."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        addr = state["addr"]
        dummy, none = state["dummy"], state["none"]

        assert _squash(addr) in _squash(dummy), (
            "a dummy payment ID changed the address on screen, so every "
            "ordinary send now shows an address the user never typed:\n  %s"
            % dummy)
        assert _squash(addr) in _squash(none), (
            "the plain address is not drawn without a payment ID:\n  %s" % none)
        assert dummy == none, (
            "the dummy payment ID is visible somewhere in the review:\n"
            "  dummy %s\n  none  %s" % (dummy, none))


@pytest.mark.skip(reason="The old behaviour: the review was the same whichever "
                         "payment ID was used. Passes only on a build that "
                         "renders the destination with NULL. Use --run-skipped "
                         "to see it again.")
@pytest.mark.incremental
class TestReviewIgnoredPaymentId:
    """What the device did before the payment ID reached the screen.

    Kept because it is the finding: two transactions paying different customers
    of one service, reviewed identically. Its snapshots need a build without
    the fix."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_ignored_user_payment_id(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     navigator: Navigator, device,
                                     test_name: str, state):
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        addr, _v, _s, enc, review = _pay(monero, backend, navigator, device,
                                         test_name, PAY_ID_USER)
        state["addr"] = addr
        state["user"] = (enc, review)

    @staticmethod
    def test_ignored_attacker_payment_id(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator, device,
                                         test_name: str, state):
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        _a, _v, _s, enc, review = _pay(monero, backend, navigator, device,
                                       test_name, PAY_ID_ATTACKER)
        state["attacker"] = (enc, review)

    @staticmethod
    def test_ignored_reviews_are_identical(monero: MoneroCmd, device, state):
        """Identical screens, different transactions."""
        if device.is_nano:
            pytest.skip("NBGL only; BAGL pages the review with clicks")
        enc_user, review_user = state["user"]
        enc_attacker, review_attacker = state["attacker"]

        assert enc_user != enc_attacker, (
            "not reproduced: the two payment IDs encrypted to the same bytes")
        assert review_user == review_attacker, (
            "not reproduced: the reviews differ, so the payment ID is shown")
        assert _squash(state["addr"]) in _squash(review_user), (
            "the plain address is not on screen either")

        print("\n[impact] both payments reviewed as %s\n"
              "         on chain they carry %s and %s\n"
              "         -> the service credits whoever the host chose"
              % (state["addr"], enc_user.hex(), enc_attacker.hex()))


@pytest.mark.incremental
class TestSubaddressClaimRefused:
    """A payment ID with a subaddress is refused, not drawn.

    base58 prefers the payment ID over is_subaddress, so the pair would build
    an integrated address from subaddress keys, which nobody can pay. No wallet
    asks for it: the two are mutually exclusive when an address is parsed.

    Last in the file. A refusal exits the app."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _state()

    @staticmethod
    def test_subaddress_with_payment_id_refused(monero: MoneroCmd,
                                                backend: BackendInterface,
                                                navigator: Navigator, device,
                                                test_name: str, state):
        _expect_subaddress_claim_refused(monero, backend, navigator, device,
                                         test_name)
