"""
Test suite for amount=0 validation in Monero transactions.

This test demonstrates:
- Retrieves primary address keys from device at runtime (no hardcoded keys)
- Attempts to send transaction with amount=0 to a NON-CHANGE output
- Expected behavior: Firmware should reject with SW_SECURITY_AMOUNT_CHAIN_CONTROL (0x6913)
- Uses ring signature structure: 2 FAKE decoys + 1 REAL signature
- All test methods have "_zero" suffix to avoid conflicts with other tests
"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from monero_client.monero_types import SigType, Keys
from monero_client.monero_cmd import MoneroCmd

@pytest.mark.incremental
class TestSignatureRealAmountZero:
    """Monero transaction test - amount=0 validation failure test."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        # Sender keys will be retrieved from device in test_get_keys
        # Using placeholder - will be replaced with actual device keys
        sender = None
        receiver = None  # Will be set to sender (churn to self)

        return {
            "sender": sender,
            # Transaction state - 1 output: amount=0 to non-change address (should fail)
            "receiver_number": 1,
            "receiver": [receiver],
            "is_change_addr": [False],  # Non-change output with amount=0 triggers error
            "is_subaddress": [False],
            "amount": [0],  # amount=0 + is_change=False → SW_SECURITY_AMOUNT_CHAIN_CONTROL (0x6913)
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "_ak_amount": [[]],
            "blinded_amount": [[]],
            "blinded_mask": [[]],
            "y": [[]]
        }

    @staticmethod
    def test_reset_zero(monero):
        """Reset device and get version."""
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_get_keys_zero(monero: MoneroCmd, state):
        """Retrieve primary address keys from device."""
        # Get primary address keys from device
        public_view_key, public_spend_key, base58_address = monero.get_public_keys()

        sender = Keys(
            public_view_key=public_view_key,
            public_spend_key=public_spend_key,
            secret_view_key=None,
            secret_spend_key=None,
            addr=base58_address
        )

        state["sender"] = sender
        # Set single output with amount=0 to test validation failure
        state["receiver"][0] = sender

        print(f"Device public view key: {public_view_key.hex()}")
        print(f"Device public spend key: {public_spend_key.hex()}")
        print(f"Device primary address: {base58_address}")
        print("\nAttempting to send amount=0 to non-change output - should fail with 0x6913")

    # ==================== TX1 DECOY 1 (FAKE MODE) ====================

    @staticmethod
    def test_decoy1_set_sig_zero(monero):
        """Set FAKE mode for TX1 decoy 1."""
        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.FAKE)
        assert sig_mode == SigType.FAKE

    @staticmethod
    def test_decoy1_open_zero(monero, state):
        """Open TX1 decoy 1 - shows 'Preparing TX'."""
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32
        state["decoy1_tx_pub_key"] = tx_pub_key
        state["decoy1_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_decoy1_gen_txout_keys_zero(monero: MoneroCmd, state):
        """Generate output keys for TX1 decoy 1."""
        for index in range(state["receiver_number"]):
            _, _ = monero.gen_txout_keys(
                _tx_priv_key=state["decoy1_tx_priv_key"],
                tx_pub_key=state["decoy1_tx_pub_key"],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False
            )

    @staticmethod
    def test_decoy1_prefix_hash_zero(monero: MoneroCmd, device, test_name: str):
        """Prefix hash for TX1 decoy 1 - no UI validation."""
        monero.prefix_hash_init(test_name + "_tx1_decoy1", device,
                                navigator=None, version=0, timelock=0)
        _ = monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_decoy1_close_zero(monero: MoneroCmd):
        """Close TX1 decoy 1 - no 'Transaction signed' in FAKE mode."""
        monero.close_tx()

    # ==================== TX1 DECOY 2 (FAKE MODE) ====================

    @staticmethod
    def test_decoy2_set_sig_zero(monero):
        """Set FAKE mode for TX1 decoy 2."""
        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.FAKE)
        assert sig_mode == SigType.FAKE

    @staticmethod
    def test_decoy2_open_zero(monero, state):
        """Open TX1 decoy 2 - shows 'Preparing TX'."""
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32
        state["decoy2_tx_pub_key"] = tx_pub_key
        state["decoy2_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_decoy2_gen_txout_keys_zero(monero: MoneroCmd, state):
        """Generate output keys for TX1 decoy 2."""
        for index in range(state["receiver_number"]):
            _, _ = monero.gen_txout_keys(
                _tx_priv_key=state["decoy2_tx_priv_key"],
                tx_pub_key=state["decoy2_tx_pub_key"],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False
            )

    @staticmethod
    def test_decoy2_prefix_hash_zero(monero: MoneroCmd, device, test_name: str):
        """Prefix hash for TX1 decoy 2 - no UI validation."""
        monero.prefix_hash_init(test_name + "_tx1_decoy2", device,
                                navigator=None, version=0, timelock=0)
        _ = monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_decoy2_close_zero(monero: MoneroCmd):
        """Close TX1 decoy 2 - no 'Transaction signed' in FAKE mode."""
        monero.close_tx()

    # ==================== TX1 REAL SIGNATURE ====================

    @staticmethod
    def test_set_sig_zero(monero):
        """Set signature mode to REAL for first transaction."""
        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.REAL)
        assert sig_mode == SigType.REAL

    @staticmethod
    def test_open_tx_zero(monero, state):
        """Open first transaction - device generates transaction keys."""
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()

        # These should be placeholder values
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32

        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key
        print(f"TX1: Transaction public key: {tx_pub_key.hex()}")

    @staticmethod
    def test_gen_txout_keys_zero(monero: MoneroCmd, state):
        """Generate output keys for first transaction."""
        for index in range(state["receiver_number"]):
            _ak_amount, out_ephemeral_pub_key = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False
            )

            state["_ak_amount"][index].append(_ak_amount)
            print(f"TX1 Output {index}: ephemeral key = {out_ephemeral_pub_key.hex()}")

    @staticmethod
    def test_prefix_hash_zero(monero: MoneroCmd, navigator: Navigator, device, test_name: str):
        """Compute transaction prefix hash for first transaction."""
        monero.prefix_hash_init(test_name, device,
                                navigator=navigator, version=0, timelock=0)
        result = monero.prefix_hash_update(
            index=1,
            payload=b"",
            is_last=True
        )
        print(f"TX1 Prefix hash: {result.hex()}")

    @staticmethod
    def test_gen_commitment_mask_zero(monero: MoneroCmd, state):
        """Generate commitment masks for first transaction."""
        for index in range(state["receiver_number"]):
            assert len(state["_ak_amount"][index]) != 0
            s = monero.gen_commitment_mask(state["_ak_amount"][index][0])
            state["y"][index].append(s)

    @staticmethod
    def test_blind_zero(monero: MoneroCmd, state):
        """Blind amounts for first transaction."""
        for index in range(state["receiver_number"]):
            assert len(state["y"][index]) != 0
            assert len(state["_ak_amount"][index]) != 0

            print(f'TX1: Blinding output {index}, amount = {state["amount"][index]}')
            blinded_mask, blinded_amount = monero.blind(
                _ak_amount=state["_ak_amount"][index][0],
                mask=state["y"][index][0],
                amount=state["amount"][index],
                is_short=True
            )

            mask, amount = monero.unblind(
                _ak_amount=state["_ak_amount"][index][0],
                blinded_mask=blinded_mask,
                blinded_amount=blinded_amount,
                is_short=True
            )

            assert state["y"][index][0] == mask
            assert state["amount"][index] == int.from_bytes(amount, byteorder="little")

            state["blinded_mask"][index].append(blinded_mask)
            state["blinded_amount"][index].append(blinded_amount)

            assert len(state["y"][index]) != 0
            assert len(state["_ak_amount"][index]) != 0
            assert len(state["blinded_amount"][index]) != 0
            assert len(state["blinded_mask"][index]) != 0

    @staticmethod
    def test_validate_zero(monero: MoneroCmd,
                      backend: BackendInterface,
                      navigator: Navigator,
                      test_name,
                      state):
        """Validate transaction with amount=0 - EXPECTS FAILURE with SW_SECURITY_AMOUNT_CHAIN_CONTROL."""
        device = backend.device
        fee: int = 30660000  # 0.00003066 XMR

        # Fee validation - USER APPROVAL REQUIRED
        monero.validate_prehash_init(test_name,
                                     device,
                                     navigator,
                                     1,
                                     0,
                                     fee)

        # Attempt to validate output with amount=0 and is_change=False
        # This should fail with SW_SECURITY_AMOUNT_CHAIN_CONTROL (0x6913)
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.validate_prehash_update(
                backend,
                test_name,
                navigator,
                index=1,
                is_short=True,
                is_change_addr=False,  # Non-change output
                is_subaddress=False,
                dst_pub_view_key=state["receiver"][0].public_view_key,
                dst_pub_spend_key=state["receiver"][0].public_spend_key,
                _ak_amount=state["_ak_amount"][0][0],
                commitment=bytes.fromhex(32*"00"),
                blinded_amount=state["blinded_amount"][0][0],
                blinded_mask=state["blinded_mask"][0][0],
                is_last=False,  # Set to False to skip navigation - error happens before UI
                do_navigation = False
            )

        # Verify the error code is SW_SECURITY_AMOUNT_CHAIN_CONTROL
        assert exc_info.value.status == 0x6913, \
            f"Expected SW_SECURITY_AMOUNT_CHAIN_CONTROL (0x6913), got {hex(exc_info.value.status)}"

        print("\n✓ Test passed: Firmware correctly rejected amount=0 with error 0x6913")

        # Note: No validate_prehash_finalize or close_tx needed since transaction was rejected
        # No test_close_tx_zero needed - transaction is rejected before completion
