"""
Test suite for single Monero CHURN transaction with real device keys.

This test demonstrates:
- Retrieves primary address keys from device at runtime (no hardcoded keys)
- Performs churn transaction to PRIMARY address (send back to self)
- Transaction structure: 2 outputs (destination + change)
  * Output 1: 0.00090788 XMR to primary address (DISPLAYED to user)
  * Output 2: 0 XMR change to primary address (NOT displayed - amount=0 skips UI)
- Uses ring signature structure: 2 FAKE decoys + 1 REAL signature
- All test methods have "_2" suffix to avoid conflicts with test_sig.py

"""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator

from monero_client.monero_types import SigType, Keys
from monero_client.monero_cmd import MoneroCmd

@pytest.mark.incremental
class TestSignatureRealSimple:
    """Monero CHURN transaction test with real device keys - single transaction."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        # Sender keys will be retrieved from device in test_get_keys
        # Using placeholder - will be replaced with actual device keys
        sender = None
        receiver = None  # Will be set to sender (churn to self)
        change = None     # Will be set to sender (change back to self)

        return {
            "sender": sender,
            # Transaction state - 2 outputs: destination + change
            "receiver_number": 2,
            "receiver": [receiver, change],
            "is_change_addr": [False, True],  # First is destination (shown), second is change (not shown)
            "is_subaddress": [False, False],  # Both to primary address
            "amount": [907880000, 0],  # 0.00090788 XMR destination, 0 change
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "_ak_amount": [[], []],
            "blinded_amount": [[], []],
            "blinded_mask": [[], []],
            "y": [[], []]
        }

    @staticmethod
    def test_reset_2(monero):
        """Reset device and get version."""
        monero.reset_and_get_version(monero_client_version=b"0.18")

    @staticmethod
    def test_get_keys_2(monero: MoneroCmd, state):
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
        # Churn to self - both outputs go to sender
        state["receiver"][0] = sender  # Destination output
        state["receiver"][1] = sender  # Change output

        print(f"Device public view key: {public_view_key.hex()}")
        print(f"Device public spend key: {public_spend_key.hex()}")
        print(f"Device primary address: {base58_address}")
        print("\nChurn: Primary → Primary (destination + change with amount=0)")

    # ==================== TX1 DECOY 1 (FAKE MODE) ====================

    @staticmethod
    def test_decoy1_set_sig_2(monero):
        """Set FAKE mode for TX1 decoy 1."""
        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.FAKE)
        assert sig_mode == SigType.FAKE

    @staticmethod
    def test_decoy1_open_2(monero, state):
        """Open TX1 decoy 1 - shows 'Preparing TX'."""
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32
        state["decoy1_tx_pub_key"] = tx_pub_key
        state["decoy1_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_decoy1_gen_txout_keys_2(monero: MoneroCmd, state):
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
    def test_decoy1_prefix_hash_2(monero: MoneroCmd, device, test_name: str):
        """Prefix hash for TX1 decoy 1 - no UI validation."""
        monero.prefix_hash_init(test_name + "_tx1_decoy1", device,
                                navigator=None, version=0, timelock=0)
        _ = monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_decoy1_close_2(monero: MoneroCmd):
        """Close TX1 decoy 1 - no 'Transaction signed' in FAKE mode."""
        monero.close_tx()

    # ==================== TX1 DECOY 2 (FAKE MODE) ====================

    @staticmethod
    def test_decoy2_set_sig_2(monero):
        """Set FAKE mode for TX1 decoy 2."""
        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.FAKE)
        assert sig_mode == SigType.FAKE

    @staticmethod
    def test_decoy2_open_2(monero, state):
        """Open TX1 decoy 2 - shows 'Preparing TX'."""
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32
        state["decoy2_tx_pub_key"] = tx_pub_key
        state["decoy2_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_decoy2_gen_txout_keys_2(monero: MoneroCmd, state):
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
    def test_decoy2_prefix_hash_2(monero: MoneroCmd, device, test_name: str):
        """Prefix hash for TX1 decoy 2 - no UI validation."""
        monero.prefix_hash_init(test_name + "_tx1_decoy2", device,
                                navigator=None, version=0, timelock=0)
        _ = monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_decoy2_close_2(monero: MoneroCmd):
        """Close TX1 decoy 2 - no 'Transaction signed' in FAKE mode."""
        monero.close_tx()

    # ==================== TX1 REAL SIGNATURE ====================

    @staticmethod
    def test_set_sig_2(monero):
        """Set signature mode to REAL for first transaction."""
        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.REAL)
        assert sig_mode == SigType.REAL

    @staticmethod
    def test_open_tx_2(monero, state):
        """Open first transaction - device generates transaction keys."""
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()

        # These should be placeholder values
        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32

        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key
        print(f"TX1: Transaction public key: {tx_pub_key.hex()}")

    @staticmethod
    def test_gen_txout_keys_2(monero: MoneroCmd, state):
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
    def test_prefix_hash_2(monero: MoneroCmd, navigator: Navigator, device, test_name: str):
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
    def test_gen_commitment_mask_2(monero: MoneroCmd, state):
        """Generate commitment masks for first transaction."""
        for index in range(state["receiver_number"]):
            assert len(state["_ak_amount"][index]) != 0
            s = monero.gen_commitment_mask(state["_ak_amount"][index][0])
            state["y"][index].append(s)

    @staticmethod
    def test_blind_2(monero: MoneroCmd, state):
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
    def test_validate_2(monero: MoneroCmd,
                      backend: BackendInterface,
                      navigator: Navigator,
                      test_name,
                      state):
        """Validate first churn transaction - USER MUST APPROVE FEE AND DESTINATION (primary address)."""
        device = backend.device
        fee: int = 30660000  # 0.00003066 XMR

        # Fee validation - USER APPROVAL REQUIRED
        monero.validate_prehash_init(test_name,
                                     device,
                                     navigator,
                                     1,
                                     0,
                                     fee)

        # Output validation - all non-change outputs shown
        # Calculate total swipe count for Flex/Stax:
        # Screens shown: Fee + Output0(amount+address) + Output1(amount)
        # Total: 1 + 2 + 1 = 4 screens → 3 swipes needed (N-1 swipes for N screens)
        total_swipes = 3

        for index in range(state["receiver_number"]):
            is_last = index == (state["receiver_number"] - 1)
            monero.validate_prehash_update(
                backend,
                test_name,
                navigator,
                index=index+1,
                is_short=True,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0],
                commitment=bytes.fromhex(32*"00"),
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=is_last,
                swipe_count=total_swipes
            )

        for index in range(state["receiver_number"]):
            monero.validate_prehash_finalize(
                index=index+1,
                is_short=False,
                is_change_addr=False,
                is_subaddress=False,
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0],
                commitment=bytes.fromhex(32*"00"),
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=True if index == (state["receiver_number"] - 1) else False
            )

    @staticmethod
    def test_close_tx_2(monero: MoneroCmd):
        """Close first transaction - shows 'Transaction signed'."""
        monero.close_tx()
