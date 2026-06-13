"""Sweep-all/sweep-single transaction with Monero's dummy zero change output."""

import pytest

from ragger.backend.interface import BackendInterface
from ragger.navigator import Navigator, NavInsID

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_crypto_cmd import MoneroCryptoCmd, PROTOCOL_VERSION
from monero_client.monero_types import InsType, Keys, SigType, Type
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.utils import get_nano_review_instructions


INPUT_AMOUNT = 210_000_000_000
FEE = 60_300_000
OUTPUT_AMOUNT = INPUT_AMOUNT - FEE
DUMMY_CHANGE_AMOUNT = 0


def _validate_prehash_update_no_compare(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator,
                                         index: int,
                                         is_short: bool,
                                         is_change_addr: bool,
                                         is_subaddress: bool,
                                         dst_pub_view_key: bytes,
                                         dst_pub_spend_key: bytes,
                                         _ak_amount: bytes,
                                         commitment: bytes,
                                         blinded_mask: bytes,
                                         blinded_amount: bytes,
                                         is_last: bool,
                                         swipe_count: int) -> None:
    device = backend.device
    payload = b"".join((
        b"\x01" if is_subaddress else b"\x00",
        b"\x01" if is_change_addr else b"\x00",
        dst_pub_view_key,
        dst_pub_spend_key,
        _ak_amount,
        hmac_sha256(_ak_amount, MoneroCryptoCmd.HMAC_KEY, Type.AMOUNT_KEY),
        commitment,
        blinded_mask,
        blinded_amount,
    ))

    instructions = None
    if device.is_nano:
        instructions = get_nano_review_instructions(1 if is_last else 3)
    elif is_last:
        instructions = [NavInsID.SWIPE_CENTER_TO_LEFT] * swipe_count + [
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_CONFIRM,
        ]

    backend.wait_for_text_on_screen("Processing")
    with monero.transport.send_async(
        cla=PROTOCOL_VERSION,
        ins=InsType.INS_VALIDATE,
        p1=2,
        p2=index,
        option=(0 if is_last else 0x80) | (0x02 if is_short else 0),
        payload=payload,
    ):
        if instructions is not None:
            navigator.navigate(
                instructions,
                screen_change_after_last_instruction=False,
                timeout=10000,
            )

    sw, response = monero.transport.async_response()
    assert sw == 0x9000, f"Expected SW_OK, got {hex(sw)}"
    assert len(response) == 0


@pytest.mark.incremental
class TestSignatureRealSweepDummyChange:
    """One destination and one amount=0 dummy change output."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        receiver = Keys(
            public_view_key=bytes.fromhex("2e49ad29a1bfd98ab05c88713463d55212"
                                          "0906b1be380211745695134e183ed0"),
            public_spend_key=bytes.fromhex("392c4432e5a15aea227e6579a8da7d9f4"
                                           "6fb78565e18e7f0b278f3f1a1468696"),
            secret_view_key=bytes.fromhex("57fd02a94c7486722b1f9798dc0fb931d5"
                                          "477a605a6fd6593573b438c02a890f"),
            secret_spend_key=None,
            addr="53zomVuwRkDgAQDY6qKUP6TeBy5JqXSJzhG4i7447yMXS7wdt4hKh6gQCTT"
                 "a9FiYNpEjBoHZ9iTww3vL96P1hcmTQXvpFAo",
        )

        dummy_change = Keys(
            public_view_key=bytes.fromhex("1fe0cf63fc16b40b5397c47a5227e4eb4d"
                                          "9bc735dbd8d062340c11d35966f904"),
            public_spend_key=bytes.fromhex("a22faef2684feb1583f69a3d2bd87e09b3"
                                           "9f70276b69b8512876b7adc8ddfac8"),
            secret_view_key=bytes.fromhex("b9209a473237f601d66246de732680cb62"
                                          "d344fbf0d2bc23e195087d53a06f37"),
            secret_spend_key=None,
            addr="5R32BpY7seiTednbP9I7mzS7L9tyN0VmxSp1lSfkasRlgoO98XjU6gn"
                 "HpwqtX9Md0e7SBj9IaWLZR2AZeEzz6NsXhLMdRi9",
        )

        return {
            "receiver_number": 2,
            "receiver": [receiver, dummy_change],
            "is_change_addr": [False, True],
            "is_subaddress": [False, False],
            "amount": [OUTPUT_AMOUNT, DUMMY_CHANGE_AMOUNT],
            "tx_pub_key": None,
            "_tx_priv_key": None,
            "_ak_amount": [[], []],
            "blinded_amount": [[], []],
            "blinded_mask": [[], []],
            "y": [[], []],
        }

    @staticmethod
    def test_set_sig_sweep_dummy_change(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL

    @staticmethod
    def test_open_tx_sweep_dummy_change(monero: MoneroCmd, state):
        tx_pub_key, _tx_priv_key, fake_view_key, fake_spend_key = monero.open_tx()

        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32

        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_gen_txout_keys_sweep_dummy_change(monero: MoneroCmd, state):
        for index in range(state["receiver_number"]):
            _ak_amount, _ = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=state["is_subaddress"][index],
            )
            state["_ak_amount"][index].append(_ak_amount)

    @staticmethod
    def test_prefix_hash_sweep_dummy_change(monero: MoneroCmd,
                                            navigator: Navigator,
                                            device,
                                            test_name: str):
        monero.prefix_hash_init(test_name, device, navigator=navigator,
                                version=0, timelock=0)
        monero.prefix_hash_update(index=1, payload=b"", is_last=True)

    @staticmethod
    def test_gen_commitment_mask_sweep_dummy_change(monero: MoneroCmd, state):
        for index in range(state["receiver_number"]):
            state["y"][index].append(
                monero.gen_commitment_mask(state["_ak_amount"][index][0])
            )

    @staticmethod
    def test_blind_sweep_dummy_change(monero: MoneroCmd, state):
        assert OUTPUT_AMOUNT + FEE == INPUT_AMOUNT

        for index in range(state["receiver_number"]):
            blinded_mask, blinded_amount = monero.blind(
                _ak_amount=state["_ak_amount"][index][0],
                mask=state["y"][index][0],
                amount=state["amount"][index],
                is_short=True,
            )

            mask, amount = monero.unblind(
                _ak_amount=state["_ak_amount"][index][0],
                blinded_mask=blinded_mask,
                blinded_amount=blinded_amount,
                is_short=True,
            )

            assert state["y"][index][0] == mask
            assert state["amount"][index] == int.from_bytes(amount, byteorder="little")

            state["blinded_mask"][index].append(blinded_mask)
            state["blinded_amount"][index].append(blinded_amount)

    @staticmethod
    def test_validate_sweep_dummy_change(monero: MoneroCmd,
                                         backend: BackendInterface,
                                         navigator: Navigator,
                                         test_name,
                                         state):
        device = backend.device

        monero.validate_prehash_init(test_name, device, navigator, 1, 0, FEE)

        for index in range(state["receiver_number"]):
            is_last = index == state["receiver_number"] - 1
            _validate_prehash_update_no_compare(
                monero,
                backend,
                navigator,
                index=index + 1,
                is_short=True,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=state["is_subaddress"][index],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0],
                commitment=bytes(32),
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=is_last,
                swipe_count=3,
            )

        for index in range(state["receiver_number"]):
            monero.validate_prehash_finalize(
                index=index + 1,
                is_short=False,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=state["is_subaddress"][index],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                _ak_amount=state["_ak_amount"][index][0],
                commitment=bytes(32),
                blinded_amount=state["blinded_amount"][index][0],
                blinded_mask=state["blinded_mask"][index][0],
                is_last=index == state["receiver_number"] - 1,
            )

    @staticmethod
    def test_close_tx_sweep_dummy_change(monero: MoneroCmd):
        monero.close_tx()
