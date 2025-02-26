import pytest

from monero_client.monero_types import SigType, Keys

@pytest.mark.incremental
class TestSignature:
    """Monero signature test."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        sender = Keys(
            public_view_key=bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f78"
                                          "fc2154257d07522e9b79e637326dfa"),
            public_spend_key=bytes.fromhex("dae41d6b13568fdd71ec3d20c2f614c65"
                                           "fe819f36ca5da8d24df3bd89b2bad9d"),
            secret_view_key=bytes.fromhex("0f3fe25d0c6d4c94dde0c0bcc214b233e9"
                                          "c72927f813728b0f01f28f9d5e1201"),
            secret_spend_key=bytes.fromhex("3b094ca7218f175e91fa2402b4ae239a2"
                                           "fe8262792a3e718533a1a357a1e4109"),
            addr="5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSa"
                 "cMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE"
        )

        receiver = Keys(
            public_view_key=bytes.fromhex("2e49ad29a1bfd98ab05c88713463d55212"
                                          "0906b1be380211745695134e183ed0"),
            public_spend_key=bytes.fromhex("392c4432e5a15aea227e6579a8da7d9f4"
                                           "6fb78565e18e7f0b278f3f1a1468696"),
            secret_view_key=bytes.fromhex("57fd02a94c7486722b1f9798dc0fb931d5"
                                          "477a605a6fd6593573b438c02a890f"),
            secret_spend_key=None,
            addr="53zomVuwRkDgAQDY6qKUP6TeBy5JqXSJzhG4i7447yMXS7wdt4hKh6gQCTT"
                 "a9FiYNpEjBoHZ9iTww3vL96P1hcmTQXvpFAo"
        )

        receiver2 = Keys(
            public_view_key=bytes.fromhex("1fe0cf63fc16b40b5397c47a5227e4eb4d"
                                          "9bc735dbd8d062340c11d35966f904"),
            public_spend_key=bytes.fromhex("a22faef2684feb1583f69a3d2bd87e09b3"
                                           "9f70276b69b8512876b7adc8ddfac8"),
            secret_view_key=bytes.fromhex("b9209a473237f601d66246de732680cb62"
                                          "d344fbf0d2bc23e195087d53a06f37"),
            secret_spend_key=None,
            addr="5R32BpY7seiTednbP9I7mzS7L9tyN0VmxSp1lSfkasRlgoO98XjU6gnHpwqtX9Md0e7SBj9IaWLZR2AZeEzz6NsXhLMdRi9"
        )

        return {"sender": sender,
                "receiver_number": 3,
                "receiver": [receiver, receiver2, sender],
                "is_change_addr": [False, False, True],
                "amount": [int(69.36*1000000000000), int(0.37*1000000000000), int(0.55*1000000000000)],
                "tx_pub_key": None,
                "_tx_priv_key": None,
                "_ak_amount": [[], [], []],
                "blinded_amount": [[], [], []],
                "blinded_mask": [[], [], []],
                "y": [[], [], []]}

    @staticmethod
    def test_set_sig(monero):
        monero.reset_and_get_version(
            monero_client_version=b"0.18"
        )

        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.REAL)
        assert sig_mode == SigType.REAL

    @staticmethod
    def test_open_tx(monero, state):
        (tx_pub_key,
         _tx_priv_key,
         fake_view_key,
         fake_spend_key) = monero.open_tx()  # type: bytes, bytes, bytes, bytes

        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32

        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    @staticmethod
    def test_gen_txout_keys(monero, state):
        for index in range(state["receiver_number"]):
            _ak_amount, out_ephemeral_pub_key = monero.gen_txout_keys(
                _tx_priv_key=state["_tx_priv_key"],
                tx_pub_key=state["tx_pub_key"],
                dst_pub_view_key=state["receiver"][index].public_view_key,
                dst_pub_spend_key=state["receiver"][index].public_spend_key,
                output_index=index,
                is_change_addr=state["is_change_addr"][index],
                is_subaddress=False
            )  # type: bytes, bytes

            state["_ak_amount"][index].append(_ak_amount)  # _ak_amount_t

    @staticmethod
    def test_prefix_hash(monero, backend, navigator, firmware, test_name):
        expected: bytes = bytes.fromhex("9a259973bf721120aceae3d8d40696c0"
                                        "7470331e386028753123f37fee36926b")
        # should ask for timelock validation
        monero.prefix_hash_init(backend, test_name, firmware,
                                navigator=navigator, version=0, timelock=2147483650)
        result: bytes = monero.prefix_hash_update(
            index=1,
            payload=b"",
            is_last=True
        )

        assert result == expected

    @staticmethod
    def test_gen_commitment_mask(monero, state):
        for index in range(state["receiver_number"]):
            assert len(state["_ak_amount"][index]) != 0
            s: bytes = monero.gen_commitment_mask(state["_ak_amount"][index][0])
            state["y"][index].append(s)  # y_t

    @staticmethod
    def test_blind(monero, state):
        for index in range(state["receiver_number"]):
            assert len(state["y"][index]) != 0
            assert len(state["_ak_amount"][index]) != 0

            print(f'state["amount"][index] = {state["amount"][index]}')
            blinded_mask, blinded_amount = monero.blind(
                _ak_amount=state["_ak_amount"][index][0],
                mask=state["y"][index][0],
                amount=state["amount"][index],
                is_short=True
            )  # type: bytes, bytes

            mask, amount = monero.unblind(
                _ak_amount=state["_ak_amount"][index][0],
                blinded_mask=blinded_mask,
                blinded_amount=blinded_amount,
                is_short=True
            )  # type: bytes, bytes

            assert state["y"][index][0] == mask
            assert state["amount"][index] == int.from_bytes(amount, byteorder="little")

            state["blinded_mask"][index].append(blinded_mask)
            state["blinded_amount"][index].append(blinded_amount)

            assert len(state["y"][index]) != 0
            assert len(state["_ak_amount"][index]) != 0
            assert len(state["blinded_amount"][index]) != 0
            assert len(state["blinded_mask"][index]) != 0

    @staticmethod
    def test_validate(monero, backend, navigator, firmware, test_name, state):

        fee: int = 100000000  # 0.0001 XMR

        # should ask for fee validation
        monero.validate_prehash_init(backend,
                                     navigator=navigator,
                                     firmware=firmware,
                                     test_name=test_name,
                                     index=1,  # start at 1
                                     txntype=0,
                                     txnfee=fee)

        for index in range(state["receiver_number"]):
            monero.validate_prehash_update(
                backend,
                test_name,
                firmware,
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
                is_last=True if index == (state["receiver_number"] - 1) else False
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
    def test_close_tx(monero):
        monero.close_tx()
