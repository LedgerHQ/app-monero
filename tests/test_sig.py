import pytest

from monero_client.monero_types import SigType, Keys


@pytest.mark.incremental
class TestSignature:
    """Monero signature test."""

    @pytest.fixture(autouse=True, scope="class")
    def state(self):
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

        return {"sender": sender,
                "receiver": receiver,
                "amount": 10**12,  # 1.0 XMR
                "tx_pub_key": None,
                "_tx_priv_key": None,
                "_ak_amount": [],
                "blinded_amount": [],
                "blinded_mask": [],
                "y": []}

    def test_set_sig(self, monero):
        major, minor, patch = monero.reset_and_get_version(
            monero_client_version=b"0.16.0.0"
        )  # type: int, int, int
        assert (major, minor, patch) == (1, 6, 0)  # version of the Monero app

        sig_mode: SigType = monero.set_signature_mode(sig_type=SigType.REAL)
        assert sig_mode == SigType.REAL

    def test_open_tx(self, monero, state):
        (tx_pub_key,
         _tx_priv_key,
         fake_view_key,
         fake_spend_key) = monero.open_tx()  # type: bytes, bytes, bytes, bytes

        assert fake_view_key == b"\x00" * 32
        assert fake_spend_key == b"\xff" * 32

        state["tx_pub_key"] = tx_pub_key
        state["_tx_priv_key"] = _tx_priv_key

    def test_gen_txout_keys(self, monero, state):
        _ak_amount, out_ephemeral_pub_key = monero.gen_txout_keys(
            _tx_priv_key=state["_tx_priv_key"],
            tx_pub_key=state["tx_pub_key"],
            dst_pub_view_key=state["receiver"].public_view_key,
            dst_pub_spend_key=state["receiver"].public_spend_key,
            output_index=0,
            is_change_addr=False,
            is_subaddress=False
        )  # type: bytes, bytes

        state["_ak_amount"].append(_ak_amount)  # _ak_amount_t

    def test_prefix_hash(self, monero, button):
        expected: bytes = bytes.fromhex("49d03a195e239b52779866b33024210f"
                                        "c7dc66e9c2998975c0aa45c1702549d5")
        # should ask for timelock validation
        monero.prefix_hash_init(button=button, version=0, timelock=1)
        result: bytes = monero.prefix_hash_update(
            index=1,
            payload=b"",
            is_last=True
        )

        assert result == expected

    def test_gen_commitment_mask(self, monero, state):
        assert len(state["_ak_amount"]) != 0

        s: bytes = monero.gen_commitment_mask(state["_ak_amount"][0])
        state["y"].append(s)  # y_t

    def test_blind(self, monero, state):
        assert len(state["y"]) != 0
        assert len(state["_ak_amount"]) != 0

        blinded_mask, blinded_amount = monero.blind(
            _ak_amount=state["_ak_amount"][0],
            mask=state["y"][0],
            amount=state["amount"],
            is_short=False
        )  # type: bytes, bytes

        mask, amount = monero.unblind(
            _ak_amount=state["_ak_amount"][0],
            blinded_mask=blinded_mask,
            blinded_amount=blinded_amount,
            is_short=False
        )  # type: bytes, bytes

        assert state["y"][0] == mask
        assert state["amount"] == int.from_bytes(amount, byteorder="big")

        state["blinded_mask"].append(blinded_mask)
        state["blinded_amount"].append(blinded_amount)

    def test_validate(self, monero, button, state):
        assert len(state["y"]) != 0
        assert len(state["_ak_amount"]) != 0
        assert len(state["blinded_amount"]) != 0
        assert len(state["blinded_mask"]) != 0

        fee: int = 100000000  # 0.0001 XMR

        # should ask for fee validation
        monero.validate_prehash_init(button=button,
                                     index=1,  # start at 1
                                     txntype=0,
                                     txnfee=fee)

        # monero_client.validate_prehash_update(
        #     index=1,
        #     is_short=False,
        #     is_change_addr=False,
        #     is_subaddress=False,
        #     dst_pub_view_key=state["receiver"].public_view_key,
        #     dst_pub_spend_key=state["receiver"].public_spend_key,
        #     _ak_amount=state["_ak_amount"][0],
        #     commitment=...,
        #     blinded_amount=state["blinded_amount"][0],
        #     blinded_mask=state["blinded_mask"][0],
        #     is_last=True
        # )

    def test_close_tx(self, monero):
        monero.close_tx()
