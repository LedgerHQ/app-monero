def test_public_keys(monero):
    (view_pub_key,
     spend_pub_key,
     address) = monero.get_public_keys()  # type: bytes, bytes, str

    assert view_pub_key == bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f"
                                         "78fc2154257d07522e9b79e637326dfa")
    assert spend_pub_key == bytes.fromhex("dae41d6b13568fdd71ec3d20c2f614c6"
                                          "5fe819f36ca5da8d24df3bd89b2bad9d")
    assert address == ("5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fp"
                       "p5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE")


def test_private_view_key(monero, button):
    view_priv_key: bytes = monero.get_private_view_key(button)

    assert view_priv_key == bytes.fromhex("0f3fe25d0c6d4c94dde0c0bcc214b233"
                                          "e9c72927f813728b0f01f28f9d5e1201")


def test_keygen_and_verify(monero):
    pub_key, _priv_key = monero.generate_keypair()  # type: bytes, bytes

    assert monero.verify_key(_priv_key, pub_key) is True


def test_key_image(monero):
    expected_key_img: bytes = bytes.fromhex("b8af9b11b9391f0cd921863b5f774677"
                                            "29a188d31f8c7df37bd7f2dfd99defee")

    _priv_key: bytes = bytes.fromhex("6d2f327238555bf7d0eb25b2ef6f85e0"
                                     "22fb59bf43f05dfeb4d3947ca9acbc53")
    pub_key: bytes = bytes.fromhex("d8acd4d3bd9e556544284279817dfd4b"
                                   "95c03f17b3c53df6dddf646abf8b4d19")

    key_image: bytes = monero.generate_key_image(_priv_key=_priv_key,
                                                 pub_key=pub_key)

    assert expected_key_img == key_image


# Wait for PR #69 to be merged: https://github.com/LedgerHQ/app-monero/pull/69
#
# def test_put_key(monero):
#     priv_view_key: bytes = bytes.fromhex("0f3fe25d0c6d4c94dde0c0bcc214b233"
#                                          "e9c72927f813728b0f01f28f9d5e1201")
#     pub_view_key: bytes = bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f"
#                                         "78fc2154257d07522e9b79e637326dfa")
#     priv_spend_key: bytes = bytes.fromhex("3b094ca7218f175e91fa2402b4ae239a"
#                                           "2fe8262792a3e718533a1a357a1e4109")
#     pub_spend_key: bytes = bytes.fromhex("dae41d6b13568fdd71ec3d20c2f614c6"
#                                          "5fe819f36ca5da8d24df3bd89b2bad9d")
#     address: str = ("5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvm"
#                     "A45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE")

#     monero.put_key(priv_view_key=priv_view_key,
#                    pub_view_key=pub_view_key,
#                    priv_spend_key=priv_spend_key,
#                    pub_spend_key=pub_spend_key,
#                    address=address)


def test_gen_key_derivation(monero):
    # 8 * r.G
    expected: bytes = bytes.fromhex("57029f1d2a7453254be1ee81d7d8b540"
                                    "1db398f0a541315c0095fad27625ebfa")
    # r
    priv_key: bytes = bytes.fromhex("0f3fe25d0c6d4c94dde0c0bcc214b233"
                                    "e9c72927f813728b0f01f28f9d5e1201")
    # r.G
    pub_key: bytes = bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f"
                                   "78fc2154257d07522e9b79e637326dfa")
    # encrypt priv_key with XOR cipher (key = 0x55)
    _priv_key: bytes = monero.xor_cipher(priv_key, b"\x55")

    _d_in: bytes = monero.gen_key_derivation(
        pub_key=pub_key,
        _priv_key=_priv_key
    )

    assert expected == monero.xor_cipher(_d_in, b"\x55")  # decrypt _d_in
