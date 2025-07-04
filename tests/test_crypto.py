
from ledgered.devices import Device
from ragger.navigator import Navigator

from monero_client.monero_cmd import MoneroCmd


def test_public_keys(monero: MoneroCmd):
    (view_pub_key,
     spend_pub_key,
     address) = monero.get_public_keys()  # type: bytes, bytes, str

    assert view_pub_key == bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f"
                                         "78fc2154257d07522e9b79e637326dfa")
    assert spend_pub_key == bytes.fromhex("dae41d6b13568fdd71ec3d20c2f614c6"
                                          "5fe819f36ca5da8d24df3bd89b2bad9d")
    assert address == ("5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fp"
                       "p5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE")


def test_private_view_key(monero: MoneroCmd,
                          navigator: Navigator,
                          device: Device,
                          test_name: str):
    view_priv_key: bytes = monero.get_private_view_key(test_name, device, navigator)

    assert view_priv_key == bytes.fromhex("0f3fe25d0c6d4c94dde0c0bcc214b233"
                                          "e9c72927f813728b0f01f28f9d5e1201")


def test_keygen_and_verify(monero: MoneroCmd):
    pub_key, _priv_key = monero.generate_keypair()  # type: bytes, bytes

    assert monero.verify_key(_priv_key, pub_key) is True


def test_key_image(monero: MoneroCmd):
    expected_key_img: bytes = bytes.fromhex("b8af9b11b9391f0cd921863b5f774677"
                                            "29a188d31f8c7df37bd7f2dfd99defee")

    _priv_key: bytes = bytes.fromhex("6d2f327238555bf7d0eb25b2ef6f85e0"
                                     "22fb59bf43f05dfeb4d3947ca9acbc53")
    pub_key: bytes = bytes.fromhex("d8acd4d3bd9e556544284279817dfd4b"
                                   "95c03f17b3c53df6dddf646abf8b4d19")

    key_image: bytes = monero.generate_key_image(_priv_key=_priv_key,
                                                 pub_key=pub_key)

    assert expected_key_img == key_image


def test_put_key(monero: MoneroCmd):
    priv_view_key: bytes = bytes.fromhex("0f3fe25d0c6d4c94dde0c0bcc214b233"
                                         "e9c72927f813728b0f01f28f9d5e1201")
    pub_view_key: bytes = bytes.fromhex("865cbfab852a1d1ccdfc7328e4dac90f"
                                        "78fc2154257d07522e9b79e637326dfa")
    priv_spend_key: bytes = bytes.fromhex("3b094ca7218f175e91fa2402b4ae239a"
                                          "2fe8262792a3e718533a1a357a1e4109")
    pub_spend_key: bytes = bytes.fromhex("dae41d6b13568fdd71ec3d20c2f614c6"
                                         "5fe819f36ca5da8d24df3bd89b2bad9d")
    address: str = ("5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvm"
                    "A45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE")

    monero.put_key(priv_view_key=priv_view_key,
                   pub_view_key=pub_view_key,
                   priv_spend_key=priv_spend_key,
                   pub_spend_key=pub_spend_key,
                   address=address)


def test_gen_key_derivation(monero: MoneroCmd):
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


class Derivation_Test:
    _derivation: bytes
    _output_index: bytes
    _expected_view_tag: int

    def __init__(self, derivation: str, output_index: int, expected_view_tag: int):
        self._derivation = bytes.fromhex(derivation)
        self._output_index = (output_index).to_bytes(4, byteorder='big')
        self._expected_view_tag = expected_view_tag

    def do_test(self, monero: MoneroCmd):
        encrypted_derivation = monero.xor_cipher(
            self._derivation, b"\x55")  # encrypt with dummy key 0x55
        assert self._expected_view_tag == monero.derive_view_tag(
            encrypted_derivation, self._output_index)


DERIVATION_TESTS = [
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 0,  0x76),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 1,  0xd6),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 2,  0x87),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 3,  0x1b),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 12, 0xd6),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 13, 0xe9),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 14, 0x12),
    Derivation_Test(
        "0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97", 15, 0x26),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 0,  0x70),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 1,  0x81),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 2,  0xa0),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 3,  0xec),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 12, 0x22),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 13, 0x0a),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 14, 0x87),
    Derivation_Test(
        "a36ba7b4d31349ad278a6df8f77adb76748b59f4929348e67dd92adb9fa174dc", 15, 0x76),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 0,  0x93),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 1,  0x67),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 2,  0x9d),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 3,  0x2d),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 12, 0x63),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 13, 0xcf),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 14, 0xef),
    Derivation_Test(
        "7498d5bf0b69e08653f6d420a17f866dd2bd490ab43074f46065cb501fe7e2d8", 15, 0x10),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 0,  0x90),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 1,  0x5a),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 2,  0xde),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 3,  0x21),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 12, 0x57),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 13, 0x52),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 14, 0x6f),
    Derivation_Test(
        "fe7770c4b076e95ddb8026affcfab39d31c7c4a2266e0e25e343bc4badc907d0", 15, 0xeb),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 0,  0xc6),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 1,  0x60),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 2,  0xf0),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 3,  0x71),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 12, 0x0e),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 13, 0x42),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 14, 0xb2),
    Derivation_Test(
        "ea9337d0ddf480abdc4fc56a0cb223702729cb230ae7b9de50243ad25ce90e8d", 15, 0x61),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 0,  0x4c),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 1,  0x9b),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 2,  0x64),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 3,  0xff),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 12, 0xe3),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 13, 0x24),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 14, 0xea),
    Derivation_Test(
        "25d538315bcb81aff9574189ea65f418aeb0392f5cbbc84cd8a33c7ade31ef0a", 15, 0x3b),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 0,  0x74),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 1,  0x77),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 2,  0xa9),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 3,  0x44),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 12, 0x75),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 13, 0x05),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 14, 0xca),
    Derivation_Test(
        "8edfabada2b24ef4d8d915826c9ff0245910e4b835b59c2cf8ed8fc991b2e1e8", 15, 0x00),
]


def test_derive_view_tag(monero: MoneroCmd):
    for test in DERIVATION_TESTS:
        test.do_test(monero)


def test_display_address(monero: MoneroCmd, navigator: Navigator, device: Device, test_name: str):
    major: bytes = (0).to_bytes(4, byteorder='little')
    minor: bytes = (0).to_bytes(4, byteorder='little')
    payment_id: bytes = bytes.fromhex(8*"00")
    monero.display_address(test_name, device, navigator, major +
                           minor + payment_id, bytes.fromhex("00"), 2)


def test_display_subaddress(monero: MoneroCmd, navigator: Navigator, device: Device, test_name: str):
    major: bytes = (0).to_bytes(4, byteorder='little')
    minor: bytes = (1).to_bytes(4, byteorder='little')
    payment_id: bytes = bytes.fromhex(8*"00")
    monero.display_address(test_name, device, navigator, major +
                           minor + payment_id, bytes.fromhex("00"))
