"""
Test: INS_GET_CHACHA8_PREKEY returns a valid 200-byte SHAKE-256 derived prekey.

The device computes:
    SHAKE-256( "MONERO_CHACHA8_PREKEY" || a, output_len=200 )

where `a` is the secret view key. This test:
  1. Computes the expected 200-byte output locally using the known test-seed
     view key `a` and the same SHAKE-256 construction.
  2. Sends INS_GET_CHACHA8_PREKEY to the device.
  3. Verifies the response is exactly 200 bytes and matches byte-for-byte.

Test seed: "abandon abandon abandon abandon abandon abandon
            abandon abandon abandon abandon abandon about"
  a = 0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201
"""

import hashlib
from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_types import InsType

# Secret view key for the test seed
VIEW_KEY_A = bytes.fromhex(
    "0f3fe25d0c6d4c94dde0c0bcc214b233"
    "e9c72927f813728b0f01f28f9d5e1201"
)

CHACHA8_LABEL = b"MONERO_CHACHA8_PREKEY"
PREKEY_SIZE = 200


def compute_expected_prekey(view_key_a: bytes) -> bytes:
    """Compute the expected 200-byte prekey using SHAKE-256.

    Mirrors the device-side computation:
        SHAKE-256( "MONERO_CHACHA8_PREKEY" || a[32], output_len=200 )
    """
    shake = hashlib.shake_256()
    shake.update(CHACHA8_LABEL)
    shake.update(view_key_a)
    return shake.digest(PREKEY_SIZE)


def test_chacha8_prekey(monero: MoneroCmd):
    """Verify that INS_GET_CHACHA8_PREKEY returns the correct SHAKE-256 output.

    This test confirms:
    - The response is exactly 200 bytes
    - The response matches SHAKE-256("MONERO_CHACHA8_PREKEY" || a, 200)
    - The derivation is deterministic (same seed → same prekey)
    - The spend key b is NOT involved in the derivation
    """

    # ---- Compute expected value locally ----
    expected = compute_expected_prekey(VIEW_KEY_A)
    assert len(expected) == PREKEY_SIZE

    print(f"\n[*] Expected prekey (first 32 bytes): {expected[:32].hex()}")
    print(f"[*] Expected prekey (last  32 bytes): {expected[-32:].hex()}")

    # ---- Send INS_GET_CHACHA8_PREKEY ----
    print("[*] Sending INS_GET_CHACHA8_PREKEY to device...")

    monero.device.send(cla=PROTOCOL_VERSION,
                       ins=InsType.INS_GET_CHACHA8_PREKEY,
                       p1=0,
                       p2=0,
                       option=0,
                       payload=b"")

    sw, response = monero.device.recv()

    assert sw == 0x9000, f"APDU failed with SW=0x{sw:04x}"
    assert len(response) == PREKEY_SIZE, \
        f"Expected {PREKEY_SIZE} bytes, got {len(response)}"

    print(f"[*] Received  prekey (first 32 bytes): {response[:32].hex()}")
    print(f"[*] Received  prekey (last  32 bytes): {response[-32:].hex()}")

    # ---- Verify byte-for-byte match ----
    assert bytes(response) == expected, (
        f"Prekey mismatch!\n"
        f"  expected: {expected.hex()}\n"
        f"  received: {response.hex()}"
    )

    print("[*] ✓ Prekey matches SHAKE-256(\"MONERO_CHACHA8_PREKEY\" || a, 200)")

    # ---- Verify determinism: call again, must get the same result ----
    print("[*] Verifying determinism (second call)...")

    monero.device.send(cla=PROTOCOL_VERSION,
                       ins=InsType.INS_GET_CHACHA8_PREKEY,
                       p1=0,
                       p2=0,
                       option=0,
                       payload=b"")

    sw2, response2 = monero.device.recv()

    assert sw2 == 0x9000, f"Second APDU failed with SW=0x{sw2:04x}"
    assert bytes(response2) == bytes(response), \
        "Prekey is not deterministic: two calls returned different results"

    print("[*] ✓ Prekey is deterministic (identical on second call)")

    print("\n" + "=" * 60)
    print("  PASS: INS_GET_CHACHA8_PREKEY returns correct SHAKE-256")
    print("        prekey derived from view key only (no spend key).")
    print("=" * 60)
