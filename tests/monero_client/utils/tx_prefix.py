"""
Helpers to serialize a Monero transaction prefix the way the wallet streams it
to the device over INS_PREFIX_HASH (P2 chunks), i.e. everything after the
(version, unlock_time) varints that go in the P1 init step:

    vin || vout || extra

Only the vout one-time keys are security-relevant for the device's output-key
binding check (SW_SECURITY_OUTKEYS_CHAIN_CONTROL); vin/extra content is skipped
by the device parser, so we emit minimal but well-formed structures here.

Layout (Monero binary archive):
  vin  : varint count, then per txin_to_key:
           0x02 tag, varint amount, varint off_count, off_count varints,
           32-byte key image
  vout : varint count, then per output:
           varint amount (0 for RingCT),
           0x02 txout_to_key            -> 32-byte key
           0x03 txout_to_tagged_key     -> 32-byte key + 1-byte view tag
  extra: varint len, then bytes (here: a single tx pub key entry 0x01 || R)
"""

from typing import Optional, Sequence

from .varint import encode_varint

TXIN_TO_KEY_TAG = 0x02
TXOUT_TO_KEY_TAG = 0x02
TXOUT_TO_TAGGED_KEY_TAG = 0x03


def build_tx_prefix_outkeys(
    vout_keys: Sequence[bytes],
    view_tags: Optional[Sequence[int]] = None,
    n_inputs: int = 1,
    ring: int = 11,
) -> bytes:
    """Serialize the INS_PREFIX_HASH P2 stream (vin || vout || extra).

    Args:
        vout_keys:  the one-time output keys, in output-index order. To exercise
                    the honest path these must be the device-derived keys returned
                    by gen_txout_keys; to forge an attack, substitute one of them.
        view_tags:  optional per-output view-tag bytes; when provided, outputs are
                    serialized as txout_to_tagged_key (0x03). Must match vout_keys
                    length. When None, outputs are txout_to_key (0x02).
        n_inputs:   number of (dummy) ring inputs to emit.
        ring:       number of key offsets per input.

    Returns:
        The bytes to pass as the prefix_hash_update payload.
    """
    if view_tags is not None and len(view_tags) != len(vout_keys):
        raise ValueError("view_tags length must match vout_keys length")
    for key in vout_keys:
        if len(key) != 32:
            raise ValueError("each vout key must be 32 bytes")

    out = b""

    # --- vin: dummy ring inputs (content irrelevant, skipped by the device) ---
    out += encode_varint(n_inputs)
    for _ in range(n_inputs):
        out += bytes([TXIN_TO_KEY_TAG])  # txin_to_key variant tag
        out += encode_varint(0)          # amount (0 for RingCT)
        out += encode_varint(ring)       # key_offsets count
        for _ in range(ring):
            out += encode_varint(7)      # arbitrary offset delta
        out += bytes(32)                 # key image (dummy)

    # --- vout: the one-time output keys to be bound ---
    out += encode_varint(len(vout_keys))
    for idx, key in enumerate(vout_keys):
        out += encode_varint(0)          # amount (0 for RingCT)
        if view_tags is None:
            out += bytes([TXOUT_TO_KEY_TAG])
            out += key
        else:
            out += bytes([TXOUT_TO_TAGGED_KEY_TAG])
            out += key
            out += bytes([view_tags[idx] & 0xFF])

    # --- extra: a single tx public key entry (0x01 || R) ---
    extra = b"\x01" + bytes(32)
    out += encode_varint(len(extra)) + extra

    return out
