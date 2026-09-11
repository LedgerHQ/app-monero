"""
Protocol-downgrade PoC and non-regression tests.

The APDU class byte is the protocol version. `check_protocol()` accepts 0x00,
0x03 and 0x04 and pins the value for the session (src/monero_dispatch.c:37-55).
Every output and prefix binding is behind `io_protocol_version >= 2` -- nine
gates, three each in monero_key.c, monero_prefix.c and monero_prehash.c. So on
protocol 0 the OUT_EPH/EXTRA_R/ADDK state is never built, INS_PREFIX_HASH never
re-walks the signed vout and extra, and INS_VALIDATE never compares the reviewed
destination against them. Nothing tied the signature mode to the protocol, so a
host could pick 0, have the user review a benign recipient, and stream a prefix
carrying its own one-time output key. Same attack as
test_vuln_outkey_substitution.py; only the class byte differs.

What the downgrade never reached is a signature: INS_MLSAG requires protocol 3
or 4 and INS_CLSAG requires 4 (src/monero_dispatch.c:448, :517), and those are
the only two signing instructions. The one way to reach a signing protocol is
INS_RESET, whose monero_init() bzeros all of G_monero_vstate, so no unbound
transaction survives into a session that can sign. That made this a fail-open
transcript rather than a reachable theft path -- but the thing closing it was a
version guard added for MLSAG/CLSAG support, not a security control.

The fix refuses TRANSACTION_CREATE_REAL unless the protocol is 3 or 4, so the
unbound path is no longer reachable at all.

Classes:
  TestProtocolZeroRefusedForRealSigning - the fix: REAL on protocol 0 -> 0x6e00
  TestBindingSkippedUnderProtocolZeroVuln - skipped; the pre-fix behaviour
  TestProtocolThreeStillBinds   - control: the substitution still gives 0x6915
  TestProtocolFourStillWorks    - control: the wallet's own protocol is intact
  TestMlsagStaysProtocolGated   - the second layer stays in place
  TestNonCanonicalFlagsRefused  - a flag byte above 1 is refused
"""

import struct

import pytest
import nacl.bindings as nb
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU

from monero_client.monero_cmd import MoneroCmd, PROTOCOL_VERSION
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import Keys, SigType, InsType, Type
from monero_client.crypto.hmac import hmac_sha256
from monero_client.utils.tx_prefix import build_tx_prefix_outkeys
from monero_client.status_words import (
    SW_COMMAND_NOT_ALLOWED,
    SW_PROTOCOL_NOT_SUPPORTED,
    SW_SECURITY_OUTKEYS_CHAIN_CONTROL,
    SW_WRONG_DATA,
)
from monero_client.crypto.monero_math import sc_reduce32

# The downgrade: a class byte check_protocol() accepts but no binding honours.
PROTOCOL_LEGACY = 0x00
# What monero-gui sends: device_ledger.cpp:251,392, its only APDU header path.
PROTOCOL_WALLET = 0x04

# User (test seed "abandon ... about") -- the destination shown on screen.
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

# Attacker-controlled one-time output key: a valid point, not the device's.
_ATTACKER_OUT_KEY = nb.crypto_scalarmult_ed25519_base_noclamp(
    sc_reduce32(bytes([0x11] * 32))
)


def _fresh_state():
    return {"tx_pub_key": None, "tx_priv_key": None, "p_device": None}


def _open_real_tx(monero: MoneroCmd, protocol: int, state) -> bytes:
    """reset -> REAL -> open_tx -> gen_txout_keys, all at `protocol`.

    Returns the device-derived one-time output key."""
    monero.protocol = protocol
    monero.reset_and_get_version(monero_client_version=b"0.18")
    assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
    tx_pub_key, tx_priv_key, _, _ = monero.open_tx()
    state["tx_pub_key"] = tx_pub_key
    state["tx_priv_key"] = tx_priv_key

    _ak, p_device, _ = monero.gen_txout_keys(
        _tx_priv_key=tx_priv_key,
        tx_pub_key=tx_pub_key,
        dst_pub_view_key=_USER.public_view_key,
        dst_pub_spend_key=_USER.public_spend_key,
        output_index=0,
        is_change_addr=False,
        is_subaddress=False,
    )
    state["p_device"] = p_device
    return p_device


def _txout_keys_payload(tx_priv_key: bytes, tx_pub_key: bytes,
                        output_index: int, is_change: int, is_subaddress: int,
                        need_additional: int, use_view_tags: int) -> bytes:
    """An INS_GEN_TXOUT_KEYS payload with the four flags as raw bytes, so a
    test can send a value the client's bool arguments cannot express."""
    return b"".join((
        struct.pack(">I", 0),                       # tx_version
        tx_priv_key,
        hmac_sha256(tx_priv_key, MoneroCryptoCmd.HMAC_KEY, Type.SCALAR),
        tx_pub_key,
        _USER.public_view_key,
        _USER.public_spend_key,
        struct.pack(">I", output_index),
        bytes([is_change, is_subaddress, need_additional]),
        b"\x00" * 32,                               # additional tx key slot
        bytes([use_view_tags]),
    ))


# ---------------------------------------------------------------------------
# The fix
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestProtocolZeroRefusedForRealSigning:
    """
    Protocol 0 is still a protocol the device talks -- the point of the fix is
    narrower: it cannot carry a real transaction, because none of the bindings
    that make one safe exist there.
    """

    @staticmethod
    def test_reset_is_still_accepted(monero: MoneroCmd):
        monero.protocol = PROTOCOL_LEGACY
        major, minor, patch = monero.reset_and_get_version(
            monero_client_version=b"0.18")
        assert (major, minor, patch) != (0, 0, 0)

    @staticmethod
    def test_fake_mode_is_still_accepted(monero: MoneroCmd):
        monero.protocol = PROTOCOL_LEGACY
        assert monero.set_signature_mode(sig_type=SigType.FAKE) == SigType.FAKE

    @staticmethod
    def test_real_mode_is_refused(monero: MoneroCmd):
        monero.protocol = PROTOCOL_LEGACY
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.set_signature_mode(sig_type=SigType.REAL)
        assert exc_info.value.status == SW_PROTOCOL_NOT_SUPPORTED, (
            f"expected {SW_PROTOCOL_NOT_SUPPORTED:#06x}, "
            f"got {exc_info.value.status:#06x}"
        )


# ---------------------------------------------------------------------------
# The pre-fix behaviour, kept reproducible
# ---------------------------------------------------------------------------
@pytest.mark.incremental
@pytest.mark.skip(reason="Demonstrates the (now-fixed) downgrade; passes only "
                         "on a build without the protocol gate")
class TestBindingSkippedUnderProtocolZeroVuln:
    """
    Before the fix, protocol 0 reached TRANSACTION_CREATE_REAL and the whole
    binding was skipped, so INS_PREFIX_HASH returned a hash over a vout the
    device never derived. Remove the skip to re-confirm against a vulnerable
    build.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _fresh_state()

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        p_device = _open_real_tx(monero, PROTOCOL_LEGACY, state)
        assert p_device != _ATTACKER_OUT_KEY

    @staticmethod
    def test_substituted_out_key_is_accepted(
        monero: MoneroCmd, device, test_name: str, state
    ):
        monero.protocol = PROTOCOL_LEGACY
        monero.prefix_hash_init(
            test_name, device, navigator=None, version=0, timelock=0
        )
        forged = build_tx_prefix_outkeys(
            vout_keys=[_ATTACKER_OUT_KEY], tx_pubkey=state["tx_pub_key"]
        )
        prefix_hash = monero.prefix_hash_update(
            index=1, payload=forged, is_last=True)
        assert len(prefix_hash) == 32


# ---------------------------------------------------------------------------
# Controls: the binding still works on both protocols that carry a real tx
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestProtocolThreeStillBinds:
    """The substitution the downgrade slipped past is still refused here."""

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _fresh_state()

    @staticmethod
    def test_gen_txout_keys(monero: MoneroCmd, state):
        _open_real_tx(monero, PROTOCOL_VERSION, state)

    @staticmethod
    def test_substituted_out_key_is_refused(
        monero: MoneroCmd, device, test_name: str, state
    ):
        monero.protocol = PROTOCOL_VERSION
        monero.prefix_hash_init(
            test_name, device, navigator=None, version=0, timelock=0
        )
        forged = build_tx_prefix_outkeys(
            vout_keys=[_ATTACKER_OUT_KEY], tx_pubkey=state["tx_pub_key"]
        )
        with pytest.raises(ExceptionRAPDU) as exc_info:
            monero.prefix_hash_update(index=1, payload=forged, is_last=True)
        assert exc_info.value.status == SW_SECURITY_OUTKEYS_CHAIN_CONTROL, (
            f"expected {SW_SECURITY_OUTKEYS_CHAIN_CONTROL:#06x}, "
            f"got {exc_info.value.status:#06x}"
        )


@pytest.mark.incremental
class TestProtocolFourStillWorks:
    """
    The harness speaks protocol 3 but monero-gui sends 4, so a gate that only
    allowed 3 would pass every other test here and brick the wallet. An honest
    prefix on protocol 4 must still be accepted.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _fresh_state()

    @staticmethod
    def test_real_mode_and_outputs(monero: MoneroCmd, state):
        _open_real_tx(monero, PROTOCOL_WALLET, state)

    @staticmethod
    def test_honest_prefix_is_accepted(
        monero: MoneroCmd, device, test_name: str, state
    ):
        monero.protocol = PROTOCOL_WALLET
        monero.prefix_hash_init(
            test_name, device, navigator=None, version=0, timelock=0
        )
        honest = build_tx_prefix_outkeys(
            vout_keys=[state["p_device"]], tx_pubkey=state["tx_pub_key"]
        )
        prefix_hash = monero.prefix_hash_update(
            index=1, payload=honest, is_last=True)
        assert len(prefix_hash) == 32


# ---------------------------------------------------------------------------
# The second layer, which must not be the only one again
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestMlsagStaysProtocolGated:
    """
    INS_MLSAG's own protocol guard is what kept the pre-fix downgrade short of
    a signature. It is no longer load-bearing, but if it is ever relaxed the
    mode gate should be the only thing left, not nothing.
    """

    @staticmethod
    def test_open_fake_tx(monero: MoneroCmd):
        monero.protocol = PROTOCOL_LEGACY
        monero.reset_and_get_version(monero_client_version=b"0.18")
        assert monero.set_signature_mode(sig_type=SigType.FAKE) == SigType.FAKE
        monero.open_tx()

    @staticmethod
    def test_mlsag_is_refused(monero: MoneroCmd, backend: BackendInterface):
        apdu = struct.pack("BBBBBB", PROTOCOL_LEGACY,
                           InsType.INS_MLSAG.value, 1, 0, 1, 0)
        with pytest.raises(ExceptionRAPDU) as exc_info:
            backend.exchange_raw(apdu)
        assert exc_info.value.status == SW_COMMAND_NOT_ALLOWED, (
            f"expected {SW_COMMAND_NOT_ALLOWED:#06x}, "
            f"got {exc_info.value.status:#06x}"
        )


# ---------------------------------------------------------------------------
# Canonical booleans
# ---------------------------------------------------------------------------
@pytest.mark.incremental
class TestNonCanonicalFlagsRefused:
    """
    is_change, is_subaddress, need_additional_txkeys and use_view_tags are
    bools in the wallet and are only tested for truth on the device, so a byte
    above 1 means the two disagree about the transaction shape.

    use_view_tags is the flag under test because it is the one whose value the
    rest of the handler would otherwise accept: a stray 2 in is_subaddress or
    need_additional_txkeys is caught anyway by the tx-pubkey classification, so
    a test on those would still pass with the guard removed.
    """

    @staticmethod
    @pytest.fixture(autouse=True, scope="class")
    def state():
        return _fresh_state()

    @staticmethod
    def test_canonical_flags_accepted(monero: MoneroCmd, state):
        _open_real_tx(monero, PROTOCOL_VERSION, state)

    @staticmethod
    def test_use_view_tags_above_one_refused(
        monero: MoneroCmd, backend: BackendInterface, state
    ):
        # Output 1: the first one was derived above, so the index check passes
        # and the flag byte is the only thing left to refuse.
        payload = _txout_keys_payload(
            state["tx_priv_key"], state["tx_pub_key"], output_index=1,
            is_change=0, is_subaddress=0, need_additional=0, use_view_tags=2,
        )
        apdu = struct.pack("BBBBBB", PROTOCOL_VERSION,
                           InsType.INS_GEN_TXOUT_KEYS.value, 0, 0,
                           1 + len(payload), 0) + payload
        with pytest.raises(ExceptionRAPDU) as exc_info:
            backend.exchange_raw(apdu)
        assert exc_info.value.status == SW_WRONG_DATA, (
            f"expected {SW_WRONG_DATA:#06x}, "
            f"got {exc_info.value.status:#06x}"
        )
