"""INS_GEN_TXOUT_KEYS pins the tx public key but not the secret behind it.

For a real non-change output that is not the lone-subaddress shape, the device
checks `memcmp(txkey_pub, G_monero_vstate.R)` (src/monero_key.c:934) and never
looks at `tx_key`. Two hundred lines later the derivation uses `tx_key`:

    monero_generate_key_derivation(derivation, Aout,
        (is_subaddress && need_additional_txkeys) ? additional_txkey_sec : tx_key, ...)

So the public half is vouched for and the secret half is whatever the host sent.
`EXTRA_R` is taken from `txkey_pub` (src/monero_key.c:1065) and the prefix walk
binds the on-chain tx pubkey to it, so the transaction that lands carries
`R = r.G` while the one-time output key was derived under some other scalar.
The recipient scans with `8.a.R` and finds nothing: the output is unspendable.
A correct-looking review, a valid transaction, burned funds.

This is the residual left by the V-056 fix. `1e68550` accepted either `R` or
`r.Bout` for any output and never checked the secret on the `R` path; `6986a13`
made the branch selection strict but kept that comparison. The Cerberus
remediation asked for `tx_key*G == txkey_pub`, which is the missing half.

Existing coverage aims at the other side of the same check and does not reach
this: `test_vuln_txkey_substitution.py` mutates `txkey_pub` while keeping the
genuine secret, and `test_vuln_change_txkey_binding.py` covers multi-output
`txkey_pub` consistency. Here `txkey_pub` is the genuine `R` and the *secret*
is swapped.

The second wrapper comes from INS_GENERATE_KEYPAIR rather than being forged.
A DEBUG build pins hmac_key to 0xab and uses IODUMMYCRYPT, so this harness
could mint a wrapper for any scalar it likes - but that would only demonstrate
a debug-build weakness. GENERATE_KEYPAIR needs neither key: it is allowed
unconditionally by check_ins_access, and its dispatch case calls no
update_protocol(), so it slots between OPEN_TX and GEN_TXOUT_KEYS without
disturbing tx_state_ins. That is the production-reachable route.

Verified against the device's own arithmetic: the test knows the seed's secret
view key, so from the public keypair GENERATE_KEYPAIR returns it can compute
`8.a.(k'.G)` - the same derivation the device performs - without ever holding
`k'`.
"""

import pytest
import nacl.bindings as nb
from Crypto.Hash import keccak

from ragger.backend.interface import BackendInterface

from monero_client.crypto.hmac import hmac_sha256
from monero_client.monero_cmd import MoneroCmd
from monero_client.monero_crypto_cmd import MoneroCryptoCmd
from monero_client.monero_types import SigType, Type
from monero_client.utils.varint import encode_varint

from test_vuln_change_address import _USER

_L = 2 ** 252 + 27742317777372353535851937790883648493

OUTPUT_INDEX = 0


def _red(n: int) -> bytes:
    return (n % _L).to_bytes(32, "little")


def _key_derivation(pub: bytes, priv: bytes) -> bytes:
    """8 * priv * pub, Monero's ECDH derivation. No clamping."""
    return nb.crypto_scalarmult_ed25519_noclamp(
        _red(int.from_bytes(priv, "little") * 8), pub)


def _derivation_to_scalar(derivation: bytes, index: int) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(derivation)
    k.update(encode_varint(index))
    return _red(int.from_bytes(k.digest(), "little"))


def _one_time_key(derivation: bytes, index: int, spend_pub: bytes) -> bytes:
    """Hs(derivation || varint(index)).G + B, the key that lands in vout."""
    s = _derivation_to_scalar(derivation, index)
    return nb.crypto_core_ed25519_add(
        nb.crypto_scalarmult_ed25519_base_noclamp(s), spend_pub)


def _foreign_scalar(backend) -> tuple:
    """Mint a second valid scalar wrapper inside the open transaction.

    INS_GENERATE_KEYPAIR returns pub || encrypted-secret || HMAC, so take the
    32-byte ciphertext and leave the HMAC to the caller. The device's own HMAC
    is asserted equal to the one the harness computes, which is the point: an
    attacker replays the reply verbatim and needs no key material. Forging a
    wrapper outright would work too on a DEBUG build, and would prove nothing
    about production.
    """
    crypto = MoneroCryptoCmd(backend)
    crypto.is_in_tx_mode = True
    foreign_pub, blob = crypto.generate_keypair()
    assert len(blob) == 64
    wrapped, device_hmac = blob[:32], blob[32:]
    assert hmac_sha256(wrapped, MoneroCryptoCmd.HMAC_KEY,
                       Type.SCALAR) == device_hmac, \
        "the harness HMAC differs from the device's, so this would not be a replay"
    return foreign_pub, wrapped


@pytest.mark.incremental
class TestHonestSecretScans:
    """Control: with the genuine r, the derived key is the one the recipient
    computes from the on-chain R. This is what the fix must keep true."""

    @staticmethod
    def test_honest_output_is_scannable(monero: MoneroCmd):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
        tx_pub_key, wrapped_r, _fv, _fs = monero.open_tx()

        _ak, out_eph, _add = monero.gen_txout_keys(
            _tx_priv_key=wrapped_r,
            tx_pub_key=tx_pub_key,
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            output_index=OUTPUT_INDEX,
            is_change_addr=False,
            is_subaddress=False,
        )

        expected = _one_time_key(
            _key_derivation(tx_pub_key, _USER.secret_view_key),
            OUTPUT_INDEX, _USER.public_spend_key)

        assert out_eph == expected, (
            "the honest path did not produce the key the recipient scans for")


@pytest.mark.incremental
class TestSubstitutedSecretIsRefused:
    """A second valid scalar wrapper, with the genuine R, must not be accepted.

    One refusal, last in its class: a non-OK status reaches
    send_error_and_kill_app and the app exits.
    """

    @staticmethod
    def test_foreign_secret_with_genuine_txkey_pub(monero: MoneroCmd,
                                                   backend: BackendInterface):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
        tx_pub_key, _wrapped_r, _fv, _fs = monero.open_tx()

        # A fresh scalar the device will decrypt and HMAC-accept, minted inside
        # this transaction so hmac_key rotation is no defence.
        foreign_pub, wrapped_foreign = _foreign_scalar(backend)

        # txkey_pub is the genuine R, so the pin at monero_key.c:934 passes.
        with pytest.raises(Exception) as exc_info:
            monero.gen_txout_keys(
                _tx_priv_key=wrapped_foreign,
                tx_pub_key=tx_pub_key,
                dst_pub_view_key=_USER.public_view_key,
                dst_pub_spend_key=_USER.public_spend_key,
                output_index=OUTPUT_INDEX,
                is_change_addr=False,
                is_subaddress=False,
            )
        assert "0x6984" in str(exc_info.value), (
            f"a foreign tx secret with a genuine txkey_pub must be refused "
            f"with SW_WRONG_DATA (0x6984), got {exc_info.value}")

        # Unused on the refusal path, but this is the value the derivation
        # would have used, and it is not what the recipient scans for.
        assert foreign_pub != tx_pub_key


@pytest.mark.skip(reason="the behaviour before the fix; needs a build without "
                         "the tx_key.G == txkey_pub check")
@pytest.mark.incremental
class TestSecretWasUnbound:
    """Kept so the burn stays reproducible on an unfixed build.

    Run with --run-skipped: the device accepts the foreign secret, derives the
    output under it, and the resulting key is not the one the recipient computes
    from the R that lands on-chain.
    """

    @staticmethod
    def test_output_is_derived_under_a_foreign_secret(monero: MoneroCmd,
                                                      backend: BackendInterface):
        monero.reset_and_get_version(monero_client_version=b"0.18")
        assert monero.set_signature_mode(sig_type=SigType.REAL) == SigType.REAL
        tx_pub_key, _wrapped_r, _fv, _fs = monero.open_tx()

        foreign_pub, wrapped_foreign = _foreign_scalar(backend)

        _ak, out_eph, _add = monero.gen_txout_keys(
            _tx_priv_key=wrapped_foreign,
            tx_pub_key=tx_pub_key,        # the genuine R
            dst_pub_view_key=_USER.public_view_key,
            dst_pub_spend_key=_USER.public_spend_key,
            output_index=OUTPUT_INDEX,
            is_change_addr=False,
            is_subaddress=False,
        )

        # 8.a.(k'.G) is the derivation the device just did, computable here
        # from the returned public key and the seed's view secret.
        derived_under_foreign = _one_time_key(
            _key_derivation(foreign_pub, _USER.secret_view_key),
            OUTPUT_INDEX, _USER.public_spend_key)
        # 8.a.R is what the recipient computes from the on-chain tx pubkey.
        recipient_scans_for = _one_time_key(
            _key_derivation(tx_pub_key, _USER.secret_view_key),
            OUTPUT_INDEX, _USER.public_spend_key)

        assert out_eph == derived_under_foreign, (
            "the device did not derive under the host-supplied secret")
        assert out_eph != recipient_scans_for, (
            "the output is scannable, so this is not a burn")
