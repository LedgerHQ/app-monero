import pytest

# pylint: disable=wildcard-import, unused-wildcard-import
from monero_client.exception import ClientNotSupported

def check_accepted_version(monero, valid_version: bytes):
    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=valid_version
    )  # type: int, int, int
    assert (major, minor, patch) == (1, 8, 0)  # version of the Monero app

def check_refused_version(monero, invalid_version: bytes):
    with pytest.raises(ClientNotSupported) as excinfo:
        monero.reset_and_get_version(invalid_version)


def test_version(monero):
    # Monero does not have any consensus changes with minor point upgrades, we support the entire 0.18. range, except 0.18.0.0
    check_accepted_version(monero, b"0.18")
    check_accepted_version(monero, b"0.18.0.1")
    check_accepted_version(monero, b"0.18.0.10")
    check_accepted_version(monero, b"0.18.1.1")
    check_accepted_version(monero, b"0.18.9.0")
    check_accepted_version(monero, b"0.18.18.0")

def test_old_client_version(monero):
    # Not supported anymore
    check_refused_version(monero, b"0.0.0.0")
    check_refused_version(monero, b"0.17.0.0")
    check_refused_version(monero, b"0.17.18.0")
    # Explicitly disabled
    check_refused_version(monero, b"0.18.0.0")
    # Not yet supported
    check_refused_version(monero, b"0.19.0.0")
    check_refused_version(monero, b"1.0.0.0")
    # Regex shenanigans
    check_refused_version(monero, b"")
    check_refused_version(monero, b"0")
    check_refused_version(monero, b"0.0.")
    check_refused_version(monero, b"0.180")
