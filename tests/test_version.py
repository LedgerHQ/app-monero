import pytest

# pylint: disable=wildcard-import, unused-wildcard-import
from monero_client.exception import ClientNotSupported


def test_version(monero):
    # Monero does not have any consensus changes with minor point upgrades, we support 0.18.

    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=b"0.18.0.0"
    )  # type: int, int, int

    assert (major, minor) == (1, 8)  # version of the Monero app

    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=b"0.18.9.0"
    )  # type: int, int, int

    assert (major, minor) == (1, 8)  # version of the Monero app

def test_old_client_version(monero):
    # should raise ClientNotSupported[0x6a30]
    with pytest.raises(ClientNotSupported) as excinfo:
        monero.reset_and_get_version(b"0.17.0.0")
    with pytest.raises(ClientNotSupported) as excinfo:
        monero.reset_and_get_version(b"0.19.0.0")
