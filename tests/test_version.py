import pytest

# pylint: disable=wildcard-import, unused-wildcard-import
from monero_client.exception import *


def test_version(monero):
    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=b"0.17.0.0"
    )  # type: int, int, int

    assert (major, minor) == (1, 7)  # version of the Monero app

    # another compatible version of the Monero client
    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=b"0.17.1.0"
    )  # type: int, int, int

    assert (major, minor) == (1, 7)  # version of the Monero app


@pytest.mark.xfail(raises=ClientNotSupported)
def test_old_client_version(monero):
    # should raise ClientNotSupported[0x6a30]
    monero.reset_and_get_version(b"0.15.0.0")
