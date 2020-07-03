import pytest

from monero_client.exception import *


def test_version(monero):
    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=b"0.16.0.0"
    )  # type: int, int, int

    assert (major, minor, patch) == (1, 6, 0)  # version of the Monero app


@pytest.mark.xfail(raises=ClientNotSupported)
def test_old_client_version(monero):
    # should raise ClientNotSupported[0x6a30]
    monero.reset_and_get_version(b"0.15.0.0")
