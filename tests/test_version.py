from pathlib import Path
from typing import List
import re
import pytest

# pylint: disable=wildcard-import, unused-wildcard-import
from monero_client.exception import ClientNotSupported


def check_accepted_version(monero, valid_version: bytes):
    major, minor, patch = monero.reset_and_get_version(
        monero_client_version=valid_version
    )  # type: int, int, int
    _verify_version(f"{major}.{minor}.{patch}")


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


def _verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> List[str]:
    """Read lines from the parent Makefile """

    with open(Path(__file__).parent.parent / "Makefile", "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines
