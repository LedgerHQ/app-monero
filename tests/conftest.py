import pytest
from typing import Dict, Tuple

from monero_client.io.button import Button, FakeButton
from monero_client.monero_cmd import MoneroCmd


SPECULOS: bool = True


@pytest.fixture(scope="module")
def monero():
    monero = MoneroCmd(debug=True,
                       speculos=SPECULOS)

    yield monero

    monero.device.close()


@pytest.fixture(scope="module")
def button():
    button = (Button(server="127.0.0.1", port=42000)
              if SPECULOS else FakeButton())

    yield button

    button.close()


_test_failed_incremental: Dict[str, Dict[Tuple[int, ...], str]] = {}


def pytest_runtest_makereport(item, call):
    if "incremental" in item.keywords:
        if call.excinfo is not None:

            cls_name = str(item.cls)
            parametrize_index = (
                tuple(item.callspec.indices.values())
                if hasattr(item, "callspec")
                else ()
            )
            test_name = item.originalname or item.name
            _test_failed_incremental.setdefault(cls_name, {}).setdefault(
                parametrize_index, test_name
            )


def pytest_runtest_setup(item):
    if "incremental" in item.keywords:
        cls_name = str(item.cls)
        if cls_name in _test_failed_incremental:
            parametrize_index = (
                tuple(item.callspec.indices.values())
                if hasattr(item, "callspec")
                else ()
            )
            test_name = _test_failed_incremental[cls_name].get(
                parametrize_index, None
            )
            if test_name is not None:
                pytest.xfail("previous test failed ({})".format(test_name))
