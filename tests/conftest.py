from typing import Dict, Tuple
import pytest

from monero_client.monero_cmd import MoneroCmd

from ragger.conftest import configuration

###########################
### CONFIGURATION START ###
###########################
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


@pytest.fixture()
def monero(backend, debug=False):
    monero_client = MoneroCmd(debug, backend)

    yield monero_client


@pytest.fixture(autouse=True)
def _firmware_axis(firmware):
    """Force every test in the suite to depend on the `firmware` fixture so all
    tests share the same parametrize signature (e.g. [nanos-nanos]).

    Some test methods take `firmware`/`backend` as parameters (because their
    monero_cmd helpers branch on `firmware.device`), while others don't. Pytest
    groups tests by parametrize-index tuple — methods that pick up the
    `firmware` parametrize end up in a different collection group than those
    that don't, which interleaves @pytest.mark.incremental classes and breaks
    source ordering. Pulling firmware here gives every test the same signature
    and keeps incremental classes in declared order."""
    return firmware


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
