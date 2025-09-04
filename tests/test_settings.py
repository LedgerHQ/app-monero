"""Verifies settings and information navigation
"""
from pathlib import Path
from ledgered.devices import Device, DeviceType


from ragger.firmware.touch.positions import POSITIONS
from ragger.navigator import Navigator, NavInsID, NavIns

TESTS_ROOT_DIR = Path(__file__).parent

def _get_settings_element_coordinates(device: Device, number):
    return POSITIONS["ChoiceList"][device.type][number + 1]


def test_settings(navigator: Navigator, device: Device, test_name: str):
    """Verifies settings navigation
    """
    instructions = []
    if device.touchable:
        instructions = [
            # 0 (Main page)->Settings button = Page 1
            NavInsID.USE_CASE_HOME_SETTINGS,
            # 1 (Page 1)->Select Account = Select account
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 0)),
            # 2 (Select account)->Selecting account 2 = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 2)),
            # 3 (Page 1)-> Select Account = Select account
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 0)),
            # 4 (Select account)-> Back = Page 1
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
            #5 (Page 1)-> Select Network = Select network
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 1)),
            #6 (Select network)-> Test network = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 2)),
            #7 (Page 1)-> Select Network = Select network
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 1)),
            # 8 (Select account)-> Back = Page 1
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
            #9 (Page 1)-> Reset = Confirmation
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 2)),
            #10 (Confirmation)-> Reset = Text, Main page
            NavInsID.USE_CASE_CHOICE_CONFIRM,
            #11 (Main page)
            NavInsID.WAIT_FOR_HOME_SCREEN,
            # 12 (Main page)->Settings button = Page 1
            NavInsID.USE_CASE_HOME_SETTINGS,
            # 13 (Page 1)->Select Account = Select account
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 0)),
            # 14 (Select account)-> Back = Page 1
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
            #15 (Page 1)-> Select Network = Select network
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(device, 1)),
            # 16 (Select account)-> Back = Page 1
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
        ]
    elif device.is_nano:
        instructions = [
            # Setting Account 2
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.BOTH_CLICK,    # = Select Account (0+)
            NavInsID.RIGHT_CLICK,   # = 1
            NavInsID.RIGHT_CLICK,   # = 2
            NavInsID.BOTH_CLICK,    # = Main page
            # Verification Account 2
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.BOTH_CLICK,    # = Select Account (0, 2+)
            NavInsID.RIGHT_CLICK,   # = 1, 2+
            NavInsID.RIGHT_CLICK,   # = 2, 2+
            NavInsID.RIGHT_CLICK,   # = 3, 2+
            NavInsID.RIGHT_CLICK,   # = 4, 2+
            NavInsID.RIGHT_CLICK,   # = 5, 2+
            NavInsID.RIGHT_CLICK,   # = 6, 2+
            NavInsID.RIGHT_CLICK,   # = 7, 2+
            NavInsID.RIGHT_CLICK,   # = 8, 2+
            NavInsID.RIGHT_CLICK,   # = 9, 2+
            NavInsID.RIGHT_CLICK,   # = Abort, 2+
            NavInsID.BOTH_CLICK,    # = Main page
            # Setting "Test Network"
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.RIGHT_CLICK,   # = Select Network
            NavInsID.BOTH_CLICK,    # = Select Network (Main Network, Stage Network+)
            NavInsID.RIGHT_CLICK,   # = Select Network (Stage Network, Stage Network+)
            NavInsID.RIGHT_CLICK,   # = Select Network (Test Network, Stage Network+)
            NavInsID.BOTH_CLICK,    # = Main page
            # Verification "Test Network"
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.RIGHT_CLICK,   # = Select Network
            NavInsID.BOTH_CLICK,    # = Select Network (Main Network, Test Network+)
            NavInsID.RIGHT_CLICK,   # = Select Network (Stage Network, Test Network+)
            NavInsID.RIGHT_CLICK,   # = Select Network (Test Network, Test Network+)
            NavInsID.RIGHT_CLICK,   # = Select Network (Abort, Test Network+)
            NavInsID.BOTH_CLICK,    # = Main page
            # Reset settings
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.RIGHT_CLICK,   # = Select Network
            NavInsID.RIGHT_CLICK,   # = Show 25 words
            NavInsID.RIGHT_CLICK,   # = Reset
            NavInsID.BOTH_CLICK,    # = Really reset
            NavInsID.RIGHT_CLICK,   # = No
            NavInsID.RIGHT_CLICK,   # = Yes
            NavInsID.BOTH_CLICK,    # = Main page
            # Verification Account 0
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.BOTH_CLICK,    # = Select Account (0, 0+)
            NavInsID.BOTH_CLICK,    # = Main page
            # Verification "Stage Network"
            NavInsID.RIGHT_CLICK,   # = Settings HL
            NavInsID.BOTH_CLICK,    # = Settings LL
            NavInsID.RIGHT_CLICK,   # = Select Network
            NavInsID.BOTH_CLICK,    # = Select Network (Main Network, Stage Network+)
        ]
    navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                   test_name,
                                   instructions,
                                   screen_change_before_first_instruction = False)

def test_info(navigator: Navigator, device: Device, test_name: str):
    """Verifies info navigation
    """
    instructions = []
    if device.touchable:
        instructions = [
            # 0 (main page) -> Settings button = Page 1
            NavInsID.USE_CASE_HOME_SETTINGS,
            # 1 (Page 1) -> Right = Info 1
            NavInsID.SWIPE_CENTER_TO_LEFT,
            # 2 (Info 1) -> Right = Info 2
            NavInsID.SWIPE_CENTER_TO_LEFT,
        ]
    elif device.is_nano:
        if device.type == DeviceType.NANOS:
            instructions = [
                NavInsID.RIGHT_CLICK, # = Settings
                NavInsID.RIGHT_CLICK, # = About
                NavInsID.BOTH_CLICK,  # = About Info 1
                NavInsID.RIGHT_CLICK, # = About Info 2
                NavInsID.RIGHT_CLICK, # = Back
                NavInsID.BOTH_CLICK,  # = Main page
            ]
        else:
            instructions = [
                NavInsID.RIGHT_CLICK, # = Settings
                NavInsID.RIGHT_CLICK, # = About
                NavInsID.BOTH_CLICK,  # = About Info
                NavInsID.RIGHT_CLICK, # = Back
                NavInsID.BOTH_CLICK,  # = Main page
            ]
    navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                   test_name,
                                   instructions,
                                   screen_change_before_first_instruction = False)
