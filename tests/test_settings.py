"""Verifies settings and information navigation
"""
from pathlib import Path
from ragger.navigator import NavInsID, NavIns

TESTS_ROOT_DIR = Path(__file__).parent

# Flex screen parameters
FLEX_WIDTH = 480
FLEX_HEIGHT = 600
FLEX_HEADER_HEIGHT = 95
FLEX_ITEM_HEIGHT = 92
FLEX_SETTINGS_X = 404
FLEX_SETTINGS_Y = 75

# Stax screen parameters
STAX_WIDTH = 400
STAX_HEIGHT = 672
STAX_HEADER_HEIGHT = 87
STAX_ITEM_HEIGHT = 96
STAX_SETTINGS_X = 335
STAX_SETTINGS_Y = 63

def _get_settings_button_coordinates(firmware):
    if firmware.device == "flex":
        return (FLEX_SETTINGS_X, FLEX_SETTINGS_Y)
    if firmware.device == "stax":
        return (STAX_SETTINGS_X, STAX_SETTINGS_Y)
    return (0, 0)

def _get_settings_element_coordinates(firmware, number):
    if firmware.device == "flex":
        return (FLEX_WIDTH//2, FLEX_HEADER_HEIGHT + (number)*FLEX_ITEM_HEIGHT + FLEX_ITEM_HEIGHT//2)
    if firmware.device == "stax":
        return (STAX_WIDTH//2, STAX_HEADER_HEIGHT + (number)*STAX_ITEM_HEIGHT + STAX_ITEM_HEIGHT//2)
    return (0, 0)

def test_settings(navigator, firmware, test_name):
    """Verifies settings navigation
    """
    instructions = []
    if firmware.device in ["flex", "stax"]:
        instructions = [
            # 0 (Main page)->Settings button = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_button_coordinates(firmware)),
            # 1 (Page 1)->Select Account = Select account
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 0)),
            # 2 (Select account)->Selecting account 2 = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 2)),
            # 3 (Page 1)-> Select Account = Select account
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 0)),
            # 4 (Select account)-> Back = Page 1
            NavIns(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT),
            #5 (Page 1)-> Select Network = Select network
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 1)),
            #6 (Select network)-> Test network = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 2)),
            #7 (Page 1)-> Select Network = Select network
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 1)),
            # 8 (Select account)-> Back = Page 1
            NavIns(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT),
            #9 (Page 1)-> Reset = Confirmation
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 2)),
            #10 (Confirmation)-> Reset = Text, Main page
            NavIns(NavInsID.USE_CASE_CHOICE_CONFIRM),
            #11 (Main page)
            NavIns(NavInsID.WAIT_FOR_HOME_SCREEN),
            # 12 (Main page)->Settings button = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_button_coordinates(firmware)),
            # 13 (Page 1)->Select Account = Select account
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 0)),
            # 14 (Select account)-> Back = Page 1
            NavIns(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT),
            #15 (Page 1)-> Select Network = Select network
            NavIns(NavInsID.TOUCH, _get_settings_element_coordinates(firmware, 1)),
            # 16 (Select account)-> Back = Page 1
            NavIns(NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT),
        ]
    elif firmware.device in ["nanosp", "nanos", "nanox"]:
        instructions = [
            # Setting Account 2
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.BOTH_CLICK),    # = Select Account (0+)
            NavIns(NavInsID.RIGHT_CLICK),   # = 1
            NavIns(NavInsID.RIGHT_CLICK),   # = 2
            NavIns(NavInsID.BOTH_CLICK),    # = Main page
            # Verification Account 2
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.BOTH_CLICK),    # = Select Account (0, 2+)
            NavIns(NavInsID.RIGHT_CLICK),   # = 1, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 2, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 3, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 4, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 5, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 6, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 7, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 8, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = 9, 2+
            NavIns(NavInsID.RIGHT_CLICK),   # = Abort, 2+
            NavIns(NavInsID.BOTH_CLICK),    # = Main page
            # Setting "Test Network"
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network
            NavIns(NavInsID.BOTH_CLICK),    # = Select Network (Main Network, Stage Network+)
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network (Stage Network, Stage Network+)
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network (Test Network, Stage Network+)
            NavIns(NavInsID.BOTH_CLICK),    # = Main page
            # Verification "Test Network"
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network
            NavIns(NavInsID.BOTH_CLICK),    # = Select Network (Main Network, Test Network+)
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network (Stage Network, Test Network+)
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network (Test Network, Test Network+)
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network (Abort, Test Network+)
            NavIns(NavInsID.BOTH_CLICK),    # = Main page
            # Reset settings
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network
            NavIns(NavInsID.RIGHT_CLICK),   # = Show 25 words
            NavIns(NavInsID.RIGHT_CLICK),   # = Reset
            NavIns(NavInsID.BOTH_CLICK),    # = Really reset
            NavIns(NavInsID.RIGHT_CLICK),   # = No
            NavIns(NavInsID.RIGHT_CLICK),   # = Yes
            NavIns(NavInsID.BOTH_CLICK),    # = Main page
            # Verification Account 0
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.BOTH_CLICK),    # = Select Account (0, 0+)
            NavIns(NavInsID.BOTH_CLICK),    # = Main page
            # Verification "Stage Network"
            NavIns(NavInsID.RIGHT_CLICK),   # = Settings HL
            NavIns(NavInsID.BOTH_CLICK),    # = Settings LL
            NavIns(NavInsID.RIGHT_CLICK),   # = Select Network
            NavIns(NavInsID.BOTH_CLICK),    # = Select Network (Main Network, Stage Network+)
        ]
    navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                   test_name,
                                   instructions,
                                   screen_change_before_first_instruction = False)

def test_info(navigator, firmware, test_name):
    """Verifies info navigation
    """
    instructions = []
    if firmware.device in ["flex", "stax"]:
        instructions = [
            # 0 (main page) -> Settings button = Page 1
            NavIns(NavInsID.TOUCH, _get_settings_button_coordinates(firmware)),
            # 1 (Page 1) -> Right = Info 1
            NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
            # 2 (Info 1) -> Right = Info 2
            NavIns(NavInsID.SWIPE_CENTER_TO_LEFT),
        ]
    elif firmware.device in ["nanosp", "nanox"]:
        instructions = [
            NavIns(NavInsID.RIGHT_CLICK), # = Settings
            NavIns(NavInsID.RIGHT_CLICK), # = About
            NavIns(NavInsID.BOTH_CLICK),  # = About Info
            NavIns(NavInsID.RIGHT_CLICK), # = Back
            NavIns(NavInsID.BOTH_CLICK),  # = Main page
        ]
    elif firmware.device == "nanos":
        instructions = [
            NavIns(NavInsID.RIGHT_CLICK), # = Settings
            NavIns(NavInsID.RIGHT_CLICK), # = About
            NavIns(NavInsID.BOTH_CLICK),  # = About Info 1
            NavIns(NavInsID.RIGHT_CLICK), # = About Info 2
            NavIns(NavInsID.RIGHT_CLICK), # = Back
            NavIns(NavInsID.BOTH_CLICK),  # = Main page
        ]
    navigator.navigate_and_compare(TESTS_ROOT_DIR,
                                   test_name,
                                   instructions,
                                   screen_change_before_first_instruction = False)
