/*****************************************************************************
 *   Ledger Monero App.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_NBGL

#include "os.h"
#include "ux.h"
#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_ui.h"
#include "monero_vars.h"

#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"

#include "nbgl_use_case.h"

#define STR(x)  #x
#define XSTR(x) STR(x)

#define PAGE_START      0
#define NB_PAGE_SETTING 3

void __attribute__((noreturn)) app_exit(void);

/* ----------------------------------------------------------------------- */
/* ---                         Stax  UI layout                         --- */
/* ----------------------------------------------------------------------- */

typedef struct {
    char buffer[20];
    nbgl_pageContent_t content;
    nbgl_pageNavigationInfo_t nav;
} TransactionContext_t;

static TransactionContext_t transactionContext;

enum {
    ACCOUNT_TOKEN = FIRST_USER_TOKEN,
    NETWORK_TOKEN,
    RESET_TOKEN,
    ACCOUNT_CHOICE,
    ACCOUNT_CHOICE_2,
    ACCOUNT_CHOICE_3,
    NETWORK_CHOICE
};

enum { MAIN_NET, STAGE_NET, TEST_NET, MAX_NET };

#define SETTING_INFO_NB 4
static const char* const infoTypes[] = {"Spec", "Version", "Developer", "Copyright"};
static const char* const infoContents[] = {XSTR(SPEC_VERSION), APPVERSION, "Ledger",
                                           "(c) 2024 Ledger"};

static const char* const barTexts[] = {"Select Account", "Select Network", "Reset"};
static const uint8_t tokens[] = {ACCOUNT_TOKEN, NETWORK_TOKEN, RESET_TOKEN};

static const char* const accountNames[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
#ifdef MONERO_ALPHA
static const char* const networkNames[] = {"Unavailable", "Stage network", "Test network"};
#else
static const char* const networkNames[] = {"Main network", "Stage network", "Test network"};
#endif

static void display_settings_menu(void);

static void update_account(void) {
    G_monero_vstate.disp_addr_mode = 0;
    G_monero_vstate.disp_addr_M = 0;
    G_monero_vstate.disp_addr_m = 0;
}

static bool account_settings_navigation_cb(uint8_t page, nbgl_pageContent_t* content) {
    content->type = CHOICES_LIST;
    content->choicesList.nbChoices = 4;
    content->choicesList.localized = false;
    content->choicesList.tuneId = TUNE_TAP_CASUAL;

    if (page == 0) {
        content->choicesList.initChoice = N_monero_pstate->account_id;
        content->choicesList.names = accountNames;
        content->choicesList.token = ACCOUNT_CHOICE;
    } else if (page == 1) {
        if (N_monero_pstate->account_id > 3) {
            content->choicesList.initChoice = N_monero_pstate->account_id - 4;
        } else {
            content->choicesList.initChoice = 4;
        }
        content->choicesList.names = accountNames + 4;
        content->choicesList.token = ACCOUNT_CHOICE_2;
    } else if (page == 2) {
        content->choicesList.nbChoices = 2;
        if (N_monero_pstate->account_id > 7) {
            content->choicesList.initChoice = N_monero_pstate->account_id - 8;
        } else {
            content->choicesList.initChoice = 8;
        }
        content->choicesList.names = accountNames + 8;
        content->choicesList.token = ACCOUNT_CHOICE_3;
    } else {
        return false;
    }
    return true;
}

static bool network_settings_navigation_cb(uint8_t page, nbgl_pageContent_t* content) {
    if (page == 0) {
        content->type = CHOICES_LIST;
        content->choicesList.nbChoices = 3;
        content->choicesList.localized = false;
        content->choicesList.tuneId = TUNE_TAP_CASUAL;

        if (N_monero_pstate->network_id == MAINNET) {
            content->choicesList.initChoice = MAIN_NET;
        } else if (N_monero_pstate->network_id == TESTNET) {
            content->choicesList.initChoice = TEST_NET;
        } else if (N_monero_pstate->network_id == STAGENET) {
            content->choicesList.initChoice = STAGE_NET;
        }
        content->choicesList.names = networkNames;
        content->choicesList.token = NETWORK_CHOICE;
    } else {
        return false;
    }
    return true;
}

static void resetCallback(void) {
    unsigned char magic[4];
    magic[0] = 0;
    magic[1] = 0;
    magic[2] = 0;
    magic[3] = 0;
    monero_nvm_write((void*)N_monero_pstate->magic, magic, 4);
    monero_init();
    nbgl_useCaseStatus("ACCOUNT INFOS\nRESETTED", true, ui_menu_main_display);
}

static void account_settings_control_cb(int token, uint8_t index) {
    switch (token) {
        case ACCOUNT_CHOICE_3:
        case ACCOUNT_CHOICE_2:
        case ACCOUNT_CHOICE:
            index = (token - ACCOUNT_CHOICE) * 4 + index;
            if (index <= 9) {
                monero_nvm_write((void*)&N_monero_pstate->account_id, &index, sizeof(uint8_t));
                monero_init();
            }
            display_settings_menu();
            break;
        default:
            PRINTF("Should not happen !");
            break;
    }
}

static void network_settings_control_cb(int token, uint8_t index) {
    UNUSED(index);
    switch (token) {
        case NETWORK_CHOICE:
#ifdef MONERO_ALPHA
            if (index == 0) {
                display_settings_menu();
            } else
#endif
                if (index < MAX_NET) {
                if (index == MAIN_NET) {
                    monero_install(MAINNET);
                } else if (index == TEST_NET) {
                    monero_install(TESTNET);
                } else if (index == STAGE_NET) {
                    monero_install(STAGENET);
                }
                monero_init();
            }
            display_settings_menu();
            break;
        default:
            PRINTF("Should not happen !");
            break;
    }
}

static void settings_control_cb(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    switch (token) {
        case ACCOUNT_TOKEN:
            nbgl_useCaseNavigableContent("Select account", 0, 3, display_settings_menu,
                                         account_settings_navigation_cb,
                                         account_settings_control_cb);
            break;
        case NETWORK_TOKEN:
            nbgl_useCaseNavigableContent("Select network", 0, 2, display_settings_menu,
                                         network_settings_navigation_cb,
                                         network_settings_control_cb);
            break;
        case RESET_TOKEN:
            nbgl_useCaseConfirm("Reset account\ninformations ?", "", "Yes, Reset", "Go back",
                                resetCallback);
            break;

        default:
            PRINTF("Should not happen !");
            break;
    }
}

// info menu definition
static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = infoTypes,
    .infoContents = infoContents,
};

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = BARS_LIST,
     .content.barsList.barTexts = barTexts,
     .content.barsList.tokens = tokens,
     .content.barsList.nbBars = 3,
     .content.barsList.tuneId = TUNE_TAP_CASUAL,
     .contentActionCallback = settings_control_cb}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};
static nbgl_homeAction_t homeAction;

static void display_home_and_settings(bool displayHome) {
    update_account();

    explicit_bzero(G_monero_vstate.ux_address, sizeof(G_monero_vstate.ux_address));

    snprintf(transactionContext.buffer, sizeof(transactionContext.buffer), "Show %s",
             G_monero_vstate.ux_wallet_account_name);

    monero_base58_public_key(G_monero_vstate.ux_address, G_monero_vstate.A, G_monero_vstate.B, 0,
                             NULL);

    homeAction.callback = display_account;
    homeAction.icon = NULL;
    homeAction.text = transactionContext.buffer;

    nbgl_useCaseHomeAndSettings(APPNAME, &ICON_APP_MAIN, NULL, displayHome ? INIT_HOME_PAGE : 0,
                                &settingContents, &infoList, &homeAction, app_exit);
}

static void display_settings_menu(void) {
    // display settings page
    display_home_and_settings(false);
}

void ui_menu_main_display(void) {
    // display home page
    display_home_and_settings(true);
}

/* --- INIT --- */

void ui_init(void) {
    ui_menu_main_display();
}

#endif
