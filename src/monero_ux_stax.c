/*****************************************************************************
 *   Ledger Monero App.
 *   (c) 2017-2020 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS.
 *   (c) 2020 Ledger SAS.
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

#if defined(UI_STAX)

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "monero_ux_msg.h"
#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"

#include "nbgl_use_case.h"

/* ----------------------------------------------------------------------- */
/* ---                         Stax  UI layout                         --- */
/* ----------------------------------------------------------------------- */

typedef struct {
    nbgl_layoutTagValue_t tagValuePair[3];
    nbgl_layoutTagValueList_t tagValueList;
    nbgl_pageInfoLongPress_t infoLongPress;
    char buffer[20];
    nbgl_pageContent_t content;
    nbgl_pageNavigationInfo_t nav;
} TransactionContext_t;

static TransactionContext_t transactionContext;

ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

/* -------------------------------------- LOCK--------------------------------------- */

void ui_menu_pinlock_display() {
    struct {
        bolos_ux_t ux_id;
        // length of parameters in the u union to be copied during the syscall
        unsigned int len;
        union {
            struct {
                unsigned int cancellable;
            } validate_pin;
        } u;

    } ux_params;

    os_global_pin_invalidate();
    G_monero_vstate.protocol_barrier = PROTOCOL_LOCKED_UNLOCKABLE;
    ux_params.ux_id = BOLOS_UX_VALIDATE_PIN;
    ux_params.len = sizeof(ux_params.u.validate_pin);
    ux_params.u.validate_pin.cancellable = 0;
    os_ux((bolos_ux_params_t*)&ux_params);
    ui_menu_main_display(0);
}

/* -------------------------------- INFO UX --------------------------------- */

static void ui_menu_info_action(void) {
    if (G_monero_vstate.protocol_barrier == PROTOCOL_LOCKED) {
        ui_menu_pinlock_display();
    } else {
        ui_menu_main_display(0);
    }
}

void ui_menu_info_display2(unsigned int value __attribute__((unused)), char* line1 __attribute__((unused)), char* line2 __attribute__((unused))) {
    nbgl_useCaseStatus("Transaction\ncancelled", false, ui_menu_info_action);
}

void ui_menu_info_display(unsigned int value __attribute__((unused))) {
    nbgl_useCaseStatus("Security Error", false, ui_menu_info_action);
}

/* -------------------------------- OPEN TX UX --------------------------------- */
static void ui_menu_validation_action_cancel(void) {
    monero_abort_tx();
    monero_io_insert_u16(SW_DENY);
    monero_io_do(IO_RETURN_AFTER_TX);
}

static void ui_menu_validation_action_confirm(void) {
    monero_io_discard(0);
    monero_io_insert_u16(SW_OK);
    monero_io_do(IO_RETURN_AFTER_TX);
    nbgl_useCaseSpinner("Processing TX");
}

static void ui_menu_validation_action_cancel_prompt(void) {
    nbgl_useCaseConfirm("Reject transaction?", "", "Yes, Reject", "Go back to transaction", ui_menu_validation_action_cancel);
}

static void ui_menu_validation_action(bool value) {
    if (value) {
        ui_menu_validation_action_confirm();
    } else {
        ui_menu_validation_action_cancel_prompt();
    }
}

unsigned int ui_menu_transaction_start(void) {
    nbgl_useCaseReviewStart(&C_Monero_64px,
                       "Review Transaction\nto send Monero",
                       "",
                       "Reject transaction", 
                       ui_menu_validation_action_confirm,
                       ui_menu_validation_action_cancel_prompt);
    return 0;
}

unsigned int ui_menu_transaction_signed(void) {
    nbgl_useCaseStatus("TRANSACTION\nSIGNED", true, ui_menu_main_display);
    return 0;
}

void ui_menu_opentx_display(unsigned int value __attribute__((unused))) {
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        nbgl_useCaseSpinner("Processing TX");
    }
    else {
        nbgl_useCaseSpinner("Preparing TX");
    }
}

/* ----------------- FEE/CHANGE/TIMELOCK VALIDATION ----------------- */

void ui_menu_fee_validation_display(unsigned int value __attribute__((unused))) {
    transactionContext.tagValuePair[0].item = "Fee";
    transactionContext.tagValuePair[0].value = G_monero_vstate.ux_amount;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs = 1;

    transactionContext.infoLongPress.icon = &C_Monero_64px;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = 0;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = "Confirm\nFee";

    nbgl_useCaseStaticReviewLight(&transactionContext.tagValueList, &transactionContext.infoLongPress, "Cancel", ui_menu_validation_action);
}

void ui_menu_change_validation_display(unsigned int value __attribute__((unused))) {
    transactionContext.tagValuePair[0].item = "Change";
    transactionContext.tagValuePair[0].value = G_monero_vstate.ux_amount;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs = 1;

    transactionContext.infoLongPress.icon = &C_Monero_64px;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = 0;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = "Confirm\nChange";

    nbgl_useCaseStaticReviewLight(&transactionContext.tagValueList, &transactionContext.infoLongPress, "Cancel", ui_menu_validation_action);
}

static void timelock_display(void) {
    transactionContext.tagValuePair[0].item = "Timelock";
    transactionContext.tagValuePair[0].value = G_monero_vstate.ux_amount;
    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs = 1;

    transactionContext.infoLongPress.icon = &C_Monero_64px;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = 0;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = "Confirm\nTimelock";

    nbgl_useCaseStaticReviewLight(&transactionContext.tagValueList, &transactionContext.infoLongPress, "Cancel", ui_menu_validation_action);
}

void ui_menu_timelock_validation_display(unsigned int value __attribute__((unused))) {
    nbgl_useCaseReviewStart(&C_Monero_64px, "Review Transaction", "", "Cancel", timelock_display, ui_menu_validation_action_cancel_prompt);
}

/* ----------------------------- USER DEST/AMOUNT VALIDATION ----------------------------- */

void ui_menu_validation_display(unsigned int value __attribute__((unused))) {

    transactionContext.tagValuePair[0].item = "Amount";
    transactionContext.tagValuePair[0].value = G_monero_vstate.ux_amount;

    transactionContext.tagValuePair[1].item = "Destination";
    transactionContext.tagValuePair[1].value = G_monero_vstate.ux_address;

    transactionContext.infoLongPress.icon = &C_Monero_64px;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = 0;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = "Hold to confirm";

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs = 2;

    nbgl_useCaseStaticReview(&transactionContext.tagValueList, &transactionContext.infoLongPress, "Cancel", ui_menu_validation_action);
}

/* ---------------------------- PUBLIC ADDRESS UX ---------------------------- */
#define ADDR_MAJOR G_monero_vstate.ux_address + 124
#define ADDR_MINOR G_monero_vstate.ux_address + 140
#define ADDR_ID    G_monero_vstate.ux_address + 140

static void ui_menu_pubaddr_action_cancelled(void) {
    if (G_monero_vstate.disp_addr_mode) {
        monero_io_insert_u16(SW_OK);
        monero_io_do(IO_RETURN_AFTER_TX);
    }
    G_monero_vstate.disp_addr_mode = 0;
    nbgl_useCaseStatus("Address display\ncancelled", false, ui_menu_main_display);
}

static void update_account(void) {
    G_monero_vstate.disp_addr_mode = 0;
    G_monero_vstate.disp_addr_M = 0;
    G_monero_vstate.disp_addr_m = 0;
}

void ui_menu_pubaddr_action(bool confirm) {
    if (confirm) {
        if (G_monero_vstate.disp_addr_mode) {
            monero_io_insert_u16(SW_OK);
            monero_io_do(IO_RETURN_AFTER_TX);
        }
        G_monero_vstate.disp_addr_mode = 0;
        nbgl_useCaseStatus("ADDRESS\nDISPLAYED", true, ui_menu_main_display);
    }
    else {
        ui_menu_pubaddr_action_cancelled();
    }
}

static void display_account(void) {
    switch (G_monero_vstate.disp_addr_mode) {
        case 0:
        case DISP_MAIN:
            transactionContext.tagValuePair[0].item = "Type";
            transactionContext.tagValuePair[0].value = "Main address";

            transactionContext.tagValueList.nbPairs = 1;
            break;

        case DISP_SUB:
            transactionContext.tagValuePair[0].item = "Type";
            transactionContext.tagValuePair[0].value = "Sub address";

            snprintf(ADDR_MAJOR, 16, "%d", G_monero_vstate.disp_addr_M);
            snprintf(ADDR_MINOR, 16, "%d", G_monero_vstate.disp_addr_m);

            transactionContext.tagValuePair[1].item = "Major";
            transactionContext.tagValuePair[1].value = ADDR_MAJOR;

            transactionContext.tagValuePair[2].item = "Minor";
            transactionContext.tagValuePair[2].value = ADDR_MINOR;

            transactionContext.tagValueList.nbPairs = 3;
            break;

        case DISP_INTEGRATED:
            transactionContext.tagValuePair[0].item = "Type";
            transactionContext.tagValuePair[0].value = "Integrated address";

            memcpy(ADDR_ID, G_monero_vstate.payment_id, 16);

            transactionContext.tagValuePair[1].item = "Payment ID";
            transactionContext.tagValuePair[1].value = ADDR_ID;

            transactionContext.tagValueList.nbPairs = 2;
            break;
    }

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    nbgl_useCaseAddressConfirmationExt(G_monero_vstate.ux_address, ui_menu_pubaddr_action, &transactionContext.tagValueList);
}

void ui_menu_any_pubaddr_display(unsigned int value __attribute__((unused)),
                                 unsigned char* pub_view, unsigned char* pub_spend,
                                 unsigned char is_subbadress, unsigned char* paymanetID) {
    memset(G_monero_vstate.ux_address, 0, sizeof(G_monero_vstate.ux_address));

    monero_base58_public_key(G_monero_vstate.ux_address, pub_view, pub_spend, is_subbadress,
                             paymanetID);

    nbgl_useCaseReviewStart(&C_Monero_64px, "Review Address", "", "Cancel", display_account, ui_menu_pubaddr_action_cancelled);
}

/* -------------------------------- EXPORT VIEW KEY UX --------------------------------- */

static void ui_menu_export_viewkey_action(bool value) {
    unsigned int sw;
    unsigned char x[32];

    monero_io_discard(0);
    memset(x, 0, 32);
    sw = SW_OK;

    if (value) {
        monero_io_insert(G_monero_vstate.a, 32);
        G_monero_vstate.export_view_key = EXPORT_VIEW_KEY;
    } else {
        monero_io_insert(x, 32);
        G_monero_vstate.export_view_key = 0;
    }
    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
}

void ui_export_viewkey_display(unsigned int value __attribute__((unused))) {
    nbgl_useCaseChoice(&C_Monero_64px,
                       "Export\nview key",
                       "",
                       "Accept", 
                       "Reject if not sure", 
                       ui_menu_export_viewkey_action);
}

/* --------------------------------- MAIN UX --------------------------------- */
#define STR(x)  #x
#define XSTR(x) STR(x)

#define PAGE_START 0
#define NB_PAGE_SETTING 3
#define IS_TOUCHABLE true

enum {
   ACCOUNT_TOKEN  = FIRST_USER_TOKEN,
   NETWORK_TOKEN,
   RESET_TOKEN,
   ACCOUNT_CHOICE,
   ACCOUNT_CHOICE_2,
   NETWORK_CHOICE
};

enum {
    MAIN_NET,
    STAGE_NET,
    TEST_NET,
    MAX_NET
};

static const char* const infoTypes[] = {"Spec", "Version", "Developer", "Copyright"};
static const char* const infoContents[] = {XSTR(SPEC_VERSION), APPVERSION, "Ledger", "(c) 2022 Ledger"};

static const char* const barTexts[] = {"Select Account", "Select Network", "Reset"};
static const uint8_t const tokens[] = {ACCOUNT_TOKEN, NETWORK_TOKEN, RESET_TOKEN};

static const char* const accountNames[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
#ifdef MONERO_ALPHA
static const char* const networkNames[] = {"Unavailable", "Stage network", "Test network"};
#else
static const char* const networkNames[] = {"Main network", "Stage network", "Test network"};
#endif

static void exit(void) {
    os_sched_exit(-1);
}

static bool settings_navigation_cb(uint8_t page, nbgl_pageContent_t *content) {
    if (page == 0) {
        content->type = BARS_LIST;
        content->barsList.barTexts = (const char**) barTexts;
        content->barsList.tokens = (uint8_t*) tokens;
        content->barsList.nbBars = 3;
        content->barsList.tuneId = TUNE_TAP_CASUAL;
    }
    else if (page == 1) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = 3;
        content->infosList.infoTypes = (const char**) infoTypes;
        content->infosList.infoContents = (const char**) infoContents;
    }
    else if (page == 2) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = 1;
        content->infosList.infoTypes = (const char**) infoTypes + 3;
        content->infosList.infoContents = (const char**) infoContents + 3;
    }
    else {
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
    nbgl_useCaseStatus("ACCOUNT INFOS\nRESET", true, ui_menu_main_display);
}
 
static void settings_control_cb(int token, uint8_t index) {
    UNUSED(index);
    switch(token)
    {
        case ACCOUNT_TOKEN:
            transactionContext.nav.activePage = index;
            transactionContext.nav.nbPages = 2;
            transactionContext.nav.navType = NAV_WITH_BUTTONS;
            transactionContext.nav.progressIndicator = false;
            transactionContext.nav.tuneId = NBGL_NO_TUNE;
            transactionContext.nav.navWithButtons.quitButton = false;
            transactionContext.nav.navWithButtons.navToken = ACCOUNT_TOKEN;

            transactionContext.content.type = CHOICES_LIST;
            if (index == 0) {
                transactionContext.content.choicesList.names = accountNames;
                transactionContext.content.choicesList.token = ACCOUNT_CHOICE;
            }
            else if (index == 1) {
                transactionContext.content.choicesList.names = accountNames + 5;
                transactionContext.content.choicesList.token = ACCOUNT_CHOICE_2;
            }
            transactionContext.content.choicesList.localized = false;
            transactionContext.content.choicesList.nbChoices = 5;
            transactionContext.content.choicesList.initChoice = N_monero_pstate->account_id;
            transactionContext.content.choicesList.tuneId = TUNE_TAP_CASUAL;
            nbgl_pageDrawGenericContent(settings_control_cb, &transactionContext.nav, &transactionContext.content);
            nbgl_refresh();
            break;

        case ACCOUNT_CHOICE_2:
            index = index + 5;
            // fallthrough
        case ACCOUNT_CHOICE:
            if (index <= 9) {
                monero_nvm_write((void*)&N_monero_pstate->account_id, &index, sizeof(uint8_t));
                monero_init();
            }
            ui_menu_main_display(0);
            break;

        case NETWORK_TOKEN:
            transactionContext.content.type = CHOICES_LIST;
            transactionContext.content.choicesList.names = networkNames;
            transactionContext.content.choicesList.localized = false;
            transactionContext.content.choicesList.nbChoices = 3;
            if (N_monero_pstate->network_id == MAINNET) {
                transactionContext.content.choicesList.initChoice = MAIN_NET;
            }
            else if (N_monero_pstate->network_id == TESTNET) {
                transactionContext.content.choicesList.initChoice = TEST_NET;
            }
            else if (N_monero_pstate->network_id == STAGENET) {
                transactionContext.content.choicesList.initChoice = STAGE_NET;
            }
            transactionContext.content.choicesList.token = NETWORK_CHOICE;
            transactionContext.content.choicesList.tuneId = TUNE_TAP_CASUAL;
            nbgl_pageDrawGenericContent(settings_control_cb, NULL, &transactionContext.content);
            nbgl_refresh();
            break;

        case NETWORK_CHOICE:
#ifdef MONERO_ALPHA 
            if (index == 0) {
                ui_menu_main_display(0);
            }
            else
#endif
            if (index < MAX_NET) {
                if (index == MAIN_NET) {
                    monero_install(MAINNET);
                }
                else if (index == TEST_NET) {
                    monero_install(TESTNET);
                }
                else if (index == STAGE_NET) {
                    monero_install(STAGENET);
                }
                monero_init();
            }
            ui_menu_main_display(0);
            break;

        case RESET_TOKEN:
            nbgl_useCaseConfirm("Reset account\ninformations ?", "", "Yes, Reset", "Go back", resetCallback);
            break;

        default:
            PRINTF("Should not happen !");
            break;
    }
}

static void display_settings_menu(void) {
  nbgl_useCaseSettings("Monero settings", PAGE_START, NB_PAGE_SETTING, IS_TOUCHABLE, ui_menu_main_display, 
          settings_navigation_cb, settings_control_cb);
}

void ui_menu_main_display(unsigned int value __attribute__((unused))) {
    update_account();

    memset(G_monero_vstate.ux_address, 0, sizeof(G_monero_vstate.ux_address));

    snprintf(transactionContext.buffer, 20, "Show %s", G_monero_vstate.ux_wallet_account_name);

    monero_base58_public_key(G_monero_vstate.ux_address, G_monero_vstate.A, G_monero_vstate.B, 0,
                             NULL);

    nbgl_useCaseHomeExt("Monero", &C_Monero_64px, NULL, true, transactionContext.buffer, display_account, display_settings_menu, exit);
}



/* --- INIT --- */

void ui_init(void) {
    ui_menu_main_display(0);
}

void io_seproxyhal_display(void) {
    io_seproxyhal_display_default();
}

#endif

