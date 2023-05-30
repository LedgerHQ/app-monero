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

#if defined(UI_STAX)

#include "os.h"
#include "ux.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "monero_ux_msg.h"
#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"

#include "nbgl_use_case.h"

#define QUIT_TOKEN     0
#define CONTINUE_TOKEN 1
/* ----------------------------------------------------------------------- */
/* ---                         Stax  UI layout                         --- */
/* ----------------------------------------------------------------------- */

typedef struct {
    nbgl_layoutTagValue_t tagValuePair[6];
    nbgl_layoutTagValueList_t tagValueList;
    nbgl_pageInfoLongPress_t infoLongPress;
    char timelockBuffer[23];
    char feeBuffer[23];
    char changeBuffer[23];
    nbgl_pageContent_t content;
    nbgl_pageNavigationInfo_t nav;
} TransactionContext_t;

static TransactionContext_t transactionContext;
static nbgl_page_t* pageContext;

static void release_context(void) {
    if (pageContext != NULL) {
        nbgl_pageRelease(pageContext);
        pageContext = NULL;
    }
}

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
    ui_menu_main_display();
}

/* -------------------------------- INFO UX --------------------------------- */

static void ui_menu_info_action(void) {
    if (G_monero_vstate.protocol_barrier == PROTOCOL_LOCKED) {
        ui_menu_pinlock_display();
    } else {
        ui_menu_main_display();
    }
}

void ui_menu_show_tx_aborted(void) {
    nbgl_useCaseStatus("Transaction\ncancelled", false, ui_menu_info_action);
}

void ui_menu_show_security_error(void) {
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
    nbgl_useCaseConfirm("Reject transaction?", "", "Yes, Reject", "Go back to transaction",
                        ui_menu_validation_action_cancel);
}

static void ui_menu_validation_action(bool value) {
    if (value) {
        transactionContext.tagValueList.nbPairs = 0;
        ui_menu_validation_action_confirm();
    } else {
        ui_menu_validation_action_cancel_prompt();
    }
}

unsigned int ui_menu_transaction_start(void) {
    transactionContext.tagValueList.nbPairs = 0;
    nbgl_useCaseReviewStart(&C_Monero_64px, "Review Transaction\nto send Monero", "",
                            "Reject transaction", ui_menu_validation_action_confirm,
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
    } else {
        nbgl_useCaseSpinner("Preparing TX");
    }
}

/* ----------------- FEE/CHANGE/TIMELOCK VALIDATION ----------------- */

void ui_menu_fee_validation_display(unsigned int value __attribute__((unused))) {
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    strncpy(transactionContext.feeBuffer, G_monero_vstate.ux_amount,
            sizeof(transactionContext.feeBuffer));

    transactionContext.tagValuePair[nbPairs].item = "Fee";
    transactionContext.tagValuePair[nbPairs].value = transactionContext.feeBuffer;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs++;

    ui_menu_validation_action_confirm();
}

void ui_menu_change_validation_display(unsigned int value __attribute__((unused))) {
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    strncpy(transactionContext.changeBuffer, G_monero_vstate.ux_amount,
            sizeof(transactionContext.changeBuffer));

    transactionContext.tagValuePair[nbPairs].item = "Change";
    transactionContext.tagValuePair[nbPairs].value = transactionContext.changeBuffer;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs++;

    ui_menu_validation_action_confirm();
}

void ui_menu_change_validation_display_last(unsigned int value __attribute__((unused))) {
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    strncpy(transactionContext.changeBuffer, G_monero_vstate.ux_amount,
            sizeof(transactionContext.changeBuffer));

    transactionContext.tagValuePair[nbPairs].item = "Change";
    transactionContext.tagValuePair[nbPairs].value = transactionContext.changeBuffer;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs++;

    transactionContext.infoLongPress.icon = &C_Monero_64px;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = 0;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = "Hold to confirm";

    nbgl_useCaseStaticReview(&transactionContext.tagValueList, &transactionContext.infoLongPress,
                             "Cancel", ui_menu_validation_action);
}

static void timelock_callback(void) {
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    strncpy(transactionContext.timelockBuffer, G_monero_vstate.ux_amount,
            sizeof(transactionContext.timelockBuffer));

    transactionContext.tagValuePair[nbPairs].item = "Timelock";
    transactionContext.tagValuePair[nbPairs].value = transactionContext.timelockBuffer;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
    transactionContext.tagValueList.nbPairs++;

    ui_menu_validation_action_confirm();
}

void ui_menu_timelock_validation_display(unsigned int value __attribute__((unused))) {
    transactionContext.tagValueList.nbPairs = 0;

    nbgl_useCaseReviewStart(&C_Monero_64px, "Review Transaction\nto send Monero", NULL,
                            "Reject transaction", timelock_callback,
                            ui_menu_validation_action_cancel_prompt);
}

/* ----------------------------- USER DEST/AMOUNT VALIDATION ----------------------------- */
static void fill_amount_and_destination(void) {
    transactionContext.tagValuePair[0].item = "Amount";
    transactionContext.tagValuePair[0].value = G_monero_vstate.ux_amount;

    transactionContext.tagValuePair[1].item = "Destination";
    transactionContext.tagValuePair[1].value = G_monero_vstate.ux_address;

    transactionContext.tagValueList.nbPairs = 2;
    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;
}

static void page_callback(int token, unsigned char index) {
    (void)index;
    release_context();

    ui_menu_validation_action(token);
}

static void continue_display(int token, unsigned char index) {
    (void)index;

    if (token == QUIT_TOKEN) {
        ui_menu_validation_action_cancel_prompt();
    }

    fill_amount_and_destination();

    nbgl_pageNavigationInfo_t info = {.activePage = 0,
                                      .nbPages = 0,
                                      .navType = NAV_WITH_TAP,
                                      .progressIndicator = true,
                                      .navWithTap.backButton = false,
                                      .navWithTap.nextPageText = "Tap to continue",
                                      .navWithTap.nextPageToken = CONTINUE_TOKEN,
                                      .navWithTap.quitText = "Cancel",
                                      .quitToken = QUIT_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {
        .type = TAG_VALUE_LIST,
        .tagValueList.nbPairs = transactionContext.tagValueList.nbPairs,
        .tagValueList.pairs = (nbgl_layoutTagValue_t*)transactionContext.tagValueList.pairs};

    pageContext = nbgl_pageDrawGenericContent(page_callback, &info, &content);
}

static void continue_display_last(int token, unsigned char index) {
    (void)index;

    if (token == QUIT_TOKEN) {
        ui_menu_validation_action_cancel_prompt();
    }

    fill_amount_and_destination();
    transactionContext.infoLongPress.icon = &C_Monero_64px;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = 0;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = "Hold to confirm";

    nbgl_useCaseStaticReview(&transactionContext.tagValueList, &transactionContext.infoLongPress,
                             "Cancel", ui_menu_validation_action);
}

static void display_previous_infos(bool last) {
    release_context();

    nbgl_pageNavigationInfo_t info = {.activePage = 0,
                                      .nbPages = 0,
                                      .navType = NAV_WITH_TAP,
                                      .progressIndicator = true,
                                      .navWithTap.backButton = false,
                                      .navWithTap.nextPageText = "Tap to continue",
                                      .navWithTap.nextPageToken = CONTINUE_TOKEN,
                                      .navWithTap.quitText = "Cancel",
                                      .quitToken = QUIT_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {
        .type = TAG_VALUE_LIST,
        .tagValueList.nbPairs = transactionContext.tagValueList.nbPairs,
        .tagValueList.pairs = (nbgl_layoutTagValue_t*)transactionContext.tagValueList.pairs};

    if (last) {
        pageContext = nbgl_pageDrawGenericContent(continue_display_last, &info, &content);
    } else {
        pageContext = nbgl_pageDrawGenericContent(continue_display, &info, &content);
    }
}

void ui_menu_validation_display(unsigned int value __attribute__((unused))) {
    const bool last = 0;
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    if (nbPairs > 0) {
        display_previous_infos(last);
    } else {
        continue_display(CONTINUE_TOKEN, 0);
    }
}

void ui_menu_validation_display_last(unsigned int value __attribute__((unused))) {
    const bool last = 1;
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    if (nbPairs > 0) {
        display_previous_infos(last);
    } else {
        continue_display_last(CONTINUE_TOKEN, 0);
    }
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

void ui_menu_pubaddr_action(bool confirm) {
    if (confirm) {
        if (G_monero_vstate.disp_addr_mode) {
            monero_io_insert_u16(SW_OK);
            monero_io_do(IO_RETURN_AFTER_TX);
        }
        G_monero_vstate.disp_addr_mode = 0;
        nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, ui_menu_main_display);
    } else {
        ui_menu_pubaddr_action_cancelled();
    }
}

void display_account(void) {
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

    nbgl_useCaseAddressConfirmationExt(G_monero_vstate.ux_address, ui_menu_pubaddr_action,
                                       &transactionContext.tagValueList);
}

void ui_menu_any_pubaddr_display(unsigned int value __attribute__((unused)),
                                 unsigned char* pub_view, unsigned char* pub_spend,
                                 unsigned char is_subbadress, unsigned char* paymanetID) {
    memset(G_monero_vstate.ux_address, 0, sizeof(G_monero_vstate.ux_address));

    monero_base58_public_key(G_monero_vstate.ux_address, pub_view, pub_spend, is_subbadress,
                             paymanetID);

    nbgl_useCaseReviewStart(&C_Monero_64px, "Review Address", "", "Cancel", display_account,
                            ui_menu_pubaddr_action_cancelled);
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
    nbgl_useCaseStatus("VIEW KEY\nEXPORTED", true, ui_menu_main_display);
}

void ui_export_viewkey_display(unsigned int value __attribute__((unused))) {
    nbgl_useCaseChoice(&C_Monero_64px, "Export\nview key", "", "Accept", "Reject if not sure",
                       ui_menu_export_viewkey_action);
}

#endif
