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
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"

#include "nbgl_use_case.h"

#define QUIT_TOKEN     0
#define CONTINUE_TOKEN 1
/* ----------------------------------------------------------------------- */
/* ---                         Stax  UI layout                         --- */
/* ----------------------------------------------------------------------- */
#define MAX_TAGVALUE_NUMBER 9
#define MAX_AMOUNT_NUMBER   6
#define MAX_ADDR_NUMBER     3  //  MAX_AMOUNT_NUMBER - timelock - fee - change

typedef struct {
    nbgl_contentTagValue_t tagValuePair[MAX_TAGVALUE_NUMBER];
    nbgl_contentTagValueList_t tagValueList;
    nbgl_pageInfoLongPress_t infoLongPress;
    char amountBuffer[MAX_AMOUNT_NUMBER][MAX_AMOUNT_LENGTH];
    uint32_t amountNum;
    char dstBuffer[MAX_ADDR_NUMBER][MAX_ADDR_LENGTH];
    uint32_t addrNum;
    nbgl_pageContent_t content;
    nbgl_pageNavigationInfo_t nav;
} TransactionContext_t;

static TransactionContext_t transactionContext;

/* -------------------------------- TITLES ---------------------------------- */
const char feeTitle[] = "Fee";
const char changeTitle[] = "Change";
const char amountTitle[] = "Amount";
const char dstTitle[] = "Destination";
const char timelockTitle[] = "Timelock";

/* ------------------------------ STATIC HELPERS ---------------------------- */
static void reset_context(void) {
    transactionContext.tagValueList.nbPairs = 0;
    transactionContext.amountNum = 0;
    transactionContext.addrNum = 0;
}

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

static void ui_menu_validation_action(bool value) {
    if (value) {
        reset_context();
        ui_menu_validation_action_confirm();
    } else {
        ui_menu_validation_action_cancel();
    }
}

static void add_amount(const char* title, bool forcePageStart) {
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;
    if ((transactionContext.amountNum >= MAX_AMOUNT_NUMBER) || (nbPairs >= MAX_TAGVALUE_NUMBER)) {
        ui_menu_validation_action_cancel();
        return;
    }

    strncpy(transactionContext.amountBuffer[transactionContext.amountNum],
            G_monero_vstate.ux_amount, MAX_AMOUNT_LENGTH);

    transactionContext.tagValuePair[nbPairs].item = title;
    transactionContext.tagValuePair[nbPairs].value =
        transactionContext.amountBuffer[transactionContext.amountNum];
    if (forcePageStart) transactionContext.tagValuePair[nbPairs].forcePageStart = 1;

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    transactionContext.tagValueList.nbPairs++;
    transactionContext.amountNum++;
}

static void add_address(void) {
    uint8_t nbPairs = transactionContext.tagValueList.nbPairs;

    if ((transactionContext.addrNum >= MAX_ADDR_NUMBER) || (nbPairs >= MAX_TAGVALUE_NUMBER)) {
        ui_menu_validation_action_cancel();
        return;
    }

    strncpy(transactionContext.dstBuffer[transactionContext.addrNum], G_monero_vstate.ux_address,
            MAX_ADDR_LENGTH);

    transactionContext.tagValuePair[nbPairs].item = dstTitle;
    transactionContext.tagValuePair[nbPairs].value =
        transactionContext.dstBuffer[transactionContext.addrNum];

    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    transactionContext.tagValueList.nbPairs++;
    transactionContext.addrNum++;
}

/* ------------------------------- OPEN TX UX ------------------------------- */

unsigned int ui_menu_transaction_start(void) {
    reset_context();
    return SW_OK;
}

unsigned int ui_menu_transaction_signed(void) {
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main_display);
    return 0;
}

void ui_menu_opentx_display(unsigned int value __attribute__((unused))) {
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        nbgl_useCaseSpinner("Processing TX");
    } else {
        nbgl_useCaseSpinner("Preparing TX");
    }
}

/* -------------------------------- INFO UX --------------------------------- */

void ui_menu_show_tx_aborted(void) {
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main_display);
}

/* --------------------- FEE/CHANGE/TIMELOCK VALIDATION --------------------- */

static void start_signature(void) {
    nbgl_useCaseReview(TYPE_TRANSACTION, &transactionContext.tagValueList, &C_Monero_64px,
                       "Review Transaction\nto send Monero", NULL, "Sign transaction?",
                       ui_menu_validation_action);
}

void ui_menu_fee_validation_display(unsigned int value __attribute__((unused))) {
    add_amount(feeTitle, false);
    ui_menu_validation_action_confirm();
}

void ui_menu_change_validation_display(unsigned int value __attribute__((unused))) {
    add_amount(changeTitle, false);
    ui_menu_validation_action_confirm();
}

void ui_menu_change_validation_display_last(unsigned int value __attribute__((unused))) {
    add_amount(changeTitle, true);
    start_signature();
}

void ui_menu_timelock_validation_display(unsigned int value __attribute__((unused))) {
    reset_context();
    if (transactionContext.addrNum == 0) {
        /* If no yet receivers addresses let us add the change on the same page */
        add_amount(timelockTitle, false);
    } else {
        /* In the other case let us for new page */
        add_amount(timelockTitle, true);
    }
    ui_menu_validation_action_confirm();
}

/* ---------------------- USER DEST/AMOUNT VALIDATION ----------------------- */

void ui_menu_validation_display(unsigned int value __attribute__((unused))) {
    add_amount(amountTitle, true);
    add_address();
    ui_menu_validation_action_confirm();
}

void ui_menu_validation_display_last(unsigned int value __attribute__((unused))) {
    add_amount(amountTitle, true);
    add_address();
    start_signature();
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
    nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main_display);
}

void ui_menu_pubaddr_action(bool confirm) {
    if (confirm) {
        if (G_monero_vstate.disp_addr_mode) {
            monero_io_insert_u16(SW_OK);
            monero_io_do(IO_RETURN_AFTER_TX);
        }
        G_monero_vstate.disp_addr_mode = 0;
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main_display);
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

    nbgl_useCaseAddressReview(G_monero_vstate.ux_address, &transactionContext.tagValueList,
                              &C_Monero_64px, "Verify Monero\naddress", NULL,
                              ui_menu_pubaddr_action);
}

int ui_menu_any_pubaddr_display(unsigned int value __attribute__((unused)), unsigned char* pub_view,
                                unsigned char* pub_spend, unsigned char is_subbadress,
                                unsigned char* paymanetID) {
    int error;
    explicit_bzero(G_monero_vstate.ux_address, sizeof(G_monero_vstate.ux_address));

    error = monero_base58_public_key(G_monero_vstate.ux_address, pub_view, pub_spend, is_subbadress,
                                     paymanetID);
    if (error) {
        return error;
    }

    display_account();

    return 0;
}

/* -------------------------- EXPORT VIEW KEY UX ---------------------------- */

static void ui_menu_export_viewkey_action(bool value) {
    unsigned int sw;
    const char* exp_msg = "VIEW KEY\nEXPORTED";
    const char* rej_msg = "THE EXPORT IS\nREJECTED";
    const char* set_msg = NULL;

    monero_io_discard(0);

    if (value) {
        sw = SW_OK;
        monero_io_insert(G_monero_vstate.a, KEY_SIZE);
        set_msg = exp_msg;

    } else {
        sw = SW_DENY;
        set_msg = rej_msg;
    }

    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    nbgl_useCaseStatus(set_msg, true, ui_menu_main_display);
}

void ui_export_viewkey_display(unsigned int value __attribute__((unused))) {
    nbgl_useCaseChoice(&C_Monero_64px, "Export\nview key", "", "Accept", "Reject if not sure",
                       ui_menu_export_viewkey_action);
}

#endif
