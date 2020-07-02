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

#if defined(UI_NANO_X) || defined(UI_NANO_SX)

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "monero_ux_msg.h"
#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"

/* ----------------------------------------------------------------------- */
/* ---                        NanoX  UI layout                         --- */
/* ----------------------------------------------------------------------- */

#define ACCEPT 0xACCE
#define REJECT ~ACCEPT

void ui_menu_main_display(unsigned int value);

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

/* -------------------------------------- 25 WORDS --------------------------------------- */
void ui_menu_words_display(unsigned int value);
void ui_menu_words_clear(unsigned int value);
void ui_menu_words_back(unsigned int value);

UX_STEP_NOCB(ux_menu_words_1_step,
#ifdef UI_NANO_X
             bnnn_paging,
#else
             bn_paging,
#endif
             {
                 .title = "Electrum Seed",
                 .text = "NOTSET",
             });

UX_STEP_CB(ux_menu_words_2_step, bn, ui_menu_words_clear(0),
           {"CLEAR WORDS", "(Do not wipe the wallet)"});

UX_STEP_CB(ux_menu_words_3_step, pb, ui_menu_words_back(0), {&C_icon_back, "back"});

UX_FLOW(ux_flow_words, &ux_menu_words_1_step, &ux_menu_words_2_step, &ux_menu_words_3_step);

void ui_menu_words_clear(unsigned int value) {
    monero_clear_words();
    ui_menu_main_display(0);
}

void ui_menu_words_back(unsigned int value) { ui_menu_main_display(1); }

void ui_menu_words_display(unsigned int value) { ux_flow_init(0, ux_flow_words, NULL); }

void settings_show_25_words(void) { ui_menu_words_display(0); }
/* -------------------------------- INFO UX --------------------------------- */
unsigned int ui_menu_info_action(unsigned int value);

UX_STEP_CB(ux_menu_info_1_step, nn, ui_menu_info_action(0),
           {
               G_monero_vstate.ux_info1,
               G_monero_vstate.ux_info2,
           });

UX_FLOW(ux_flow_info, &ux_menu_info_1_step);

unsigned int ui_menu_info_action(unsigned int value) {
    if (G_monero_vstate.protocol_barrier == PROTOCOL_LOCKED) {
        ui_menu_pinlock_display();
    } else {
        ui_menu_main_display(0);
    }
    return 0;
}

void ui_menu_info_display2(unsigned int value, char* line1, char* line2) {
    snprintf(G_monero_vstate.ux_info1, sizeof(G_monero_vstate.ux_info1), "%s", line1);
    snprintf(G_monero_vstate.ux_info2, sizeof(G_monero_vstate.ux_info2), "%s", line2);
    ux_flow_init(0, ux_flow_info, NULL);
}

void ui_menu_info_display(unsigned int value) { ux_flow_init(0, ux_flow_info, NULL); }

/* -------------------------------- OPEN TX UX --------------------------------- */
unsigned int ui_menu_opentx_action(unsigned int value);

UX_STEP_NOCB(ux_menu_opentx_1_step, nn, {"Process", "new TX ?"});

UX_STEP_CB(ux_menu_opentx_2_step, pb, ui_menu_opentx_action(ACCEPT), {&C_icon_validate_14, "Yes"});

UX_STEP_CB(ux_menu_opentx_3_step, pb, ui_menu_opentx_action(REJECT), {&C_icon_crossmark, "No!"});

UX_FLOW(ux_flow_opentx, &ux_menu_opentx_1_step, &ux_menu_opentx_2_step, &ux_menu_opentx_3_step);

unsigned int ui_menu_opentx_action(unsigned int value) {
    unsigned int sw;
    unsigned char x[32];

    monero_io_discard(0);
    os_memset(x, 0, 32);
    sw = SW_OK;

    if (value == ACCEPT) {
        sw = monero_apdu_open_tx_cont();
        ui_menu_info_display2(0, "Processing TX", "...");
    } else {
        monero_abort_tx(0);
        sw = SW_DENY;
        ui_menu_info_display2(0, "Tansaction", "aborted");
    }
    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    return 0;
}

#if 0
void ui_menu_opentx_display(unsigned int value) {
  if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
    ux_flow_init(0, ux_flow_opentx,NULL);
  } else {
    snprintf(G_monero_vstate.ux_info1, sizeof(G_monero_vstate.ux_info1), "Prepare new");
    snprintf(G_monero_vstate.ux_info2, sizeof(G_monero_vstate.ux_info2), "TX / %d", G_monero_vstate.tx_cnt);
    ui_menu_info_display(0);
  }
}
#else
void ui_menu_opentx_display(unsigned int value) {
    uint32_t i;
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        snprintf(G_monero_vstate.ux_info1, sizeof(G_monero_vstate.ux_info1), "Processing TX");
    } else {
        snprintf(G_monero_vstate.ux_info1, sizeof(G_monero_vstate.ux_info1), "Preparing TX");
    }
    for (i = 0; (i < G_monero_vstate.tx_cnt) && (i < 12); i++) {
        G_monero_vstate.ux_info2[i] = '.';
    }
    G_monero_vstate.ux_info2[i] = 0;
    ui_menu_info_display(0);
}
#endif

/* ----------------- FEE/CHANGE/TIMELOCK VALIDATION ----------------- */

void ui_menu_amount_validation_action(unsigned int value);

UX_STEP_NOCB(ux_menu_validation_fee_1_step, bn,
             {
                 "Fee",
                 G_monero_vstate.ux_amount,
             });

UX_STEP_NOCB(ux_menu_validation_change_1_step, bn,
             {
                 "Change",
                 G_monero_vstate.ux_amount,
             });

UX_STEP_NOCB(ux_menu_validation_timelock_1_step, bn,
             {
                 "Timelock",
                 G_monero_vstate.ux_amount,
             });

UX_STEP_CB(ux_menu_validation_cf_2_step, pb, ui_menu_amount_validation_action(ACCEPT),
           {
               &C_icon_validate_14,
               "Accept",
           });

UX_STEP_CB(ux_menu_validation_cf_3_step, pb, ui_menu_amount_validation_action(REJECT),
           {
               &C_icon_crossmark,
               "Reject",
           });

UX_FLOW(ux_flow_fee, &ux_menu_validation_fee_1_step, &ux_menu_validation_cf_2_step,
        &ux_menu_validation_cf_3_step);

UX_FLOW(ux_flow_change, &ux_menu_validation_change_1_step, &ux_menu_validation_cf_2_step,
        &ux_menu_validation_cf_3_step);

UX_FLOW(ux_flow_timelock, &ux_menu_validation_timelock_1_step, &ux_menu_validation_cf_2_step,
        &ux_menu_validation_cf_3_step);

void ui_menu_amount_validation_action(unsigned int value) {
    unsigned short sw;
    if (value == ACCEPT) {
        sw = SW_OK;
    } else {
        monero_abort_tx(0);
        sw = SW_DENY;
    }
    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    ui_menu_info_display2(0, "Processing TX", "...");
}

void ui_menu_fee_validation_display(unsigned int value) { ux_flow_init(0, ux_flow_fee, NULL); }

void ui_menu_change_validation_display(unsigned int value) {
    ux_flow_init(0, ux_flow_change, NULL);
}

void ui_menu_timelock_validation_display(unsigned int value) {
    ux_flow_init(0, ux_flow_timelock, NULL);
}
/* ----------------------------- USER DEST/AMOUNT VALIDATION ----------------------------- */
void ui_menu_validation_action(unsigned int value);

UX_STEP_NOCB(ux_menu_validation_1_step, bn, {"Amout", G_monero_vstate.ux_amount});

UX_STEP_NOCB(ux_menu_validation_2_step,
#ifdef UI_NANO_X
             bnnn_paging,
#else
             bn_paging,
#endif
             {"Destination", G_monero_vstate.ux_address});

UX_STEP_CB(ux_menu_validation_3_step, pb, ui_menu_validation_action(ACCEPT),
           {&C_icon_validate_14, "Accept"});

UX_STEP_CB(ux_menu_validation_4_step, pb, ui_menu_validation_action(REJECT),
           {&C_icon_crossmark, "Reject"});

UX_FLOW(ux_flow_validation, &ux_menu_validation_1_step, &ux_menu_validation_2_step,
        &ux_menu_validation_3_step, &ux_menu_validation_4_step);

void ui_menu_validation_display(unsigned int value) { ux_flow_init(0, ux_flow_validation, NULL); }

void ui_menu_validation_action(unsigned int value) {
    unsigned short sw;
    if (value == ACCEPT) {
        sw = SW_OK;
    } else {
        monero_abort_tx(0);
        sw = SW_DENY;
    }
    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    ui_menu_info_display2(0, "Processing TX", "...");
}

/* -------------------------------- EXPORT VIEW KEY UX --------------------------------- */
unsigned int ui_menu_export_viewkey_action(unsigned int value);

UX_STEP_NOCB(ux_menu_export_viewkey_1_step, nn, {"Export", "View Key"});

UX_STEP_CB(ux_menu_export_viewkey_2_step, pb, ui_menu_export_viewkey_action(ACCEPT),
           {&C_icon_validate_14, "Accept"});

UX_STEP_CB(ux_menu_export_viewkey_3_step, pb, ui_menu_export_viewkey_action(REJECT),
           {&C_icon_crossmark, "Reject"});

UX_FLOW(ux_flow_export_viewkey, &ux_menu_export_viewkey_1_step, &ux_menu_export_viewkey_2_step,
        &ux_menu_export_viewkey_3_step);

void ui_export_viewkey_display(unsigned int value) {
    ux_flow_init(0, ux_flow_export_viewkey, NULL);
}

unsigned int ui_menu_export_viewkey_action(unsigned int value) {
    unsigned int sw;
    unsigned char x[32];

    monero_io_discard(0);
    os_memset(x, 0, 32);
    sw = SW_OK;

    if (value == ACCEPT) {
        monero_io_insert(G_monero_vstate.a, 32);
        G_monero_vstate.export_view_key = EXPORT_VIEW_KEY;
    } else {
        monero_io_insert(x, 32);
        G_monero_vstate.export_view_key = 0;
    }
    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    return 0;
}

/* -------------------------------- ACCOUNT UX --------------------------------- */

const char* const account_submenu_getter_values[] = {"0", "1", "2", "3", "4",    "5",
                                                     "6", "7", "8", "9", "Abort"};
const char* const account_submenu_getter_values_selected[] = {
    "0 +", "1 +", "2 +", "3 +", "4 +", "5 +", "6 +", "7 +", "8 +", "9 +", "Abort"};

const char* account_submenu_getter(unsigned int idx) {
    if (idx >= ARRAYLEN(account_submenu_getter_values)) {
        return NULL;
    }
    if (N_monero_pstate->account_id == idx) {
        return account_submenu_getter_values_selected[idx];
    } else {
        return account_submenu_getter_values[idx];
    }
}

void account_back(void) { ui_menu_main_display(0); }

void account_submenu_selector(unsigned int idx) {
    if (idx <= 9) {
        monero_nvm_write((void*)&N_monero_pstate->account_id, &idx, sizeof(unsigned int));
        monero_init();
    }
    ui_menu_main_display(0);
}

void ui_menu_account_display(unsigned int value) {
    ux_menulist_init(G_ux.stack_count - 1, account_submenu_getter, account_submenu_selector);
}

void settings_change_account(void) { ui_menu_account_display(0); }

/* -------------------------------- NETWORK UX --------------------------------- */

const char* const network_submenu_getter_values[] = {
#ifdef MONERO_ALPHA
    "Unvailable",
#else
    "Main Network",
#endif
    "Stage Network", "Test Network", "Abort"};
const char* const network_submenu_getter_values_selected[] = {
#ifdef MONERO_ALPHA
    "Unvailable",
#else
    "Main Network +",
#endif
    "Stage Network +", "Test Network +", "Abort"};

const char* network_submenu_getter(unsigned int idx) {
    if (idx >= ARRAYLEN(network_submenu_getter_values)) {
        return NULL;
    }
    int net;
    switch (idx) {
        case 0:
#ifdef MONERO_ALPHA
            net = -1;
#else
            net = MAINNET;
#endif
            break;
        case 1:
            net = STAGENET;
            break;
        case 2:
            net = TESTNET;
            break;
        default:
            net = -1;
            break;
    }
    if (N_monero_pstate->network_id == net) {
        return network_submenu_getter_values_selected[idx];
    } else {
        return network_submenu_getter_values[idx];
    }
}

void network_back(void) { ui_menu_main_display(0); }

static void network_set_net(unsigned int network) {
    monero_install(network);
    monero_init();
}

void network_submenu_selector(unsigned int idx) {
    switch (idx) {
        case 0:
#ifndef MONERO_ALPHA
            network_set_net(MAINNET);
#endif
            break;
        case 1:
            network_set_net(STAGENET);
            break;
        case 2:
            network_set_net(TESTNET);
            break;
        default:
            break;
    }
    ui_menu_main_display(0);
}

void ui_menu_network_display(unsigned int value) {
    ux_menulist_init(G_ux.stack_count - 1, network_submenu_getter, network_submenu_selector);
}

void settings_change_network(void) { ui_menu_network_display(0); }
/* -------------------------------- RESET UX --------------------------------- */
void ui_menu_reset_display(unsigned int value);
void ui_menu_reset_action(unsigned int value);

UX_STEP_NOCB(ux_menu_reset_1_step, nn,
             {
                 "",
                 "Really Reset?",
             });

UX_STEP_CB(ux_menu_reset_2_step, pb, ui_menu_reset_action(REJECT),
           {
               &C_icon_crossmark,
               "No",
           });

UX_STEP_CB(ux_menu_reset_3_step, pb, ui_menu_reset_action(ACCEPT),
           {
               &C_icon_validate_14,
               "Yes",
           });

UX_FLOW(ux_flow_reset, &ux_menu_reset_1_step, &ux_menu_reset_2_step, &ux_menu_reset_3_step);

void ui_menu_reset_display(unsigned int value) { ux_flow_init(0, ux_flow_reset, 0); }

void settings_reset(void) { ui_menu_reset_display(0); }

void ui_menu_reset_action(unsigned int value) {
    if (value == ACCEPT) {
        unsigned char magic[4];
        magic[0] = 0;
        magic[1] = 0;
        magic[2] = 0;
        magic[3] = 0;
        monero_nvm_write((void*)N_monero_pstate->magic, magic, 4);
        monero_init();
    }
    ui_menu_main_display(0);
}
/* ------------------------------- SETTINGS UX ------------------------------- */

const char* const settings_submenu_getter_values[] = {
    "Select Account", "Select Network", "Show 25 words", "Reset", "Back",
};

const char* settings_submenu_getter(unsigned int idx) {
    if (idx < ARRAYLEN(settings_submenu_getter_values)) {
        return settings_submenu_getter_values[idx];
    }
    return NULL;
}

void settings_back(void) { ui_menu_main_display(0); }

void settings_submenu_selector(unsigned int idx) {
    switch (idx) {
        case 0:
            settings_change_account();
            break;
        case 1:
            settings_change_network();
            break;
        case 2:
            settings_show_25_words();
            break;
        case 3:
            settings_reset();
            break;
        default:
            settings_back();
    }
}

/* --------------------------------- ABOUT UX --------------------------------- */
#define STR(x)  #x
#define XSTR(x) STR(x)

#ifdef UI_NANO_X
UX_STEP_NOCB(ux_menu_about_1_step, bnnn,
             {
                 "Monero",
                 "(c) Ledger SAS",
                 "Spec  " XSTR(SPEC_VERSION),
                 "App  " XSTR(MONERO_VERSION),
             });
#else
UX_STEP_NOCB(ux_menu_about_1a_step, bn,
             {
                 "Monero",
                 "(c) Ledger SAS",
             });

UX_STEP_NOCB(ux_menu_about_1b_step, nn,
             {
                 "Spec  " XSTR(SPEC_VERSION),
                 "App  " XSTR(MONERO_VERSION),
             });

#endif

UX_STEP_CB(ux_menu_about_2_step, pb, ui_menu_main_display(0),
           {
               &C_icon_back,
               "Back",
           });

UX_FLOW(ux_flow_about,
#ifdef UI_NANO_X
        &ux_menu_about_1_step,
#else
        &ux_menu_about_1a_step, &ux_menu_about_1b_step,
#endif
        &ux_menu_about_2_step);

void ui_menu_about_display(unsigned int value) { ux_flow_init(0, ux_flow_about, NULL); }

#undef STR
#undef XSTR

/* ---------------------------- PUBLIC ADDRESS UX ---------------------------- */
void ui_menu_pubaddr_action(unsigned int value);

#define ADDR_TYPE  G_monero_vstate.ux_address + 108
#define ADDR_MAJOR G_monero_vstate.ux_address + 124
#define ADDR_MINOR G_monero_vstate.ux_address + 140
#define ADDR_IDSTR G_monero_vstate.ux_address + 124
#define ADDR_ID    G_monero_vstate.ux_address + 140

UX_STEP_NOCB(ux_menu_pubaddr_01_step, nn,
             {
                 ADDR_TYPE,
                 "Address",
             });

UX_STEP_NOCB(ux_menu_pubaddr_02_step, nn,
             {
                 ADDR_MAJOR,
                 ADDR_MINOR,
             });

UX_STEP_NOCB(ux_menu_pubaddr_1_step, bnnn_paging,
             {.title = "Address", .text = G_monero_vstate.ux_address});

UX_STEP_CB(ux_menu_pubaddr_2_step, pb, ui_menu_pubaddr_action(0), {&C_icon_back, "Ok"});

UX_FLOW(ux_flow_pubaddr, &ux_menu_pubaddr_01_step, &ux_menu_pubaddr_02_step,
        &ux_menu_pubaddr_1_step, &ux_menu_pubaddr_2_step);

void ui_menu_pubaddr_action(unsigned int value) {
    if (G_monero_vstate.disp_addr_mode) {
        monero_io_insert_u16(SW_OK);
        monero_io_do(IO_RETURN_AFTER_TX);
    }
    G_monero_vstate.disp_addr_mode = 0;
    ui_menu_main_display(0);
}

/**
 *
 */
void ui_menu_any_pubaddr_display(unsigned int value, unsigned char* pub_view,
                                 unsigned char* pub_spend, unsigned char is_subbadress,
                                 unsigned char* paymanetID) {
    memset(G_monero_vstate.ux_address, 0, sizeof(G_monero_vstate.ux_address));

    switch (G_monero_vstate.disp_addr_mode) {
        case 0:
        case DISP_MAIN:
            os_memmove(ADDR_TYPE, "Main", 4);
            os_memmove(ADDR_MAJOR, "Major: 0", 8);
            os_memmove(ADDR_MINOR, "minor: 0", 8);
            break;

        case DISP_SUB:
            os_memmove(ADDR_TYPE, "Sub", 3);
            snprintf(ADDR_MAJOR, 16, "Major: %d", G_monero_vstate.disp_addr_M);
            snprintf(ADDR_MINOR, 16, "minor: %d", G_monero_vstate.disp_addr_m);
            break;

        case DISP_INTEGRATED:
            os_memmove(ADDR_TYPE, "Integrated", 10);
            os_memmove(ADDR_IDSTR, "Payment ID", 10);
            os_memmove(ADDR_ID, G_monero_vstate.payment_id, 16);
            break;
    }

    monero_base58_public_key(G_monero_vstate.ux_address + strlen(G_monero_vstate.ux_address),
                             pub_view, pub_spend, is_subbadress, paymanetID);
    ux_layout_bnnn_paging_reset();
    ux_flow_init(0, ux_flow_pubaddr, NULL);
}

void ui_menu_pubaddr_display(unsigned int value) {
    G_monero_vstate.disp_addr_mode = 0;
    G_monero_vstate.disp_addr_M = 0;
    G_monero_vstate.disp_addr_M = 0;
    ui_menu_any_pubaddr_display(value, G_monero_vstate.A, G_monero_vstate.B, 0, NULL);
}

#undef ADDR_TYPE
#undef ADDR_MAJOR
#undef ADDR_MINOR
#undef ADDR_IDSTR
#undef ADDR_ID

/* --------------------------------- MAIN UX --------------------------------- */

UX_STEP_CB(ux_menu_main_1_step, pbb, ui_menu_pubaddr_display(0),
           {&C_icon_monero, G_monero_vstate.ux_wallet_account_name,
            G_monero_vstate.ux_wallet_public_short_address});

UX_STEP_CB(ux_menu_main_2_step, pb,
           ux_menulist_init(G_ux.stack_count - 1, settings_submenu_getter,
                            settings_submenu_selector),
           {&C_icon_coggle, "Settings"});

UX_STEP_CB(ux_menu_main_3_step, pb, ui_menu_about_display(0), {&C_icon_certificate, "About"});

UX_STEP_CB(ux_menu_main_4_step, pb, os_sched_exit(0), {&C_icon_dashboard_x, "Quit app"});

UX_FLOW(ux_flow_main, &ux_menu_main_1_step, &ux_menu_main_2_step, &ux_menu_main_3_step,
        &ux_menu_main_4_step);

void ui_menu_main_display(unsigned int value) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_flow_main, NULL);
}
/* --- INIT --- */

void ui_init(void) { ui_menu_main_display(0); }

void io_seproxyhal_display(const bagl_element_t* element) {
    io_seproxyhal_display_default((bagl_element_t*)element);
}

#endif
