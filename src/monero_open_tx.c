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

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_reset_tx(int reset_tx_cnt) {
    os_memset(G_monero_vstate.r, 0, 32);
    os_memset(G_monero_vstate.R, 0, 32);
    cx_rng(G_monero_vstate.hmac_key, 32);

    monero_keccak_init_H();
    monero_sha256_commitment_init();
    monero_sha256_outkeys_init();
    G_monero_vstate.tx_in_progress = 0;
    G_monero_vstate.tx_output_cnt = 0;
    if (reset_tx_cnt) {
        G_monero_vstate.tx_cnt = 0;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * HD wallet not yet supported : account is assumed to be zero
 */
int monero_apdu_open_tx() {
    unsigned int account;

    account = monero_io_fetch_u32();

    monero_io_discard(1);

    monero_reset_tx(0);
    G_monero_vstate.tx_cnt++;
    ui_menu_opentx_display(0);
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        // return 0;
    }
    return monero_apdu_open_tx_cont();
}

int monero_apdu_open_tx_cont() {
    G_monero_vstate.tx_in_progress = 1;

#ifdef DEBUG_HWDEVICE
    os_memset(G_monero_vstate.hmac_key, 0xab, 32);
#else
    cx_rng(G_monero_vstate.hmac_key, 32);
#endif

    monero_rng_mod_order(G_monero_vstate.r);
    monero_ecmul_G(G_monero_vstate.R, G_monero_vstate.r);

    monero_io_insert(G_monero_vstate.R, 32);
    monero_io_insert_encrypt(G_monero_vstate.r, 32, TYPE_SCALAR);
    monero_io_insert(C_FAKE_SEC_VIEW_KEY, 32);
    monero_io_insert_hmac_for((void*)C_FAKE_SEC_VIEW_KEY, 32, TYPE_SCALAR);
    monero_io_insert(C_FAKE_SEC_SPEND_KEY, 32);
    monero_io_insert_hmac_for((void*)C_FAKE_SEC_SPEND_KEY, 32, TYPE_SCALAR);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_close_tx() {
    monero_io_discard(1);
    monero_reset_tx(G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL);
    ui_menu_main_display(0);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_abort_tx() {
    monero_reset_tx(1);
    ui_menu_info_display2(0, "TX", "Aborted");
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_set_signature_mode() {
    unsigned int sig_mode;

    G_monero_vstate.tx_sig_mode = TRANSACTION_CREATE_FAKE;

    sig_mode = monero_io_fetch_u8();
    monero_io_discard(0);
    switch (sig_mode) {
        case TRANSACTION_CREATE_REAL:
        case TRANSACTION_CREATE_FAKE:
            break;
        default:
            monero_lock_and_throw(SW_WRONG_DATA);
    }
    G_monero_vstate.tx_sig_mode = sig_mode;

    monero_io_insert_u32(G_monero_vstate.tx_sig_mode);
    return SW_OK;
}
