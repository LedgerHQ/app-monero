/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * HD wallet not yet supported : account is assumed to be zero
 */
#define OPTION_KEEP_r 1
int monero_apdu_open_tx() {

    unsigned int account;

    //monero_sha256_commitment_init();
    monero_sha256_amount_init();

    account = monero_io_fetch_u32();

    monero_io_discard(1);

    monero_rng(G_monero_vstate.r,32);
    monero_reduce(G_monero_vstate.r, G_monero_vstate.r);
    monero_ecmul_G(G_monero_vstate.R, G_monero_vstate.r);

    monero_io_insert(G_monero_vstate.R,32);
    monero_io_insert_encrypt(G_monero_vstate.r,32);
#ifdef DEBUG_HWDEVICE    
    monero_io_insert(G_monero_vstate.r,32);
#endif
    return SW_OK;
}
#undef OPTION_KEEP_r

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_close_tx() {
   monero_io_discard(0);
   return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * Sub dest address not yet supported: P1 = 2 not supported
 */
int monero_abort_tx() {
    os_memset(G_monero_vstate.r, 0, 32);
    os_memset(G_monero_vstate.R, 0, 32);
    monero_keccak_init_H();
    monero_sha256_commitment_init();
    monero_sha256_amount_init();
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
 * Sub dest address not yet supported: P1 = 2 not supported
 */
int monero_apdu_set_signature_mode() {
    unsigned int sig_mode;

    G_monero_vstate.sig_mode = TRANSACTION_CREATE_FAKE;

    sig_mode = monero_io_fetch_u8();
    monero_io_discard(0);
    switch(sig_mode) {
    case TRANSACTION_CREATE_REAL:
    case TRANSACTION_CREATE_FAKE:
        break;
    default:
        THROW(SW_WRONG_DATA);
    }
    G_monero_vstate.sig_mode = sig_mode;

    monero_io_insert_u32( G_monero_vstate.sig_mode );
    return SW_OK;
}
