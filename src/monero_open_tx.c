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
#include "usbd_ccid_impl.h"


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*  
 * HD wallet not yet supported : account is assumed to be zero
 */
#define OPTION_KEEP_r 1
int monero_apdu_open_tx() {

    unsigned int account;

    G_monero_vstate.rnd = 1;

    account = monero_io_fetch_u32();

    monero_io_discard(1);
   
    monero_rng(G_monero_vstate.r,32);
    monero_reduce(G_monero_vstate.r, G_monero_vstate.r);
    monero_ecmul_G(G_monero_vstate.R, G_monero_vstate.r);

    if (G_monero_vstate.options & OPTION_KEEP_r) {
        monero_aes_derive(&G_monero_vstate.spk,
                          G_monero_vstate.R, N_monero_pstate->a,  N_monero_pstate->b);
    } else {
        monero_aes_generate(&G_monero_vstate.spk);
    }

    monero_io_insert(G_monero_vstate.R,32);
    monero_io_insert_encrypt(G_monero_vstate.r,32);

    return SW_OK;
}
#undef OPTION_KEEP_r

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_open_subtx() {
    monero_io_fetch(G_monero_vstate.R, 32);
    monero_ecmul_G(G_monero_vstate.R, G_monero_vstate.r);
    monero_io_discard(1);
    monero_io_insert(G_monero_vstate.R,32);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_additional_key() {
    unsigned char s[32];
    unsigned char R[32];
    monero_io_discard(1);

    monero_rng(s,32);
    monero_reduce(s, s);
    if (G_monero_vstate.options&1) {
        monero_ecmul_k(R, N_monero_pstate->B,s);
    } else {
        monero_ecmul_G(R, s);
    }

    monero_io_insert(R,32);
    monero_io_insert_encrypt(s,32);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* 
 * Sub dest address not yet supported: P1 = 2 not supported
 */
int monero_abort_tx() {
    os_memset(&G_monero_vstate.state, 0, SIZEOF_TX_VSTATE);
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
    
    G_monero_vstate.sig_mode = SIG_REAL;

    sig_mode = monero_io_fetch_u8();
    monero_io_discard(0);
    switch(sig_mode) {
    case SIG_REAL:
    case SIG_FAKE:
        break;
    default:
        THROW(SW_WRONG_DATA);
    }
    G_monero_vstate.sig_mode = sig_mode;
   
    monero_io_insert_u32( G_monero_vstate.sig_mode );
    return SW_OK;
}
