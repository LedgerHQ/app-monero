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
int monero_apdu_open_tx() {
    unsigned int account;
    account = monero_io_fetch_u32();

    monero_io_discard(0);
   
    cx_rng(G_monero_vstate.r,32);
    cx_math_modm(G_monero_vstate.r,32, (unsigned char*)C_ED25519_ORDER, 32);
    monero_ecmul_G(G_monero_vstate.R, G_monero_vstate.r);
    monero_io_insert(G_monero_vstate.R,32);

    if (G_monero_vstate.options & OPTION_KEEP_r) {
        monero_aes_derive(&G_monero_vstate.spk,
                          G_monero_vstate.R, N_monero_pstate->a,  N_monero_pstate->b);
        
    } else {
        monero_aes_generate(&G_monero_vstate.spk);
        
    }

    monero_io_insert_encrypt(G_monero_vstate.r,32);
    monero_hash_init_L();
    monero_hash_init_C();
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* 
 * Sub dest address not yet supported: P1 = 2 not supported
 */
int monero_apdu_open_subtx() {
    THROW(SW_WRONG_P1P2);
    return SW_WRONG_P1P2;
}