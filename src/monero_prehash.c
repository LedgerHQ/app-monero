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

/*
* Client: rctSigs.cpp.c -> get_pre_mlsag_hash
*/

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_ux_nanos.h"
#include "monero_vars.h"
#include "usbd_ccid_impl.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_init() {
    if (G_monero_vstate.io_p2 == 1) {
        monero_keccak_init_H();
    }
    monero_keccak_update_H(G_monero_vstate.io_buffer+G_monero_vstate.io_offset,
                          G_monero_vstate.io_length-G_monero_vstate.io_offset);

    if ((G_monero_vstate.sig_mode == SIG_REAL) &&(G_monero_vstate.io_p2==1)) {
        // skip type
        monero_io_fetch_u8();
        // fee str
        monero_vamount2str(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, G_monero_vstate.ux_amount, 15);
         //ask user
        monero_io_discard(1);
        ui_menu_fee_validation_display(0);
        return 0;
    } else {
        monero_io_discard(1);
        return SW_OK;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_update() {
    unsigned char Aout[32];
    unsigned char Bout[32];
    #define AKout Aout
    unsigned char C[32];
    unsigned char v[32];
    unsigned char k[32];
    int changed;

    changed = 0;
    monero_io_fetch(Aout,32);
    monero_io_fetch(Bout,32);
    if (G_monero_vstate.sig_mode == SIG_REAL) {
        if (os_memcmp(Aout, N_monero_pstate->A, 32) || os_memcmp(Bout, N_monero_pstate->B, 32) ) {
            //encode dest adress
            monero_base58_public_key(&G_monero_vstate.ux_address[0], Aout, Bout);
        } else {
            changed = 1;
        }
    }
    monero_io_fetch_decrypt(AKout,32);
    monero_io_fetch(C,32);
    monero_io_fetch(k,32);
    monero_io_fetch(v,32);

    monero_keccak_update_H(k,32);
    monero_keccak_update_H(v,32);

    if ((G_monero_vstate.sig_mode == SIG_REAL)&& !changed) {
        //unblind amount to str
        monero_unblind(v,k, AKout);
        monero_io_insert(v,32);
        monero_io_insert(k,32);
        monero_bamount2str(v, G_monero_vstate.ux_amount, 15);
        //ask user
        monero_io_discard(1);
        ui_menu_validation_display(0);
        return 0;
    } else  {
        monero_io_discard(1);
        return SW_OK;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_finalize() {
    unsigned char message[32];
    unsigned char proof[32];
    unsigned char H[32];

    if (G_monero_vstate.options & 0x80) {
        monero_io_fetch(H,32);
        monero_io_discard(1);
        monero_keccak_update_H(H,32);
#ifdef DEBUGLEDGER
        monero_io_insert(H, 32);
#endif
    } else {
        monero_io_fetch(message,32);
        monero_io_fetch(proof,32);
        monero_io_discard(1);
        monero_keccak_final_H(H);
        monero_keccak_init_H();
        monero_keccak_update_H(message,32);
        monero_keccak_update_H(H,32);
        monero_keccak_update_H(proof,32);
        monero_keccak_final_H(NULL);
#ifdef DEBUGLEDGER
        monero_io_insert(G_monero_vstate.H, 32);
        monero_io_insert(H, 32);
#endif
    }

    return SW_OK;
}

