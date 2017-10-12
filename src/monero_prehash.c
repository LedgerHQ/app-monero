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
        monero_hash_init_H();
    }
    monero_hash_update_H(G_monero_vstate.io_buffer+G_monero_vstate.io_offset,
                         G_monero_vstate.io_length-G_monero_vstate.io_offset);
    monero_io_discard(1);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_update() {
    unsigned char Aout[32];
    unsigned char Bout[32];
    unsigned char C[32];
    unsigned char v[32];
    unsigned char k[32];
    monero_io_fetch(Aout,32);
    monero_io_fetch(Bout,32);
    monero_io_fetch(C,32);
    monero_io_fetch(v,32);
    monero_io_fetch(k,32);
    //TODO insert check C,k,v and Aout,Bout here

    monero_hash_update_H(v,32);
    monero_hash_update_H(k,32);
    monero_io_discard(1);
#ifdef DEBUGLEDGER
    if ((G_monero_vstate.options & 0x80) == 0) {
        monero_io_insert(v, 32);
        monero_io_insert(k, 32);
    } 
#endif
    return SW_OK;
     
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
        monero_hash_update_H(H,32);
#ifdef DEBUGLEDGER   
        monero_io_insert(H, 32);
#endif
    } else {
        monero_io_fetch(message,32);
        monero_io_fetch(proof,32);
        monero_io_discard(1);
        monero_hash_final_H(H);
        monero_hash_init_H();
        monero_hash_update_H(message,32);
        monero_hash_update_H(H,32);
        monero_hash_update_H(proof,32);
        monero_hash_final_H(NULL);
#ifdef DEBUGLEDGER   
        monero_io_insert(G_monero_vstate.H, 32);
        monero_io_insert(H, 32);
#endif
    }
   

    return SW_OK;
}

