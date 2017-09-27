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
#include "monero_ux_nanos.h"
#include "monero_vars.h"
#include "usbd_ccid_impl.h"


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* 
 * ecdhinfo                   [in]  : serialized ecdh info {~mask, ~amount, pk}
 * ecdhinfo_len               [in]  : ecdh info byte length
 * G_monero_vstate.Aout       [in]  : dest view key to unblind mask and amount
 * G_monero_vstate.commitment [in]  : C  = mask.G+ammount.H
 * G_monero_vstate.amount     [out] : unblinded ammount
 * G_monero_vstate.Dinout     [out] : Derivation Data
 */
static void monero_validate_ecdh_info(unsigned char *ecdhinfo, int ecdhinfo_len){
                                    

}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_init_validate() {
    
    //finish L hash
    monero_hash_final_L(NULL);

    //start mlsag hash
    monero_hash_init_H();
    monero_hash_update_H(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, G_monero_vstate.io_length);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_update_validate_pre_validation() {
    
    monero_io_fetch(G_monero_vstate.Aout,32);
    monero_io_fetch(G_monero_vstate.Bout,32);
    monero_io_fetch(G_monero_vstate.commitment,32);
    monero_validate_ecdh_info(G_monero_vstate.io_buffer+G_monero_vstate.io_offset,
                              G_monero_vstate.io_length-G_monero_vstate.io_offset);
    monero_ux_user_validation();    
    return 0;
}

int monero_apdu_update_validate_post_validation() {
    //mslsag hash
    monero_hash_update_H(G_monero_vstate.io_buffer+G_monero_vstate.io_offset,
                       G_monero_vstate.io_length-G_monero_vstate.io_offset);
    //C hash
    monero_hash_update_C(G_monero_vstate.commitment,32);
    //L hash
    monero_hash_update_L(G_monero_vstate.Aout,32);
    monero_hash_update_L(G_monero_vstate.Bout,32);
    monero_hash_update_L(G_monero_vstate.Dinout,32);
    monero_hash_update_L(G_monero_vstate.Pout,32);
    monero_hash_update_L(G_monero_vstate.amount,32);
    monero_hash_update_L(G_monero_vstate.mask,32);
    monero_hash_update_L(G_monero_vstate.Dinout,32);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_finalize_validate() { 
    unsigned char message[32];
    unsigned char proof[32];
    unsigned char h[32];
    
    monero_io_fetch(message,32);
    monero_io_fetch(proof,32);

    //check L
    monero_hash_final_L(h);
    if (os_memcmp(h, G_monero_vstate.L, 32)) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }
    //check C
    monero_hash_final_C(G_monero_vstate.C);
    monero_hash_C(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, G_monero_vstate.io_length-G_monero_vstate.io_offset, h);
    
    if (os_memcmp(h, G_monero_vstate.C, 32)) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }
    //finalize prehash
    monero_hash_update_H(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, 
                         G_monero_vstate.io_length-G_monero_vstate.io_offset);
    monero_hash_final_H(NULL);
    monero_hash_init_H();
    monero_hash_update_H(message, 32);
    monero_hash_update_H(G_monero_vstate.H, 32);
    monero_hash_update_H(proof, 32);
    monero_hash_final_H(NULL);

    return SW_OK;
}
