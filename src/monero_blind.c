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
int monero_apdu_blind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout,32);
    monero_io_fetch(k,32);
    monero_io_fetch(v,32);

    monero_io_discard(1);

    if ((G_monero_vstate.options&0x03)==2) {
        os_memset(k,0,32);
        monero_ecdhHash(AKout, AKout);
        for (int i = 0; i<8; i++){
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        //blind mask
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_addm(k,k,AKout);
        //blind value
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_addm(v,v,AKout);
    }
    //ret all
    monero_io_insert(v,32);
    monero_io_insert(k,32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout, unsigned int short_amount) {
    if (short_amount==2) {
        monero_genCommitmentMask(k,AKout);
        monero_ecdhHash(AKout, AKout);
        for (int i = 0; i<8; i++) {
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        //unblind mask
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_subm(k,k,AKout);
        //unblind value
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_subm(v,v,AKout);
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_unblind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout,32);
    monero_io_fetch(k,32);
    monero_io_fetch(v,32);

    monero_io_discard(1);

    monero_unblind(v, k, AKout, G_monero_vstate.options&0x03);

    //ret all
    monero_io_insert(v,32);
    monero_io_insert(k,32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_gen_commitment_mask() {
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout,32);

    monero_io_discard(1);
    monero_genCommitmentMask(k,AKout);

    //ret all
    monero_io_insert(k,32);

    return SW_OK;
}
