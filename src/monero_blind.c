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
int monero_apdu_blind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout, 32, TYPE_AMOUNT_KEY);
    monero_io_fetch(k, 32);
    monero_io_fetch(v, 32);
    monero_io_discard(1);

    if ((G_monero_vstate.options & 0x03) == 2) {
        memset(k, 0, 32);
        monero_ecdhHash(AKout, AKout, sizeof(AKout));
        for (int i = 0; i < 8; i++) {
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        // blind mask
        monero_hash_to_scalar(AKout, AKout, sizeof(AKout), sizeof(AKout));
        monero_addm(k, k, AKout, sizeof(k), sizeof(k), sizeof(AKout));
        // blind value
        monero_hash_to_scalar(AKout, AKout, sizeof(AKout), sizeof(AKout));
        monero_addm(v, v, AKout, sizeof(v), sizeof(v), sizeof(AKout));
    }
    // ret all
    monero_io_insert(v, 32);
    monero_io_insert(k, 32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout,
                   unsigned int short_amount, size_t v_len, size_t k_len, size_t AKout_len) {
    if (short_amount == 2) {
        monero_genCommitmentMask(k, AKout, k_len, AKout_len);
        monero_ecdhHash(AKout, AKout, AKout_len);
        for (int i = 0; i < 8; i++) {
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        // unblind mask
        monero_hash_to_scalar(AKout, AKout, AKout_len, AKout_len);
        monero_subm(k, k, AKout, k_len, k_len, AKout_len);
        // unblind value
        monero_hash_to_scalar(AKout, AKout, AKout_len, AKout_len);
        monero_subm(v, v, AKout, v_len, v_len, AKout_len);
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

    monero_io_fetch_decrypt(AKout, 32, TYPE_AMOUNT_KEY);
    monero_io_fetch(k, 32);
    monero_io_fetch(v, 32);

    monero_io_discard(1);

    monero_unblind(v, k, AKout, G_monero_vstate.options & 0x03, sizeof(v), sizeof(k), sizeof(AKout));

    // ret all
    monero_io_insert(v, 32);
    monero_io_insert(k, 32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_gen_commitment_mask() {
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout, 32, TYPE_AMOUNT_KEY);

    monero_io_discard(1);
    monero_genCommitmentMask(k, AKout, sizeof(k), sizeof(AKout));

    // ret all
    monero_io_insert(k, 32);

    return SW_OK;
}
