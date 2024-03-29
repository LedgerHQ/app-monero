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
int monero_apdu_mlsag_prepare() {
    int options;
    unsigned char Hi[32];
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char mul[32];
    int err;

    G_monero_vstate.tx_sign_cnt++;
    if (G_monero_vstate.tx_sign_cnt == 0) {
        return SW_SECURITY_MAX_SIGNATURE_REACHED;
    }

    if (G_monero_vstate.io_length > 1) {
        monero_io_fetch(Hi, 32);
        if (G_monero_vstate.options & 0x40) {
            monero_io_fetch(xin, 32);
        } else {
            err = monero_io_fetch_decrypt(xin, 32, TYPE_SCALAR);
            if (err) {
                return err;
            }
        }
        options = 1;
    } else {
        options = 0;
    }

    monero_io_discard(1);

    // ai
    err = monero_rng_mod_order(alpha, sizeof(alpha));
    if (err) {
        return err;
    }

    err = monero_reduce(alpha, alpha, sizeof(alpha), sizeof(alpha));
    if (err) {
        return err;
    }

    monero_io_insert_encrypt(alpha, 32, TYPE_ALPHA);

    // ai.G
    err = monero_ecmul_G(mul, alpha, sizeof(mul), sizeof(alpha));
    if (err) {
        return err;
    }

    monero_io_insert(mul, 32);

    if (options) {
        // ai.Hi
        err = monero_ecmul_k(mul, Hi, alpha, sizeof(mul), sizeof(Hi), sizeof(alpha));
        if (err) {
            return err;
        }
        monero_io_insert(mul, 32);
        // IIi = xin.Hi
        err = monero_ecmul_k(mul, Hi, xin, sizeof(mul), sizeof(Hi), sizeof(xin));
        if (err) {
            return err;
        }
        monero_io_insert(mul, 32);
    }
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_hash() {
    unsigned char msg[32];
    unsigned char c[32];
    int err;
    if (G_monero_vstate.io_p2 == 1) {
        if (monero_keccak_init_H()) {
            return SW_WRONG_DATA;
        }
        memcpy(msg, G_monero_vstate.mlsagH, 32);
    } else {
        monero_io_fetch(msg, 32);
    }
    monero_io_discard(1);

    err = monero_keccak_update_H(msg, 32);
    if (err) {
        return err;
    }

    if ((G_monero_vstate.options & 0x80) == 0) {
        err = monero_keccak_final_H(c);
        if (err) {
            return err;
        }

        err = monero_reduce(c, c, sizeof(c), sizeof(c));
        if (err) {
            return err;
        }
        monero_io_insert(c, 32);
        memcpy(G_monero_vstate.c, c, 32);
    }
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_sign() {
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char ss[32];
    unsigned char ss2[32];
    int err;

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_FAKE) {
        monero_io_fetch(xin, 32);
        monero_io_fetch(alpha, 32);
    } else if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        err = monero_io_fetch_decrypt(xin, 32, TYPE_SCALAR);
        if (err) {
            return err;
        }
        err = monero_io_fetch_decrypt(alpha, 32, TYPE_ALPHA);
        if (err) {
            return err;
        }
    } else {
        return SW_SECURITY_INTERNAL;
    }
    monero_io_discard(1);

    // check xin and alpha are not null
    if (cx_math_is_zero(xin, 32) || cx_math_is_zero(alpha, 32)) {
        return SW_SECURITY_RANGE_VALUE;
    }

    err = monero_reduce(ss, G_monero_vstate.c, sizeof(ss), sizeof(G_monero_vstate.c));
    if (err) {
        return err;
    }

    err = monero_reduce(xin, xin, sizeof(xin), sizeof(xin));
    if (err) {
        return err;
    }

    err = monero_multm(ss, ss, xin, sizeof(ss), sizeof(ss), sizeof(xin));
    if (err) {
        return err;
    }

    err = monero_reduce(alpha, alpha, sizeof(alpha), sizeof(alpha));
    if (err) {
        return err;
    }
    err = monero_subm(ss2, alpha, ss, sizeof(ss2), sizeof(alpha), sizeof(ss));
    if (err) {
        return err;
    }

    monero_io_insert(ss2, 32);
    monero_io_insert_u32(G_monero_vstate.tx_sig_mode);
    return SW_OK;
}
