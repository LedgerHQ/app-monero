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
int monero_apdu_get_tx_proof() {
    unsigned char *msg;
    unsigned char *R;
    unsigned char *A;
    unsigned char *B;
    unsigned char *D;
    unsigned char r[32];
    unsigned char XY[32];
    unsigned char sig_c[32];
    unsigned char sig_r[32];
    unsigned char sep[32];
    int err = 0;
#define k     (G_monero_vstate.tmp + 256)
#define k_len (sizeof(G_monero_vstate.tmp) - 256)

    msg = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    R = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    A = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    B = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    D = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    err = monero_io_fetch_decrypt_key(r, sizeof(r));
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }

    monero_io_discard(0);

    // Generate random k
    err = monero_rng_mod_order(k, k_len);
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }

    // tmp = msg
    memcpy(G_monero_vstate.tmp + 32 * 0, msg, 32);
    // tmp = msg || D
    memcpy(G_monero_vstate.tmp + 32 * 1, D, 32);

    if (G_monero_vstate.options & 1) {
        // X = kB
        err = monero_ecmul_k(XY, B, k, sizeof(XY), 32, k_len);
        if (err) {
            explicit_bzero(r, sizeof(r));
            return err;
        }
    } else {
        // X = kG
        err = monero_ecmul_G(XY, k, sizeof(XY), k_len);
        if (err) {
            explicit_bzero(r, sizeof(r));
            return err;
        }
    }
    // tmp = msg || D || X
    memcpy(G_monero_vstate.tmp + 32 * 2, XY, 32);

    // Y = kA
    err = monero_ecmul_k(XY, A, k, sizeof(XY), 32, k_len);
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }
    // tmp = msg || D || X || Y
    memcpy(G_monero_vstate.tmp + 32 * 3, XY, 32);
    err = monero_keccak_H((unsigned char *)"TXPROOF_V2", 10, sep);
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }
    // tmp = msg || D || X || Y || sep
    memcpy(G_monero_vstate.tmp + 32 * 4, sep, 32);
    // tmp = msg || D || X || Y || sep || R
    memcpy(G_monero_vstate.tmp + 32 * 5, R, 32);
    // tmp = msg || D || X || Y || sep || R || A
    memcpy(G_monero_vstate.tmp + 32 * 6, A, 32);
    // tmp = msg || D || X || Y || sep || R || B or [0]
    memcpy(G_monero_vstate.tmp + 32 * 7, B, 32);

    // sig_c = H_n(tmp)
    err = monero_hash_to_scalar(sig_c, &G_monero_vstate.tmp[0], sizeof(sig_c), 32 * 8);
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }

    // sig_c*r
    err = monero_multm(XY, sig_c, r, sizeof(XY), sizeof(sig_c), sizeof(r));
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }

    // sig_r = k - sig_c*r
    err = monero_subm(sig_r, k, XY, sizeof(sig_r), k_len, sizeof(r));
    if (err) {
        explicit_bzero(r, sizeof(r));
        return err;
    }

    monero_io_insert(sig_c, 32);
    monero_io_insert(sig_r, 32);

    explicit_bzero(r, sizeof(r));
    return SW_OK;
}
