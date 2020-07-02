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
/*
 * pick random k
 * if B:
 *   compute X = k*B
 * else:
 *   compute X = k*G
 * compute Y = k*A
 * sig.c = Hs(Msg || D || X || Y)
 * sig.r = k - sig.c*r
 */
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
#define k (G_monero_vstate.tmp + 256)

    msg = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    R = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    A = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    B = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    D = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    monero_io_fetch_decrypt_key(r);

    monero_io_discard(0);

    monero_rng_mod_order(k);
    os_memmove(G_monero_vstate.tmp + 32 * 0, msg, 32);
    os_memmove(G_monero_vstate.tmp + 32 * 1, D, 32);

    if (G_monero_vstate.options & 1) {
        monero_ecmul_k(XY, B, k);
    } else {
        monero_ecmul_G(XY, k);
    }
    os_memmove(G_monero_vstate.tmp + 32 * 2, XY, 32);

    monero_ecmul_k(XY, A, k);
    os_memmove(G_monero_vstate.tmp + 32 * 3, XY, 32);

    monero_hash_to_scalar(sig_c, &G_monero_vstate.tmp[0], 32 * 4);

    monero_multm(XY, sig_c, r);
    monero_subm(sig_r, k, XY);

    monero_io_insert(sig_c, 32);
    monero_io_insert(sig_r, 32);

    return SW_OK;
}
