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
    bool device_default::clsag_prepare(const rct::key &p,
                                       const rct::key &z,
                                       rct::key &I, rct::key &D,
                                       const rct::key &H,
                                       rct::key &a, rct::key &aG,
                                       rct::key &aH) {
        rct::skpkGen(a, aG);          // aG = a*G
        rct::scalarmultKey(aH, H, a); // aH = a*H
        rct::scalarmultKey(I, H, p);  // I = p*H
        rct::scalarmultKey(D, H,  z); // D = z*H
        return true;
    }
*/
int monero_apdu_clsag_prepare() {
    int options;
    unsigned char a[32];
    unsigned char p[32];
    unsigned char z[32];
    unsigned char H[32];
    unsigned char W[32];

    G_monero_vstate.tx_sign_cnt++;
    if (G_monero_vstate.tx_sign_cnt == 0) {
        monero_lock_and_throw(SW_SECURITY_MAX_SIGNATURE_REACHED);
    }

    monero_io_fetch_decrypt(p, 32, TYPE_SCALAR);
    monero_io_fetch(z, 32);
    monero_io_fetch(H, 32);
    monero_io_discard(1);

    // a
    monero_rng_mod_order(a);
    monero_io_insert_encrypt(a, 32, TYPE_ALPHA);
    // a.G
    monero_ecmul_G(W, a);
    monero_io_insert(W, 32);
    // a.H
    monero_ecmul_k(W, H, a);
    monero_io_insert(W, 32);
    // I = p.H
    monero_ecmul_k(W, H, p);
    monero_io_insert(W, 32);

    // D = z.H
    monero_ecmul_k(W, H, z);
    monero_io_insert(W, 32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    bool device_default::clsag_hash(const rct::keyV &data,
                                    rct::key &hash) {
        hash = rct::hash_to_scalar(data);
        return true;
    }
*/
int monero_apdu_clsag_hash() {
    unsigned char msg[32];
    unsigned char c[32];

    if (G_monero_vstate.io_p2 == 1) {
        monero_keccak_init_H();
    }

    monero_io_fetch(msg, 32);
    monero_io_discard(1);

    monero_keccak_update_H(msg, 32);
    if ((G_monero_vstate.options & 0x80) == 0) {
        monero_keccak_final_H(c);
        monero_reduce(c, c);
        monero_io_insert(c, 32);
        os_memmove(G_monero_vstate.c, c, 32);
    }
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
bool device_default::clsag_sign(const rct::key &c,
                                const rct::key &a,
                                const rct::key &p, const
                                rct::key &z,
                                const rct::key &mu_P,
                                const rct::key &mu_C,
                                rct::key &s) {
        rct::key s0_p_mu_P;
        sc_mul(s0_p_mu_P.bytes, mu_P.bytes, p.bytes);
        rct::key s0_add_z_mu_C;
        sc_muladd(s0_add_z_mu_C.bytes, mu_C.bytes, z.bytes, s0_p_mu_P.bytes);
        sc_mulsub(s.bytes, c.bytes, s0_add_z_mu_C.bytes, a.bytes);

        return true;
    }
*/
int monero_apdu_clsag_sign() {
    unsigned char s[32];
    unsigned char a[32];
    unsigned char p[32];
    unsigned char z[32];
    unsigned char mu_P[32];
    unsigned char mu_C[32];

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_FAKE) {
        monero_io_fetch(a, 32);
        monero_io_fetch(p, 32);
        monero_io_fetch(z, 32);
        monero_io_fetch(mu_P, 32);
        monero_io_fetch(mu_C, 32);
    } else if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        monero_io_fetch_decrypt(a, 32, TYPE_ALPHA);
        monero_io_fetch_decrypt(p, 32, TYPE_SCALAR);
        monero_io_fetch(z, 32);
        monero_io_fetch(mu_P, 32);
        monero_io_fetch(mu_C, 32);
    } else {
        monero_lock_and_throw(SW_SECURITY_INTERNAL);
    }

    monero_io_discard(1);

    monero_check_scalar_not_null(a);
    monero_check_scalar_not_null(p);
    monero_check_scalar_not_null(z);

    monero_reduce(a, a);
    monero_reduce(p, p);
    monero_reduce(z, z);
    monero_reduce(mu_P, mu_P);
    monero_reduce(mu_C, mu_C);
    monero_reduce(G_monero_vstate.c, G_monero_vstate.c);

    // s0_p_mu_P = mu_P*p
    // s0_add_z_mu_C = mu_C*z + s0_p_mu_P
    //
    // s = a - c*s0_add_z_mu_C
    //   = a - c*(mu_C*z + mu_P*p)

    // s = p*mu_P
    monero_multm(s, p, mu_P);
    // mu_P = mu_C*z
    monero_multm(mu_P, mu_C, z);
    // s = p*mu_P + mu_C*z
    monero_addm(s, s, mu_P);
    // mu_P = c * (p*mu_P + mu_C*z)
    monero_multm(mu_P, G_monero_vstate.c, s);
    // s = a - c*(p*mu_P + mu_C*z)
    monero_subm(s, a, mu_P);

    monero_io_insert(s, 32);

    return SW_OK;
}
