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
int monero_apdu_mlsag_prepare() {
    int options;
    unsigned char Hi[32];
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char mul[32];


    if (G_monero_vstate.io_length>1) {        
        monero_io_fetch(Hi,32);
        monero_io_fetch_decrypt(xin,32);
        options = 1;
    }  else {
        options = 0;
    }

    monero_io_discard(0);
    
    //ai
    cx_rng(alpha, 32);
    monero_io_insert_encrypt(alpha, 32);
    
    //ai.G
    monero_ecmul_G(mul, alpha);
    monero_io_insert(mul,32);
       
    if (options) {
        //ai.Hi
        monero_ecmul(mul, Hi, alpha);
        monero_io_insert(mul,32);
        //IIi = xin.Hi
        monero_ecmul(mul, Hi, xin);
        monero_io_insert(mul,32);
    }

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_start() {
    unsigned int options;
    options = monero_io_fetch_u8();

    os_memmove(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, 
               G_monero_vstate.H, 32);
    monero_hash_H(G_monero_vstate.io_buffer+G_monero_vstate.io_offset,
                  G_monero_vstate.io_length-G_monero_vstate.io_offset,
                  NULL);
    monero_io_discard(0);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
    int monero_apdu_mlsag_sign() {
    unsigned int options;
    options = monero_io_fetch_u8();
    unsigned char xin[32];
    unsigned char alpha[32];
    unsigned char ss[32];

    monero_io_fetch_decrypt(xin,32);
    monero_io_fetch_decrypt(alpha,32);

    cx_math_multm(ss, G_monero_vstate.H, xin, (unsigned char *)C_ED25519_ORDER, 32);
    cx_math_subm(ss, alpha, ss, (unsigned char *) C_ED25519_ORDER, 32);

    monero_io_discard(0);
    monero_io_insert(ss,32);
    return SW_OK;
}
