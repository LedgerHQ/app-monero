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
#include "usbd_ccid_impl.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_blind() {
    unsigned int options,len;
    unsigned char v[32];
    unsigned char k[32];
    unsigned char Dout[32];

    options = monero_io_fetch_u8();
    monero_io_fetch(v,32);
    monero_io_fetch(k,32);
    monero_io_fetch_decrypt(Dout,32);
    
    //update LHash
    monero_hash_update_L(v,   32);
    monero_hash_update_L(k,   32);
    monero_hash_update_L(Dout,32);

    //blind
    monero_hash_H(Dout, 32, Dout);
    for (len = 0; len<32; len++) {
        k[len] = k[len] ^ Dout[len];
    }
    monero_hash_H(Dout, 32, Dout);
    for (len = 0; len<32; len++) {
        v[len] = v[len] ^ Dout[len];
    }

    //ret all
    monero_io_discard(0);
    monero_io_insert(v,32);
    monero_io_insert(k,32);

    return SW_OK;

}
