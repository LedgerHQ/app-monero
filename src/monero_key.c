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


int monero_apdu_put_key() {
    unsigned char *raw;
    unsigned char pub[32];
    //view key
    raw = G_monero_vstate.io_buffer;
    monero_ecmul_G(pub,raw);
    if (os_memcmp(pub, raw+32, 32)) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }

    //spend key
    raw = G_monero_vstate.io_buffer+64;
    monero_ecmul_G(pub,raw);
    if (os_memcmp(pub, raw+32, 32)) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }

    //write key
    raw = G_monero_vstate.io_buffer;
    nvm_write(&N_monero_pstate->a, raw,    sizeof(cx_ecfp_private_key_t));
    nvm_write(&N_monero_pstate->A, raw+32, sizeof(cx_ecfp_public_key_t));
    raw = G_monero_vstate.io_buffer+64;
    nvm_write(&N_monero_pstate->b, raw,    sizeof(cx_ecfp_private_key_t));
    nvm_write(&N_monero_pstate->B, raw+32, sizeof(cx_ecfp_public_key_t));

    return SW_OK;
}