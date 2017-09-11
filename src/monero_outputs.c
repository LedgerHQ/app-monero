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
int monero_apdu_get_output_key() {
    unsigned int options;
    unsigned char Dout[32];    
    unsigned char Pout[32];    

    options = monero_io_fetch_u8();
    if (options != 0) {
        THROW (SW_ALGORITHM_UNSUPPORTED);
        return SW_ALGORITHM_UNSUPPORTED;
    }
    //fetch Aout,compute Dout, update LHash
    monero_io_fetch(Dout,32); 
    monero_hash_update_L(Dout,32);
    monero_derive_dh(Dout,G_monero_vstate.r, Dout);
    monero_hash_update_L(Dout,32);

    //fetch Bout,compute Pout, update LHash
    monero_io_fetch(Pout,32);
    monero_hash_update_L(Pout,32);
    monero_derive_pub(Pout,Dout,Pout);
    monero_hash_update_L(Pout,32);

    //ret all
    monero_io_discard(0);
    monero_io_insert(Pout,32);
    monero_io_insert_encrypt(Dout,32);

    return SW_OK;
}
