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
    unsigned char Aout[32];    
    unsigned char Bout[32];   
    unsigned char drv[32];
    unsigned int  output_index;

    monero_io_fetch(Aout,32); 
    monero_io_fetch(Bout,32); 
    output_index = monero_io_fetch_u32();
    monero_io_discard(1);

    //update hash L
    monero_hash_update_L(Aout,32);
    monero_hash_update_L(Bout,32);

    //compute amountkey, update LHash
    monero_derive_dh(drv, Aout, G_monero_vstate.r);
    monero_derivation_to_scalar(Aout, drv, output_index);
    monero_hash_update_L(Aout,32);
    monero_io_insert_encrypt(Aout,32);
    
    //compute Pout, update LHash
    monero_derive_pub(Aout, drv, output_index, Bout);
    monero_hash_update_L(Aout,32);
    monero_io_insert(Aout, 32);

    return SW_OK;
}
