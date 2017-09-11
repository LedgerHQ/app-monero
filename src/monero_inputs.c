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
int monero_apdu_get_derivation_data() {
    unsigned int options;
    #define  Din   &G_monero_vstate.Dinout[0]

    options = monero_io_fetch_u8();

    //fetch Rin
    monero_io_fetch(Din,32);
    //Derive Din
    monero_derive_dh(Din, (void*)&G_monero_vstate.r,Din);
    monero_io_discard(0);
    monero_io_insert(Din,32);
    
    return SW_OK;
    #undef  Din 
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_input_key() {
    unsigned int options,index;
    unsigned char xin[32];
    unsigned char Pin[32];
    unsigned char Iin[32];
    

    options = monero_io_fetch_u8();
    index= monero_io_fetch_u8();
    monero_io_discard(0);

    if (index != 0) {
        THROW (SW_ALGORITHM_UNSUPPORTED);
    }

    //derive xin
    monero_derive_priv(xin, G_monero_vstate.Dinout, N_monero_pstate->b);

    //Compute Pin
    monero_ecmul_G(Pin,xin);
    monero_io_insert(Pin,32);

    //Compute Iin
    monero_derive_img(Iin, xin, Pin);
    monero_io_insert(Iin,32);

    //compute xin_enc
    monero_io_insert_encrypt(xin, 32);
    
    return SW_OK;
}