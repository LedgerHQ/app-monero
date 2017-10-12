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
    unsigned char Rin[32];
   
    //fetch Rin
    monero_io_fetch(Rin,32);
    monero_io_discard(0);

    //Derive Din
    monero_derive_dh(G_monero_vstate.Dinout, Rin, N_monero_pstate->a);

    monero_io_insert(G_monero_vstate.Dinout,32);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_input_key() {
    unsigned int  sub_index;
    unsigned int  out_index;

    unsigned char xin[32];
    unsigned char Pin[32];
    unsigned char Iin[32];
    
    sub_index= monero_io_fetch_u32();
    out_index= monero_io_fetch_u32();
    monero_io_discard(1);

    if (sub_index != 0) {
        THROW (SW_ALGORITHM_UNSUPPORTED);
    }

    os_memset(xin, 0, 32);xin[31] = 1;
    os_memset(Pin, 0, 32);
    os_memset(Iin, 0, 32);
    //derive xin
    monero_derive_priv(xin, G_monero_vstate.Dinout, out_index, N_monero_pstate->b);
    monero_io_insert_encrypt(xin,32);

    //Compute Pin
    monero_ecmul_G(Pin,xin);
    monero_io_insert(Pin,32);

    ////Compute Iin
    monero_derive_img(Iin, Pin, xin);
    monero_io_insert(Iin,32);
    return SW_OK;
}
