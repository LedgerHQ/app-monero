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


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_stealth() {
    int i ;
    unsigned char pub[32];
    unsigned char sec[32];
    unsigned char drv[33];
    unsigned char payID[8];
    
    //fetch pub
    monero_io_fetch(pub,32);
    //fetch sec
    monero_io_fetch_decrypt_key(sec);
    //fetch paymentID
    monero_io_fetch(payID,8);

    monero_io_discard(0);

    //Compute Dout
    monero_generate_key_derivation(drv, pub, sec);
    
    //compute mask
    drv[32] = ENCRYPTED_PAYMENT_ID_TAIL;
    monero_keccak_F(drv,33,sec);
    
    //stealth!
    for (i=0; i<8; i++) {
        payID[i] = payID[i] ^ sec[i];
    }
    
    monero_io_insert(payID,8);

    return SW_OK;
}