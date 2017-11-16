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
    unsigned char raw[32];
    unsigned char pub[32];
    unsigned char sec[32];
    
    if (G_monero_vstate.io_length != (32*2 + 32*2 + 95)) {
        THROW(SW_WRONG_LENGTH);
    }

    //view key
    monero_io_fetch(sec, 32);    
    monero_io_fetch(pub, 32);
    monero_ecmul_G(raw,sec);
    if (os_memcmp(pub, raw, 32)) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }
    nvm_write(N_monero_pstate->a, sec, 32);
    nvm_write(N_monero_pstate->A, pub, 32);

    //spend key
    monero_io_fetch(sec, 32);    
    monero_io_fetch(pub, 32);
    monero_ecmul_G(raw,sec);
    if (os_memcmp(pub, raw, 32)) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
    }
    nvm_write(N_monero_pstate->b, sec, 32);
    nvm_write(N_monero_pstate->B, pub, 32);

    //public base 58 address key
    monero_io_fetch_nv((unsigned char*)N_monero_pstate->public_address, 95);

    monero_io_discard(1);
    return SW_OK;
}


int monero_apdu_get_key() {
    monero_io_discard(0);
    switch (G_monero_vstate.io_p1) {
    //get pub
    case 1: 
       //view key
        monero_io_insert(N_monero_pstate->A, 32);
        //spend key
        monero_io_insert(N_monero_pstate->B, 32);
        //public address 
        monero_io_insert((unsigned char*)N_monero_pstate->public_address, 95);
        break;
    
#ifdef DEBUGLEDGER 
    //get private          
    case 2:
        //view key
        monero_io_insert(N_monero_pstate->a, 32);
        //spend key
        monero_io_insert(N_monero_pstate->b, 32);
        break;
#endif
    default:
        THROW(SW_WRONG_P1P2);
        return SW_WRONG_P1P2;
    }
    return SW_OK;
}

int monero_apdu_verify_key() {
    unsigned char key[32];

    if ((G_monero_vstate.io_p1 != 1) & (G_monero_vstate.io_p1 != 2))  {
        THROW(SW_WRONG_P1P2);
        return SW_WRONG_P1P2;
    }
    if ((G_monero_vstate.io_p1 == 1) || (G_monero_vstate.io_p1 == 2)) {
        monero_io_fetch(key, 32);
        if (os_memcmp(N_monero_pstate->A, key, 32)) {
           THROW(0x6B01);
           return 0x6B01;
        }
    }
    if (G_monero_vstate.io_p1 == 2) {
        monero_io_fetch(key, 32);   ;
        if (os_memcmp(N_monero_pstate->B, key, 32)) {
           THROW(0x6B02);
           return 0x6B02;
        }
    }
    monero_io_discard(1);
    monero_io_insert((void*)N_monero_pstate->public_address, 95);
    return SW_OK;
}


#define CHACHA8_KEY_TAIL 0x8c


int monero_apdu_get_chacha_prekey() {
    unsigned char abt[65];
    unsigned char pre[32];
    monero_io_discard(0);
    os_memmove(abt, N_monero_pstate->a, 32);
    os_memmove(abt+32, N_monero_pstate->b, 32);
    abt[64] = CHACHA8_KEY_TAIL;
    monero_keccak_F(abt, 65, pre);
    monero_io_insert((unsigned char*)G_monero_vstate.keccakF.acc, 200);
    return SW_OK;
}



