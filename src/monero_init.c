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


/* ---------------*/
/* -- Wallet 3 -- */
/* ---------------*/
/*
[wallet 9uuioL]: viewkey
secret(LE): 39dcfdbd3d97312cab52cc75960b4e8ae2c3c073287a7ce5ad0071ab55157900
public(02): b243923237bd4273803289f6f91c5ccd128c88553ac9dec0d3fb8ea06b1dbde3

[wallet 9uuioL]: spendkey 
secret(LE): 6017623f78cc577a340561b71e1224ebef921aca5f755b5f5f351944c4483807
public(02): 485f50564bcb8daeb8198bdf766b12b3ff9f59eed1ea47070a804d447b7310c6
*/

const unsigned char C_w3_a[32] = {
  0x39, 0xdc, 0xfd, 0xbd, 0x3d, 0x97, 0x31, 0x2c, 0xab, 0x52, 0xcc, 0x75, 0x96, 0x0b, 0x4e, 0x8a, 
  0xe2, 0xc3, 0xc0, 0x73, 0x28, 0x7a, 0x7c, 0xe5, 0xad, 0x00, 0x71, 0xab, 0x55, 0x15, 0x79, 0x00
};
const unsigned char C_w3_b[32] = {
  0x60, 0x17, 0x62, 0x3f, 0x78, 0xcc, 0x57, 0x7a, 0x34, 0x05, 0x61, 0xb7, 0x1e, 0x12, 0x24, 0xeb, 
  0xef, 0x92, 0x1a, 0xca, 0x5f, 0x75, 0x5b, 0x5f, 0x5f, 0x35, 0x19, 0x44, 0xc4, 0x48, 0x38, 0x07
};

/* ----------------------*/
/* -- A Kind of Magic -- */
/* ----------------------*/

const unsigned char C_MAGIC[8] = {
 'M','O','N','E','R','O',' ','A'
};

/* ----------------------------------------------------------------------- */
/* --- boot init                                                       --- */
/* ----------------------------------------------------------------------- */


void monero_init() {
  

  os_memset(&G_monero_vstate, 0, sizeof(monero_v_state_t));
  //first init ?
  if (os_memcmp(N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC)) != 0) {
    monero_install(STATE_ACTIVATE);
    
    
    monero_nvm_write(N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC));

    os_memset(&G_monero_vstate, 0, sizeof(monero_v_state_t));
  }

  //ux conf
  monero_init_ux();
}

void monero_init_ux() {

}

/* ----------------------------------------------------------------------- */
/* ---  Install/ReInstall GPGapp                                       --- */
/* ----------------------------------------------------------------------- */
int monero_install(unsigned char app_state) {

  //full reset data
  monero_nvm_write(N_monero_pstate, NULL, sizeof(monero_nv_state_t));

  if (app_state == STATE_ACTIVATE) {
    //init BIP44 key

    //TESTKEY W3
    unsigned char AB[32];
    unsigned char   ab[32];

    os_memmove(ab,C_w3_a,32);
    monero_ecmul_G(AB, ab);
    monero_nvm_write(N_monero_pstate->a, ab, 32);
    monero_nvm_write(N_monero_pstate->A, AB, 32);

    os_memmove(ab,C_w3_b,32);
    monero_ecmul_G(AB, ab);
    monero_nvm_write(N_monero_pstate->b, ab, 32);
    monero_nvm_write(N_monero_pstate->B, AB, 32);

  }

  return 0;
}
