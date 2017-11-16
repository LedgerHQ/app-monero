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


/* ----------------------*/
/* -- A Kind of Magic -- */
/* ----------------------*/

const unsigned char C_MAGIC[8] = {
 'M','O','N','E','R','O','H','W'
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
    unsigned char AB[32];
    unsigned char ab[32];

    unsigned int  path[5];
    unsigned char seed[32];

    os_memset(ab, 0,  32);
    path[0] = 0x8000002C;
    path[1] = 0x80000080;
    path[2] = 0x80000000;
    path[3] = 0x00000000;
    path[4] = 0x00000000;
 
    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, 5 , seed, ab);
    monero_keccak_F(seed,32,ab);
    ab[0]  &= 0xF8;    
    ab[31]  = (ab[31] & 0x7F) | 0x40;
    monero_ecmul_G(AB, ab);
    monero_nvm_write(N_monero_pstate->b, ab, 32);
    monero_nvm_write(N_monero_pstate->B, AB, 32);

    monero_keccak_F(ab,32,ab);
    ab[0]  &= 0xF8;    
    ab[31]  = (ab[31] & 0x7F) | 0x40;
    monero_ecmul_G(AB, ab);
    monero_nvm_write(N_monero_pstate->a, ab, 32);
    monero_nvm_write(N_monero_pstate->A, AB, 32);

    app_state = CRYPTONOTE_TESTNET_PUBLIC_ADDRESS_BASE58_PREFIX;
    monero_nvm_write(&N_monero_pstate->network_id, &app_state, 1);

    monero_base58_public_key((char*)G_monero_vstate.io_buffer, N_monero_pstate->A,N_monero_pstate->B);
    G_monero_vstate.io_buffer[95] = 0;
    monero_nvm_write(N_monero_pstate->public_address, G_monero_vstate.io_buffer, 96);
  }

  return 0;
}
