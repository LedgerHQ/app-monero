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


/* ------------------*/
/* -- TEST KEY W1 -- */
/* ------------------*/
#ifdef TESTKEY
const unsigned char C_a[32] = {
  0x52, 0xd7, 0x2c, 0x39, 0xc5, 0x93, 0x1e, 0x68, 0xb8, 0xdb, 0x5e, 0x38, 0x63, 0xd9, 0x57, 0xaf, 
  0x8f, 0xbc, 0xc0, 0x11, 0x1b, 0x7d, 0xa2, 0x1a, 0x5b, 0x38, 0x0f, 0xf4, 0x3e, 0xb8, 0x85, 0x07};
const unsigned char C_b[32] = {
  0x1c, 0x2e, 0x77, 0xb6, 0xed, 0xe0, 0xcb, 0x13, 0x78, 0x9f, 0xff, 0x64, 0x75, 0x09, 0x13, 0x20, 
  0x1b, 0x9d, 0x01, 0xb7, 0xe9, 0xff, 0xa8, 0x56, 0xe8, 0x07, 0xd5, 0x5d, 0x52, 0xa3, 0xde, 0x04};
#endif

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
#ifdef TESTKEY
    os_memmove(ab, C_a, 32);
    monero_ecmul_G(AB, ab);
    monero_nvm_write(N_monero_pstate->a, ab, 32);
    monero_nvm_write(N_monero_pstate->A, AB, 32);

    os_memmove(ab, C_b, 32);
    monero_ecmul_G(AB, ab);
    monero_nvm_write(N_monero_pstate->b, ab, 32);
    monero_nvm_write(N_monero_pstate->B, AB, 32);
#else
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
#endif

#ifdef TESTNET
    app_state = CRYPTONOTE_TESTNET_PUBLIC_ADDRESS_BASE58_PREFIX;
#else
    app_state = CRYPTONOTE_MAINNET_PUBLIC_ADDRESS_BASE58_PREFIX;
#endif
    monero_nvm_write(&N_monero_pstate->network_id, &app_state, 1);

    monero_base58_public_key((char*)G_monero_vstate.io_buffer, N_monero_pstate->A,N_monero_pstate->B);
    G_monero_vstate.io_buffer[95] = 0;
    monero_nvm_write(N_monero_pstate->public_address, G_monero_vstate.io_buffer, 96);
  }

  return 0;
}
