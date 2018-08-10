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
//view key:
//  priv: 52d72c39c5931e68b8db5e3863d957af8fbcc0111b7da21a5b380ff43eb88507
//   pub: 4e0fda0a0bb8917a4d5e0815e52aac801859212e902cc0d8596e481663a8b949
const unsigned char C_a[32] = {
  0x52, 0xd7, 0x2c, 0x39, 0xc5, 0x93, 0x1e, 0x68, 0xb8, 0xdb, 0x5e, 0x38, 0x63, 0xd9, 0x57, 0xaf,
  0x8f, 0xbc, 0xc0, 0x11, 0x1b, 0x7d, 0xa2, 0x1a, 0x5b, 0x38, 0x0f, 0xf4, 0x3e, 0xb8, 0x85, 0x07};

//spend key:
//  priv: 1c2e77b6ede0cb13789fff64750913201b9d01b7e9ffa856e807d55d52a3de04
//   pub: bd05a680d7f5490bd34be298183819ddf01d0cdb47bd7dfa3671e8eb6cf7c6e7
const unsigned char C_b[32] = {
  0x1c, 0x2e, 0x77, 0xb6, 0xed, 0xe0, 0xcb, 0x13, 0x78, 0x9f, 0xff, 0x64, 0x75, 0x09, 0x13, 0x20,
  0x1b, 0x9d, 0x01, 0xb7, 0xe9, 0xff, 0xa8, 0x56, 0xe8, 0x07, 0xd5, 0x5d, 0x52, 0xa3, 0xde, 0x04};
#endif


/* ----------------------------------------------------------------------- */
/* --- Boot                                                            --- */
/* ----------------------------------------------------------------------- */

void monero_init() {
  os_memset(&G_monero_vstate, 0, sizeof(monero_v_state_t));

  //first init ?
  if (os_memcmp(N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC)) != 0) {
    monero_install(MAINNET);
  }

  //generate key protection
  monero_aes_generate(&G_monero_vstate.spk);

  //load key
  monero_init_private_key();
  monero_ecmul_G(G_monero_vstate.A, G_monero_vstate.a);
  monero_ecmul_G(G_monero_vstate.B, G_monero_vstate.b);

  //ux conf
  monero_init_ux();

  // Let's go!
  G_monero_vstate.state = 42;
}

/* ----------------------------------------------------------------------- */
/* --- init private keys                                               --- */
/* ----------------------------------------------------------------------- */
void monero_init_private_key() {
  #ifndef TESTKEY
  unsigned int  path[5];
  unsigned char seed[32];

  // m/44'/128'/0'/0/0
  path[0] = 0x8000002C;
  path[1] = 0x80000080;
  path[2] = 0x80000000;
  path[3] = 0x00000000;
  path[4] = 0x00000000;
  #endif

  switch(N_monero_pstate->key_mode) {
  case KEY_MODE_SEED:
    #ifdef TESTKEY
    os_memmove(G_monero_vstate.a, C_a, 32);
    os_memmove(G_monero_vstate.b, C_b, 32);
    #else
    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, 5 , seed, G_monero_vstate.a);

    monero_keccak_F(seed,32,G_monero_vstate.b);
    monero_reduce(G_monero_vstate.b,G_monero_vstate.b);
    
    monero_keccak_F(G_monero_vstate.b,32,G_monero_vstate.a);
    monero_reduce(G_monero_vstate.a,G_monero_vstate.a);
   
    #endif
    break;

  case KEY_MODE_EXTERNAL:
    os_memmove(G_monero_vstate.a,  N_monero_pstate->a, 32);
    os_memmove(G_monero_vstate.b,  N_monero_pstate->b, 32);
    break;

  default :
    THROW(SW_SECURITY_LOAD_KEY);
    return;
  }
}

/* ----------------------------------------------------------------------- */
/* ---  Set up ui/ux                                                   --- */
/* ----------------------------------------------------------------------- */
void monero_init_ux() {
}

/* ----------------------------------------------------------------------- */
/* ---  Install/ReInstall Monero app                                   --- */
/* ----------------------------------------------------------------------- */
void monero_install(unsigned char netId) {
  unsigned char c;

  //full reset data
  monero_nvm_write(N_monero_pstate, NULL, sizeof(monero_nv_state_t));

  //set mode key
  c = KEY_MODE_SEED;
  nvm_write(&N_monero_pstate->key_mode, &c, 1);

  //set net id
  monero_nvm_write(&N_monero_pstate->network_id, &netId, 1);

  //write magic
  monero_nvm_write(N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC));
}
