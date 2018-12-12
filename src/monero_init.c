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

/* ----------------------------------------------------------------------- */
/* --- Boot                                                            --- */
/* ----------------------------------------------------------------------- */
void monero_init() {
  os_memset(&G_monero_vstate, 0, sizeof(monero_v_state_t));

  //first init ?
  if (os_memcmp(N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC)) != 0) {
    monero_install(MAINNET);
  }

  G_monero_vstate.protocol = 0xff;

  //generate key protection
  monero_aes_generate(&G_monero_vstate.spk);
  //load key
  monero_init_private_key();
  //ux conf
  monero_init_ux();
  // Let's go!
  G_monero_vstate.state = STATE_IDLE;
}

/* ----------------------------------------------------------------------- */
/* --- init private keys                                               --- */
/* ----------------------------------------------------------------------- */
void monero_wipe_private_key() {
 os_memset(G_monero_vstate.a,  0, 32);
 os_memset(G_monero_vstate.b,  0, 32);
 os_memset(G_monero_vstate.A,  0, 32);
 os_memset(G_monero_vstate.B,  0, 32);
 G_monero_vstate.key_set = 0;
}

void monero_init_private_key() {
  unsigned int  path[5];
  unsigned char seed[32];

  // m/44'/128'/0'/0/0
  path[0] = 0x8000002C;
  path[1] = 0x80000080;
  path[2] = 0x80000000;
  path[3] = 0x00000000;
  path[4] = 0x00000000;

  switch(N_monero_pstate->key_mode) {
  case KEY_MODE_SEED:
    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, 5 , seed, G_monero_vstate.a);

    monero_keccak_F(seed,32,G_monero_vstate.b);
    monero_reduce(G_monero_vstate.b,G_monero_vstate.b);
    monero_keccak_F(G_monero_vstate.b,32,G_monero_vstate.a);
    monero_reduce(G_monero_vstate.a,G_monero_vstate.a);
    break;

  case KEY_MODE_EXTERNAL:
    os_memmove(G_monero_vstate.a,  N_monero_pstate->a, 32);
    os_memmove(G_monero_vstate.b,  N_monero_pstate->b, 32);
    break;

  default :
    THROW(SW_SECURITY_LOAD_KEY);
    return;
  }
  
  monero_ecmul_G(G_monero_vstate.A, G_monero_vstate.a);
  monero_ecmul_G(G_monero_vstate.B, G_monero_vstate.b);
  G_monero_vstate.key_set = 1;
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
