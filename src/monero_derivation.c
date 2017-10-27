
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

#if 0
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_secret_key() {
  
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_public_key() {
 
  return SW_OK;
}
#endif
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_key_derivation() {
  unsigned char P[32];
  unsigned char s[32];
  unsigned char D[32];
  unsigned char *ps;

  //fetch P,s
  monero_io_fetch(P,32);
  switch (G_monero_vstate.io_p1&0x0F) {
  case 0x00:
     ps =  N_monero_pstate->a;
     break;
  case 0x01:
     monero_io_fetch_decrypt(s,32);
     ps = s;
     break;
  default:
    THROW(SW_INCORRECT_P1P2);
    return SW_INCORRECT_P1P2;
  }
  monero_io_discard(0);

  //Derive D
  monero_gerenrate_key_derivation(D, P, ps);

  //ret
  switch (G_monero_vstate.io_p1&0xF0) {
  case 0x00:
    monero_io_insert(D,32);
    break;
  case 0x10:
    monero_io_insert_encrypt(D,32);
    break;
  default:
    THROW(SW_INCORRECT_P1P2);
    return SW_INCORRECT_P1P2;
  }
  return SW_OK;
}

