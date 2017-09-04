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

#define STATE(ins,p1)  ((INS_##ins<<8)|(p1))

void monero_reset_state_machine() {
   G_monero_vstate.state = STATE(NONE,0);
}


void monero_ensure_state_machine() {
  int next_state = (G_monero_vstate.io_ins<<8)| G_monero_vstate.io_p1;

  switch (G_monero_vstate.state) {
    case STATE(NONE,0):
    if  (next_state == STATE(OPEN_TX,1))  {
      break;
    }
    goto _default;

  case STATE(OPEN_TX,1):
    if ( (next_state == STATE(OPEN_TX,2)) || 
         (next_state == STATE(STEALTH,0)) || 
         (next_state == STATE(PROCESS_INPUT,1)) ) {
      break;
    }
    goto _default;

  case STATE(OPEN_TX,2):
    if ( (next_state == STATE(STEALTH,0)) || 
         (next_state == STATE(PROCESS_INPUT,1)) ) {
      break;
    }
    break;

  case STATE(PROCESS_INPUT,1):
    if (next_state == STATE(PROCESS_INPUT,2)) {
      break;
    }
    goto _default;

  case STATE(PROCESS_INPUT,2):
    if ( (next_state == STATE(PROCESS_INPUT, 1)) || 
         (next_state == STATE(PROCESS_OUTPUT,0)) ) {
      break;
    }
    goto _default;

  case STATE(PROCESS_OUTPUT,0):
    if ( (next_state == STATE(PROCESS_OUTPUT,0)) || 
         (next_state == STATE(BLIND,0))  ) {
      break;
    }
    goto _default;

  case STATE(BLIND,0):
    if ( (next_state == STATE(BLIND,0)) || 
         (next_state == STATE(MLSAG,1))  ) {
      break;
    }
   goto _default;

  case STATE(MLSAG,1):
    if (next_state == STATE(MLSAG,2)) {
      break;
    }
    goto _default;

  case STATE(MLSAG,2):
    if ( (next_state == STATE(MLSAG,2))|| 
         (next_state == STATE(MLSAG,3)) ) {
      break;
    }
    goto _default;

  default:
  _default:
    THROW(SW_CONDITIONS_NOT_SATISFIED);
    return ;
  }

  G_monero_vstate.state = next_state;
  return;
}


int monero_dispatch() {

  int sw;

  if ((G_monero_vstate.io_cla != 0x00) && (G_monero_vstate.io_cla != 0x10)) {
    THROW(SW_CLA_NOT_SUPPORTED);
    return SW_CLA_NOT_SUPPORTED;
  }

  monero_ensure_state_machine();
  
  sw = 0x6F01;

  switch (G_monero_vstate.io_ins) {

    /* --- START TX --- */
  case INS_OPEN_TX:  
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_open_tx();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_open_subtx();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;
  
    /* --- STEATH PAYMENT --- */
  case INS_STEALTH:
    sw = monero_stealth();
    break;

    /* --- PROCESS IN TX */
  case INS_PROCESS_INPUT:
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_get_derivation_data();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_get_input_key();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;


    /* --- PROCESS OUT TX */
  case INS_PROCESS_OUTPUT:
    sw = monero_get_output_key();
    break;

    /* --- RANGE PROOF */
  case INS_BLIND:
    sw = monero_blind();
    break;

    /* --- MLSAG -- */
  case INS_MLSAG:
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_init_mlsag();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_update_mlsag();
    }  else if (G_monero_vstate.io_p1 == 3) {
      sw = monero_finalize_mlsag();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;

  default:
    THROW(SW_INS_NOT_SUPPORTED);
    return SW_INS_NOT_SUPPORTED;
    break;
  }

  return sw;
}
