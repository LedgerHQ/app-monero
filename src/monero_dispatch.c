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

enum monero_state_e{
    STATE_NONE,

    STATE_TX_OPENED,
    STATE_TX_SUBOPENED,

    STATE_STEALH_PAID,

    STATE_INith_DERIVATTION_RETRIEVED,
    STATE_INith_KEY_RETRIEVED,
    STATE_INPUTS_PROCESSED,

    STATE_OUTjth_KEY_RETRIEVED,
    STATE_OUTPUTS_PROCESSED,

    STATE_OUTith_BLINDED,
    STATE_OUTPUTS_BLINDED,

    STATE_VALIDATE_INITED,
    STATE_OUTith_VALIDATED,
    STATE_OUTPUTS_VALIDATED,
    STATE_OUTPUTS_HASHED,

    STATE_MLSAG_INith_PREPARED,
    STATE_MLSAG_PREPARED,
    STATE_MLSAG_STARTED,
    STATE_MSLSAG_INith_DONE,
    STATE_MSLSAG_DONE,

    STATE_TX_CLOSED
} ;

#define OP(ins,p1)  (((ins)<<8)|(p1))

void monero_reset_state_machine() {
    G_monero_vstate.state = STATE_NONE;
}

void monero_check_state_machine() {
    switch (G_monero_vstate.state) {

#define RECEIVE_OP OP(G_monero_vstate.io_ins, G_monero_vstate.io_p1)

    /* -- INS OPEN TX -- */
    
    case STATE_NONE : 
    case STATE_TX_CLOSED:
        if (RECEIVE_OP == OP(INS_OPEN_TX,1)) {
            return;
        }//  => STATE_TX_OPENED
        break;

    case STATE_TX_OPENED :
        if ( (RECEIVE_OP == OP(INS_OPEN_TX,2)) ||
             (RECEIVE_OP == OP(INS_PROCESS_INPUT,1))  ||
             (RECEIVE_OP == OP(INS_STEALTH,1)) ) {
            return;
        }// => STATE_TX_SUBOPENED
        break;
  

    /* -- INS STEALTH -- */
    
    case STATE_TX_SUBOPENED :
        if ( (RECEIVE_OP == OP(INS_STEALTH,1)) ||
             (RECEIVE_OP == OP(INS_PROCESS_INPUT,1)) ) {
          return;
        } // => STATE_STEALH_PAID
        break;
  
    /** -- INS PROCESS INPUT -- */

    case STATE_STEALH_PAID :
    case STATE_INith_KEY_RETRIEVED :
        if (RECEIVE_OP == OP(INS_PROCESS_INPUT,1)) {
            return;
        } // => STATE_INith_DERIVATTION_RETRIEVED
        break;

    case STATE_INith_DERIVATTION_RETRIEVED :
        if (RECEIVE_OP == OP(INS_PROCESS_INPUT,2)) {
            return;
        }// => STATE_INith_KEY_RETRIEVED, STATE_INPUTS_PROCESSED
        break;
  
    /** -- INS PROCESS OUTPUT -- */

     case STATE_INPUTS_PROCESSED:
     case STATE_OUTjth_KEY_RETRIEVED:
       if (RECEIVE_OP == OP(INS_PROCESS_OUTPUT,1)) {
            return;
        } // => STATE_OUTjth_KEY_RETRIEVED, STATE_OUPUTS_PROCESSED
  
    /** -- INS BLIND -- */

    case STATE_OUTPUTS_PROCESSED:
    case STATE_OUTith_BLINDED:
        if (RECEIVE_OP == OP(INS_BLIND,1)) {
            return;
        } // => STATE_OUTith_BLINDED, STATE_OUT_BLINDED
        break;

    /* -- INS VALIDATE -- */

    case STATE_OUTPUTS_BLINDED :
        if (RECEIVE_OP == OP(INS_VALIDATE,1)) {
            return;
        } // => STATE_VALIDATE_INITED
        break;
  
    case STATE_VALIDATE_INITED :
    case STATE_OUTith_VALIDATED:
        if (RECEIVE_OP == OP(INS_VALIDATE,2)) {
            return;
        } // => STATE_OUTith_VALIDATED, STATE_OUTPUTS_VALIDATED
        break;
  
    case STATE_OUTPUTS_VALIDATED:
        if (RECEIVE_OP == OP(INS_VALIDATE,3)) {
            return;
        } //=> STATE_OUTPUTS_HASHED
        break;

    /* -- INS MLSAG -- */

    case STATE_OUTPUTS_HASHED:
    case STATE_MLSAG_INith_PREPARED:
        if (RECEIVE_OP == OP(INS_MLSAG,1)) {
            return;
        } // => STATE_MLSAG_INith_PREPARED, STATE_MLSAG_PREPARED
        break;
     
    case STATE_MLSAG_PREPARED:
        if (RECEIVE_OP == OP(INS_MLSAG,2)) {
            return;
        } //=> STATE_MLSAG_STARTED
        break;

    case STATE_MLSAG_STARTED:
    case STATE_MSLSAG_INith_DONE:
        if (RECEIVE_OP == OP(INS_MLSAG,3)) {
            return;
        } //=> STATE_MSLSAG_INith_SIGNED, STATE_TX_CLOSED
        break;

    }
    THROW(SW_CLA_NOT_SUPPORTED);
    return ;
}



int monero_dispatch() {

  int sw;

  if ((G_monero_vstate.io_cla != 0x00) && (G_monero_vstate.io_cla != 0x10)) {
    THROW(SW_CLA_NOT_SUPPORTED);
    return SW_CLA_NOT_SUPPORTED;
  }


  if (G_monero_vstate.io_ins == INS_PUT_KEY) {
    //TODO : Insert user confirmation here
    sw = monero_apdu_put_key();
    return sw;
  }

  G_monero_vstate.options = monero_io_fetch_u8();
  monero_check_state_machine();
  
  sw = 0x6F01;

  switch (G_monero_vstate.io_ins) {

    /* --- START TX --- */
  case INS_OPEN_TX:  
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_apdu_open_tx();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_apdu_open_subtx();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;
  
    /* --- STEATH PAYMENT --- */
  case INS_STEALTH:
    sw = monero_apdu_stealth();
    break;

    /* --- PROCESS IN TX */
  case INS_PROCESS_INPUT:

    if (G_monero_vstate.io_p1 == 1) {

      sw = monero_apdu_get_derivation_data();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_apdu_get_input_key();      
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;


    /* --- PROCESS OUT TX */
  case INS_PROCESS_OUTPUT:
    sw = monero_apdu_get_output_key();
    break;

    /* --- RANGE PROOF */
  case INS_BLIND:
    sw = monero_apdu_blind();
    break;

    /* --- VALIDATE-- */
  case INS_VALIDATE:
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_apdu_init_validate();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_apdu_update_validate_pre_validation();
    }  else if (G_monero_vstate.io_p1 == 3) {
      sw = monero_apdu_finalize_validate();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;

  /* --- MLSAG-- */
  case INS_MLSAG:
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_apdu_mlsag_prepare();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_apdu_mlsag_start();
    }  else if (G_monero_vstate.io_p1 == 3) {
      sw = monero_apdu_mlsag_sign();
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
