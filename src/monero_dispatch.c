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



void check_potocol()  {
  /* the first command enforce the protocol version until application quits */
  switch(G_monero_vstate.io_protocol_version) {
   case 0x00: /* the first one: PCSC epoch */
   case 0x02: /* protocol V2 */
    if (G_monero_vstate.protocol == 0xff) {
      G_monero_vstate.protocol = G_monero_vstate.io_protocol_version;
    }
    if (G_monero_vstate.protocol == G_monero_vstate.io_protocol_version) {
        break;
    }
    //unknown protocol or hot protocol switch is not allowed
    //FALL THROUGH

   default:
    THROW(SW_CLA_NOT_SUPPORTED);
    return ;
  }
}

void check_ins_access() {

  if (G_monero_vstate.key_set != 1) {
    THROW(SW_CONDITIONS_NOT_SATISFIED);
    return;
  }

  switch (G_monero_vstate.io_ins) {
  case INS_RESET:
  case INS_PUT_KEY:
  case INS_GET_KEY:
  case INS_DISPLAY_ADDRESS:
  case INS_VERIFY_KEY:
  case INS_GET_CHACHA8_PREKEY:
  case INS_GEN_KEY_DERIVATION:
  case INS_DERIVATION_TO_SCALAR:
  case INS_DERIVE_PUBLIC_KEY:
  case INS_DERIVE_SECRET_KEY:
  case INS_GEN_KEY_IMAGE:
  case INS_SECRET_KEY_TO_PUBLIC_KEY:
  case INS_SECRET_KEY_ADD:
  case INS_SECRET_KEY_SUB:
  case INS_GENERATE_KEYPAIR:
  case INS_SECRET_SCAL_MUL_KEY:
  case INS_SECRET_SCAL_MUL_BASE:
  case INS_DERIVE_SUBADDRESS_PUBLIC_KEY:
  case INS_GET_SUBADDRESS:
  case INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY:
  case INS_GET_SUBADDRESS_SECRET_KEY:
  case INS_MANAGE_SEEDWORDS:
  case INS_UNBLIND:
  case INS_STEALTH:
  case INS_GET_TX_PROOF:
  case INS_CLOSE_TX:
    return;

  case INS_OPEN_TX:
  case INS_SET_SIGNATURE_MODE:
    if (os_global_pin_is_validated() != PIN_VERIFIED) {
      break;
    }
    return;

  case INS_GEN_TXOUT_KEYS:
  case INS_BLIND:
  case INS_VALIDATE:
  case INS_MLSAG:
  case INS_GEN_COMMITMENT_MASK:
    if ((os_global_pin_is_validated() != PIN_VERIFIED) ||
        (G_monero_vstate.tx_in_progress != 1)) {
      break;
    }
    return;
  }

  THROW(SW_CONDITIONS_NOT_SATISFIED);
  return;

}

int monero_dispatch() {

  int sw;

  check_potocol();
  check_ins_access();

  G_monero_vstate.options = monero_io_fetch_u8();

  if (G_monero_vstate.io_ins == INS_RESET) {
    sw = monero_apdu_reset();
    return sw;
  }

  sw = 0x6F01;

  switch (G_monero_vstate.io_ins) {

    /* --- START TX --- */
  case INS_OPEN_TX:
    sw = monero_apdu_open_tx();
    break;

  case INS_CLOSE_TX:
    sw = monero_apdu_close_tx();
    break;

     /* --- SIG MODE --- */
  case INS_SET_SIGNATURE_MODE:
    sw = monero_apdu_set_signature_mode();
    break;

    /* --- STEATH PAYMENT --- */
  case INS_STEALTH:
    if ((G_monero_vstate.io_p1 != 0) ||
        (G_monero_vstate.io_p2 != 0)) {
      THROW(SW_WRONG_P1P2);
    }
    sw = monero_apdu_stealth();
    break;

   /* --- KEYS --- */
  case INS_PUT_KEY:
    sw = monero_apdu_put_key();
    break;
  case INS_GET_KEY:
    sw = monero_apdu_get_key();
    break;
  case INS_DISPLAY_ADDRESS:
    sw = monero_apdu_display_address();
    break;
  case INS_MANAGE_SEEDWORDS:
    sw = monero_apdu_manage_seedwords();
    break;

   /* --- PROVISIONING--- */
  case INS_VERIFY_KEY:
    sw = monero_apdu_verify_key();
    break;
  case INS_GET_CHACHA8_PREKEY:
    sw = monero_apdu_get_chacha8_prekey();
    break;
  case INS_SECRET_KEY_TO_PUBLIC_KEY:
    sw = monero_apdu_secret_key_to_public_key();
    break;
  case INS_GEN_KEY_DERIVATION:
    sw = monero_apdu_generate_key_derivation();
    break;
  case INS_DERIVATION_TO_SCALAR:
    sw = monero_apdu_derivation_to_scalar();
    break;
  case INS_DERIVE_PUBLIC_KEY:
    sw = monero_apdu_derive_public_key();
    break;
  case INS_DERIVE_SECRET_KEY:
    sw = monero_apdu_derive_secret_key();
    break;
  case INS_GEN_KEY_IMAGE:
    sw = monero_apdu_generate_key_image();
    break;
  case INS_SECRET_KEY_ADD:
    sw = monero_apdu_sc_add();
    break;
  case INS_SECRET_KEY_SUB:
    sw = monero_apdu_sc_sub();
    break;
  case INS_GENERATE_KEYPAIR:
    sw = monero_apdu_generate_keypair();
    break;
  case INS_SECRET_SCAL_MUL_KEY:
    sw = monero_apdu_scal_mul_key();
    break;
  case INS_SECRET_SCAL_MUL_BASE:
    sw = monero_apdu_scal_mul_base();
    break;

  /* --- ADRESSES --- */
  case INS_DERIVE_SUBADDRESS_PUBLIC_KEY:
    sw = monero_apdu_derive_subaddress_public_key();
    break;
  case INS_GET_SUBADDRESS:
    sw = monero_apdu_get_subaddress();
    break;
  case INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY:
     sw = monero_apdu_get_subaddress_spend_public_key();
    break;
  case INS_GET_SUBADDRESS_SECRET_KEY:
    sw = monero_apdu_get_subaddress_secret_key();
    break;

    /* --- PROOF --- */

  case INS_GET_TX_PROOF:
    sw = monero_apdu_get_tx_proof();
    break;

    /* --- TX OUT KEYS --- */
  case INS_GEN_TXOUT_KEYS:
    sw = monero_apu_generate_txout_keys();
    break;

    /*--- COMMITMENT MASK --- */
  case INS_GEN_COMMITMENT_MASK:
    sw = monero_apdu_gen_commitment_mask();
    break;

    /* --- BLIND --- */
  case INS_BLIND:
    sw = monero_apdu_blind();
    break;
  case INS_UNBLIND:
    sw = monero_apdu_unblind();
    break;

    /* --- VALIDATE/PREHASH --- */
  case INS_VALIDATE:
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_apdu_mlsag_prehash_init();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_apdu_mlsag_prehash_update();
    }  else if (G_monero_vstate.io_p1 == 3) {
      sw = monero_apdu_mlsag_prehash_finalize();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;

  /* --- MLSAG --- */
  case INS_MLSAG:
    if (G_monero_vstate.io_p1 == 1) {
      sw = monero_apdu_mlsag_prepare();
    }  else if (G_monero_vstate.io_p1 == 2) {
      sw = monero_apdu_mlsag_hash();
    }  else if (G_monero_vstate.io_p1 == 3) {
      sw = monero_apdu_mlsag_sign();
    } else {
      THROW(SW_WRONG_P1P2);
    }
    break;

  /* --- KEYS --- */

  default:
    THROW(SW_INS_NOT_SUPPORTED);
    break;
  }
  return sw;
}
