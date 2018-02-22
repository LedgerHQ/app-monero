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


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_put_key() {


  unsigned char raw[32];
  unsigned char pub[32];
  unsigned char sec[32];

  if (G_monero_vstate.io_length != (32*2 + 32*2 + 95)) {
    THROW(SW_WRONG_LENGTH);
    return SW_WRONG_LENGTH;
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


  //change mode
  unsigned char key_mode = KEY_MODE_EXTERNAL;
  nvm_write(&N_monero_pstate->key_mode, &key_mode, 1);

  monero_io_discard(1);

  return SW_OK;
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_key() {

  monero_io_discard(0);
  switch (G_monero_vstate.io_p1) {
  //get pub
  case 1:
    //view key
    monero_io_insert(N_monero_pstate->A, 32);
    //spend key
    monero_io_insert(N_monero_pstate->B, 32);
    //public base (_ address
    monero_io_insert((unsigned char*)N_monero_pstate->public_address, 95);
    break;

#ifdef DEBUGLEDGER
  //get private
  case 2:
    //view key
    monero_io_insert_encrypt(G_monero_vstate.a, 32);
    //spend key
    monero_io_insert_encrypt(G_monero_vstate.b, 32);
    //view key
    monero_io_insert(G_monero_vstate.a, 32);
    //spend key
    monero_io_insert(G_monero_vstate.b, 32);
    break;
#endif
  default:
    THROW(SW_WRONG_P1P2);
    return SW_WRONG_P1P2;
  }
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_verify_key() {
  unsigned char pub[32];
  unsigned char priv[32];
  unsigned char computed_pub[32];
  unsigned int verified = 0;

  monero_io_fetch_decrypt_key(priv);
  monero_io_fetch(pub, 32);
  switch (G_monero_vstate.io_p1) {
  case 0:
    monero_secret_key_to_public_key(computed_pub, priv);
    break;
  case 1:
    os_memmove(pub, N_monero_pstate->A, 32);
    break;
  case 2:
    os_memmove(pub, N_monero_pstate->B, 32);
    break;
  default:
    THROW(SW_WRONG_P1P2);
    return SW_WRONG_P1P2;
  }
  if (os_memcmp(computed_pub, pub, 32) ==0 ) {
    verified = 1;
  }

  monero_io_discard(1);
  monero_io_insert_u32(verified);
  monero_io_insert((void*)N_monero_pstate->public_address, 95);
  return SW_OK;
}



/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
#define CHACHA8_KEY_TAIL 0x8c
int monero_apdu_get_chacha8_prekey(/*char  *prekey*/) {
  unsigned char abt[65];
  unsigned char pre[32];

  monero_io_discard(0);
  os_memmove(abt, G_monero_vstate.a, 32);
  os_memmove(abt+32, G_monero_vstate.b, 32);
  abt[64] = CHACHA8_KEY_TAIL;
  monero_keccak_F(abt, 65, pre);
  monero_io_insert((unsigned char*)G_monero_vstate.keccakF.acc, 200);
  return SW_OK;
}
#undef CHACHA8_KEY_TAIL

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_sc_add(/*unsigned char *r, unsigned char *s1, unsigned char *s2*/) {
  unsigned char s1[32];
  unsigned char s2[32];
  unsigned char r[32];
  //fetch
  monero_io_fetch_decrypt(s1,32);
  monero_io_fetch_decrypt(s2,32);
  monero_io_discard(0);
  monero_addm(r,s1,s2);
  monero_io_insert_encrypt(r,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_sc_sub(/*unsigned char *r, unsigned char *s1, unsigned char *s2*/) {
  unsigned char s1[32];
  unsigned char s2[32];
  unsigned char r[32];
  //fetch
  monero_io_fetch_decrypt(s1,32);
  monero_io_fetch_decrypt(s2,32);
  monero_io_discard(0);
  monero_subm(r,s1,s2);
  monero_io_insert_encrypt(r,32);
  return SW_OK;
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_scal_mul_key(/*const rct::key &pub, const rct::key &sec, rct::key mulkey*/) {
  unsigned char pub[32];
  unsigned char sec[32];
  unsigned char r[32];
  //fetch
  monero_io_fetch(pub,32);
  monero_io_fetch_decrypt(sec,32);
  monero_io_discard(0);

  monero_ecmul_k(r,pub,sec);
  monero_io_insert(r, 32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_scal_mul_base(/*const rct::key &sec, rct::key mulkey*/) {
  unsigned char sec[32];
  unsigned char r[32];
  //fetch
  monero_io_fetch_decrypt(sec,32);
  monero_io_discard(0);

  monero_ecmul_G(r,sec);
  monero_io_insert(r, 32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_keypair(/*crypto::public_key &pub, crypto::secret_key &sec*/) {
  unsigned char sec[32];
  unsigned char pub[32];

  monero_io_discard(0);
  monero_generate_keypair(pub,sec);
  monero_io_insert(pub,32);
  monero_io_insert_encrypt(sec,32);
  return SW_OK;
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_secret_key_to_public_key(/*const crypto::secret_key &sec, crypto::public_key &pub*/) {
  unsigned char sec[32];
  unsigned char pub[32];
  //fetch
  monero_io_fetch_decrypt(sec,32);
  monero_io_discard(0);
  //pub
  monero_ecmul_G(pub,sec);
  //pub key
  monero_io_insert(pub,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_key_derivation(/*const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation*/) {
  unsigned char pub[32];
  unsigned char sec[32];
  //fetch
  monero_io_fetch(pub,32);
  monero_io_fetch_decrypt_key(sec);

  monero_io_discard(0);

  //Derive  and keep
  monero_generate_key_derivation(G_monero_vstate.Dinout, pub, sec);

  monero_io_insert_encrypt(G_monero_vstate.Dinout,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derivation_to_scalar(/*const crypto::key_derivation &derivation, const size_t output_index, ec_scalar &res*/) {
  unsigned char derivation[32];
  unsigned int  output_index;
  unsigned char res[32];

  //fetch
  monero_io_fetch_decrypt(derivation,32);
  output_index = monero_io_fetch_u32();
  monero_io_discard(0);

  //pub
  monero_derivation_to_scalar(res, derivation, output_index);

  //pub key
  monero_io_insert_encrypt(res,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_public_key(/*const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub, public_key &derived_pub*/) {
  unsigned char derivation[32];
  unsigned int  output_index;
  unsigned char pub[32];
  unsigned char drvpub[32];

  //fetch
  monero_io_fetch_decrypt(derivation,32);
  output_index = monero_io_fetch_u32();
  monero_io_fetch(pub, 32);
  monero_io_discard(0);

  //pub
  monero_derive_public_key(drvpub, derivation, output_index, pub);

  //pub key
  monero_io_insert(drvpub,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_secret_key(/*const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec, secret_key &derived_sec*/){
  unsigned char derivation[32];
  unsigned int  output_index;
  unsigned char sec[32];
  unsigned char drvsec[32];

  //fetch
  monero_io_fetch_decrypt(derivation,32);
  output_index = monero_io_fetch_u32();
  monero_io_fetch_decrypt_key(sec);
  monero_io_discard(0);

  //pub
  monero_derive_secret_key(drvsec, derivation, output_index, sec);

  //pub key
  monero_io_insert_encrypt(drvsec,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_key_image(/*const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image*/){
  unsigned char pub[32];
  unsigned char sec[32];
  unsigned char image[32];

  //fetch
  monero_io_fetch(pub,32);
  monero_io_fetch_decrypt(sec, 32);
  monero_io_discard(0);

  //pub
  monero_generate_key_image(image, pub, sec);

  //pub key
  monero_io_insert(image,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_subaddress_public_key(/*const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index, public_key &derived_pub*/) {
  unsigned char pub[32];
  unsigned char derivation[32];
  unsigned int  output_index;
  unsigned char sub_pub[32];

  //fetch
  monero_io_fetch(pub,32);
  monero_io_fetch_decrypt(derivation, 32);
  output_index = monero_io_fetch_u32();
  monero_io_discard(0);

  //pub
  monero_derive_subaddress_public_key(sub_pub, pub, derivation, output_index);
  //pub key
  monero_io_insert(sub_pub,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_subaddress(/*const cryptonote::subaddress_index& index, cryptonote::account_public_address &address*/) {
  unsigned char index[8];
  unsigned char C[32];
  unsigned char D[32];

  //fetch
  monero_io_fetch(index,8);
  monero_io_discard(0);

  //pub
  monero_get_subaddress(C,D,index);

  //pub key
  monero_io_insert(C,32);
  monero_io_insert(D,32);
  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_subaddress_spend_public_key(/*const cryptonote::subaddress_index& index, crypto::public_key D*/) {
  unsigned char index[8];
  unsigned char D[32];

  //fetch
  monero_io_fetch(index,8);
  monero_io_discard(1);

  //pub
  monero_get_subaddress_spend_public_key(D, index);

  //pub key
  monero_io_insert(D,32);

  return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_subaddress_secret_key(/*const crypto::secret_key& sec, const cryptonote::subaddress_index& index, crypto::secret_key &sub_sec*/) {
  unsigned char sec[32];
  unsigned char index[8];
  unsigned char sub_sec[32];

  monero_io_fetch_decrypt_key(sec);
  monero_io_fetch(index,8);
  monero_io_discard(0);

  //pub
  monero_get_subaddress_secret_key(sub_sec,sec,index);

  //pub key
  monero_io_insert_encrypt(sub_sec,32);
  return SW_OK;
}




