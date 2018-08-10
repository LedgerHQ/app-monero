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

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
static const unsigned int crcTable[256] = {
   0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
   0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
   0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
   0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
   0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
   0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
   0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
   0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
   0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
   0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
   0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
   0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
   0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
   0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
   0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
   0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
   0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
   0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
   0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
   0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
   0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
   0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
   0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
   0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
   0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
   0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
   0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
   0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
   0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
   0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
   0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
   0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
   0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
   0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
   0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
   0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
   0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };

static unsigned long monero_crc32( unsigned long inCrc32, const void *buf,
                                       size_t bufLen )
{
    
    unsigned long crc32;
    unsigned char *byteBuf;
    size_t i;

    /** accumulate crc32 for buffer **/
    crc32 = inCrc32 ^ 0xFFFFFFFF;
    byteBuf = (unsigned char*) buf;
    for (i=0; i < bufLen; i++) {
        crc32 = (crc32 >> 8) ^ crcTable[ (crc32 ^ byteBuf[i]) & 0xFF ];
    }
    return( crc32 ^ 0xFFFFFFFF );
}


void monero_clear_words() {
  for (int i = 0; i<25; i++) {
    monero_nvm_write(N_monero_pstate->words[i], NULL,WORDS_MAX_LENGTH);
  }
}
/**
 * n :  word to write
 * idx: index of word to copy
 * w_start: first wordd index in list
 * word_list
 * len : word_list length
 */

static void  monero_set_word(unsigned int n, unsigned int idx, unsigned int w_start, unsigned char* word_list, int len) {
  while (w_start < idx) {
    len -= 1 + word_list[0];
    if (len < 0) {
      monero_clear_words();
      THROW(SW_WRONG_DATA+1);
      return;
    }
    word_list += 1 + word_list[0];
    w_start++;
  }
  
  if ((w_start != idx) || (word_list[0] > (len-1)) || (word_list[0] > 19)) {
    THROW(SW_WRONG_DATA+2);
    return;
  }
  len = word_list[0];
  word_list++;
  monero_nvm_write(N_monero_pstate->words[n], word_list, len);
}

#define word_list_length 1626
#define seed G_monero_vstate.b

int monero_apdu_manage_seedwords() {
  unsigned int w_start, w_end;
  unsigned short wc[4]; 
  switch (G_monero_vstate.io_p1) {
    //SETUP
  case 1:
    w_start = monero_io_fetch_u32();
    w_end   = w_start+monero_io_fetch_u32();
    if ((w_start >= word_list_length) || (w_end > word_list_length) || (w_start > w_end)) {
      THROW(SW_WRONG_DATA);
      return SW_WRONG_DATA;
    }
    for (int i = 0; i<8; i++) {
      unsigned int val = (seed[i*4+0]<<0) | (seed[i*4+1]<<8) | (seed[i*4+2]<<16) | (seed[i*4+3]<<24);
      wc[0] = val % word_list_length;
      wc[1] = ((val / word_list_length) +  wc[0]) % word_list_length;
      wc[2] = (((val / word_list_length) / word_list_length) +  wc[1]) % word_list_length;

      for (int wi = 0; wi < 3; wi++) {
        if ((wc[wi] >= w_start) && (wc[wi] < w_end)) {
          monero_set_word(i*3+wi, wc[wi], w_start, G_monero_vstate.io_buffer+G_monero_vstate.io_offset, MONERO_IO_BUFFER_LENGTH-G_monero_vstate.io_offset);
        }
      }
    }
    
    monero_io_discard(1);
    if (G_monero_vstate.io_p2) {
      for (int i = 0; i<24; i++) {
        for (int j = 0; j<G_monero_vstate.io_p2; j++) {
          G_monero_vstate.io_buffer[i*G_monero_vstate.io_p2+j] = N_monero_pstate->words[i][j];
        }
      }
      w_start = monero_crc32(0, G_monero_vstate.io_buffer, G_monero_vstate.io_p2*24)%24;
      monero_nvm_write(N_monero_pstate->words[24], N_monero_pstate->words[w_start], WORDS_MAX_LENGTH);
    }
    
    break;

    //CLEAR
  case 2:
    monero_io_discard(0);
    monero_clear_words();    
    break;
  }

 return SW_OK;
}
#undef seed
#undef word_list_length

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

  //spend key
  monero_io_fetch(sec, 32);
  monero_io_fetch(pub, 32);
  monero_ecmul_G(raw,sec);
  if (os_memcmp(pub, raw, 32)) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }
  nvm_write(N_monero_pstate->b, sec, 32);

  
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

  monero_io_discard(1);
  switch (G_monero_vstate.io_p1) {
  //get pub
  case 1:
    //view key
    monero_io_insert(G_monero_vstate.A, 32);
    //spend key
    monero_io_insert(G_monero_vstate.B, 32);
    //public base address
    monero_base58_public_key((char*)G_monero_vstate.io_buffer+G_monero_vstate.io_offset, G_monero_vstate.A, G_monero_vstate.B, 0);
    monero_io_inserted(95);
    break;

  //get private
  case 2:
    //view key
    ui_export_viewkey_display();
    return 0;

  #if DEBUG_HWDEVICE
  //get info
  case 3:{
    unsigned int  path[5];
    unsigned char seed[32];
    
    // m/44'/128'/0'/0/0
    path[0] = 0x8000002C;
    path[1] = 0x80000080;
    path[2] = 0x80000000;
    path[3] = 0x00000000;
    path[4] = 0x00000000;

    os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, 5 , seed, G_monero_vstate.a);
    monero_io_insert(seed, 32);

    monero_io_insert(G_monero_vstate.b, 32);
    monero_io_insert(G_monero_vstate.a, 32);

    break;
    }
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
    os_memmove(pub, G_monero_vstate.A, 32);
    break;
  case 2:
    os_memmove(pub, G_monero_vstate.B, 32);
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
  monero_base58_public_key((char*)G_monero_vstate.io_buffer+G_monero_vstate.io_offset, G_monero_vstate.A,G_monero_vstate.B, 0);
  monero_io_inserted(95);
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
  unsigned char drv[32];
  //fetch
  monero_io_fetch(pub,32);
  monero_io_fetch_decrypt_key(sec);

  monero_io_discard(0);

  //Derive  and keep
  monero_generate_key_derivation(drv, pub, sec);

  monero_io_insert_encrypt(drv,32);
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
  monero_io_set_offset(0);
  monero_io_insert_encrypt(drvsec,32);
  monero_io_set_offset(IO_OFFSET_END);
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
