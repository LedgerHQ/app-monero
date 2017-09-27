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

#ifndef MONERO_API_H
#define  MONERO_API_H


void monero_init(void);
void monero_init_ux(void);
int  monero_install(unsigned char app_state) ;
int  monero_dispatch(void);

int monero_apdu_put_key();

int monero_apdu_open_tx(void);
int monero_apdu_open_subtx(void) ;

int monero_apdu_stealth();

int monero_apdu_get_derivation_data(void) ;
int monero_apdu_get_input_key(void);

int monero_apdu_get_output_key(void);

int monero_apdu_blind(void);

int monero_apdu_init_validate(void) ;
int monero_apdu_update_validate_pre_validation(void) ;
int monero_apdu_update_validate_post_validation(void) ;
int monero_apdu_finalize_validate(void);

int monero_apdu_mlsag_prepare();
int monero_apdu_mlsag_start();
int monero_apdu_mlsag_sign();


 
/* ----------------------------------------------------------------------- */
/* ---                              CRYPTO                            ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_ED25519_ORDER[];


void monero_aes_derive(cx_aes_key_t *sk, unsigned char *R, unsigned char *a, unsigned char *b);
void monero_aes_generate(cx_aes_key_t *sk);

/* Compute Monero-Hash of data*/
void monero_hash_init_keccak(cx_hash_t * hasher);
void monero_hash_init_sha256(cx_hash_t * hasher);
void monero_hash_update(cx_hash_t * hasher, unsigned char* buf, unsigned int len) ;
int  monero_hash_final(cx_hash_t * hasher, unsigned char* out);
int  monero_hash(cx_hash_t * hasher, unsigned char* buf, unsigned int len, unsigned char* out);

#define monero_hash_init_H() \
    monero_hash_init_keccak((cx_hash_t *)&G_monero_vstate.keccakH)
#define monero_hash_update_H(buf,len)  \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.keccakH,(buf), (len))
#define monero_hash_final_H(out) \
    monero_hash_final((cx_hash_t *)&G_monero_vstate.keccakH, (out)?(out):G_monero_vstate.H)
#define monero_hash_H(buf,len,out) \
    monero_hash((cx_hash_t *)&G_monero_vstate.keccakH, (buf),(len), (out)?(out):G_monero_vstate.H)

#define monero_hash_init_C() \
    monero_hash_init_sha256((cx_hash_t *)&G_monero_vstate.sha256C)
#define monero_hash_update_C(buf,len) \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.sha256C,(buf), (len))
#define monero_hash_final_C(out) \
    monero_hash_final((cx_hash_t *)&G_monero_vstate.sha256C, (out)?(out):G_monero_vstate.C)
#define monero_hash_C(buf,len,out) \
    monero_hash((cx_hash_t *)&G_monero_vstate.sha256C, (buf), (len), (out)?(out):G_monero_vstate.C)

#define monero_hash_init_L() \
    monero_hash_init_sha256((cx_hash_t *)&G_monero_vstate.sha256L)
#define monero_hash_update_L(buf,len) \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.sha256L, (buf), (len))
#define monero_hash_final_L(out) \
    monero_hash_final((cx_hash_t *)&G_monero_vstate.sha256L, (out)?(out):G_monero_vstate.L)
#define monero_hash_L(buf,len,out) \
    monero_hash((cx_hash_t *)&G_monero_vstate.sha256L, (buf), (len), (out)?(out):G_monero_vstate.L)

/**
 * LE-7-bits encoding. High bit set says one more byte to decode.
 */
unsigned int monero_encode_varint(unsigned char varint[8], unsigned int out_idx);
 
/*
 *  compute s = 8 * (k*P)
 *
 * s [out] 32 bytes derivation value
 * P [in]  point in 02 y or 04 x y format
 * k [in]  32 bytes scalar
 */
void monero_derive_dh(unsigned char *s, unsigned char *P, unsigned char *k);


/*
 *  compute x = Hps(drv_data) + ec_pv
 *
 * x        [out] 32 bytes private key
 * drv_data [in]  32 bytes derivation data (point) 
 * ec_pv    [in]  32 bytes private key
 */
void monero_derive_priv(unsigned char *x, unsigned char *drv_data, unsigned int out_idx, unsigned char *ec_pv);

/*
 *  compute x = Hps(drv_data)*G + ec_pub
 *
 * x        [out] 32 bytes public key
 * drv_data [in]  32 bytes derivation data (point) 
 * ec_pub   [in]  32 bytes public key
 */
void monero_derive_pub(unsigned char *P, unsigned char* drv_data, unsigned int out_idx, unsigned char *ec_pub);

/*
 *
 */
void monero_derive_img(unsigned char *img, unsigned char* x, unsigned char *P);


/*
 * W = k.P
 */
void monero_ecmul(unsigned char *W, unsigned char *P, unsigned char *scalar32);
/*
 * W = 8k.P
 */
void monero_ecmul_8(unsigned char *W, unsigned char *P, unsigned char *scalar32);
/*
 * W = k.G
 */
void monero_ecmul_G(unsigned char *W, unsigned char *scalar32);
/*
 * W = P+Q
 */
void monero_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q);

/* ----------------------------------------------------------------------- */
/* ---                                IO                              ---- */
/* ----------------------------------------------------------------------- */

void monero_io_discard(int clear) ;
void monero_io_clear(void);
void monero_io_set_offset(unsigned int offset) ;
void monero_io_mark(void) ;
void monero_io_rewind(void) ;
void monero_io_hole(unsigned int sz) ;
void monero_io_inserted(unsigned int len);
void monero_io_insert(unsigned char const * buffer, unsigned int len) ;
void monero_io_insert_encrypt(unsigned char* buffer, int len);

void monero_io_insert_u32(unsigned  int v32) ;
void monero_io_insert_u24(unsigned  int v24) ;
void monero_io_insert_u16(unsigned  int v16) ;
void monero_io_insert_u8(unsigned int v8) ;
void monero_io_insert_t(unsigned int T) ;
void monero_io_insert_tl(unsigned int T, unsigned int L) ;
void monero_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) ;

void monero_io_fetch_buffer(unsigned char  * buffer, unsigned int len) ;
unsigned int monero_io_fetch_u32(void) ;
unsigned int monero_io_fetch_u24(void) ;
unsigned int monero_io_fetch_u16(void) ;
unsigned int monero_io_fetch_u8(void) ;
int monero_io_fetch_t(unsigned int *T) ;
int monero_io_fetch_l(unsigned int *L) ;
int monero_io_fetch_tl(unsigned int *T, unsigned int *L) ;
int monero_io_fetch_nv(unsigned char* buffer, int len) ;
int monero_io_fetch(unsigned char* buffer, int len) ;
int monero_io_fetch_decrypt(unsigned char* buffer, int len);

int monero_io_do(unsigned int io_flags) ;
/* ----------------------------------------------------------------------- */
/* ---                                DEBUG                           ---- */
/* ----------------------------------------------------------------------- */
#ifdef MONERO_DEBUG

#include "monero_debug.h"

#else

#define monero_nvm_write   nvm_write
#define monero_io_exchange io_exchange

#endif

#endif
