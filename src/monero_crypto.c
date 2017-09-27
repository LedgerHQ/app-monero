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
static unsigned char const WIDE  C_ED25519_G[] = { 
    //uncompressed
    0x04,
    //x
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe, 0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2, 0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a,
    //y
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58};

unsigned char const C_ED25519_ORDER[32] = {
    //l:  0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED};

unsigned char const C_EIGHT[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08};

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_aes_derive(cx_aes_key_t *sk, unsigned char *R, unsigned char *a, unsigned char *b) {
    unsigned char  h1[32];
    
    monero_hash_init_H();
    monero_hash_update_H(R, 32);
    monero_hash_update_H(a, 32);
    monero_hash_update_H(b, 32);
    monero_hash_update_H(R, 32);
    monero_hash_final_H(h1);
    
    monero_hash_H(h1,32,h1);
    
    cx_aes_init_key(h1,16,sk);
}
                  
void monero_aes_generate(cx_aes_key_t *sk) {
    unsigned char  h1[16];
    cx_rng(h1,16);
    cx_aes_init_key(h1,16,sk);
} 

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_encode_varint(unsigned char varint[8], unsigned int out_idx) {
    unsigned int len;
    len = 0;
    while(out_idx >= 0x80) {
        varint[len] = (out_idx & 0x7F) | 0x80;
        out_idx = out_idx>>7;
        len++;
    }
    varint[len] = out_idx;
    len++;
    return len;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_reverse32(unsigned char *scal) {
    unsigned char x;
    unsigned int i;
    for (i = 0; i<16; i++) {
        x          = scal[i];
        scal[i]    = scal [31-i];
        scal[31-i] = x;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_init_sha256(cx_hash_t * hasher) {
    cx_sha256_init((cx_sha256_t *)hasher);
}

void monero_hash_init_keccak(cx_hash_t * hasher) {
    cx_keccak_init((cx_sha3_t *)hasher, 256);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_update(cx_hash_t * hasher, unsigned char* buf, unsigned int len) {
    cx_hash(hasher, 0, buf, len, NULL);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash_final(cx_hash_t * hasher, unsigned char* out) { 
    return cx_hash(hasher, CX_LAST, NULL, 0, out);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash(cx_hash_t * hasher, unsigned char* buf, unsigned int len, unsigned char* out) {
    if (hasher->algo == CX_SHA256) {
         cx_sha256_init((cx_sha256_t *)hasher);
    } else {
        cx_keccak_init((cx_sha3_t *)hasher, 256);
    }
    return cx_hash(hasher, CX_LAST, buf, len, out);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* thanks to knaccc and moneromoo on IRC #monero-research-lab */
static void monero_ge_fromfe_frombytes(unsigned char *bytes) {

    //TODO INSERT MAGIC CODE HERE

}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_dh(unsigned char *s, unsigned char *P, unsigned char *k) {
    monero_ecmul_8(s,P,k);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_priv(unsigned char *x, 
                        unsigned char *drv_data, unsigned int out_idx, unsigned char *ec_priv) {
    unsigned char varint[32+8];
    unsigned int len_varint;
      
    os_memmove(varint, drv_data, 32);
    len_varint = monero_encode_varint(varint+32, out_idx);
    len_varint += 32;
    monero_hash_H(varint,len_varint,x);
    monero_reverse32(x);  
    cx_math_modm(x, 32, (unsigned char *)C_ED25519_ORDER, 32); 
    cx_math_addm(x, x,  ec_priv, (unsigned char *)C_ED25519_ORDER, 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_pub(unsigned char *x, 
                       unsigned char* drv_data, unsigned int out_idx, unsigned char *ec_pub) { 
    
    unsigned char varint[32+8];
    unsigned int len_varint;
      
    os_memmove(varint, drv_data, 32);
    len_varint = monero_encode_varint(varint+32, out_idx);
    len_varint += 32;
    monero_hash_H(varint,len_varint,x);
    monero_reverse32(x);  
    cx_math_modm(x, 32, (unsigned char *)C_ED25519_ORDER, 32); 
    monero_ecmul_G(x,x);
    monero_ecadd(x,x,ec_pub);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_img(unsigned char *img, unsigned char *P, unsigned char* x) {
#if 0
    monero_hash_H(P,32,img);
    monero_ge_fromfe_frombytes(img);
    monero_ecmul_8(img, img, x);
#else
    //tmp code, waiting for monero_ge_fromfe_frombytes
    monero_ge_fromfe_frombytes(img);
    os_memset(img, 0, 32);
#endif
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_G(unsigned char *W,  unsigned char *scalar32) {
    unsigned char Pxy[65];

    os_memmove(Pxy, C_ED25519_G, 65);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, scalar32, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul(unsigned char *W, unsigned char *P, unsigned char *scalar32) {
    unsigned char Pxy[65];

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, scalar32, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_8(unsigned char *W, unsigned char *P, unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char eight = 8;

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, scalar32, 32);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, &eight, 1);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q) {
    unsigned char Pxy[65];
    unsigned char Qxy[65];
    
    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy);
    
    Qxy[0] = 0x02;
    os_memmove(&Qxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Qxy);
    
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Qxy);
    
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}
