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

unsigned char const C_ED25519_FIELD[32] = {
   //q:  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed};

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
    monero_rng(h1,16);
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
void monero_reverse32(unsigned char *rscal, unsigned char *scal) {
    unsigned char x;
    unsigned int i;
    for (i = 0; i<16; i++) {
        x           = scal[i];
        rscal[i]    = scal [31-i];
        rscal[31-i] = x;
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
/* thanks to knaccc and moneromoo help on IRC #monero-research-lab */
/* From Monero code
 *
 *  fe_sq2(v, u);            // 2 * u^2 
 *  fe_1(w);
 *  fe_add(w, v, w);         // w = 2 * u^2 + 1 
 *  fe_sq(x, w);             // w^2 
 *  fe_mul(y, fe_ma2, v);    // -2 * A^2 * u^2 
 *  fe_add(x, x, y);         // x = w^2 - 2 * A^2 * u^2 
 *  fe_divpowm1(r->X, w, x); // (w / x)^(m + 1) 
 *  fe_sq(y, r->X);
 *  fe_mul(x, y, x);
 *  fe_sub(y, w, x);
 *  fe_copy(z, fe_ma);
 *  if (fe_isnonzero(y)) {
 *    fe_add(y, w, x);
 *    if (fe_isnonzero(y)) {
 *      goto negative;
 *    } else {
 *      fe_mul(r->X, r->X, fe_fffb1);
 *    }
 *  } else {
 *    fe_mul(r->X, r->X, fe_fffb2);
 *  }
 *  fe_mul(r->X, r->X, u);  // u * sqrt(2 * A * (A + 2) * w / x) 
 *  fe_mul(z, z, v);        // -2 * A * u^2 
 *  sign = 0;
 *  goto setsign;
 *negative:
 *  fe_mul(x, x, fe_sqrtm1);
 *  fe_sub(y, w, x);
 *  if (fe_isnonzero(y)) {
 *    assert((fe_add(y, w, x), !fe_isnonzero(y)));
 *    fe_mul(r->X, r->X, fe_fffb3);
 *  } else {
 *    fe_mul(r->X, r->X, fe_fffb4);
 *  }
 *  // r->X = sqrt(A * (A + 2) * w / x) 
 *  // z = -A 
 *  sign = 1;
 *setsign:
 *  if (fe_isnegative(r->X) != sign) {
 *    assert(fe_isnonzero(r->X));
 *    fe_neg(r->X, r->X);
 *  }
 *  fe_add(r->Z, z, w);
 *  fe_sub(r->Y, z, w);
 *  fe_mul(r->X, r->X, r->Z);
 */

// A = 486662
const unsigned char C_fe_ma2[] = { 
    /* -A^2 
     *  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffc8db3de3c9
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0xdb, 0x3d, 0xe3, 0xc9
}; 

const unsigned char C_fe_ma[] = { 
    /* -A    
     *  0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff892e7
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x92, 0xe7
}; 
const unsigned char C_fe_fffb1[] = {

    /* sqrt(-2 * A * (A + 2)) 
     * 0x7e71fbefdad61b1720a9c53741fb19e3d19404a8b92a738d22a76975321c41ee
     */
    0x7e, 0x71, 0xfb, 0xef, 0xda, 0xd6, 0x1b, 0x17, 0x20, 0xa9, 0xc5, 0x37, 0x41, 0xfb, 0x19, 0xe3, 
    0xd1, 0x94, 0x04, 0xa8, 0xb9, 0x2a, 0x73, 0x8d, 0x22, 0xa7, 0x69, 0x75, 0x32, 0x1c, 0x41, 0xee
};
const unsigned char C_fe_fffb2[] = {
    /* sqrt(2 * A * (A + 2)) 
     * 0x4d061e0a045a2cf691d451b7c0165fbe51de03460456f7dfd2de6483607c9ae0
     */
    0x4d, 0x06, 0x1e, 0x0a, 0x04, 0x5a, 0x2c, 0xf6, 0x91, 0xd4, 0x51, 0xb7, 0xc0, 0x16, 0x5f, 0xbe, 
    0x51, 0xde, 0x03, 0x46, 0x04, 0x56, 0xf7, 0xdf, 0xd2, 0xde, 0x64, 0x83, 0x60, 0x7c, 0x9a, 0xe0
};
const unsigned char C_fe_fffb3[] = {
    /* sqrt(-sqrt(-1) * A * (A + 2)) 
     * 674a110d14c208efb89546403f0da2ed4024ff4ea5964229581b7d8717302c66
     */
    0x67, 0x4a, 0x11, 0x0d, 0x14, 0xc2, 0x08, 0xef, 0xb8, 0x95, 0x46, 0x40, 0x3f, 0x0d, 0xa2, 0xed, 
    0x40, 0x24, 0xff, 0x4e, 0xa5, 0x96, 0x42, 0x29, 0x58, 0x1b, 0x7d, 0x87, 0x17, 0x30, 0x2c, 0x66
    
};
const unsigned char C_fe_fffb4[] = {
    /* sqrt(sqrt(-1) * A * (A + 2)) 
     * 1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186
     */
   0x1a, 0x43, 0xf3, 0x03, 0x10, 0x67, 0xdb, 0xf9, 0x26, 0xc0, 0xf4, 0x88, 0x7e, 0xf7, 0x43, 0x2e,
   0xee, 0x46, 0xfc, 0x08, 0xa1, 0x3f, 0x4a, 0x49, 0x85, 0x3d, 0x19, 0x03, 0xb6, 0xb3, 0x91, 0x86

};
const unsigned char C_fe_sqrtm1[] = {
    /* sqrt(2 * A * (A + 2)) 
     * 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
     */
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b, 0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7, 
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78, 0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0
};
const unsigned char C_fe_qm5div8[] = {
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd
};

static void monero_ge_fromfe_frombytes(unsigned char *ge , unsigned char *bytes) {

    #define  MOD (unsigned char *)C_ED25519_FIELD,32
    #define fe_isnegative(f)      (f[31]&1)
    
    unsigned char u[32], v[32], w[32], x[32], y[32], z[32];
    unsigned char rX[32], rY[32], rZ[32]; 
    union {
        struct {
            unsigned char uv7[32];
            unsigned char  v3[32];
        };
        unsigned char Pxy[65];

    } uv;
    unsigned char sign;
    
    //cx works in BE
    monero_reverse32(u,bytes);
    cx_math_modm(u, 32, (unsigned char *)C_ED25519_FIELD, 32);
    
    //go on
    cx_math_multm(v, u, u, MOD);                           /* 2 * u^2 */
    cx_math_addm (v,  v, v, MOD);
    
    os_memset    (w, 0, 32); w[31] = 1;                   /* w = 1 */
    cx_math_addm (w, v, w,MOD );                          /* w = 2 * u^2 + 1 */
    cx_math_multm(x, w, w, MOD);                          /* w^2 */
    cx_math_multm(y, (unsigned char *)C_fe_ma2, v, MOD);  /* -2 * A^2 * u^2 */
    cx_math_addm (x, x, y, MOD);                          /* x = w^2 - 2 * A^2 * u^2 */

    //inline fe_divpowm1(r->X, w, x);     // (w / x)^(m + 1) => fe_divpowm1(r,u,v)
    #define u w
    #define v x
    cx_math_multm(uv.v3, v, v, MOD);
    cx_math_multm(uv.v3, uv.v3, v, MOD);                       /* v3 = v^3 */
    cx_math_multm(uv.uv7, uv.v3, uv.v3, MOD);
    cx_math_multm(uv.uv7, uv.uv7, v, MOD);
    cx_math_multm(uv.uv7, uv.uv7, u, MOD);                     /* uv7 = uv^7 */
    cx_math_powm(uv.uv7, uv.uv7, (unsigned char *)C_fe_qm5div8, 32, MOD); /* (uv^7)^((q-5)/8)*/
    cx_math_multm(uv.uv7, uv.uv7, uv.v3, MOD);
    cx_math_multm(rX, uv.uv7, w, MOD);                      /* u^(m+1)v^(-(m+1)) */
    #undef u
    #undef v
    
    cx_math_multm(y, rX,rX, MOD);            
    cx_math_multm(x, y, x, MOD);             
    cx_math_subm(y, w, x, MOD);              
    os_memmove(z, C_fe_ma, 32);

    if (!cx_math_is_zero(y,32)) {
     cx_math_addm(y, w, x, MOD);
     if (!cx_math_is_zero(y,32)) {
       goto negative;
     } else {
      cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb1, MOD);
     }
   } else {
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb2, MOD);
   }
   cx_math_multm(rX, rX, u, MOD);  // u * sqrt(2 * A * (A + 2) * w / x) 
   cx_math_multm(z, z, v, MOD);        // -2 * A * u^2 
   sign = 0;

   goto setsign;

  negative:
   cx_math_multm(x, x, (unsigned char *)C_fe_sqrtm1, MOD);
   cx_math_subm(y, w, x, MOD);
   if (!cx_math_is_zero(y,32)) {
     cx_math_addm(y, w, x, MOD);
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb3, MOD);
   } else {
     cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb4, MOD);
   }
   // r->X = sqrt(A * (A + 2) * w / x) 
   // z = -A 
   sign = 1;

 setsign:
   if (fe_isnegative(rX) != sign) {
     //fe_neg(r->X, r->X);
    cx_math_subm(rX, (unsigned char *)C_ED25519_FIELD, rX, MOD);
   }
   cx_math_addm(rZ, z, w, MOD);
   cx_math_subm(rY, z, w, MOD);
   cx_math_multm(rX, rX, rZ, MOD);

   //back to monero y-affine
   cx_math_invprimem(u, rZ, MOD);
   uv.Pxy[0] = 0x04;
   cx_math_multm(&uv.Pxy[1],    rX, u, MOD);
   cx_math_multm(&uv.Pxy[1+32], rY, u, MOD);
   cx_edward_compress_point(CX_CURVE_Ed25519, uv.Pxy);
   os_memmove(ge, &uv.Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data, unsigned int out_idx) {
    unsigned char varint[32+8];
    unsigned int len_varint;
    
    os_memmove(varint, drv_data, 32);
    len_varint = monero_encode_varint(varint+32, out_idx);
    len_varint += 32;
    monero_hash_H(varint,len_varint,varint);
    monero_reduce(scalar, varint);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_to_ec(unsigned char *ec, unsigned char *ec_pub) {
    monero_hash_H(ec_pub, 32, ec);
    monero_ge_fromfe_frombytes(ec, ec);
    //monero_ecmul_8(ec, ec);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_to_scalar(unsigned char *scalar, unsigned char *raw) {
    monero_hash_H(raw,32,scalar);
    monero_reduce(scalar, scalar);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_dh(unsigned char *drv_data, unsigned char *P, unsigned char *scalar) {
    monero_ecmul_8k(drv_data,P,scalar);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_priv(unsigned char *x, 
                        unsigned char *drv_data, unsigned int out_idx, unsigned char *ec_priv) {
    unsigned char tmp[32];

    //derivation to scalar
    monero_derivation_to_scalar(tmp,drv_data,out_idx);
    //generate
    monero_addm(x, tmp, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_pub(unsigned char *x, 
                       unsigned char* drv_data, unsigned int out_idx, unsigned char *ec_pub) { 
    unsigned char tmp[32];

    //derivation to scalar
    monero_derivation_to_scalar(tmp,drv_data,out_idx);
    //generate 
    monero_ecmul_G(tmp,tmp);
    monero_ecadd(x,tmp,ec_pub);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_img(unsigned char *img, unsigned char *P, unsigned char* x) {
    unsigned char I[32];
    monero_hash_to_ec(I,P);
    monero_ecmul_k(img, I,x);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_G(unsigned char *W,  unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];
    monero_reverse32(s, scalar32);
    os_memmove(Pxy, C_ED25519_G, 65);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];
    monero_reverse32(s, scalar32);
    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32) {
    unsigned char s[32];
    monero_multm_8(s, scalar32);
    monero_ecmul_k(W, P, s);    
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_8(unsigned char *W, unsigned char *P) {
    unsigned char Pxy[65];
    unsigned char eight = 8;
    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy);
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
    os_memmove(&Qxy[1], Q, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Qxy);
    
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Qxy);
    
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy);
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_addm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra,a);
    monero_reverse32(rb,b);
    cx_math_addm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r,r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_subm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra,a);
    monero_reverse32(rb,b);
    cx_math_subm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r,r);
}
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_multm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra,a);
    monero_reverse32(rb,b);
    cx_math_multm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r,r);
}


/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_multm_8(unsigned char *r, unsigned char *a) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra,a);
    os_memset(rb,0,32);
    rb[31] = 8;
    cx_math_multm(r, ra,  rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r,r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_reduce(unsigned char *r, unsigned char *a) {
    monero_reverse32(r,a); 
    cx_math_modm(r, 32, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r,r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */

void monero_rng(unsigned char *r,  int len) {
    #if 1
    cx_rng(G_monero_vstate.r,32);
    #else
    int i;
    for (i = 0; i<len;i++) {
       r[i] = ++G_monero_vstate.rnd;
    }
    #endif
}

