/*****************************************************************************
 *   Ledger Monero App.
 *   (c) 2017-2020 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
static unsigned char const WIDE C_ED25519_G[] = {
    // uncompressed
    0x04,
    // x
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe, 0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2, 0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a,
    // y
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58};

static unsigned char const WIDE C_ED25519_Hy[] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94};

unsigned char const C_ED25519_ORDER[32] = {
    // l: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED};

unsigned char const C_ED25519_FIELD[32] = {
    // q:  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed};

unsigned char const C_EIGHT[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08};

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_aes_derive(cx_aes_key_t *sk, unsigned char *seed32, unsigned char *a,
                       unsigned char *b) {
    unsigned char h1[32];

    monero_keccak_init_H();
    monero_keccak_update_H(seed32, 32);
    monero_keccak_update_H(a, 32);
    monero_keccak_update_H(b, 32);
    monero_keccak_final_H(h1);

    monero_keccak_H(h1, 32, h1);

    cx_aes_init_key(h1, 16, sk);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_aes_generate(cx_aes_key_t *sk) {
    unsigned char h1[16];
    cx_rng(h1, 16);
    cx_aes_init_key(h1, 16, sk);
}

/* ----------------------------------------------------------------------- */
/* --- assert: max_len>0                                               --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_encode_varint(unsigned char *varint, unsigned int max_len, uint64_t value) {
    unsigned int len;
    len = 0;
    while (value >= 0x80) {
        if (len == (max_len - 1)) {
            THROW(SW_WRONG_DATA_RANGE);
        }
        varint[len] = (value & 0x7F) | 0x80;
        value = value >> 7;
        len++;
    }
    varint[len] = value;
    return len + 1;
}

/* ----------------------------------------------------------------------- */
/* --- assert: max_len>0                                               --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_decode_varint(unsigned char *varint, unsigned int max_len, uint64_t *value) {
    uint64_t v;
    int len;
    v = 0;
    len = 0;
    while ((varint[len]) & 0x80) {
        if (len == (max_len - 1)) {
            THROW(SW_WRONG_DATA_RANGE);
        }
        v = v + (((varint[len]) & 0x7f) << (len * 7));
        len++;
    }

    v = v + (((varint[len]) & 0x7f) << (len * 7));
    *value = v;
    return len + 1;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_reverse32(unsigned char *rscal, unsigned char *scal) {
    unsigned char x;
    unsigned int i;
    for (i = 0; i < 16; i++) {
        x = scal[i];
        rscal[i] = scal[31 - i];
        rscal[31 - i] = x;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_init_sha256(cx_hash_t *hasher) { cx_sha256_init((cx_sha256_t *)hasher); }

void monero_hash_init_keccak(cx_hash_t *hasher) { cx_keccak_init((cx_sha3_t *)hasher, 256); }

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_update(cx_hash_t *hasher, unsigned char *buf, unsigned int len) {
    cx_hash(hasher, 0, buf, len, NULL, 0);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash_final(cx_hash_t *hasher, unsigned char *out) {
    return cx_hash(hasher, CX_LAST, NULL, 0, out, 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash(unsigned int algo, cx_hash_t *hasher, unsigned char *buf, unsigned int len,
                unsigned char *out) {
    hasher->algo = algo;
    if (algo == CX_SHA256) {
        cx_sha256_init((cx_sha256_t *)hasher);
    } else {
        cx_keccak_init((cx_sha3_t *)hasher, 256);
    }
    return cx_hash(hasher, CX_LAST, buf, len, out, 32);
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
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc8, 0xdb, 0x3d, 0xe3, 0xc9};

const unsigned char C_fe_ma[] = {
    /* -A
     *  0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff892e7
     */
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf8, 0x92, 0xe7};
const unsigned char C_fe_fffb1[] = {

    /* sqrt(-2 * A * (A + 2))
     * 0x7e71fbefdad61b1720a9c53741fb19e3d19404a8b92a738d22a76975321c41ee
     */
    0x7e, 0x71, 0xfb, 0xef, 0xda, 0xd6, 0x1b, 0x17, 0x20, 0xa9, 0xc5, 0x37, 0x41, 0xfb, 0x19, 0xe3,
    0xd1, 0x94, 0x04, 0xa8, 0xb9, 0x2a, 0x73, 0x8d, 0x22, 0xa7, 0x69, 0x75, 0x32, 0x1c, 0x41, 0xee};
const unsigned char C_fe_fffb2[] = {
    /* sqrt(2 * A * (A + 2))
     * 0x4d061e0a045a2cf691d451b7c0165fbe51de03460456f7dfd2de6483607c9ae0
     */
    0x4d, 0x06, 0x1e, 0x0a, 0x04, 0x5a, 0x2c, 0xf6, 0x91, 0xd4, 0x51, 0xb7, 0xc0, 0x16, 0x5f, 0xbe,
    0x51, 0xde, 0x03, 0x46, 0x04, 0x56, 0xf7, 0xdf, 0xd2, 0xde, 0x64, 0x83, 0x60, 0x7c, 0x9a, 0xe0};
const unsigned char C_fe_fffb3[] = {
    /* sqrt(-sqrt(-1) * A * (A + 2))
     * 674a110d14c208efb89546403f0da2ed4024ff4ea5964229581b7d8717302c66
     */
    0x67, 0x4a, 0x11, 0x0d, 0x14, 0xc2, 0x08, 0xef, 0xb8, 0x95, 0x46,
    0x40, 0x3f, 0x0d, 0xa2, 0xed, 0x40, 0x24, 0xff, 0x4e, 0xa5, 0x96,
    0x42, 0x29, 0x58, 0x1b, 0x7d, 0x87, 0x17, 0x30, 0x2c, 0x66

};
const unsigned char C_fe_fffb4[] = {
    /* sqrt(sqrt(-1) * A * (A + 2))
     * 1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186
     */
    0x1a, 0x43, 0xf3, 0x03, 0x10, 0x67, 0xdb, 0xf9, 0x26, 0xc0, 0xf4,
    0x88, 0x7e, 0xf7, 0x43, 0x2e, 0xee, 0x46, 0xfc, 0x08, 0xa1, 0x3f,
    0x4a, 0x49, 0x85, 0x3d, 0x19, 0x03, 0xb6, 0xb3, 0x91, 0x86

};
const unsigned char C_fe_sqrtm1[] = {
    /* sqrt(2 * A * (A + 2))
     * 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
     */
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b, 0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78, 0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0};
const unsigned char C_fe_qm5div8[] = {
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd};

static void monero_ge_fromfe_frombytes(unsigned char *ge, unsigned char *bytes) {
#define MOD              (unsigned char *)C_ED25519_FIELD, 32
#define fe_isnegative(f) (f[31] & 1)
#if 0
    unsigned char u[32], v[32], w[32], x[32], y[32], z[32];
    unsigned char rX[32], rY[32], rZ[32];
    union {
        struct {
            unsigned char _uv7[32];
            unsigned char  _v3[32];
        };
        unsigned char _Pxy[65];

    } uv;

#define uv7 uv._uv7
#define v3  uv._v3

#define Pxy uv._Pxy
#else
#define u  (G_monero_vstate.io_buffer + 0 * 32)
#define v  (G_monero_vstate.io_buffer + 1 * 32)
#define w  (G_monero_vstate.io_buffer + 2 * 32)
#define x  (G_monero_vstate.io_buffer + 3 * 32)
#define y  (G_monero_vstate.io_buffer + 4 * 32)
#define z  (G_monero_vstate.io_buffer + 5 * 32)
#define rX (G_monero_vstate.io_buffer + 6 * 32)
#define rY (G_monero_vstate.io_buffer + 7 * 32)
#define rZ (G_monero_vstate.io_buffer + 8 * 32)

    //#define uv7 (G_monero_vstate.io_buffer+9*32)
    //#define v3  (G_monero_vstate.io_buffer+10*32)
    union {
        unsigned char _Pxy[65];
        struct {
            unsigned char _uv7[32];
            unsigned char _v3[32];
        };

    } uv;

#define uv7 uv._uv7
#define v3  uv._v3

#define Pxy uv._Pxy

#if MONERO_IO_BUFFER_LENGTH < (9 * 32)
#error MONERO_IO_BUFFER_LENGTH is too small
#endif
#endif

    unsigned char sign;

    // cx works in BE
    monero_reverse32(u, bytes);
    cx_math_modm(u, 32, (unsigned char *)C_ED25519_FIELD, 32);

    // go on
    cx_math_multm(v, u, u, MOD); /* 2 * u^2 */
    cx_math_addm(v, v, v, MOD);

    os_memset(w, 0, 32);
    w[31] = 1;                                           /* w = 1 */
    cx_math_addm(w, v, w, MOD);                          /* w = 2 * u^2 + 1 */
    cx_math_multm(x, w, w, MOD);                         /* w^2 */
    cx_math_multm(y, (unsigned char *)C_fe_ma2, v, MOD); /* -2 * A^2 * u^2 */
    cx_math_addm(x, x, y, MOD);                          /* x = w^2 - 2 * A^2 * u^2 */

// inline fe_divpowm1(r->X, w, x);     // (w / x)^(m + 1) => fe_divpowm1(r,u,v)
#define _u w
#define _v x
    cx_math_multm(v3, _v, _v, MOD);
    cx_math_multm(v3, v3, _v, MOD); /* v3 = v^3 */
    cx_math_multm(uv7, v3, v3, MOD);
    cx_math_multm(uv7, uv7, _v, MOD);
    cx_math_multm(uv7, uv7, _u, MOD);                               /* uv7 = uv^7 */
    cx_math_powm(uv7, uv7, (unsigned char *)C_fe_qm5div8, 32, MOD); /* (uv^7)^((q-5)/8)*/
    cx_math_multm(uv7, uv7, v3, MOD);
    cx_math_multm(rX, uv7, w, MOD); /* u^(m+1)v^(-(m+1)) */
#undef _u
#undef _v

    cx_math_multm(y, rX, rX, MOD);
    cx_math_multm(x, y, x, MOD);
    cx_math_subm(y, w, x, MOD);
    os_memmove(z, C_fe_ma, 32);

    if (!cx_math_is_zero(y, 32)) {
        cx_math_addm(y, w, x, MOD);
        if (!cx_math_is_zero(y, 32)) {
            goto negative;
        } else {
            cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb1, MOD);
        }
    } else {
        cx_math_multm(rX, rX, (unsigned char *)C_fe_fffb2, MOD);
    }
    cx_math_multm(rX, rX, u, MOD);  // u * sqrt(2 * A * (A + 2) * w / x)
    cx_math_multm(z, z, v, MOD);    // -2 * A * u^2
    sign = 0;

    goto setsign;

negative:
    cx_math_multm(x, x, (unsigned char *)C_fe_sqrtm1, MOD);
    cx_math_subm(y, w, x, MOD);
    if (!cx_math_is_zero(y, 32)) {
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
        // fe_neg(r->X, r->X);
        cx_math_sub(rX, (unsigned char *)C_ED25519_FIELD, rX, 32);
    }
    cx_math_addm(rZ, z, w, MOD);
    cx_math_subm(rY, z, w, MOD);
    cx_math_multm(rX, rX, rZ, MOD);

    // back to monero y-affine
    cx_math_invprimem(u, rZ, MOD);
    Pxy[0] = 0x04;
    cx_math_multm(&Pxy[1], rX, u, MOD);
    cx_math_multm(&Pxy[1 + 32], rY, u, MOD);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(ge, &Pxy[1], 32);

#undef u
#undef v
#undef w
#undef x
#undef y
#undef z
#undef rX
#undef rY
#undef rZ

#undef uv7
#undef v3

#undef Pxy
}

/* ======================================================================= */
/*                            DERIVATION & KEY                             */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_to_scalar(unsigned char *scalar, unsigned char *raw, unsigned int raw_len) {
    monero_keccak_F(raw, raw_len, scalar);
    monero_reduce(scalar, scalar);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_to_ec(unsigned char *ec, unsigned char *ec_pub) {
    monero_keccak_F(ec_pub, 32, ec);
    monero_ge_fromfe_frombytes(ec, ec);
    monero_ecmul_8(ec, ec);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv) {
    monero_rng_mod_order(ec_priv);
    monero_ecmul_G(ec_pub, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
void monero_generate_key_derivation(unsigned char *drv_data, unsigned char *P,
                                    unsigned char *scalar) {
    monero_ecmul_8k(drv_data, P, scalar);
}

/* ----------------------------------------------------------------------- */
/* ---  ok                                                             --- */
/* ----------------------------------------------------------------------- */
void monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data,
                                 unsigned int out_idx) {
    unsigned char varint[32 + 8];
    unsigned int len_varint;

    os_memmove(varint, drv_data, 32);
    len_varint = monero_encode_varint(varint + 32, 8, out_idx);
    len_varint += 32;
    monero_keccak_F(varint, len_varint, varint);
    monero_reduce(scalar, varint);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_secret_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                              unsigned char *ec_priv) {
    unsigned char tmp[32];

    // derivation to scalar
    monero_derivation_to_scalar(tmp, drv_data, out_idx);

    // generate
    monero_addm(x, tmp, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_derive_public_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                              unsigned char *ec_pub) {
    unsigned char tmp[32];

    // derivation to scalar
    monero_derivation_to_scalar(tmp, drv_data, out_idx);
    // generate
    monero_ecmul_G(tmp, tmp);
    monero_ecadd(x, tmp, ec_pub);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv) {
    monero_ecmul_G(ec_pub, ec_priv);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_generate_key_image(unsigned char *img, unsigned char *P, unsigned char *x) {
    unsigned char I[32];
    monero_hash_to_ec(I, P);
    monero_ecmul_k(img, I, x);
}

/* ======================================================================= */
/*                               SUB ADDRESS                               */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
void monero_derive_subaddress_public_key(unsigned char *x, unsigned char *pub,
                                         unsigned char *drv_data, unsigned int index) {
    unsigned char scalarG[32];

    monero_derivation_to_scalar(scalarG, drv_data, index);
    monero_ecmul_G(scalarG, scalarG);
    monero_ecsub(x, pub, scalarG);
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
void monero_get_subaddress_spend_public_key(unsigned char *x, unsigned char *index) {
    // m = Hs(a || index_major || index_minor)
    monero_get_subaddress_secret_key(x, G_monero_vstate.a, index);
    // M = m*G
    monero_secret_key_to_public_key(x, x);
    // D = B + M
    monero_ecadd(x, x, G_monero_vstate.B);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index) {
    // retrieve D
    monero_get_subaddress_spend_public_key(D, index);
    // C = a*D
    monero_ecmul_k(C, D, G_monero_vstate.a);
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
static const char C_sub_address_prefix[] = {'S', 'u', 'b', 'A', 'd', 'd', 'r', 0};

void monero_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s,
                                      unsigned char *index) {
    unsigned char in[sizeof(C_sub_address_prefix) + 32 + 8];

    os_memmove(in, C_sub_address_prefix, sizeof(C_sub_address_prefix)),
        os_memmove(in + sizeof(C_sub_address_prefix), s, 32);
    os_memmove(in + sizeof(C_sub_address_prefix) + 32, index, 8);
    // hash_to_scalar with more that 32bytes:
    monero_keccak_F(in, sizeof(in), sub_s);
    monero_reduce(sub_s, sub_s);
}

/* ======================================================================= */
/*                                  MATH                                   */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_check_scalar_range_1N(unsigned char *s) {
    unsigned char x[32];
    monero_reverse32(x, s);
    if (cx_math_is_zero(x, 32) || cx_math_cmp(x, C_ED25519_ORDER, 32) >= 0) {
        THROW(SW_WRONG_DATA_RANGE);
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_check_scalar_not_null(unsigned char *s) {
    if (cx_math_is_zero(s, 32)) {
        THROW(SW_WRONG_DATA_RANGE);
    }
}
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_G(unsigned char *W, unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];
    monero_reverse32(s, scalar32);
    os_memmove(Pxy, C_ED25519_G, 65);
    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, sizeof(Pxy), s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecmul_H(unsigned char *W, unsigned char *scalar32) {
    unsigned char Pxy[65];
    unsigned char s[32];

    monero_reverse32(s, scalar32);

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], C_ED25519_Hy, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, sizeof(Pxy), s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

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
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    cx_ecfp_scalar_mult(CX_CURVE_Ed25519, Pxy, sizeof(Pxy), s, 32);
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

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

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Pxy, sizeof(Pxy));
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Pxy, sizeof(Pxy));
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Pxy, sizeof(Pxy));
    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
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
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    Qxy[0] = 0x02;
    os_memmove(&Qxy[1], Q, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Qxy, sizeof(Qxy));

    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Qxy, sizeof(Pxy));

    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q) {
    unsigned char Pxy[65];
    unsigned char Qxy[65];

    Pxy[0] = 0x02;
    os_memmove(&Pxy[1], P, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    Qxy[0] = 0x02;
    os_memmove(&Qxy[1], Q, 32);
    cx_edward_decompress_point(CX_CURVE_Ed25519, Qxy, sizeof(Qxy));

    cx_math_sub(Qxy + 1, (unsigned char *)C_ED25519_FIELD, Qxy + 1, 32);
    cx_ecfp_add_point(CX_CURVE_Ed25519, Pxy, Pxy, Qxy, sizeof(Pxy));

    cx_edward_compress_point(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    os_memmove(W, &Pxy[1], 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    static key ecdhHash(const key &k)
    {
        char data[38];
        rct::key hash;
        memcpy(data, "amount", 6);
        memcpy(data + 6, &k, sizeof(k));
        cn_fast_hash(hash, data, sizeof(data));
        return hash;
    }
*/
void monero_ecdhHash(unsigned char *x, unsigned char *k) {
    unsigned char data[38];
    os_memmove(data, "amount", 6);
    os_memmove(data + 6, k, 32);
    monero_keccak_F(data, 38, x);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    key genCommitmentMask(const key &sk)
    {
        char data[15 + sizeof(key)];
        memcpy(data, "commitment_mask", 15);
        memcpy(data + 15, &sk, sizeof(sk));
        key scalar;
        hash_to_scalar(scalar, data, sizeof(data));
        return scalar;
    }
*/
void monero_genCommitmentMask(unsigned char *c, unsigned char *sk) {
    unsigned char data[15 + 32];
    os_memmove(data, "commitment_mask", 15);
    os_memmove(data + 15, sk, 32);
    monero_hash_to_scalar(c, data, 15 + 32);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_addm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra, a);
    monero_reverse32(rb, b);
    cx_math_addm(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r, r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_subm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra, a);
    monero_reverse32(rb, b);
    cx_math_subm(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r, r);
}
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_multm(unsigned char *r, unsigned char *a, unsigned char *b) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra, a);
    monero_reverse32(rb, b);
    cx_math_multm(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r, r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_multm_8(unsigned char *r, unsigned char *a) {
    unsigned char ra[32];
    unsigned char rb[32];

    monero_reverse32(ra, a);
    os_memset(rb, 0, 32);
    rb[31] = 8;
    cx_math_multm(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r, r);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_reduce(unsigned char *r, unsigned char *a) {
    unsigned char ra[32];
    monero_reverse32(ra, a);
    cx_math_modm(ra, 32, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r, ra);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_rng_mod_order(unsigned char *r) {
    unsigned char rnd[32 + 8];
    cx_rng(rnd, 32 + 8);
    cx_math_modm(rnd, 32 + 8, (unsigned char *)C_ED25519_ORDER, 32);
    monero_reverse32(r, rnd + 8);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* return 0 if ok, 1 if missing decimal */
void monero_uint642str(uint64_t val, char *str, unsigned int str_len) {
    char stramount[22];
    unsigned int offset, len;

    os_memset(str, 0, str_len);

    offset = 22;
    while (val) {
        offset--;
        stramount[offset] = '0' + val % 10;
        val = val / 10;
    }
    len = sizeof(stramount) - offset;
    if (len > str_len) {
        THROW(SW_WRONG_DATA_RANGE);
    }
    os_memmove(str, stramount + offset, len);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/* return 0 if ok, 1 if missing decimal */
int monero_amount2str(uint64_t xmr, char *str, unsigned int str_len) {
    // max uint64 is 18446744073709551616, aka 20 char, plus dot
    char stramount[22];
    unsigned int offset, len, ov;

    os_memset(str, 0, str_len);

    os_memset(stramount, '0', sizeof(stramount));
    stramount[21] = 0;
    // special case
    if (xmr == 0) {
        str[0] = '0';
        return 1;
    }

    // uint64 units to str
    // offset: 0 | 1-20     | 21
    // ----------------------
    // value:  0 | xmrunits | 0

    offset = 20;
    while (xmr) {
        stramount[offset] = '0' + xmr % 10;
        xmr = xmr / 10;
        offset--;
    }
    // offset: 0-7 | 8 | 9-20 |21
    // ----------------------
    // value:  xmr | . | units| 0
    os_memmove(stramount, stramount + 1, 8);
    stramount[8] = '.';
    offset = 0;
    while ((stramount[offset] == '0') && (stramount[offset] != '.')) {
        offset++;
    }
    if (stramount[offset] == '.') {
        offset--;
    }
    len = 20;
    while ((stramount[len] == '0') && (stramount[len] != '.')) {
        len--;
    }
    len = len - offset + 1;
    ov = 0;
    if (len > (str_len - 1)) {
        len = str_len - 1;
        ov = 1;
    }
    os_memmove(str, stramount + offset, len);
    return ov;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
uint64_t monero_bamount2uint64(unsigned char *binary) {
    uint64_t xmr;
    int i;
    xmr = 0;
    for (i = 7; i >= 0; i--) {
        xmr = xmr * 256 + binary[i];
    }
    return xmr;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_bamount2str(unsigned char *binary, char *str, unsigned int str_len) {
    return monero_amount2str(monero_bamount2uint64(binary), str, str_len);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_vamount2str(unsigned char *binary, char *str, unsigned int str_len) {
    // return monero_amount2str(monero_vamount2uint64(binary), str,str_len);
    uint64_t amount;
    monero_decode_varint(binary, 8, &amount);
    return monero_amount2str(amount, str, str_len);
}
