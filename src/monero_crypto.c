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

#define PXY_SIZE 65

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
int monero_aes_derive(cx_aes_key_t *sk, unsigned char *seed32, unsigned char *a, unsigned char *b) {
    unsigned char h1[KEY_SIZE];
    int error;

    error = monero_keccak_init_H();
    if (error) {
        return error;
    }

    error = monero_keccak_update_H(seed32, KEY_SIZE);
    if (error) {
        return error;
    }

    error = monero_keccak_update_H(a, KEY_SIZE);
    if (error) {
        return error;
    }

    error = monero_keccak_update_H(b, KEY_SIZE);
    if (error) {
        return error;
    }

    error = monero_keccak_final_H(h1);
    if (error) {
        return error;
    }

    error = monero_keccak_H(h1, KEY_SIZE, h1);
    if (error) {
        return error;
    }

    error = cx_aes_init_key_no_throw(h1, 16, sk);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* --- assert: max_len>0                                               --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_encode_varint(unsigned char *varint, unsigned int max_len, uint64_t value,
                                  unsigned int *out_len) {
    if (!varint || !out_len) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA;
    }

    *out_len = 0;
    while (value >= 0x80) {
        if (*out_len == (max_len - 1)) {
            return SW_WRONG_DATA_RANGE;
        }
        varint[*out_len] = (value & 0x7F) | 0x80;
        value = value >> 7;
        *out_len = *out_len + 1;
    }
    varint[*out_len] = value;
    *out_len = *out_len + 1;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* --- assert: max_len>0                                               --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_decode_varint(const unsigned char *varint, size_t max_len, uint64_t *value,
                                  unsigned int *out_len) {
    uint64_t v;
    size_t len;
    v = 0;
    len = 0;
    if (!varint || !out_len) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA;
    }
    while ((varint[len]) & 0x80) {
        if (len == (max_len - 1)) {
            return SW_WRONG_DATA_RANGE;
        }
        v = v + ((uint64_t)((varint[len]) & 0x7f) << (len * 7));
        len++;
    }

    v = v + ((uint64_t)((varint[len]) & 0x7f) << (len * 7));
    *value = v;
    *out_len = len + 1;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_reverse32(unsigned char *rscal, unsigned char *scal, size_t rscal_len, size_t scal_len) {
    unsigned char x;
    unsigned int i;
    if (!rscal || !scal) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA;
    }
    if (rscal_len < 32 || scal_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }
    for (i = 0; i < 16; i++) {
        x = scal[i];
        rscal[i] = scal[31 - i];
        rscal[31 - i] = x;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
void monero_hash_init_sha256(cx_hash_t *hasher) {
    cx_sha256_init((cx_sha256_t *)hasher);
}

int monero_hash_init_keccak(cx_hash_t *hasher) {
    int error = cx_keccak_init_no_throw((cx_sha3_t *)hasher, 256);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash_update(cx_hash_t *hasher, const unsigned char *buf, unsigned int len) {
    int error = cx_hash_no_throw(hasher, 0, buf, len, NULL, 0);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash_final(cx_hash_t *hasher, unsigned char *out) {
    int error = cx_hash_no_throw(hasher, CX_LAST, NULL, 0, out, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash(unsigned int algo, cx_hash_t *hasher, const unsigned char *buf, unsigned int len,
                unsigned char *out) {
    int err = 0;
    if (algo == CX_SHA256) {
        cx_sha256_init((cx_sha256_t *)hasher);
    } else {
        err = cx_keccak_init_no_throw((cx_sha3_t *)hasher, 256);
        if (err) {
            return SW_SECURITY_INTERNAL;
        }
    }
    err = cx_hash_no_throw(hasher, CX_LAST, buf, len, out, 32);
    if (err) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
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

int monero_ge_fromfe_frombytes(unsigned char *ge, unsigned char *bytes, size_t ge_len,
                               size_t bytes_len) {
    int error = 0;
#define MOD              (unsigned char *)C_ED25519_FIELD, 32
#define fe_isnegative(f) (f[31] & 1)
#define u                (G_monero_vstate.io_buffer + 0 * 32)
#define v                (G_monero_vstate.io_buffer + 1 * 32)
#define w                (G_monero_vstate.io_buffer + 2 * 32)
#define x                (G_monero_vstate.io_buffer + 3 * 32)
#define y                (G_monero_vstate.io_buffer + 4 * 32)
#define z                (G_monero_vstate.io_buffer + 5 * 32)
#define rX               (G_monero_vstate.io_buffer + 6 * 32)
#define rY               (G_monero_vstate.io_buffer + 7 * 32)
#define rZ               (G_monero_vstate.io_buffer + 8 * 32)

    union {
        unsigned char _Pxy[PXY_SIZE];
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

    unsigned char sign;
    if (!ge) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA;
    }

    if (ge_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }
    // cx works in BE
    error |= monero_reverse32(u, bytes, 32, bytes_len);
    error |= cx_math_modm_no_throw(u, 32, (unsigned char *)C_ED25519_FIELD, 32);

    // go on
    error |= cx_math_multm_no_throw(v, u, u, MOD); /* 2 * u^2 */
    error |= cx_math_addm_no_throw(v, v, v, MOD);

    explicit_bzero(w, 32);
    w[31] = 1;                                                             /* w = 1 */
    error |= cx_math_addm_no_throw(w, v, w, MOD);                          /* w = 2 * u^2 + 1 */
    error |= cx_math_multm_no_throw(x, w, w, MOD);                         /* w^2 */
    error |= cx_math_multm_no_throw(y, (unsigned char *)C_fe_ma2, v, MOD); /* -2 * A^2 * u^2 */
    error |= cx_math_addm_no_throw(x, x, y, MOD); /* x = w^2 - 2 * A^2 * u^2 */

// inline fe_divpowm1(r->X, w, x);     // (w / x)^(m + 1) => fe_divpowm1(r,u,v)
#define _u w
#define _v x
    error |= cx_math_multm_no_throw(v3, _v, _v, MOD);
    error |= cx_math_multm_no_throw(v3, v3, _v, MOD); /* v3 = v^3 */
    error |= cx_math_multm_no_throw(uv7, v3, v3, MOD);
    error |= cx_math_multm_no_throw(uv7, uv7, _v, MOD);
    error |= cx_math_multm_no_throw(uv7, uv7, _u, MOD); /* uv7 = uv^7 */
    error |= cx_math_powm_no_throw(uv7, uv7, (unsigned char *)C_fe_qm5div8, 32,
                                   MOD); /* (uv^7)^((q-5)/8)*/
    error |= cx_math_multm_no_throw(uv7, uv7, v3, MOD);
    error |= cx_math_multm_no_throw(rX, uv7, w, MOD); /* u^(m+1)v^(-(m+1)) */
#undef _u
#undef _v

    error |= cx_math_multm_no_throw(y, rX, rX, MOD);
    error |= cx_math_multm_no_throw(x, y, x, MOD);
    error |= cx_math_subm_no_throw(y, w, x, MOD);
    memcpy(z, C_fe_ma, 32);

    if (!cx_math_is_zero(y, 32)) {
        error |= cx_math_addm_no_throw(y, w, x, MOD);
        if (!cx_math_is_zero(y, 32)) {
            goto negative;
        } else {
            error |= cx_math_multm_no_throw(rX, rX, (unsigned char *)C_fe_fffb1, MOD);
        }
    } else {
        error |= cx_math_multm_no_throw(rX, rX, (unsigned char *)C_fe_fffb2, MOD);
    }
    error |= cx_math_multm_no_throw(rX, rX, u, MOD);  // u * sqrt(2 * A * (A + 2) * w / x)
    error |= cx_math_multm_no_throw(z, z, v, MOD);    // -2 * A * u^2
    sign = 0;

    goto setsign;

negative:
    error |= cx_math_multm_no_throw(x, x, (unsigned char *)C_fe_sqrtm1, MOD);
    error |= cx_math_subm_no_throw(y, w, x, MOD);
    if (!cx_math_is_zero(y, 32)) {
        error |= cx_math_addm_no_throw(y, w, x, MOD);
        error |= cx_math_multm_no_throw(rX, rX, (unsigned char *)C_fe_fffb3, MOD);
    } else {
        error |= cx_math_multm_no_throw(rX, rX, (unsigned char *)C_fe_fffb4, MOD);
    }
    // r->X = sqrt(A * (A + 2) * w / x)
    // z = -A
    sign = 1;

setsign:
    if (fe_isnegative(rX) != sign) {
        error |= cx_math_sub(rX, (unsigned char *)C_ED25519_FIELD, rX, 32);
    }
    error |= cx_math_addm_no_throw(rZ, z, w, MOD);
    error |= cx_math_subm_no_throw(rY, z, w, MOD);
    error |= cx_math_multm_no_throw(rX, rX, rZ, MOD);

    // back to monero y-affine
    error |= cx_math_invprimem_no_throw(u, rZ, MOD);
    Pxy[0] = 0x04;
    error |= cx_math_multm_no_throw(&Pxy[1], rX, u, MOD);
    error |= cx_math_multm_no_throw(&Pxy[1 + 32], rY, u, MOD);
    error |= cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    memcpy(ge, &Pxy[1], 32);

    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;

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
int monero_hash_to_scalar(unsigned char *scalar, unsigned char *raw, size_t scalar_len,
                          unsigned int raw_len) {
    int error;

    error = monero_keccak_F(raw, raw_len, scalar);
    if (error) {
        return error;
    }

    error = monero_reduce(scalar, scalar, scalar_len, scalar_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_hash_to_ec(unsigned char *ec, unsigned char *ec_pub, size_t ec_len) {
    int error;
    error = monero_keccak_F(ec_pub, 32, ec);
    if (error) {
        return error;
    }

    error = monero_ge_fromfe_frombytes(ec, ec, ec_len, ec_len);
    if (error) {
        return error;
    }

    error = monero_ecmul_8(ec, ec, ec_len, ec_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv, size_t ec_pub_len,
                            size_t ec_priv_len) {
    int error;
    error = monero_rng_mod_order(ec_priv, ec_priv_len);
    if (error) {
        return error;
    }

    error = monero_ecmul_G(ec_pub, ec_priv, ec_pub_len, ec_priv_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
int monero_generate_key_derivation(unsigned char *drv_data, unsigned char *P, unsigned char *scalar,
                                   size_t drv_data_len, size_t P_len, size_t scalar_len) {
    return monero_ecmul_8k(drv_data, P, scalar, drv_data_len, P_len, scalar_len);
}

/* ----------------------------------------------------------------------- */
/* ---  ok                                                             --- */
/* ----------------------------------------------------------------------- */
int monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data,
                                unsigned int out_idx, size_t scalar_len, size_t drv_data_len) {
    unsigned char varint[32 + 8];
    unsigned int len_varint;
    int error = 0;

    if (drv_data_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    memcpy(varint, drv_data, 32);
    error = monero_encode_varint(varint + 32, 8, out_idx, &len_varint);
    if (error) {
        return error;
    }
    len_varint += 32;

    error = monero_keccak_F(varint, len_varint, varint);
    if (error) {
        return error;
    }

    error = monero_reduce(scalar, varint, scalar_len, sizeof(varint));
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_derive_secret_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                             unsigned char *ec_priv, size_t x_len, size_t drv_data_len,
                             size_t ec_priv_len) {
    unsigned char tmp[32];
    int error;

    // derivation to scalar
    error = monero_derivation_to_scalar(tmp, drv_data, out_idx, sizeof(tmp), drv_data_len);
    if (error) {
        return error;
    }

    // generate
    error = monero_addm(x, tmp, ec_priv, x_len, sizeof(tmp), ec_priv_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_derive_public_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                             unsigned char *ec_pub, size_t x_len, size_t drv_data_len,
                             size_t ec_pub_len) {
    unsigned char tmp[32];

    // derivation to scalar
    int error = monero_derivation_to_scalar(tmp, drv_data, out_idx, sizeof(tmp), drv_data_len);
    if (error) {
        return error;
    }
    // generate
    error = monero_ecmul_G(tmp, tmp, sizeof(tmp), sizeof(tmp));
    if (error) {
        return error;
    }

    error = monero_ecadd(x, tmp, ec_pub, x_len, sizeof(tmp), ec_pub_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv,
                                    size_t ec_pub_len, size_t ec_priv_len) {
    return monero_ecmul_G(ec_pub, ec_priv, ec_pub_len, ec_priv_len);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_generate_key_image(unsigned char *img, unsigned char *P, unsigned char *x,
                              size_t img_len, size_t x_len) {
    unsigned char I[32];
    int error;
    error = monero_hash_to_ec(I, P, sizeof(I));
    if (error) {
        return error;
    }

    error = monero_ecmul_k(img, I, x, img_len, sizeof(I), x_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_derive_view_tag(unsigned char *view_tag, const unsigned char drv_data[static 32],
                           unsigned int out_idx) {
    unsigned char varint[8 + 32 + 8];
    unsigned int len_varint;
    int error = 0;

    memcpy(varint, "view_tag", 8);
    memcpy(varint + 8, drv_data, 32);
    error = monero_encode_varint(varint + 8 + 32, 8, out_idx, &len_varint);
    if (error) {
        return error;
    }
    len_varint += 8 + 32;

    error = monero_keccak_F(varint, len_varint, varint);
    if (error) {
        return error;
    }

    *view_tag = varint[0];
    return 0;
}

/* ======================================================================= */
/*                               SUB ADDRESS                               */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
int monero_derive_subaddress_public_key(unsigned char *x, unsigned char *pub,
                                        unsigned char *drv_data, unsigned int index, size_t x_len,
                                        size_t pub_len, size_t drv_data_len) {
    unsigned char scalarG[32];
    int error;

    error = monero_derivation_to_scalar(scalarG, drv_data, index, sizeof(scalarG), drv_data_len);
    if (error) {
        return error;
    }
    error = monero_ecmul_G(scalarG, scalarG, sizeof(scalarG), sizeof(scalarG));
    if (error) {
        return error;
    }
    error = monero_ecsub(x, pub, scalarG, x_len, pub_len, sizeof(scalarG));
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
int monero_get_subaddress_spend_public_key(unsigned char *x, unsigned char *index, size_t x_len,
                                           size_t index_len) {
    int error;
    // m = Hs(a || index_major || index_minor)
    error = monero_get_subaddress_secret_key(x, G_monero_vstate.a, index, x_len,
                                             sizeof(G_monero_vstate.a), index_len);
    if (error) {
        return error;
    }

    // M = m*G
    error = monero_secret_key_to_public_key(x, x, x_len, x_len);
    if (error) {
        return error;
    }

    // D = B + M
    error = monero_ecadd(x, x, G_monero_vstate.B, x_len, x_len, sizeof(G_monero_vstate.B));
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index, size_t C_len,
                          size_t D_len, size_t index_len) {
    // retrieve D
    int error = monero_get_subaddress_spend_public_key(D, index, D_len, index_len);
    if (error) {
        return error;
    }
    // C = a*D
    error = monero_ecmul_k(C, D, G_monero_vstate.a, C_len, D_len, sizeof(G_monero_vstate.a));
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* --- ok                                                              --- */
/* ----------------------------------------------------------------------- */
static const char C_sub_address_prefix[] = {'S', 'u', 'b', 'A', 'd', 'd', 'r', 0};

int monero_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s, unsigned char *index,
                                     size_t sub_s_len, size_t s_len, size_t index_len) {
    unsigned char in[sizeof(C_sub_address_prefix) + 32 + 8];
    int error;

    if (!s || s_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!index || index_len < 8) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    memcpy(in, C_sub_address_prefix, sizeof(C_sub_address_prefix));
    memcpy(in + sizeof(C_sub_address_prefix), s, 32);
    memcpy(in + sizeof(C_sub_address_prefix) + 32, index, 8);
    // hash_to_scalar with more that 32bytes:

    error = monero_keccak_F(in, sizeof(in), sub_s);
    if (error) {
        return error;
    }

    error = monero_reduce(sub_s, sub_s, sub_s_len, sub_s_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ======================================================================= */
/*                                  MATH                                   */
/* ======================================================================= */

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_check_scalar_range_1N(unsigned char *s, size_t s_len) {
    unsigned char x[32];
    int diff;
    int error = monero_reverse32(x, s, sizeof(x), s_len);
    if (error) {
        return error;
    }
    if (cx_math_cmp_no_throw(x, C_ED25519_ORDER, 32, &diff)) {
        return SW_SECURITY_INTERNAL;
    }
    if (cx_math_is_zero(x, 32) || diff >= 0) {
        return SW_WRONG_DATA_RANGE;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_check_scalar_not_null(unsigned char *s) {
    if (cx_math_is_zero(s, 32)) {
        return SW_WRONG_DATA_RANGE;
    }
    return 0;
}
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecmul_G(unsigned char *W, unsigned char *scalar32, size_t W_len, size_t scalar32_len) {
    unsigned char Pxy[PXY_SIZE];
    unsigned char s[32];
    int error;

    if (!W || W_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    error = monero_reverse32(s, scalar32, sizeof(s), scalar32_len);
    if (error) {
        return error;
    }
    memcpy(Pxy, C_ED25519_G, PXY_SIZE);
    error = cx_ecfp_scalar_mult_no_throw(CX_CURVE_Ed25519, Pxy, s, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    error = cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    memcpy(W, &Pxy[1], 32);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecmul_H(unsigned char *W, unsigned char *scalar32, size_t W_len, size_t scalar32_len) {
    unsigned char Pxy[PXY_SIZE];
    unsigned char s[32];

    int error = 0;

    if (!W || W_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }
    error = monero_reverse32(s, scalar32, sizeof(s), scalar32_len);
    if (error) {
        return error;
    }

    Pxy[0] = 0x02;
    memcpy(&Pxy[1], C_ED25519_Hy, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    error |= cx_ecfp_scalar_mult_no_throw(CX_CURVE_Ed25519, Pxy, s, 32);

    error |= cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    if (error) {
        return SW_SECURITY_INTERNAL;
    }

    memcpy(W, &Pxy[1], 32);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32, size_t W_len,
                   size_t P_len, size_t scalar32_len) {
    unsigned char Pxy[PXY_SIZE];
    unsigned char s[32];
    int error = 0;

    if (!W || W_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!P || P_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }
    error = monero_reverse32(s, scalar32, sizeof(s), scalar32_len);
    if (error) {
        return error;
    }

    Pxy[0] = 0x02;
    memcpy(&Pxy[1], P, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    error |= cx_ecfp_scalar_mult_no_throw(CX_CURVE_Ed25519, Pxy, s, 32);
    error |= cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    if (error) {
        return SW_SECURITY_INTERNAL;
    }

    memcpy(W, &Pxy[1], 32);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32, size_t W_len,
                    size_t P_len, size_t scalar32_len) {
    unsigned char s[32];
    int error = 0;
    error = monero_multm_8(s, scalar32, sizeof(s), scalar32_len);
    if (error) {
        return error;
    }

    error = monero_ecmul_k(W, P, s, W_len, P_len, sizeof(s));
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecmul_8(unsigned char *W, unsigned char *P, size_t W_len, size_t P_len) {
    unsigned char Pxy[PXY_SIZE];
    int error = 0;

    if (!W || W_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!P || P_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    Pxy[0] = 0x02;
    memcpy(&Pxy[1], P, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    error |= cx_ecfp_add_point_no_throw(CX_CURVE_Ed25519, Pxy, Pxy, Pxy);
    error |= cx_ecfp_add_point_no_throw(CX_CURVE_Ed25519, Pxy, Pxy, Pxy);
    error |= cx_ecfp_add_point_no_throw(CX_CURVE_Ed25519, Pxy, Pxy, Pxy);
    error |= cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    memcpy(W, &Pxy[1], 32);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q, size_t W_len, size_t P_len,
                 size_t Q_len) {
    unsigned char Pxy[PXY_SIZE];
    unsigned char Qxy[PXY_SIZE];
    int error = 0;

    if (!W || W_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!P || P_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!Q || Q_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    Pxy[0] = 0x02;
    memcpy(&Pxy[1], P, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    Qxy[0] = 0x02;
    memcpy(&Qxy[1], Q, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Qxy, sizeof(Qxy));

    error |= cx_ecfp_add_point_no_throw(CX_CURVE_Ed25519, Pxy, Pxy, Qxy);

    error |= cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    memcpy(W, &Pxy[1], 32);

    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q, size_t W_len, size_t P_len,
                 size_t Q_len) {
    unsigned char Pxy[PXY_SIZE];
    unsigned char Qxy[PXY_SIZE];
    int error = 0;

    if (!W || W_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!P || P_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    if (!Q || Q_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    Pxy[0] = 0x02;
    memcpy(&Pxy[1], P, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));

    Qxy[0] = 0x02;
    memcpy(&Qxy[1], Q, 32);
    error |= cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, Qxy, sizeof(Qxy));

    error |= cx_math_sub(Qxy + 1, (unsigned char *)C_ED25519_FIELD, Qxy + 1, 32);
    error |= cx_ecfp_add_point_no_throw(CX_CURVE_Ed25519, Pxy, Pxy, Qxy);

    error |= cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519, Pxy, sizeof(Pxy));
    memcpy(W, &Pxy[1], 32);

    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    return 0;
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
int monero_ecdhHash(unsigned char *x, unsigned char *k, size_t k_len) {
    unsigned char data[38];
    int error;

    if (!k || k_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA;
    }

    memcpy(data, "amount", 6);
    memcpy(data + 6, k, 32);
    error = monero_keccak_F(data, 38, x);
    return error;
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
int monero_genCommitmentMask(unsigned char *c, unsigned char *sk, size_t c_len, size_t sk_len) {
    unsigned char data[15 + 32];
    int error;

    if (!sk || sk_len < 32) {
        PRINTF("Buffer Error: %s:%d \n", __LINE__);
        return SW_WRONG_DATA_RANGE;
    }

    memcpy(data, "commitment_mask", 15);
    memcpy(data + 15, sk, 32);
    error = monero_hash_to_scalar(c, data, c_len, 15 + 32);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_addm(unsigned char *r, unsigned char *a, unsigned char *b, size_t r_len, size_t a_len,
                size_t b_len) {
    unsigned char ra[32];
    unsigned char rb[32];
    int error;

    error = monero_reverse32(ra, a, sizeof(ra), a_len);
    if (error) {
        return error;
    }
    error = monero_reverse32(rb, b, sizeof(rb), b_len);
    if (error) {
        return error;
    }
    error = cx_math_addm_no_throw(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }

    error = monero_reverse32(r, r, r_len, r_len);
    if (error) {
        return error;
    }

    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_subm(unsigned char *r, unsigned char *a, unsigned char *b, size_t r_len, size_t a_len,
                size_t b_len) {
    unsigned char ra[32];
    unsigned char rb[32];
    int error;

    error = monero_reverse32(ra, a, sizeof(ra), a_len);
    if (error) {
        return error;
    }
    error = monero_reverse32(rb, b, sizeof(rb), b_len);
    if (error) {
        return error;
    }
    error = cx_math_subm_no_throw(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }

    error = monero_reverse32(r, r, r_len, r_len);
    if (error) {
        return error;
    }
    return 0;
}
/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_multm(unsigned char *r, unsigned char *a, unsigned char *b, size_t r_len, size_t a_len,
                 size_t b_len) {
    unsigned char ra[32];
    unsigned char rb[32];
    int error;

    error = monero_reverse32(ra, a, sizeof(ra), a_len);
    if (error) {
        return error;
    }
    error = monero_reverse32(rb, b, sizeof(rb), b_len);
    if (error) {
        return error;
    }
    error = cx_math_multm_no_throw(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }

    error = monero_reverse32(r, r, r_len, r_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_multm_8(unsigned char *r, unsigned char *a, size_t r_len, size_t a_len) {
    unsigned char ra[32];
    unsigned char rb[32];
    int error;

    error = monero_reverse32(ra, a, sizeof(ra), a_len);
    if (error) {
        return error;
    }
    explicit_bzero(rb, 32);
    rb[31] = 8;
    error = cx_math_multm_no_throw(r, ra, rb, (unsigned char *)C_ED25519_ORDER, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    error = monero_reverse32(r, r, r_len, r_len);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_reduce(unsigned char *r, unsigned char *a, size_t r_len, size_t a_len) {
    unsigned char ra[32];
    int error;

    error = monero_reverse32(ra, a, sizeof(ra), a_len);
    if (error) {
        return error;
    }
    error = cx_math_modm_no_throw(ra, 32, (unsigned char *)C_ED25519_ORDER, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    error = monero_reverse32(r, ra, r_len, sizeof(ra));
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_rng_mod_order(unsigned char *r, size_t r_len) {
    unsigned char rnd[32 + 8];
    int error;
    cx_rng(rnd, 32 + 8);
    /* To uncomment in order to freeze the secret for test purposes */
    /* memset(rnd, 0xBB, 32 + 8);                      */
    error = cx_math_modm_no_throw(rnd, 32 + 8, (unsigned char *)C_ED25519_ORDER, 32);
    if (error) {
        return SW_SECURITY_INTERNAL;
    }
    error = monero_reverse32(r, rnd + 8, r_len, 32);
    if (error) {
        return error;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_uint642str(uint64_t val, char *str, unsigned int str_len) {
    char stramount[22];
    unsigned int offset, len;

    if (!str) {
        PRINTF("%d \n\n", __LINE__);
        return SW_WRONG_DATA;
    }
    explicit_bzero(str, str_len);

    offset = 22;
    while (val) {
        offset--;
        stramount[offset] = '0' + val % 10;
        val = val / 10;
    }
    len = sizeof(stramount) - offset;
    if (len > str_len) {
        return SW_WRONG_DATA_RANGE;
    }
    memcpy(str, stramount + offset, len);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_amount2str(uint64_t xmr, char *str, unsigned int str_len) {
    // max uint64 is 18446744073709551616, aka 20 char, plus dot
    char stramount[22];
    unsigned int offset, len;

    if (!str) {
        PRINTF("%d \n\n", __LINE__);
        return SW_WRONG_DATA;
    }
    explicit_bzero(str, str_len);

    memset(stramount, '0', sizeof(stramount));
    stramount[21] = 0;
    // special case
    if (xmr == 0) {
        str[0] = '0';
        return 0;
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
    memmove(stramount, stramount + 1, 8);
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
    if (len > (str_len - 1)) {
        len = str_len - 1;
    }
    memcpy(str, stramount + offset, len);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
uint64_t monero_bamount2uint64(unsigned char *binary, size_t binary_len) {
    uint64_t xmr;
    int i;
    if (!binary || binary_len < 8) {
        PRINTF("%d \n\n", __LINE__);
        return 0;
    }
    xmr = 0;
    for (i = 7; i >= 0; i--) {
        xmr = xmr * 256 + binary[i];
    }
    return xmr;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_bamount2str(unsigned char *binary, char *str, size_t binary_len, unsigned int str_len) {
    return monero_amount2str(monero_bamount2uint64(binary, binary_len), str, str_len);
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_vamount2str(unsigned char *binary, char *str, unsigned int str_len) {
    uint64_t amount;
    unsigned int out_len;
    unsigned int error = monero_decode_varint(binary, 8, &amount, &out_len);
    if (error) {
        return error;
    }
    return monero_amount2str(amount, str, str_len);
}
