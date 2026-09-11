/*
 * What monero_crypto.c needs from the SDK, so the test links only the file
 * under test.
 *
 * These are not crypto. Each writes the number of bytes the real one writes,
 * because that is what these tests are about: which buffer gets how many
 * bytes, and whether the length was checked first.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_crypto.h"

monero_v_state_t G_monero_vstate;

/* const NVRAM on device, so it would land in .rodata and fault on write. */
static monero_nv_state_t nv_storage;
extern const monero_nv_state_t N_state_pic __attribute__((alias("nv_storage")));

#define FILLER 0xc3

int stub_crypto_fail_scalar_mult = 0;
int stub_crypto_fail_addm = 0;

void stub_crypto_reset(void) {
    memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
    memset(&nv_storage, 0, sizeof(nv_storage));
    stub_crypto_fail_scalar_mult = 0;
    stub_crypto_fail_addm = 0;
}

void __attribute__((noreturn)) send_error_and_kill_app(int sw) {
    (void) sw;
    /* Nothing under test here reaches it; abort rather than pretend. */
    abort();
}

/* -- hashing: writes out_len, which monero_hash always calls with 32 -- */
cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in,
                          size_t len, uint8_t *out, size_t out_len) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) len;
    if (out && out_len) {
        memset(out, FILLER, out_len);
    }
    return CX_OK;
}

cx_err_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void) hash;
    (void) size;
    return CX_OK;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return CX_OK;
}

/* -- modular arithmetic: each writes len bytes into r -- */
cx_err_t cx_math_addm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b,
                               const uint8_t *m, size_t len) {
    (void) b;
    (void) m;
    (void) a;
    if (stub_crypto_fail_addm) {
        stub_crypto_fail_addm = 0;
        return CX_INVALID_PARAMETER;
    }
    memset(r, FILLER, len);
    return CX_OK;
}

cx_err_t cx_math_subm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b,
                               const uint8_t *m, size_t len) {
    (void) a;
    (void) b;
    (void) m;
    memset(r, FILLER, len);
    return CX_OK;
}

cx_err_t cx_math_multm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b,
                                const uint8_t *m, size_t len) {
    (void) a;
    (void) b;
    (void) m;
    memset(r, FILLER, len);
    return CX_OK;
}

cx_err_t cx_math_modm_no_throw(uint8_t *v, size_t len_v, const uint8_t *m,
                               size_t len_m) {
    (void) v;
    (void) len_v;
    (void) m;
    (void) len_m;
    return CX_OK;
}

cx_err_t cx_math_powm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *e,
                               size_t len_e, const uint8_t *m, size_t len) {
    (void) a;
    (void) e;
    (void) len_e;
    (void) m;
    memset(r, FILLER, len);
    return CX_OK;
}

cx_err_t cx_math_invprimem_no_throw(uint8_t *r, const uint8_t *a,
                                    const uint8_t *m, size_t len) {
    (void) a;
    (void) m;
    memset(r, FILLER, len);
    return CX_OK;
}

cx_err_t cx_math_sub_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b,
                              size_t len) {
    (void) a;
    (void) b;
    memset(r, 0, len);
    return CX_OK;
}

cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b, size_t length,
                              int *diff) {
    *diff = memcmp(a, b, length);
    return CX_OK;
}

cx_err_t cx_math_is_zero_no_throw(bool *is_zero, const uint8_t *a, size_t len) {
    *is_zero = true;
    for (size_t i = 0; i < len; i++) {
        if (a[i]) {
            *is_zero = false;
            break;
        }
    }
    return CX_OK;
}

/* -- curve operations: write the compressed/uncompressed point width -- */
cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t curve, uint8_t *R,
                                    const uint8_t *P, const uint8_t *Q) {
    (void) curve;
    (void) P;
    (void) Q;
    memset(R, FILLER, 65);
    return CX_OK;
}

cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve, uint8_t *P,
                                      const uint8_t *k, size_t k_len) {
    (void) curve;
    (void) k_len;
    (void) k;
    if (stub_crypto_fail_scalar_mult) {
        stub_crypto_fail_scalar_mult = 0;
        return CX_INVALID_PARAMETER;
    }
    memset(P, FILLER, 65);
    return CX_OK;
}

cx_err_t cx_edwards_compress_point_no_throw(cx_curve_t curve, uint8_t *p,
                                            size_t p_len) {
    (void) curve;
    (void) p_len;
    memset(p, FILLER, 33);
    return CX_OK;
}

cx_err_t cx_edwards_decompress_point_no_throw(cx_curve_t curve, uint8_t *p,
                                              size_t p_len) {
    (void) curve;
    (void) p_len;
    memset(p, FILLER, 65);
    return CX_OK;
}

cx_err_t cx_aes_init_key_no_throw(const uint8_t *rawkey, size_t key_len,
                                  cx_aes_key_t *key) {
    (void) rawkey;
    (void) key_len;
    (void) key;
    return CX_OK;
}

void cx_rng_no_throw(uint8_t *buffer, size_t len) {
    memset(buffer, 0x5a, len);
}

/* cx_math_is_zero is a static inline that throws on error, and throwing is
 * os_longjmp. Nothing here provokes it. */
void __attribute__((noreturn)) os_longjmp(unsigned int exception) {
    (void) exception;
    abort();
}
