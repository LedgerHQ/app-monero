/*
 * What monero_blind.c needs from the rest of the app, so the test links only
 * the file under test.
 *
 * The crypto helpers are not crypto here. Each writes what the real one
 * writes and honours the length it is given, so the only unchecked write left
 * is the one under test.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_blind.h"

monero_v_state_t G_monero_vstate;

static unsigned int inserted;

static monero_nv_state_t nv_storage;
extern const monero_nv_state_t N_state_pic __attribute__((alias("nv_storage")));

void stub_blind_reset(void) {
    memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
    memset(&nv_storage, 0, sizeof(nv_storage));
    inserted = 0;
}

unsigned int stub_blind_inserted(void) {
    return inserted;
}

void __attribute__((noreturn)) send_error_and_kill_app(int sw) {
    (void) sw;
    abort();
}

int monero_genCommitmentMask(unsigned char* c, unsigned char* sk, size_t c_len,
                             size_t sk_len) {
    (void) sk;
    (void) sk_len;
    if (c_len < 32) {
        return SW_WRONG_DATA_RANGE;
    }
    memset(c, 0x31, 32);
    return 0;
}

int monero_ecdhHash(unsigned char* x, unsigned char* k, size_t x_len) {
    (void) k;
    if (x_len < 32) {
        return SW_WRONG_DATA_RANGE;
    }
    memset(x, 0x32, 32);
    return 0;
}

int monero_hash_to_scalar(unsigned char* scalar, unsigned char* raw,
                          size_t scalar_len, unsigned int raw_len) {
    (void) raw;
    (void) raw_len;
    if (scalar_len < 32) {
        return SW_WRONG_DATA_RANGE;
    }
    memset(scalar, 0x33, 32);
    return 0;
}

int monero_subm(unsigned char* r, unsigned char* a, unsigned char* b,
                size_t r_len, size_t a_len, size_t b_len) {
    (void) a;
    (void) b;
    (void) a_len;
    (void) b_len;
    if (r_len < 32) {
        return SW_WRONG_DATA_RANGE;
    }
    memset(r, 0x34, 32);
    return 0;
}

int monero_addm(unsigned char* r, unsigned char* a, unsigned char* b,
                size_t r_len, size_t a_len, size_t b_len) {
    (void) a;
    (void) b;
    (void) a_len;
    (void) b_len;
    if (r_len < 32) {
        return SW_WRONG_DATA_RANGE;
    }
    memset(r, 0x35, 32);
    return 0;
}

/* The io layer: fetches give zeros, decrypt succeeds as the real one does, and
 * inserts are only counted. */
void monero_io_discard(int clear) { (void) clear; }

int monero_io_fetch(unsigned char* buffer, int len) {
    memset(buffer, 0, len);
    return len;
}

int monero_io_fetch_decrypt(unsigned char* buffer, size_t len, int type) {
    (void) type;
    memset(buffer, 0, len);
    return 0;
}

void monero_io_insert(unsigned char const* buff, unsigned int len) {
    (void) buff;
    inserted += len;
}

/* The SDK's constant-time compare: zero when equal. */
char os_secure_memcmp(const void *src1, const void *src2, size_t length) {
    const unsigned char *a = src1;
    const unsigned char *b = src2;
    unsigned char acc = 0;

    for (size_t i = 0; i < length; i++) {
        acc |= a[i] ^ b[i];
    }
    return acc;
}
