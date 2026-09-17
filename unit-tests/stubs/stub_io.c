/*
 * What monero_io.c needs from outside itself, so the test links only the file
 * under test.
 *
 *   io_exchange        scripted: returns the length the test chose, which is
 *                      the whole point -- the device cannot be made to receive
 *                      fewer than five bytes, but a stub can.
 *   G_io_tx_buffer     the real name behind G_io_apdu_buffer. Kept dirty on
 *                      purpose, the way the SDK leaves it.
 *   send_error_and_kill_app  noreturn on device, a longjmp here.
 *   the rest           never reached by the length paths, present to link.
 */

#include <setjmp.h>
#include <stdint.h>
#include <string.h>

/* Order matters, as in stub_monero.c: monero_api.h first because its static
 * inlines use G_monero_vstate, cx.h before it for cx_sha3_t. */
#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_io.h"

monero_v_state_t G_monero_vstate;

/* On device this is const NVRAM, so a const object would land in .rodata and
 * a write would fault. Alias it onto writable storage. */
static monero_nv_state_t nv_storage;
extern const monero_nv_state_t N_state_pic __attribute__((alias("nv_storage")));

unsigned char G_io_tx_buffer[OS_IO_BUFFER_SIZE + 1];

jmp_buf stub_kill_jmp;
int stub_kill_sw;

static unsigned short stub_rx;

void stub_io_reset(void) {
    memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
    memset(&nv_storage, 0, sizeof(nv_storage));
    memset(G_io_tx_buffer, 0, sizeof(G_io_tx_buffer));
    stub_kill_sw = 0;
    stub_rx = 0;
}

void stub_set_rx(const unsigned char *apdu, unsigned short len,
                 unsigned short rx) {
    memcpy(G_io_tx_buffer, apdu, len);
    stub_rx = rx;
}

void stub_fill_stale(unsigned char value) {
    memset(G_io_tx_buffer, value, sizeof(G_io_tx_buffer));
}

unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len) {
    (void) channel_and_flags;
    (void) tx_len;
    return stub_rx;
}

void __attribute__((noreturn)) send_error_and_kill_app(int sw) {
    stub_kill_sw = sw;
    longjmp(stub_kill_jmp, 1);
}

/* Linked, not exercised: the length guard returns or kills before any of these
 * can be reached. */
void nvm_write(void *dst, void *src, unsigned int len) {
    if (src) {
        memcpy(dst, src, len);
    } else {
        memset(dst, 0, len);
    }
}

unsigned int monero_check_scalar_not_null(unsigned char *s) {
    (void) s;
    return 0;
}

unsigned int monero_check_scalar_range_1N(unsigned char *s, size_t s_len) {
    (void) s;
    (void) s_len;
    return 0;
}

const unsigned char C_FAKE_SEC_VIEW_KEY[KEY_SIZE] = {0};
const unsigned char C_FAKE_SEC_SPEND_KEY[KEY_SIZE] = {0};

size_t cx_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *in,
                      size_t len, uint8_t *mac, size_t mac_len) {
    (void) key;
    (void) key_len;
    (void) in;
    (void) len;
    memset(mac, 0, mac_len);
    return mac_len;
}

/* The real cx_aes_no_throw is AES-128 in CBC with a zero IV. The handle-format
 * tests need CBC over a keyed 16-byte permutation that diffuses; they do not
 * need AES itself. This is an eight-round Feistel, and
 * test_the_stub_cipher_diffuses checks that assumption instead of trusting it.
 */
static uint64_t stub_load64(const uint8_t *p) {
    uint64_t v = 0;

    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void stub_store64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t) (v & 0xff);
        v >>= 8;
    }
}

static uint64_t stub_round(uint64_t x, unsigned int r) {
    x ^= 0x9e3779b97f4a7c15ULL + r;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 31;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 29;
    return x;
}

static void stub_block(uint8_t *b, int decrypt) {
    uint64_t l = stub_load64(b);
    uint64_t r = stub_load64(b + 8);
    uint64_t t;

    for (unsigned int k = 0; k < 8; k++) {
        if (decrypt) {
            t = r ^ stub_round(l, 7 - k);
            r = l;
            l = t;
        } else {
            t = l ^ stub_round(r, k);
            l = r;
            r = t;
        }
    }
    stub_store64(b, l);
    stub_store64(b + 8, r);
}

cx_err_t cx_aes_no_throw(const cx_aes_key_t *key, uint32_t mode,
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t *out_len) {
    uint8_t prev[16] = {0}; /* zero IV, as cx_aes_no_throw passes NULL, 0 */
    uint8_t blk[16];
    uint8_t ct[16];
    int decrypt = (mode & CX_ENCRYPT) == 0;

    (void) key;
    if (in_len % 16) {
        return CX_INVALID_PARAMETER_SIZE;
    }
    for (size_t off = 0; off < in_len; off += 16) {
        memcpy(blk, in + off, 16);
        if (decrypt) {
            memcpy(ct, blk, 16);
            stub_block(blk, 1);
            for (int i = 0; i < 16; i++) {
                blk[i] ^= prev[i];
            }
            memcpy(prev, ct, 16);
        } else {
            for (int i = 0; i < 16; i++) {
                blk[i] ^= prev[i];
            }
            stub_block(blk, 0);
            memcpy(prev, blk, 16);
        }
        memcpy(out + off, blk, 16);
    }
    *out_len = in_len;
    return CX_OK;
}

uint16_t read_u16_be(const uint8_t *ptr, size_t offset) {
    return (uint16_t) ((ptr[offset] << 8) | ptr[offset + 1]);
}

uint32_t read_u32_be(const uint8_t *ptr, size_t offset) {
    return ((uint32_t) ptr[offset] << 24) | ((uint32_t) ptr[offset + 1] << 16) |
           ((uint32_t) ptr[offset + 2] << 8) | (uint32_t) ptr[offset + 3];
}

unsigned int monero_decode_varint(const unsigned char *varint, size_t max_len,
                                  uint64_t *value, unsigned int *len) {
    (void) varint;
    (void) max_len;
    *value = 0;
    *len = 1;
    return 0;
}
