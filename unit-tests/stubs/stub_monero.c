/*
 * What monero_monero.c needs from the rest of the app, so the test links only
 * the file under test.
 *
 *   monero_encode_varint  the real thing, small enough to write out here.
 *   monero_hash           stubbed. monero_keccak_F is a static inline calling
 *                         it, so this is the symbol to replace. Not keccak,
 *                         just a digest that changes with the input, which is
 *                         all the checksum needs to differ per address.
 *   the two globals       G_monero_vstate for the keccak context, N_state_pic
 *                         for the network id. stub_set_network() sets it.
 */

#include <stdint.h>
#include <string.h>

/* Order matters. monero_api.h and monero_vars.h include each other, and the
 * static inlines in monero_api.h use G_monero_vstate, which monero_vars.h
 * declares -- so monero_api.h has to come first. cx.h precedes it because
 * monero_types.h uses cx_sha3_t. */
#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_monero.h"

monero_v_state_t G_monero_vstate;

/* On device this lives in NVRAM and is const to the app, so the type has to
 * stay const here. A const object lands in .rodata, where the tests could not
 * write the network id, so the symbol is an alias for writable storage. */
static monero_nv_state_t nv_storage;
extern const monero_nv_state_t N_state_pic __attribute__((alias("nv_storage")));

void stub_set_network(unsigned char network_id) {
    memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
    memset(&nv_storage, 0, sizeof(nv_storage));
    nv_storage.network_id = network_id;
}

unsigned int monero_encode_varint(unsigned char* varint, unsigned int max_len,
                                 uint64_t v, unsigned int* len) {
    unsigned int n = 0;

    do {
        if (n == max_len) {
            return 0x6984; /* SW_WRONG_DATA */
        }
        varint[n] = v & 0x7F;
        v >>= 7;
        if (v) {
            varint[n] |= 0x80;
        }
        n++;
    } while (v);

    *len = n;
    return 0;
}

/* Depends on every input byte, so addresses that differ anywhere get different
 * checksum bytes. */
int monero_hash(unsigned int algo, cx_hash_t* hasher, const unsigned char* buf,
                unsigned int len, unsigned char* out) {
    uint32_t h = 0x811c9dc5;

    (void) algo;
    (void) hasher;

    for (unsigned int i = 0; i < len; i++) {
        h = (h ^ buf[i]) * 0x01000193;
    }
    for (unsigned int i = 0; i < 32; i++) {
        h = (h ^ (uint8_t) i) * 0x01000193;
        out[i] = (unsigned char) (h >> 24);
    }
    return 0;
}
