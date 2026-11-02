/*
 * monero_io_do() and the APDU length it is told versus the one it got.
 *
 * The host sets Lc; the transport reports how many bytes actually arrived.
 * Believing Lc lets a short APDU be completed out of G_io_apdu_buffer, which
 * is the same array the previous reply was sent from and is never cleared.
 *
 * tests/test_vuln_apdu_length_unchecked.py covers this over real APDUs. What
 * it cannot reach is an APDU shorter than the five-byte header: the transport
 * always delivers at least a full header, so only a scripted io_exchange gets
 * there. That case is why this suite exists.
 */

#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_io.h"

/* CLA INS P1 P2 Lc, then one option byte and eight of payload: an honest
 * INS_GET_SUBADDRESS, the shape the ragger test uses. */
#define LC 9
static const unsigned char APDU[5 + LC] = {
    0x03, 0x48, 0x00, 0x00, LC,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

void setUp(void) { stub_io_reset(); }

void tearDown(void) {}

/* Run monero_io_do and report whether the app was killed. */
static int killed(void) {
    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_do(0);
        return 0;
    }
    return 1;
}

static void test_matching_length_is_accepted(void) {
    stub_set_rx(APDU, sizeof(APDU), sizeof(APDU));

    TEST_ASSERT_FALSE_MESSAGE(killed(), "a well-formed APDU was refused");
    TEST_ASSERT_EQUAL_UINT(LC, G_monero_vstate.io_length);
    TEST_ASSERT_EQUAL_HEX8(0x48, G_monero_vstate.io_ins);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(APDU + 5, G_monero_vstate.io_buffer, LC);
}

static void test_empty_payload_is_accepted(void) {
    /* Lc = 0 with nothing after it is consistent, so it must pass. */
    const unsigned char header[5] = {0x03, 0x48, 0x00, 0x00, 0x00};
    stub_set_rx(header, sizeof(header), sizeof(header));

    TEST_ASSERT_FALSE_MESSAGE(killed(), "an empty but honest APDU was refused");
    TEST_ASSERT_EQUAL_UINT(0, G_monero_vstate.io_length);
}

static void test_declared_more_than_arrived_is_refused(void) {
    /* The finding: five bytes claiming nine follow. */
    stub_fill_stale(0xAA);
    stub_set_rx(APDU, 5, 5);

    TEST_ASSERT_TRUE_MESSAGE(killed(), "a truncated APDU was accepted");
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_LENGTH, stub_kill_sw);
}

static void test_stale_bytes_are_not_adopted(void) {
    /* Refusing is only half of it: io_length must not be left claiming data
     * the parser would then read out of the buffer. */
    stub_fill_stale(0xAA);
    stub_set_rx(APDU, 5, 5);

    TEST_ASSERT_TRUE(killed());
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, G_monero_vstate.io_length,
                                   "io_length took the declared Lc anyway");
}

static void test_shorter_than_the_header_is_refused(void) {
    /* Four bytes: no Lc at all. No transport delivers this, which is why the
     * ragger test cannot cover it. */
    const unsigned char runt[4] = {0x03, 0x48, 0x00, 0x00};
    stub_set_rx(runt, sizeof(runt), sizeof(runt));

    TEST_ASSERT_TRUE_MESSAGE(killed(), "a headerless APDU was accepted");
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_LENGTH, stub_kill_sw);
}

static void test_more_arrived_than_declared_is_refused(void) {
    /* Trailing bytes the host did not account for: also a mismatch, and
     * refusing keeps the rule one-to-one rather than "at least". */
    stub_set_rx(APDU, sizeof(APDU), sizeof(APDU) + 3);

    TEST_ASSERT_TRUE_MESSAGE(killed(), "trailing bytes were accepted");
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_LENGTH, stub_kill_sw);
}

/* ------------------------------ key fetch and response-buffer holes */

/* A short destination with a guard behind it, so an overrun is visible. */
#define GUARD_BYTE 0x7e
#define GUARD_LEN  32

typedef struct {
    unsigned char buf[16];
    unsigned char guard[GUARD_LEN];
} guarded_short_t;

static int guard_intact(const unsigned char *guard) {
    for (size_t i = 0; i < GUARD_LEN; i++) {
        if (guard[i] != GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

static void arm_short(guarded_short_t *b) {
    memset(b->buf, 0, sizeof(b->buf));
    memset(b->guard, GUARD_BYTE, GUARD_LEN);
}

/* Put 32 readable bytes in the io buffer, so the honest path has something to
 * decrypt. Not the fake view or spend key, so it takes the decrypt branch. */
static void give_io_a_key(void) {
    memset(G_monero_vstate.io_buffer, 0x5c, 32);
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 32;
}

static void test_fetch_decrypt_key_rejects_a_short_buffer(void) {
    /* The check read `buffer_size > 32`, so it turned away the buffers that
     * were big enough and waved through the ones that were not. */
    guarded_short_t b;
    arm_short(&b);
    give_io_a_key();

    int err = monero_io_fetch_decrypt_key(b.buf, sizeof(b.buf));

    TEST_ASSERT_TRUE_MESSAGE(guard_intact(b.guard),
                             "wrote 32 bytes into a 16-byte buffer");
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_DATA_RANGE, err);
}

static void test_fetch_decrypt_key_accepts_a_full_buffer(void) {
    /* Every caller in the app passes sizeof() of a 32-byte array. */
    struct {
        unsigned char buf[32];
        unsigned char guard[GUARD_LEN];
    } b;
    memset(b.buf, 0, sizeof(b.buf));
    memset(b.guard, GUARD_BYTE, GUARD_LEN);
    give_io_a_key();

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        0, monero_io_fetch_decrypt_key(b.buf, sizeof(b.buf)),
        "a 32-byte buffer was refused");
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

static void test_io_hole_refuses_a_wrapping_size(void) {
    /* The check added io_length to sz first, so a size near UINT_MAX wrapped
     * to something small and passed. The memmove that follows would then use
     * that size as an offset. */
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 10;

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_hole(0xFFFFFFF8u);
        TEST_FAIL_MESSAGE("a wrapping size was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
}

static void test_io_hole_still_takes_a_normal_size(void) {
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 10;

    if (setjmp(stub_kill_jmp) != 0) {
        TEST_FAIL_MESSAGE("a 32-byte hole in a 300-byte buffer was refused");
    }
    monero_io_hole(32);
    TEST_ASSERT_EQUAL_UINT(42, G_monero_vstate.io_length);
}

/* The wrap check was only half of it. monero_io_inserted() still added into
 * the unsigned-short counters unchecked, and monero_io_hole() never required
 * io_offset <= io_length before subtracting one from the other. The sequence
 * below is the one the 2026-09-11 verdict set out. */

static void test_io_inserted_refuses_growth_past_capacity(void) {
    /* offset 0, length 10, then grow by 65530: the counters are unsigned short,
     * so offset became 65530 and length wrapped to 4. monero_io_hole(1) then
     * passed the capacity check on a length of 4 and handed memmove a negative
     * 4 - 65530 as a size_t. */
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 10;

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_inserted(65530);
        TEST_FAIL_MESSAGE("growth past the buffer was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
}

static void test_io_inserted_still_takes_what_the_app_asks_for(void) {
    /* The only real caller is monero_key.c, with 95. */
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 0;

    if (setjmp(stub_kill_jmp) != 0) {
        TEST_FAIL_MESSAGE("95 bytes into an empty 300-byte buffer was refused");
    }
    monero_io_inserted(95);
    TEST_ASSERT_EQUAL_UINT(95, G_monero_vstate.io_offset);
    TEST_ASSERT_EQUAL_UINT(95, G_monero_vstate.io_length);
}

static void test_io_hole_refuses_an_offset_past_the_length(void) {
    /* The state monero_io_inserted() used to be able to leave behind. The
     * subtraction below it would be negative, and memmove takes a size_t. */
    G_monero_vstate.io_offset = 50;
    G_monero_vstate.io_length = 10;

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_hole(1);
        TEST_FAIL_MESSAGE("an offset past the length was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(SW_SECURITY_INTERNAL, (unsigned int) stub_kill_sw);
}

static void test_io_hole_refuses_a_length_past_the_buffer(void) {
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = MONERO_IO_BUFFER_LENGTH + 1;

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_hole(1);
        TEST_FAIL_MESSAGE("a length past the buffer was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(SW_SECURITY_INTERNAL, (unsigned int) stub_kill_sw);
}

static void test_io_inserted_refuses_a_broken_state(void) {
    G_monero_vstate.io_offset = 50;
    G_monero_vstate.io_length = 10;

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_inserted(1);
        TEST_FAIL_MESSAGE("an offset past the length was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(SW_SECURITY_INTERNAL, (unsigned int) stub_kill_sw);
}

/* ------------------------------ negative parser lengths */

/* io_length and io_offset are unsigned short, so the guard's subtraction
 * promotes to signed int and the whole comparison is signed. A negative length
 * used to pass it and reach memcpy, which takes a size_t: -1 becomes SIZE_MAX.
 * No caller in the app passes one, so only a direct call gets here. */

static void give_io_a_payload(unsigned short len) {
    memset(G_monero_vstate.io_buffer, 0x5c, len);
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = len;
}

static void test_skip_refuses_a_negative_length(void) {
    give_io_a_payload(64);

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_skip(-1);
        TEST_FAIL_MESSAGE("a negative skip was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, G_monero_vstate.io_offset,
                                   "io_offset moved on a refused skip");
}

static void test_fetch_refuses_a_negative_length(void) {
    /* Unfixed, this is memcpy(dst, src, SIZE_MAX) and the suite dies rather
     * than reporting a failure. */
    guarded_short_t b;
    arm_short(&b);
    give_io_a_payload(64);

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_fetch(b.buf, -1);
        TEST_FAIL_MESSAGE("a negative fetch was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
    TEST_ASSERT_TRUE_MESSAGE(guard_intact(b.guard),
                             "wrote past the destination");
}

static void test_fetch_refuses_more_than_remains(void) {
    /* The direction that always worked, kept so a fix cannot lose it. */
    guarded_short_t b;
    arm_short(&b);
    give_io_a_payload(8);

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_fetch(b.buf, 16);
        TEST_FAIL_MESSAGE("read past the end of the payload");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

static void test_fetch_still_takes_a_legal_length(void) {
    guarded_short_t b;
    arm_short(&b);
    give_io_a_payload(64);

    if (setjmp(stub_kill_jmp) != 0) {
        TEST_FAIL_MESSAGE("an eight-byte fetch from 64 bytes was refused");
    }
    TEST_ASSERT_EQUAL_INT(8, monero_io_fetch(b.buf, 8));
    TEST_ASSERT_EQUAL_UINT(8, G_monero_vstate.io_offset);
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

static void test_fetch_still_takes_a_zero_length(void) {
    /* monero_apdu_reset fetches io_length - io_offset bytes, which is zero for
     * an empty INS_RESET, so the boundary has to stay open. */
    guarded_short_t b;
    arm_short(&b);
    give_io_a_payload(0);

    if (setjmp(stub_kill_jmp) != 0) {
        TEST_FAIL_MESSAGE("a zero-length fetch was refused");
    }
    TEST_ASSERT_EQUAL_INT(0, monero_io_fetch(b.buf, 0));
    TEST_ASSERT_EQUAL_UINT(0, G_monero_vstate.io_offset);
}

static void test_skip_refuses_the_most_negative_length(void) {
    /* INT_MIN has no positive counterpart, so a fix that negates rather than
     * rejects would still be broken here. */
    give_io_a_payload(64);

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_skip(INT_MIN);
        TEST_FAIL_MESSAGE("INT_MIN was accepted as a length");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
    TEST_ASSERT_EQUAL_UINT(0, G_monero_vstate.io_offset);
}

static void test_fetch_nv_refuses_a_negative_length(void) {
    /* No caller in the app, but it is the third helper taking a signed length
     * and its sink is an NVM write. */
    guarded_short_t b;
    arm_short(&b);
    give_io_a_payload(64);

    if (setjmp(stub_kill_jmp) == 0) {
        monero_io_fetch_nv(b.buf, -1);
        TEST_FAIL_MESSAGE("a negative NVM write length was accepted");
    }
    TEST_ASSERT_EQUAL_HEX32(ERROR_IO_FULL, (unsigned int) stub_kill_sw);
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

static void test_fetch_takes_exactly_what_remains(void) {
    /* The boundary the guard must not close: len == available. */
    struct {
        unsigned char buf[16];
        unsigned char guard[GUARD_LEN];
    } b;
    memset(b.buf, 0, sizeof(b.buf));
    memset(b.guard, GUARD_BYTE, GUARD_LEN);
    give_io_a_payload(16);

    if (setjmp(stub_kill_jmp) != 0) {
        TEST_FAIL_MESSAGE("a fetch of exactly the remaining bytes was refused");
    }
    TEST_ASSERT_EQUAL_INT(16, monero_io_fetch(b.buf, 16));
    TEST_ASSERT_EQUAL_UINT(16, G_monero_vstate.io_offset);
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

/* ------------------------------------------ handle format */

/* A handle is 32 bytes and the wallet carries no tag beside one, so the fix
 * cannot add integrity. What it adds is diffusion: a handle is two CBC passes
 * with the halves swapped between them, so one spliced from two others no
 * longer hands back a half of either.
 *
 * One format for every handle. An earlier version chose per instruction, to
 * keep handles in old wallet caches readable, and that was wrong: the wallet
 * reads a handle minted inside a transaction from outside one, in the sanity
 * check it runs after every send.
 *
 * None of this is reachable from a functional test: DEBUG=1 builds define
 * IODUMMYCRYPT, so the device the ragger suite drives never runs the AES path.
 * That is why this file is the only guard on it.
 */

static const unsigned char PLAIN_A[32] = {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x03};
static const unsigned char PLAIN_B[32] = {
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
    0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0x04};

/* insert_encrypt kills the app on failure, which is a longjmp here, so a mint
 * runs under the jump target. */
static int mint(unsigned char handle[32], const unsigned char plain[32],
                unsigned int ins, int in_tx) {
    if (setjmp(stub_kill_jmp) != 0) {
        return 0;
    }
    G_monero_vstate.tx_in_progress = in_tx;
    G_monero_vstate.io_ins = ins;
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 0;
    monero_io_insert_encrypt((unsigned char *) plain, 32, TYPE_SCALAR);
    memcpy(handle, G_monero_vstate.io_buffer, 32);
    return 1;
}

static int redeem(unsigned char plain[32], const unsigned char handle[32],
                  unsigned int ins) {
    if (setjmp(stub_kill_jmp) != 0) {
        return -1;
    }
    memcpy(G_monero_vstate.io_buffer, handle, 32);
    G_monero_vstate.tx_in_progress = 0;
    G_monero_vstate.io_ins = ins;
    G_monero_vstate.io_offset = 0;
    G_monero_vstate.io_length = 32;
    return monero_io_fetch_decrypt(plain, 32, TYPE_SCALAR);
}

static int bits_differing(const unsigned char *a, const unsigned char *b,
                          size_t len) {
    int n = 0;

    for (size_t i = 0; i < len; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (((a[i] ^ b[i]) >> bit) & 1) {
                n++;
            }
        }
    }
    return n;
}

/* The venue itself. Every claim below rests on the stub cipher behaving like a
 * block cipher, so that is checked rather than assumed. */
static void test_the_stub_cipher_diffuses(void) {
    unsigned char in[16] = {0};
    unsigned char a[16];
    unsigned char b[16];
    unsigned char back[16];
    size_t len = sizeof(a);

    TEST_ASSERT_EQUAL_INT(CX_OK, cx_aes_no_throw(NULL, CX_ENCRYPT, in,
                                                 sizeof(in), a, &len));
    in[0] ^= 1;
    len = sizeof(b);
    TEST_ASSERT_EQUAL_INT(CX_OK, cx_aes_no_throw(NULL, CX_ENCRYPT, in,
                                                 sizeof(in), b, &len));
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(
        40, bits_differing(a, b, sizeof(a)),
        "the stub cipher does not diffuse, so the tests below prove nothing");

    len = sizeof(back);
    TEST_ASSERT_EQUAL_INT(CX_OK, cx_aes_no_throw(NULL, CX_DECRYPT, b,
                                                 sizeof(b), back, &len));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(in, back, sizeof(in));
}

static void test_a_handle_round_trips(void) {
    unsigned char handle[32];
    unsigned char out[32];

    TEST_ASSERT_TRUE(mint(handle, PLAIN_A, INS_SECRET_SCAL_MUL_BASE, 0));
    TEST_ASSERT_EQUAL_INT(0, redeem(out, handle, INS_SECRET_SCAL_MUL_BASE));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PLAIN_A, out, 32);
}

/* The leak, on CBC itself. One pass leaves the first plaintext block a
 * function of the first ciphertext block alone, so a splice hands back the low
 * half of whichever handle supplied it. This is why one pass is not enough. */
static void test_a_single_cbc_pass_hands_back_a_half(void) {
    unsigned char ca[32];
    unsigned char cb[32];
    unsigned char spliced[32];
    unsigned char out[32];
    size_t len = 32;

    TEST_ASSERT_EQUAL_INT(CX_OK, cx_aes_no_throw(NULL, CX_ENCRYPT, PLAIN_A, 32,
                                                 ca, &len));
    len = 32;
    TEST_ASSERT_EQUAL_INT(CX_OK, cx_aes_no_throw(NULL, CX_ENCRYPT, PLAIN_B, 32,
                                                 cb, &len));
    memcpy(spliced, ca, 16);
    memcpy(spliced + 16, cb + 16, 16);

    len = 32;
    TEST_ASSERT_EQUAL_INT(CX_OK, cx_aes_no_throw(NULL, CX_DECRYPT, spliced, 32,
                                                 out, &len));
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(PLAIN_A, out, 16,
                                         "expected the low half to leak");
}

/* And closed. Two passes make both plaintext halves depend on both ciphertext
 * blocks, so the same splice yields neither half of either source. */
static void test_a_two_pass_splice_hands_back_neither_half(void) {
    unsigned char ha[32];
    unsigned char hb[32];
    unsigned char spliced[32];
    unsigned char out[32];

    TEST_ASSERT_TRUE(mint(ha, PLAIN_A, INS_SECRET_SCAL_MUL_BASE, 0));
    TEST_ASSERT_TRUE(mint(hb, PLAIN_B, INS_SECRET_SCAL_MUL_BASE, 0));
    memcpy(spliced, ha, 16);
    memcpy(spliced + 16, hb + 16, 16);

    TEST_ASSERT_EQUAL_INT(0, redeem(out, spliced, INS_SECRET_SCAL_MUL_BASE));
    TEST_ASSERT_TRUE_MESSAGE(memcmp(out, PLAIN_A, 16) != 0,
                             "low half of the first source leaked");
    TEST_ASSERT_TRUE_MESSAGE(memcmp(out + 16, PLAIN_A + 16, 16) != 0,
                             "high half of the first source leaked");
    TEST_ASSERT_TRUE_MESSAGE(memcmp(out, PLAIN_B, 16) != 0,
                             "low half of the second source leaked");
    TEST_ASSERT_TRUE_MESSAGE(memcmp(out + 16, PLAIN_B + 16, 16) != 0,
                             "high half of the second source leaked");
}

/* The regression that reached a real wallet. wallet2 runs a sanity check after
 * every send: it asks for a transaction proof, which feeds the tx-secret handle
 * minted inside the transaction to INS_SECRET_SCAL_MUL_KEY from outside one
 * (wallet2.cpp:12991). While the format depended on the instruction, that
 * handle came back as garbage and every send with change failed. */
static void test_a_transaction_handle_redeems_outside_a_transaction(void) {
    unsigned char handle[32];
    unsigned char out[32];

    TEST_ASSERT_TRUE(mint(handle, PLAIN_A, INS_OPEN_TX, 1));
    TEST_ASSERT_EQUAL_INT(0, redeem(out, handle, INS_SECRET_SCAL_MUL_KEY));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PLAIN_A, out, 32);
}

/* And the other direction, which the same mistake would have broken. */
static void test_a_plain_handle_redeems_inside_a_transaction(void) {
    unsigned char handle[32];
    unsigned char out[32];

    TEST_ASSERT_TRUE(mint(handle, PLAIN_A, INS_SECRET_SCAL_MUL_KEY, 0));
    TEST_ASSERT_EQUAL_INT(0, redeem(out, handle, INS_GET_TX_PROOF));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PLAIN_A, out, 32);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_matching_length_is_accepted);
    RUN_TEST(test_empty_payload_is_accepted);
    RUN_TEST(test_declared_more_than_arrived_is_refused);
    RUN_TEST(test_stale_bytes_are_not_adopted);
    RUN_TEST(test_shorter_than_the_header_is_refused);
    RUN_TEST(test_more_arrived_than_declared_is_refused);
    RUN_TEST(test_fetch_decrypt_key_rejects_a_short_buffer);
    RUN_TEST(test_fetch_decrypt_key_accepts_a_full_buffer);
    RUN_TEST(test_the_stub_cipher_diffuses);
    RUN_TEST(test_a_handle_round_trips);
    RUN_TEST(test_a_single_cbc_pass_hands_back_a_half);
    RUN_TEST(test_a_two_pass_splice_hands_back_neither_half);
    RUN_TEST(test_a_transaction_handle_redeems_outside_a_transaction);
    RUN_TEST(test_a_plain_handle_redeems_inside_a_transaction);
    RUN_TEST(test_io_hole_refuses_a_wrapping_size);
    RUN_TEST(test_io_hole_still_takes_a_normal_size);
    RUN_TEST(test_io_inserted_refuses_growth_past_capacity);
    RUN_TEST(test_io_inserted_still_takes_what_the_app_asks_for);
    RUN_TEST(test_io_hole_refuses_an_offset_past_the_length);
    RUN_TEST(test_io_hole_refuses_a_length_past_the_buffer);
    RUN_TEST(test_io_inserted_refuses_a_broken_state);
    RUN_TEST(test_skip_refuses_a_negative_length);
    RUN_TEST(test_fetch_refuses_a_negative_length);
    RUN_TEST(test_fetch_refuses_more_than_remains);
    RUN_TEST(test_fetch_still_takes_a_legal_length);
    RUN_TEST(test_fetch_still_takes_a_zero_length);
    RUN_TEST(test_skip_refuses_the_most_negative_length);
    RUN_TEST(test_fetch_nv_refuses_a_negative_length);
    RUN_TEST(test_fetch_takes_exactly_what_remains);
    return UNITY_END();
}
