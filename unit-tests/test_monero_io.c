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
    RUN_TEST(test_io_hole_refuses_a_wrapping_size);
    RUN_TEST(test_io_hole_still_takes_a_normal_size);
    return UNITY_END();
}
