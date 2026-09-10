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

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_matching_length_is_accepted);
    RUN_TEST(test_empty_payload_is_accepted);
    RUN_TEST(test_declared_more_than_arrived_is_refused);
    RUN_TEST(test_stale_bytes_are_not_adopted);
    RUN_TEST(test_shorter_than_the_header_is_refused);
    RUN_TEST(test_more_arrived_than_declared_is_refused);
    return UNITY_END();
}
