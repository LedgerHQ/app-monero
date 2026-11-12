/*
 * monero_unblind() and the length of the value buffer.
 *
 * With a short amount the function xors eight bytes into v. The other branch
 * goes through monero_subm, which checks the length it is handed; the short
 * branch checked nothing, so a v shorter than eight bytes was overrun.
 *
 * Both in-tree callers pass sizeof() of a 32-byte array (monero_blind.c:154,
 * monero_prehash.c:226), so no APDU reaches this. The contract is what is
 * being fixed, which is why the test lives here and not in tests/.

 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_blind.h"

#define GUARD_BYTE   0x7e
#define GUARD_LEN    32
#define SHORT_AMOUNT 2

/* Four bytes: shorter than the eight the short-amount branch writes. */
typedef struct {
    unsigned char v[4];
    unsigned char guard[GUARD_LEN];
} guarded_v_t;

static unsigned char k[32];
static unsigned char akout[32];

static int intact(const unsigned char *guard) {
    for (size_t i = 0; i < GUARD_LEN; i++) {
        if (guard[i] != GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

void setUp(void) {
    stub_blind_reset();
    memset(k, 0x11, sizeof(k));
    memset(akout, 0x22, sizeof(akout));
}

void tearDown(void) {}

static void test_short_amount_rejects_a_short_value_buffer(void) {
    guarded_v_t b;
    memset(b.v, 0, sizeof(b.v));
    memset(b.guard, GUARD_BYTE, GUARD_LEN);

    int err = monero_unblind(b.v, k, akout, SHORT_AMOUNT, sizeof(b.v),
                             sizeof(k), sizeof(akout));

    TEST_ASSERT_TRUE_MESSAGE(intact(b.guard),
                             "xored eight bytes into a four-byte buffer");
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_DATA_RANGE, err);
}

/* What both callers actually pass. */
static void test_short_amount_accepts_a_full_value_buffer(void) {
    struct {
        unsigned char v[32];
        unsigned char guard[GUARD_LEN];
    } b;
    memset(b.v, 0, sizeof(b.v));
    memset(b.guard, GUARD_BYTE, GUARD_LEN);

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        0,
        monero_unblind(b.v, k, akout, SHORT_AMOUNT, sizeof(b.v), sizeof(k),
                       sizeof(akout)),
        "a 32-byte value buffer was refused");
    TEST_ASSERT_TRUE(intact(b.guard));
}

/* The acceptance criteria ask for NULL and every short-branch length, not just
 * one sample. A NULL destination is the half the length check cannot see: the
 * xor loop would write straight through it. */
static void test_rejects_a_null_value_buffer(void) {
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(
        SW_WRONG_DATA,
        monero_unblind(NULL, k, akout, SHORT_AMOUNT, 32, sizeof(k),
                       sizeof(akout)),
        "a NULL value buffer was accepted");
}

static void test_rejects_null_key_buffers(void) {
    unsigned char v[32] = {0};
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(
        SW_WRONG_DATA,
        monero_unblind(v, NULL, akout, SHORT_AMOUNT, sizeof(v), sizeof(k),
                       sizeof(akout)),
        "a NULL mask buffer was accepted");
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(
        SW_WRONG_DATA,
        monero_unblind(v, k, NULL, SHORT_AMOUNT, sizeof(v), sizeof(k),
                       sizeof(akout)),
        "a NULL amount-key buffer was accepted");
}

/* Every length from 0 to 7 refused, 8 accepted: the boundary itself, not a
 * sample either side of it. */
static void test_short_amount_every_length_below_eight_is_refused(void) {
    for (size_t len = 0; len < 8; len++) {
        struct {
            unsigned char v[8];
            unsigned char guard[GUARD_LEN];
        } b;
        char msg[64];

        memset(b.v, 0, sizeof(b.v));
        memset(b.guard, GUARD_BYTE, GUARD_LEN);
        stub_blind_reset();

        int err = monero_unblind(b.v, k, akout, SHORT_AMOUNT, len, sizeof(k),
                                 sizeof(akout));

        snprintf(msg, sizeof(msg), "v_len %zu was accepted", len);
        TEST_ASSERT_EQUAL_HEX16_MESSAGE(SW_WRONG_DATA_RANGE, err, msg);
        snprintf(msg, sizeof(msg), "v_len %zu wrote past the buffer", len);
        TEST_ASSERT_TRUE_MESSAGE(intact(b.guard), msg);
    }
}

static void test_short_amount_length_eight_is_accepted(void) {
    struct {
        unsigned char v[8];
        unsigned char guard[GUARD_LEN];
    } b;
    memset(b.v, 0, sizeof(b.v));
    memset(b.guard, GUARD_BYTE, GUARD_LEN);

    TEST_ASSERT_EQUAL_INT_MESSAGE(
        0,
        monero_unblind(b.v, k, akout, SHORT_AMOUNT, sizeof(b.v), sizeof(k),
                       sizeof(akout)),
        "eight bytes is the documented minimum and was refused");
    TEST_ASSERT_TRUE(intact(b.guard));
}

/* The long branch was never the problem: monero_subm checks the length it is
 * given. Here so a future change cannot quietly drop that. */
static void test_long_amount_rejects_a_short_value_buffer(void) {
    guarded_v_t b;
    memset(b.v, 0, sizeof(b.v));
    memset(b.guard, GUARD_BYTE, GUARD_LEN);

    int err = monero_unblind(b.v, k, akout, 0, sizeof(b.v), sizeof(k),
                             sizeof(akout));

    TEST_ASSERT_TRUE(intact(b.guard));
    TEST_ASSERT_NOT_EQUAL(0, err);
}

/* Hs of the spend key is the view key, and the long branch returns
 * k - Hs(AKout). The io layer already refuses a handle of the spend key, so no
 * APDU reaches this; it is the second line. The stub hash gives 0x33 bytes. */
static void test_long_unblind_refuses_a_key_hashing_to_the_view_key(void) {
    unsigned char v[32] = {0};

    memset(G_monero_vstate.a, 0x33, sizeof(G_monero_vstate.a));
    TEST_ASSERT_EQUAL_INT(SW_WRONG_DATA,
                          monero_unblind(v, k, akout, 0, sizeof(v), sizeof(k),
                                         sizeof(akout)));
}

/* Control: any other view key, the long branch still unblinds. */
static void test_long_unblind_still_works_for_other_keys(void) {
    unsigned char v[32] = {0};

    memset(G_monero_vstate.a, 0x44, sizeof(G_monero_vstate.a));
    TEST_ASSERT_EQUAL_INT(0, monero_unblind(v, k, akout, 0, sizeof(v),
                                            sizeof(k), sizeof(akout)));
}

/* The short branch never hashes the key to a scalar, so it is not refused. */
static void test_short_unblind_is_not_affected(void) {
    unsigned char v[32] = {0};

    memset(G_monero_vstate.a, 0x33, sizeof(G_monero_vstate.a));
    TEST_ASSERT_EQUAL_INT(0, monero_unblind(v, k, akout, SHORT_AMOUNT,
                                            sizeof(v), sizeof(k),
                                            sizeof(akout)));
}

/* The same guard in INS_BLIND: refused before anything goes in the reply. */
static void test_long_blind_refuses_a_key_hashing_to_the_view_key(void) {
    memset(G_monero_vstate.a, 0x33, sizeof(G_monero_vstate.a));
    TEST_ASSERT_EQUAL_INT(SW_WRONG_DATA, monero_apdu_blind());
    TEST_ASSERT_EQUAL_UINT(0, stub_blind_inserted());
}

/* Control: any other view key, INS_BLIND returns the blinded value and mask. */
static void test_long_blind_still_works_for_other_keys(void) {
    memset(G_monero_vstate.a, 0x44, sizeof(G_monero_vstate.a));
    TEST_ASSERT_EQUAL_INT(SW_OK, monero_apdu_blind());
    TEST_ASSERT_EQUAL_UINT(64, stub_blind_inserted());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_long_unblind_refuses_a_key_hashing_to_the_view_key);
    RUN_TEST(test_long_unblind_still_works_for_other_keys);
    RUN_TEST(test_short_unblind_is_not_affected);
    RUN_TEST(test_long_blind_refuses_a_key_hashing_to_the_view_key);
    RUN_TEST(test_long_blind_still_works_for_other_keys);
    RUN_TEST(test_short_amount_rejects_a_short_value_buffer);
    RUN_TEST(test_short_amount_accepts_a_full_value_buffer);
    RUN_TEST(test_rejects_a_null_value_buffer);
    RUN_TEST(test_rejects_null_key_buffers);
    RUN_TEST(test_short_amount_every_length_below_eight_is_refused);
    RUN_TEST(test_short_amount_length_eight_is_accepted);
    RUN_TEST(test_long_amount_rejects_a_short_value_buffer);
    return UNITY_END();
}
