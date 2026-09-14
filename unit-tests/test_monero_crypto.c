/*
 * Destination lengths in monero_crypto.c, and when they are checked.
 *
 * Each helper takes the size of its output buffer, but several write the
 * result first and validate the size afterwards, through monero_reverse32 or
 * monero_reduce. By then the bytes are already down. A caller that passes a
 * buffer smaller than 32 gets it overrun.
 *
 * Every in-tree caller passes sizeof() of a 32-byte array, so no APDU reaches
 * any of this; the contract is what is being fixed, for the next caller.
 * That is why these live here and not in tests/.
 *
 * Covers the hash-to-scalar and hash-to-EC helpers, the modular arithmetic
 * helpers, and the amount formatter.
 */

#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"

#include "stub_crypto.h"

/* A short destination with a guard behind it, so a write past the end is
 * visible instead of fatal. 16 is any size under the 32 these helpers
 * unconditionally write. */
#define GUARD_BYTE 0x7e
#define GUARD_LEN  32
#define SHORT_LEN  16

typedef struct {
    unsigned char buf[SHORT_LEN];
    unsigned char guard[GUARD_LEN];
} guarded_short_t;

typedef struct {
    unsigned char buf[32];
    unsigned char guard[GUARD_LEN];
} guarded_full_t;

static void arm(void *b, size_t buf_len) {
    memset(b, 0, buf_len);
    memset((unsigned char *) b + buf_len, GUARD_BYTE, GUARD_LEN);
}

static int intact(const unsigned char *guard) {
    for (size_t i = 0; i < GUARD_LEN; i++) {
        if (guard[i] != GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

static unsigned char A[32];
static unsigned char B[32];

void setUp(void) {
    stub_crypto_reset();
    memset(A, 0x11, sizeof(A));
    memset(B, 0x22, sizeof(B));
}

void tearDown(void) {}

/* ------------------------------------------ secret-scalar cleanup */

/* The helpers copy the caller's scalar into a local and used to return without
 * clearing it. Every exit now routes through one explicit_bzero block.
 *
 * That the local ends up zero is NOT asserted here. Doing so means reading the
 * callee's frame after it has returned, which is undefined and duly behaved
 * differently on CI than on a developer machine. The erasure is verified by
 * inspection; what these tests hold is the part a refactor actually breaks,
 * which is that routing every exit through one label did not change any
 * return value on either path. */

static void test_ecmul_G_success_path_unchanged(void) {
    guarded_full_t w;
    arm(&w, sizeof(w.buf));

    TEST_ASSERT_EQUAL_INT(0, monero_ecmul_G(w.buf, A, sizeof(w.buf), sizeof(A)));
    TEST_ASSERT_TRUE(intact(w.guard));
}

static void test_ecmul_G_sdk_error_still_reports_internal(void) {
    guarded_full_t w;
    arm(&w, sizeof(w.buf));

    stub_crypto_fail_scalar_mult = 1;
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(
        SW_SECURITY_INTERNAL,
        monero_ecmul_G(w.buf, A, sizeof(w.buf), sizeof(A)),
        "the SDK-error exit stopped reporting SW_SECURITY_INTERNAL");
    TEST_ASSERT_TRUE(intact(w.guard));
}

static void test_ecmul_H_success_path_unchanged(void) {
    guarded_full_t w;
    arm(&w, sizeof(w.buf));

    TEST_ASSERT_EQUAL_INT(0, monero_ecmul_H(w.buf, A, sizeof(w.buf), sizeof(A)));
    TEST_ASSERT_TRUE(intact(w.guard));
}

static void test_ecmul_H_sdk_error_still_reports_internal(void) {
    guarded_full_t w;
    arm(&w, sizeof(w.buf));

    stub_crypto_fail_scalar_mult = 1;
    TEST_ASSERT_EQUAL_HEX16(SW_SECURITY_INTERNAL,
                            monero_ecmul_H(w.buf, A, sizeof(w.buf), sizeof(A)));
}

static void test_addm_sdk_error_still_reports_internal(void) {
    guarded_full_t r;
    arm(&r, sizeof(r.buf));

    stub_crypto_fail_addm = 1;
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(
        SW_SECURITY_INTERNAL,
        monero_addm(r.buf, A, B, sizeof(r.buf), sizeof(A), sizeof(B)),
        "the SDK-error exit stopped reporting SW_SECURITY_INTERNAL");
    TEST_ASSERT_TRUE(intact(r.guard));
}

/* The argument checks run before any copy exists, so they must still refuse
 * exactly as before rather than fall through into the cleanup path. */
static void test_argument_checks_are_unchanged(void) {
    unsigned char out[32];
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_DATA_RANGE,
                            monero_ecmul_G(NULL, A, 32, sizeof(A)));
    TEST_ASSERT_EQUAL_HEX16(SW_WRONG_DATA_RANGE,
                            monero_ecmul_G(out, A, 31, sizeof(A)));
    TEST_ASSERT_EQUAL_HEX16(
        SW_WRONG_DATA_RANGE,
        monero_addm(NULL, A, B, 32, sizeof(A), sizeof(B)));
}

/* ------------------------------------------ modular arithmetic */

/* cx_math_*m_no_throw writes 32 bytes into r before monero_reverse32 gets to
 * look at r_len. */
static void check_short_dest_refused(int err, const guarded_short_t *b,
                                     const char *name) {
    char msg[96];
    snprintf(msg, sizeof(msg), "%s wrote past a %d-byte destination", name,
             SHORT_LEN);
    TEST_ASSERT_TRUE_MESSAGE(intact(b->guard), msg);
    snprintf(msg, sizeof(msg), "%s accepted a %d-byte destination", name,
             SHORT_LEN);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, err, msg);
}

static void test_addm_rejects_a_short_destination(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    check_short_dest_refused(
        monero_addm(b.buf, A, B, sizeof(b.buf), sizeof(A), sizeof(B)), &b,
        "monero_addm");
}

static void test_subm_rejects_a_short_destination(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    check_short_dest_refused(
        monero_subm(b.buf, A, B, sizeof(b.buf), sizeof(A), sizeof(B)), &b,
        "monero_subm");
}

static void test_multm_rejects_a_short_destination(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    check_short_dest_refused(
        monero_multm(b.buf, A, B, sizeof(b.buf), sizeof(A), sizeof(B)), &b,
        "monero_multm");
}

static void test_multm_8_rejects_a_short_destination(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    check_short_dest_refused(
        monero_multm_8(b.buf, A, sizeof(b.buf), sizeof(A)), &b,
        "monero_multm_8");
}

/* A short destination is only half the contract: r_len >= 32 says nothing
 * about r being a real address. The SDK math exports len bytes to r with no
 * pointer check of its own, and the stubs here memset it directly, so without
 * an entry check these calls would fault rather than return. */
static void check_null_dest_refused(int err, const char *name) {
    char msg[96];
    snprintf(msg, sizeof(msg), "%s accepted a NULL destination", name);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, err, msg);
    /* A non-zero status is not enough on its own: these stubs skip a write to
     * NULL, where the real SDK would not, so the call can "fail" for some
     * later reason while the guard is missing. Require that nothing reached an
     * SDK call with a NULL destination at all. */
    snprintf(msg, sizeof(msg), "%s let a NULL destination reach the SDK", name);
    TEST_ASSERT_FALSE_MESSAGE(stub_crypto_null_dest_seen, msg);
}

static void test_addm_rejects_a_null_destination(void) {
    check_null_dest_refused(monero_addm(NULL, A, B, 32, sizeof(A), sizeof(B)),
                            "monero_addm");
}

static void test_subm_rejects_a_null_destination(void) {
    check_null_dest_refused(monero_subm(NULL, A, B, 32, sizeof(A), sizeof(B)),
                            "monero_subm");
}

static void test_multm_rejects_a_null_destination(void) {
    check_null_dest_refused(monero_multm(NULL, A, B, 32, sizeof(A), sizeof(B)),
                            "monero_multm");
}

static void test_multm_8_rejects_a_null_destination(void) {
    check_null_dest_refused(monero_multm_8(NULL, A, 32, sizeof(A)),
                            "monero_multm_8");
}

static void test_hash_to_scalar_rejects_a_null_destination(void) {
    check_null_dest_refused(monero_hash_to_scalar(NULL, A, 32, sizeof(A)),
                            "monero_hash_to_scalar");
}

static void test_hash_to_ec_rejects_a_null_destination(void) {
    check_null_dest_refused(monero_hash_to_ec(NULL, A, 32),
                            "monero_hash_to_ec");
}

static void test_subaddress_secret_key_rejects_a_null_destination(void) {
    unsigned char index[8] = {0};
    check_null_dest_refused(
        monero_get_subaddress_secret_key(NULL, A, index, 32, sizeof(A),
                                         sizeof(index)),
        "monero_get_subaddress_secret_key");
}

/* monero_reduce is the sibling that already got it right: it works in a local
 * and only then reverses into r, so monero_reverse32 sees r_len in time. Here
 * to keep it that way. */
static void test_reduce_was_already_safe(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    int err = monero_reduce(b.buf, A, sizeof(b.buf), sizeof(A));

    TEST_ASSERT_TRUE_MESSAGE(intact(b.guard),
                             "monero_reduce wrote past a short destination");
    TEST_ASSERT_NOT_EQUAL(0, err);
}

/* ------------------------------------------------ hash helpers */

static void test_hash_to_scalar_rejects_a_short_destination(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    check_short_dest_refused(
        monero_hash_to_scalar(b.buf, A, sizeof(b.buf), sizeof(A)), &b,
        "monero_hash_to_scalar");
}

static void test_hash_to_ec_rejects_a_short_destination(void) {
    guarded_short_t b;
    arm(&b, sizeof(b.buf));
    check_short_dest_refused(monero_hash_to_ec(b.buf, A, sizeof(b.buf)), &b,
                             "monero_hash_to_ec");
}

/* -------------------------------------------------- amount2str */

/* The verdict asked for every boundary length, not one sample: 0, 1 and 31 all
 * have to refuse with the destination and the canary untouched. One buffer
 * serves all three, since the point is the declared length rather than the
 * allocation. */
static void check_every_short_length_refused(
    int (*call)(unsigned char *dest, size_t dest_len), const char *name) {
    static const size_t lens[] = {0, 1, 31};

    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        struct {
            unsigned char buf[31];
            unsigned char guard[GUARD_LEN];
        } b;
        char msg[96];

        memset(b.buf, 0, sizeof(b.buf));
        memset(b.guard, GUARD_BYTE, GUARD_LEN);

        int err = call(b.buf, lens[i]);

        snprintf(msg, sizeof(msg), "%s accepted a %zu-byte destination", name,
                 lens[i]);
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, err, msg);
        snprintf(msg, sizeof(msg), "%s wrote past a %zu-byte destination", name,
                 lens[i]);
        TEST_ASSERT_TRUE_MESSAGE(intact(b.guard), msg);
        for (size_t j = 0; j < sizeof(b.buf); j++) {
            snprintf(msg, sizeof(msg), "%s touched a %zu-byte destination",
                     name, lens[i]);
            TEST_ASSERT_EQUAL_HEX8_MESSAGE(0, b.buf[j], msg);
        }
    }
}

static int call_hash_to_scalar(unsigned char *dest, size_t dest_len) {
    return monero_hash_to_scalar(dest, A, dest_len, sizeof(A));
}

static int call_hash_to_ec(unsigned char *dest, size_t dest_len) {
    return monero_hash_to_ec(dest, A, dest_len);
}

static int call_subaddress_secret_key(unsigned char *dest, size_t dest_len) {
    unsigned char index[8] = {0};
    return monero_get_subaddress_secret_key(dest, A, index, dest_len, sizeof(A),
                                            sizeof(index));
}

static void test_hash_to_scalar_refuses_every_short_length(void) {
    check_every_short_length_refused(call_hash_to_scalar,
                                     "monero_hash_to_scalar");
}

static void test_hash_to_ec_refuses_every_short_length(void) {
    check_every_short_length_refused(call_hash_to_ec, "monero_hash_to_ec");
}

/* The one the verdict found still unguarded: it checked s and index but never
 * its own output. */
static void test_subaddress_secret_key_refuses_every_short_length(void) {
    check_every_short_length_refused(call_subaddress_secret_key,
                                     "monero_get_subaddress_secret_key");
}

static void test_amount2str_rejects_a_zero_length_buffer(void) {
    /* xmr == 0 takes the special case, which wrote str[0] with no room. */
    guarded_short_t b;
    arm(&b, 0);
    unsigned int err = monero_amount2str(0, (char *) b.buf, 0);

    TEST_ASSERT_TRUE_MESSAGE(intact(b.buf),
                             "the zero case wrote into a zero-length buffer");
    TEST_ASSERT_NOT_EQUAL(0, err);
}

static void test_amount2str_zero_length_does_not_underflow(void) {
    /* The other path is worse: `len > (str_len - 1)` with str_len 0 wraps to
     * UINT_MAX, so the clamp never fires and the memcpy runs to full width. */
    guarded_short_t b;
    arm(&b, 0);
    unsigned int err = monero_amount2str(1234567890123ULL, (char *) b.buf, 0);

    TEST_ASSERT_TRUE_MESSAGE(intact(b.buf),
                             "the clamp underflowed and the memcpy ran");
    TEST_ASSERT_NOT_EQUAL(0, err);
}

/* ------------------------------------------------- controls */

/* A full-size destination is what every caller in the app passes, and must
 * keep working. A fix that just refused everything would pass the tests above
 * and fail here. */
static void test_full_size_destinations_still_work(void) {
    guarded_full_t b;

    arm(&b, sizeof(b.buf));
    TEST_ASSERT_EQUAL_INT(
        0, monero_addm(b.buf, A, B, sizeof(b.buf), sizeof(A), sizeof(B)));
    TEST_ASSERT_TRUE(intact(b.guard));

    arm(&b, sizeof(b.buf));
    TEST_ASSERT_EQUAL_INT(
        0, monero_multm_8(b.buf, A, sizeof(b.buf), sizeof(A)));
    TEST_ASSERT_TRUE(intact(b.guard));

    arm(&b, sizeof(b.buf));
    TEST_ASSERT_EQUAL_INT(
        0, monero_hash_to_scalar(b.buf, A, sizeof(b.buf), sizeof(A)));
    TEST_ASSERT_TRUE(intact(b.guard));
}

static void test_amount2str_formats_normally(void) {
    char out[32];

    TEST_ASSERT_EQUAL_UINT(0, monero_amount2str(0, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("0", out);

    /* 1.5 XMR, i.e. 1.5e12 atomic units. Trailing zeros are stripped, which
     * is why a round 1 XMR comes out as "1." and this uses a value that does
     * not hide that. */
    TEST_ASSERT_EQUAL_UINT(
        0, monero_amount2str(1500000000000ULL, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("1.5", out);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ecmul_G_success_path_unchanged);
    RUN_TEST(test_ecmul_G_sdk_error_still_reports_internal);
    RUN_TEST(test_ecmul_H_success_path_unchanged);
    RUN_TEST(test_ecmul_H_sdk_error_still_reports_internal);
    RUN_TEST(test_addm_sdk_error_still_reports_internal);
    RUN_TEST(test_argument_checks_are_unchanged);
    RUN_TEST(test_addm_rejects_a_short_destination);
    RUN_TEST(test_subm_rejects_a_short_destination);
    RUN_TEST(test_multm_rejects_a_short_destination);
    RUN_TEST(test_multm_8_rejects_a_short_destination);
    RUN_TEST(test_addm_rejects_a_null_destination);
    RUN_TEST(test_subm_rejects_a_null_destination);
    RUN_TEST(test_multm_rejects_a_null_destination);
    RUN_TEST(test_multm_8_rejects_a_null_destination);
    RUN_TEST(test_hash_to_scalar_rejects_a_null_destination);
    RUN_TEST(test_hash_to_ec_rejects_a_null_destination);
    RUN_TEST(test_subaddress_secret_key_rejects_a_null_destination);
    RUN_TEST(test_reduce_was_already_safe);
    RUN_TEST(test_hash_to_scalar_rejects_a_short_destination);
    RUN_TEST(test_hash_to_ec_rejects_a_short_destination);
    RUN_TEST(test_hash_to_scalar_refuses_every_short_length);
    RUN_TEST(test_hash_to_ec_refuses_every_short_length);
    RUN_TEST(test_subaddress_secret_key_refuses_every_short_length);
    RUN_TEST(test_amount2str_rejects_a_zero_length_buffer);
    RUN_TEST(test_amount2str_zero_length_does_not_underflow);
    RUN_TEST(test_full_size_destinations_still_work);
    RUN_TEST(test_amount2str_formats_normally);
    return UNITY_END();
}
