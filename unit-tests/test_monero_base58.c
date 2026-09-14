/*
 * Unit tests for monero_base58_public_key() in src/monero_monero.c.
 *
 * How much it writes depends on an argument: 96 bytes for a plain address, 107
 * with a payment ID. It takes str_b58_len and refuses anything shorter.
 *
 * A short buffer is unreachable over APDUs -- no command makes the app pass
 * one -- so only a direct call can ask what happens. That is why these are here
 * and not in tests/.
 *
 * stubs/stub_monero.c replaces monero_hash, so the 4 checksum bytes are not a
 * real keccak. base58 encodes 8 bytes at a time into 11 characters and the
 * checksum lands in the last block, so characters 0..87 are the real encoding
 * and only the tail is stubbed. Whole-address correctness is covered by the
 * ragger tests, which compare against an address built in Python.
 *
 * Run: cmake -B build -S . && cmake --build build && ctest --test-dir build -V
 *      (needs BOLOS_SDK set)
 */

#include <string.h>

#include "unity.h"

/* monero_api.h before monero_types.h -- see the note in stubs/stub_monero.c. */
#include "monero_api.h"
#include "monero_types.h"

#include "stub_monero.h"

/* Lengths the function hardcodes (monero_monero.c:78-79). */
#define ADDR_LEN            95
#define INTEGRATED_ADDR_LEN 106

#define B58_ALPHABET \
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

/* base58 encodes 8 bytes at a time into 11 characters. The 4 checksum bytes sit
 * in the last block either way, so everything before it is real even with a
 * stubbed digest. */
#define REAL_CHARS 88

/* The test seed's keys, the same pair the ragger tests use. */
static const unsigned char VIEW[KEY_SIZE] = {
    0x86, 0x5c, 0xbf, 0xab, 0x85, 0x2a, 0x1d, 0x1c, 0xcd, 0xfc, 0x73,
    0x28, 0xe4, 0xda, 0xc9, 0x0f, 0x78, 0xfc, 0x21, 0x54, 0x25, 0x7d,
    0x07, 0x52, 0x2e, 0x9b, 0x79, 0xe6, 0x37, 0x32, 0x6d, 0xfa};
static const unsigned char SPEND[KEY_SIZE] = {
    0xda, 0xe4, 0x1d, 0x6b, 0x13, 0x56, 0x8f, 0xdd, 0x71, 0xec, 0x3d,
    0x20, 0xc2, 0xf6, 0x14, 0xc6, 0x5f, 0xe8, 0x19, 0xf3, 0x6c, 0xa5,
    0xda, 0x8d, 0x24, 0xdf, 0x3b, 0xd8, 0x9b, 0x2b, 0xad, 0x9d};

static const unsigned char PAY_ID[8] = {0x11, 0x22, 0x33, 0x44,
                                        0x55, 0x66, 0x77, 0x88};
static const unsigned char PAY_ID_2[8] = {0x99, 0xaa, 0xbb, 0xcc,
                                          0xdd, 0xee, 0xff, 0x00};

/* A buffer with a guard behind it, so a write past the end is visible. One
 * object rather than two allocations, so an overrun is seen and not fatal. */
#define GUARD_BYTE 0x7e
#define GUARD_LEN  32

typedef struct {
    char addr[MAX_ADDR_LENGTH];
    unsigned char guard[GUARD_LEN];
} guarded_160_t;

typedef struct {
    char addr[ADDR_LEN + 1]; /* exactly enough for a plain address */
    unsigned char guard[GUARD_LEN];
} guarded_96_t;

static void arm(void* buf, size_t addr_len) {
    memset(buf, 0, addr_len);
    memset((unsigned char*) buf + addr_len, GUARD_BYTE, GUARD_LEN);
}

static int guard_intact(const unsigned char* guard) {
    for (size_t i = 0; i < GUARD_LEN; i++) {
        if (guard[i] != GUARD_BYTE) {
            return 0;
        }
    }
    return 1;
}

void setUp(void) {
    stub_set_network(STAGENET);
}

void tearDown(void) {
}

/* ------------------------------------------------------------------ lengths */

void test_plain_address_is_95_chars(void) {
    guarded_160_t b;
    arm(&b, sizeof(b.addr));

    TEST_ASSERT_EQUAL_INT(
        0, monero_base58_public_key(b.addr, sizeof(b.addr),
                                    (unsigned char*) VIEW,
                                    (unsigned char*) SPEND, 0, NULL));
    TEST_ASSERT_EQUAL_size_t(ADDR_LEN, strlen(b.addr));
}

void test_subaddress_is_95_chars(void) {
    guarded_160_t b;
    arm(&b, sizeof(b.addr));

    TEST_ASSERT_EQUAL_INT(
        0, monero_base58_public_key(b.addr, sizeof(b.addr),
                                    (unsigned char*) VIEW,
                                    (unsigned char*) SPEND, 1, NULL));
    TEST_ASSERT_EQUAL_size_t(ADDR_LEN, strlen(b.addr));
}

void test_integrated_address_is_106_chars(void) {
    guarded_160_t b;
    arm(&b, sizeof(b.addr));

    TEST_ASSERT_EQUAL_INT(
        0, monero_base58_public_key(b.addr, sizeof(b.addr),
                                    (unsigned char*) VIEW,
                                    (unsigned char*) SPEND, 0,
                                    (unsigned char*) PAY_ID));
    /* 11 more than a plain address, which is why the safe buffer size
     * depends on an argument. */
    TEST_ASSERT_EQUAL_size_t(INTEGRATED_ADDR_LEN, strlen(b.addr));
}

/* ------------------------------------------------------------------- bounds */

/* The control. Every caller in the app passes ux_address, which is this size,
 * and neither form may touch anything past the string. */
void test_no_write_past_a_160_byte_buffer(void) {
    guarded_160_t b;

    arm(&b, sizeof(b.addr));
    monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, NULL);
    TEST_ASSERT_TRUE_MESSAGE(guard_intact(b.guard),
                             "plain address wrote past 160 bytes");

    arm(&b, sizeof(b.addr));
    monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID);
    TEST_ASSERT_TRUE_MESSAGE(guard_intact(b.guard),
                             "integrated address wrote past 160 bytes");
}

/* A buffer sized for a plain address is still fine for a plain address. */
void test_no_write_past_a_96_byte_buffer_without_payment_id(void) {
    guarded_96_t b;

    arm(&b, sizeof(b.addr));
    monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, NULL);

    TEST_ASSERT_EQUAL_size_t(ADDR_LEN, strlen(b.addr));
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

/* A buffer too small for the form asked for is refused, and nothing is written
 * past it. An integrated address needs 107 bytes; this one holds 96. */
void test_short_buffer_is_refused(void) {
    guarded_96_t b;

    arm(&b, sizeof(b.addr));

    /* An integrated address needs 107 bytes and this buffer holds 96. */
    TEST_ASSERT_EQUAL_HEX16_MESSAGE(
        SW_SECURITY_INTERNAL,
        monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                                 (unsigned char*) SPEND, 0,
                                 (unsigned char*) PAY_ID),
        "a buffer 11 bytes too small was not refused with "
        "SW_SECURITY_INTERNAL");
    TEST_ASSERT_TRUE_MESSAGE(guard_intact(b.guard),
                             "the refusal still wrote past the buffer");
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, strlen(b.addr),
                                     "the refusal left a partial address");
}

/* The old behaviour: with no length to check, this call overran the buffer by
 * 11 bytes. Ignored, because it asserts the bug and now fails -- remove the
 * ignore on a build without the length parameter to see it again. */
void test_reproduce_the_old_overflow(void) {
    guarded_96_t b;

    TEST_IGNORE_MESSAGE(
        "the old behaviour, fixed -- needs a build without the length check");

    arm(&b, sizeof(b.addr));
    monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID);

    TEST_ASSERT_FALSE_MESSAGE(guard_intact(b.guard),
                              "not reproduced: the guard survived");
}

/* ---------------------------------------------------------- what it encodes */

void test_output_uses_only_base58_characters(void) {
    guarded_160_t b;
    arm(&b, sizeof(b.addr));

    monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID);

    for (size_t i = 0; i < strlen(b.addr); i++) {
        TEST_ASSERT_NOT_NULL_MESSAGE(strchr(B58_ALPHABET, b.addr[i]),
                                     "character outside the base58 alphabet");
    }
}

/* The payment ID is the last field before the checksum, so two integrated
 * addresses for one key pair share every earlier block -- which is why a user
 * comparing them has to read the tail. */
void test_payment_id_changes_only_the_tail(void) {
    guarded_160_t one, two;

    arm(&one, sizeof(one.addr));
    arm(&two, sizeof(two.addr));

    monero_base58_public_key(one.addr, sizeof(one.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID);
    monero_base58_public_key(two.addr, sizeof(two.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID_2);

    TEST_ASSERT_EQUAL_STRING_LEN(one.addr, two.addr, REAL_CHARS);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, strcmp(one.addr, two.addr),
                                  "two payment IDs gave the same address");
}

/* The network and address kind pick the base58 prefix, the first character a
 * user reads. Values computed independently for these keys. A plain and an
 * integrated address share it; a subaddress does not. */
void test_network_and_kind_pick_the_first_character(void) {
    guarded_160_t b;
    struct {
        unsigned char net;
        char plain;
        char integrated;
        char subaddress;
    } cases[] = {
        {MAINNET, '4', '4', '8'},
        {TESTNET, 'A', 'A', 'B'},
        {STAGENET, '5', '5', '7'},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        stub_set_network(cases[i].net);

        arm(&b, sizeof(b.addr));
        monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                                 (unsigned char*) SPEND, 0, NULL);
        TEST_ASSERT_EQUAL_CHAR(cases[i].plain, b.addr[0]);

        arm(&b, sizeof(b.addr));
        monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                                 (unsigned char*) SPEND, 1, NULL);
        TEST_ASSERT_EQUAL_CHAR(cases[i].subaddress, b.addr[0]);

        arm(&b, sizeof(b.addr));
        monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                                 (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID);
        TEST_ASSERT_EQUAL_CHAR(cases[i].integrated, b.addr[0]);
    }
}

/* A payment ID wins over is_subaddress, giving an integrated address built from
 * subaddress keys that nobody can pay. This is why payment_id_to_display() in
 * monero_prehash.c refuses that pair rather than calling here with both -- if
 * this ever changes, that refusal can go. */
void test_payment_id_wins_over_is_subaddress(void) {
    guarded_160_t with_flag, without;

    arm(&with_flag, sizeof(with_flag.addr));
    arm(&without, sizeof(without.addr));

    monero_base58_public_key(with_flag.addr, sizeof(with_flag.addr),
                             (unsigned char*) VIEW, (unsigned char*) SPEND, 1,
                             (unsigned char*) PAY_ID);
    monero_base58_public_key(without.addr, sizeof(without.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, (unsigned char*) PAY_ID);

    TEST_ASSERT_EQUAL_size_t(INTEGRATED_ADDR_LEN, strlen(with_flag.addr));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(without.addr, with_flag.addr,
                                     "is_subaddress changed the result, so the "
                                     "payment ID no longer takes precedence");
}

/* An unknown network is refused with an empty string rather than a wrong
 * address. */
void test_unknown_network_yields_an_empty_string(void) {
    guarded_160_t b;

    stub_set_network(FAKECHAIN);
    arm(&b, sizeof(b.addr));

    monero_base58_public_key(b.addr, sizeof(b.addr), (unsigned char*) VIEW,
                             (unsigned char*) SPEND, 0, NULL);

    TEST_ASSERT_EQUAL_size_t(0, strlen(b.addr));
    TEST_ASSERT_TRUE(guard_intact(b.guard));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_plain_address_is_95_chars);
    RUN_TEST(test_subaddress_is_95_chars);
    RUN_TEST(test_integrated_address_is_106_chars);

    RUN_TEST(test_no_write_past_a_160_byte_buffer);
    RUN_TEST(test_no_write_past_a_96_byte_buffer_without_payment_id);
    RUN_TEST(test_short_buffer_is_refused);
    RUN_TEST(test_reproduce_the_old_overflow);

    RUN_TEST(test_output_uses_only_base58_characters);
    RUN_TEST(test_payment_id_changes_only_the_tail);
    RUN_TEST(test_network_and_kind_pick_the_first_character);
    RUN_TEST(test_payment_id_wins_over_is_subaddress);
    RUN_TEST(test_unknown_network_yields_an_empty_string);

    return UNITY_END();
}
