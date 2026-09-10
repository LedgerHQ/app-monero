#pragma once

#include <setjmp.h>

/* send_error_and_kill_app is noreturn, so the stub longjmps here instead of
 * exiting. Wrap the call under test:
 *
 *   if (setjmp(stub_kill_jmp) == 0) {
 *       monero_io_do(0);
 *       TEST_FAIL_MESSAGE("expected a refusal");
 *   }
 *   TEST_ASSERT_EQUAL_HEX16(SW_WRONG_LENGTH, stub_kill_sw);
 */
extern jmp_buf stub_kill_jmp;
extern int stub_kill_sw;

/* What the next io_exchange() hands back: `rx` bytes already sitting in
 * G_io_apdu_buffer. Call before the function under test. */
void stub_set_rx(const unsigned char *apdu, unsigned short len,
                 unsigned short rx);

/* Fill the buffer past the APDU, standing in for a previous reply the receive
 * path never clears. */
void stub_fill_stale(unsigned char value);

/* Zero both globals and forget any recorded kill. Call from setUp(). */
void stub_io_reset(void);
