#pragma once

/* Zero the globals monero_crypto.c reaches for. Call from setUp(). */
void stub_crypto_reset(void);

/* Force the next SDK call of that kind to fail, so a helper's error exit can
 * be reached. Cleared by the call and by stub_crypto_reset(). */
extern int stub_crypto_fail_scalar_mult;
extern int stub_crypto_fail_addm;
