#pragma once

/* Zero the globals monero_crypto.c reaches for. Call from setUp(). */
void stub_crypto_reset(void);
