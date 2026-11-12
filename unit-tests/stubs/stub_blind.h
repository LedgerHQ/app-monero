#pragma once

/* Zero the globals monero_blind.c reaches for. Call from setUp(). */
void stub_blind_reset(void);

/* Bytes the code under test put in the reply since the last reset. */
unsigned int stub_blind_inserted(void);
