/*****************************************************************************
 *   Ledger Monero App.
 *   (c) 2017-2020 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

/*
 * Client: rctSigs.cpp.c -> get_pre_mlsag_hash
 */

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

/* ----------------------------------------------------------------------- */
/* --- Tx-prefix output-key verifier                                   --- */
/* ----------------------------------------------------------------------- */
/*
 * The transaction prefix is streamed over INS_PREFIX_HASH and only ever hashed
 * by the device, so a malicious host could place attacker-chosen one-time output
 * keys into the bytes that get signed while showing a benign destination in the
 * UI. To bind the signed outputs to the reviewed destinations, INS_GEN_TXOUT_KEYS
 * chains every device-derived out_eph_public_key into G_monero_vstate.OUT_EPH; the
 * state machine below re-walks the signed prefix, hashes the one-time keys present
 * in vout, and checks the resulting digest against OUT_EPH.
 *
 * Prefix layout after (version, unlock_time) -- which are handled separately in
 * the init step -- is the concatenation streamed over the P2 chunks:
 *
 *   vin  : varint count, then per input:
 *            1 byte  variant tag (0x02 = txin_to_key)
 *            varint  amount
 *            varint  key_offsets count, then that many varints
 *            32 byte key image
 *   vout : varint count, then per output:
 *            varint  amount (0 for RingCT)
 *            1 byte  variant tag (0x02 txout_to_key | 0x03 txout_to_tagged_key)
 *            32 byte one-time output key          <-- bound here
 *            1 byte  view tag (only for tag 0x03)  <-- bound here
 *   extra: varint count, then that many bytes (not parsed)
 *
 * Chunks split at arbitrary byte boundaries, so the parser is fully resumable:
 * all progress lives in G_monero_vstate.prefix_*.
 */

#define TXIN_TO_KEY_TAG          0x02
#define TXOUT_TO_KEY_TAG         0x02
#define TXOUT_TO_TAGGED_KEY_TAG  0x03

enum {
    PFX_VIN_CNT = 0, /* varint: number of inputs                       */
    PFX_VIN_TAG,     /* 1 byte: input variant tag (expect 0x02)        */
    PFX_VIN_AMOUNT,  /* varint: input amount (skipped)                 */
    PFX_VIN_OFF_CNT, /* varint: key_offsets count                      */
    PFX_VIN_OFF,     /* varint: one key_offset (skipped)               */
    PFX_VIN_KIMG,    /* 32 bytes: key image (skipped)                  */
    PFX_VOUT_CNT,    /* varint: number of outputs                      */
    PFX_VOUT_AMOUNT, /* varint: output amount (skipped, 0 for RingCT)  */
    PFX_VOUT_TAG,    /* 1 byte: output variant tag (0x02 / 0x03)       */
    PFX_VOUT_KEY,    /* 32 bytes: one-time output key (bound)          */
    PFX_VOUT_VTAG,   /* 1 byte: view tag (bound, tag 0x03 only)        */
    PFX_DONE         /* all outputs verified; remaining bytes ignored  */
};

/* Accumulate one varint byte. Returns 1 when the varint is complete (value in
 * prefix_vi_val), 0 when more bytes are needed, -1 on overflow/malformed. */
static int pfx_varint_byte(unsigned char c) {
    if (G_monero_vstate.prefix_vi_shift >= 64) {
        return -1;
    }
    G_monero_vstate.prefix_vi_val |= (uint64_t)(c & 0x7f) << G_monero_vstate.prefix_vi_shift;
    G_monero_vstate.prefix_vi_shift += 7;
    return (c & 0x80) ? 0 : 1;
}

/* Move to a state that reads a varint, resetting the accumulator. */
static void pfx_enter_varint(unsigned char state) {
    G_monero_vstate.prefix_state = state;
    G_monero_vstate.prefix_vi_val = 0;
    G_monero_vstate.prefix_vi_shift = 0;
}

/* Finalize the verify-side digest and compare it to the build-side OUT_EPH. */
static int pfx_finalize_outkeys(void) {
    unsigned char digest[KEY_SIZE];
    int err = monero_sha256_out_eph_final(digest);
    if (err) {
        return err;
    }
    if (memcmp(digest, G_monero_vstate.OUT_EPH, KEY_SIZE) != 0) {
        return SW_SECURITY_OUTKEYS_CHAIN_CONTROL;
    }
    G_monero_vstate.prefix_outkeys_done = 1;
    return 0;
}

/* Advance past a fully-parsed output, finalizing when the last one is done. */
static int pfx_finish_output(void) {
    G_monero_vstate.prefix_vout_remaining--;
    if (G_monero_vstate.prefix_vout_remaining == 0) {
        int err = pfx_finalize_outkeys();
        if (err) {
            return err;
        }
        G_monero_vstate.prefix_state = PFX_DONE;
    } else {
        pfx_enter_varint(PFX_VOUT_AMOUNT);
    }
    return 0;
}

void monero_prefix_outkeys_reset(void) {
    G_monero_vstate.prefix_state = PFX_VIN_CNT;
    G_monero_vstate.prefix_vi_val = 0;
    G_monero_vstate.prefix_vi_shift = 0;
    G_monero_vstate.prefix_vin_remaining = 0;
    G_monero_vstate.prefix_off_remaining = 0;
    G_monero_vstate.prefix_vout_remaining = 0;
    G_monero_vstate.prefix_field_off = 0;
    G_monero_vstate.prefix_outkey_tag = 0;
    G_monero_vstate.prefix_outkeys_done = 0;
}

int monero_prefix_outkeys_parse(const unsigned char *buf, size_t len) {
    int err;
    int r;
    size_t i = 0;

    while (i < len) {
        switch (G_monero_vstate.prefix_state) {
            case PFX_VIN_CNT:
                r = pfx_varint_byte(buf[i++]);
                if (r < 0) {
                    return SW_WRONG_DATA;
                }
                if (r) {
                    G_monero_vstate.prefix_vin_remaining = G_monero_vstate.prefix_vi_val;
                    if (G_monero_vstate.prefix_vin_remaining == 0) {
                        pfx_enter_varint(PFX_VOUT_CNT);
                    } else {
                        G_monero_vstate.prefix_state = PFX_VIN_TAG;
                    }
                }
                break;

            case PFX_VIN_TAG:
                /* Wallet-built transactions only ever spend txin_to_key inputs. */
                if (buf[i++] != TXIN_TO_KEY_TAG) {
                    return SW_WRONG_DATA;
                }
                pfx_enter_varint(PFX_VIN_AMOUNT);
                break;

            case PFX_VIN_AMOUNT:
                r = pfx_varint_byte(buf[i++]);
                if (r < 0) {
                    return SW_WRONG_DATA;
                }
                if (r) {
                    pfx_enter_varint(PFX_VIN_OFF_CNT);
                }
                break;

            case PFX_VIN_OFF_CNT:
                r = pfx_varint_byte(buf[i++]);
                if (r < 0) {
                    return SW_WRONG_DATA;
                }
                if (r) {
                    G_monero_vstate.prefix_off_remaining = G_monero_vstate.prefix_vi_val;
                    if (G_monero_vstate.prefix_off_remaining == 0) {
                        G_monero_vstate.prefix_field_off = 0;
                        G_monero_vstate.prefix_state = PFX_VIN_KIMG;
                    } else {
                        pfx_enter_varint(PFX_VIN_OFF);
                    }
                }
                break;

            case PFX_VIN_OFF:
                r = pfx_varint_byte(buf[i++]);
                if (r < 0) {
                    return SW_WRONG_DATA;
                }
                if (r) {
                    G_monero_vstate.prefix_off_remaining--;
                    if (G_monero_vstate.prefix_off_remaining == 0) {
                        G_monero_vstate.prefix_field_off = 0;
                        G_monero_vstate.prefix_state = PFX_VIN_KIMG;
                    } else {
                        pfx_enter_varint(PFX_VIN_OFF);
                    }
                }
                break;

            case PFX_VIN_KIMG: {
                /* skip 32-byte key image, resuming across chunk boundaries */
                size_t need = KEY_SIZE - G_monero_vstate.prefix_field_off;
                size_t avail = len - i;
                size_t take = (avail < need) ? avail : need;
                i += take;
                G_monero_vstate.prefix_field_off += take;
                if (G_monero_vstate.prefix_field_off == KEY_SIZE) {
                    G_monero_vstate.prefix_vin_remaining--;
                    if (G_monero_vstate.prefix_vin_remaining == 0) {
                        pfx_enter_varint(PFX_VOUT_CNT);
                    } else {
                        G_monero_vstate.prefix_state = PFX_VIN_TAG;
                    }
                }
                break;
            }

            case PFX_VOUT_CNT:
                r = pfx_varint_byte(buf[i++]);
                if (r < 0) {
                    return SW_WRONG_DATA;
                }
                if (r) {
                    G_monero_vstate.prefix_vout_remaining = G_monero_vstate.prefix_vi_val;
                    /* The number of signed outputs must match what was reviewed
                     * (and chained into OUT_EPH) during INS_GEN_TXOUT_KEYS. */
                    if (G_monero_vstate.prefix_vout_remaining != G_monero_vstate.tx_output_cnt) {
                        return SW_SECURITY_OUTKEYS_CHAIN_CONTROL;
                    }
                    if (G_monero_vstate.prefix_vout_remaining == 0) {
                        err = pfx_finalize_outkeys();
                        if (err) {
                            return err;
                        }
                        G_monero_vstate.prefix_state = PFX_DONE;
                    } else {
                        pfx_enter_varint(PFX_VOUT_AMOUNT);
                    }
                }
                break;

            case PFX_VOUT_AMOUNT:
                r = pfx_varint_byte(buf[i++]);
                if (r < 0) {
                    return SW_WRONG_DATA;
                }
                if (r) {
                    G_monero_vstate.prefix_state = PFX_VOUT_TAG;
                }
                break;

            case PFX_VOUT_TAG: {
                unsigned char tag = buf[i++];
                if ((tag != TXOUT_TO_KEY_TAG) && (tag != TXOUT_TO_TAGGED_KEY_TAG)) {
                    return SW_WRONG_DATA;
                }
                G_monero_vstate.prefix_outkey_tag = tag;
                G_monero_vstate.prefix_field_off = 0;
                G_monero_vstate.prefix_state = PFX_VOUT_KEY;
                break;
            }

            case PFX_VOUT_KEY: {
                /* bind 32-byte one-time output key, resuming across chunks */
                size_t need = KEY_SIZE - G_monero_vstate.prefix_field_off;
                size_t avail = len - i;
                size_t take = (avail < need) ? avail : need;
                err = monero_sha256_out_eph_update(buf + i, take);
                if (err) {
                    return err;
                }
                i += take;
                G_monero_vstate.prefix_field_off += take;
                if (G_monero_vstate.prefix_field_off == KEY_SIZE) {
                    if (G_monero_vstate.prefix_outkey_tag == TXOUT_TO_TAGGED_KEY_TAG) {
                        G_monero_vstate.prefix_state = PFX_VOUT_VTAG;
                    } else {
                        err = pfx_finish_output();
                        if (err) {
                            return err;
                        }
                    }
                }
                break;
            }

            case PFX_VOUT_VTAG:
                err = monero_sha256_out_eph_update(buf + i, 1);
                if (err) {
                    return err;
                }
                i++;
                err = pfx_finish_output();
                if (err) {
                    return err;
                }
                break;

            case PFX_DONE:
                /* remaining bytes belong to extra: nothing left to verify */
                i = len;
                break;

            default:
                return SW_WRONG_DATA;
        }
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_prefix_hash_init(void) {
    uint64_t timelock;
    int error = 0;

    error = monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                                   G_monero_vstate.io_length - G_monero_vstate.io_offset);
    if (error) {
        return error;
    }

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        /* Finalize the output-key chain built over INS_GEN_TXOUT_KEYS, then
         * reset the context and parser to check the prefix that follows. */
        if (G_monero_vstate.io_protocol_version >= 2) {
            error = monero_sha256_out_eph_final(G_monero_vstate.OUT_EPH);
            if (error) {
                return error;
            }
            monero_sha256_out_eph_init();
            monero_prefix_outkeys_reset();
        }

        error = monero_io_fetch_varint(&timelock);  // DUmmy call TODO
        if (error) {
            return error;
        }

        error = monero_io_fetch_varint(&timelock);
        if (error) {
            return error;
        }

        if (monero_io_fetch_available() != 0) {
            return SW_WRONG_DATA;
        }
        // ask user
        monero_io_discard(1);
        if (timelock != 0) {
            error = monero_uint642str(timelock, G_monero_vstate.ux_amount, 15);
            if (error) {
                return error;
            }
            ui_menu_timelock_validation_display(0);
            return 0;
        } else {
            return ui_menu_transaction_start();
        }
    } else {
        monero_io_discard(1);
        return SW_OK;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_prefix_hash_update(void) {
    int error;
    error = monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                                   G_monero_vstate.io_length - G_monero_vstate.io_offset);
    if (error) {
        return error;
    }

    /* Check the prefix's output keys against the ones we derived. Must run
     * before monero_io_discard(). */
    if ((G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) &&
        (G_monero_vstate.io_protocol_version >= 2)) {
        error = monero_prefix_outkeys_parse(
            G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
            G_monero_vstate.io_length - G_monero_vstate.io_offset);
        if (error) {
            return error;
        }
    }

    monero_io_discard(0);
    if ((G_monero_vstate.options & 0x80) == 0x00) {
        /* last prefix chunk: every reviewed output key must have been matched */
        if ((G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) &&
            (G_monero_vstate.io_protocol_version >= 2) &&
            (G_monero_vstate.prefix_outkeys_done == 0)) {
            return SW_SECURITY_OUTKEYS_CHAIN_CONTROL;
        }
        error = monero_keccak_final_H(G_monero_vstate.prefixH);
        if (error) {
            return error;
        }
        monero_io_insert(G_monero_vstate.prefixH, 32);
    }

    return SW_OK;
}
