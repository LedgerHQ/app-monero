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
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_init() {
    int error = 0;
    if ((G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) && (G_monero_vstate.io_p2 == 1)) {
        // The fee APDU must be exactly [u8 type] [varint fee]. Reject any trailing
        // bytes so that host-controlled data cannot be silently absorbed into the
        // transaction prehash while the UI displays only the fee (CWE-451).
        unsigned int payload_len = G_monero_vstate.io_length - G_monero_vstate.io_offset;
        if (payload_len < 2) {
            return SW_WRONG_DATA;
        }
        unsigned int fee_off = G_monero_vstate.io_offset + 1;
        unsigned int fee_max = G_monero_vstate.io_length - fee_off;
        uint64_t fee = 0;
        unsigned int fee_len = 0;
        error = monero_decode_varint(G_monero_vstate.io_buffer + fee_off, MIN(8, fee_max), &fee,
                                     &fee_len);
        if (error) {
            return error;
        }
        if (fee_off + fee_len != G_monero_vstate.io_length) {
            return SW_WRONG_DATA;
        }

        error = monero_sha256_outkeys_final(G_monero_vstate.OUTK);
        if (error) {
            return error;
        }
        monero_sha256_outkeys_init();
        monero_sha256_commitment_init();
        error = monero_keccak_init_H();
        if (error) {
            return error;
        }
        error = monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                                       1 + fee_len);
        if (error) {
            return error;
        }
        // skip type
        monero_io_fetch_u8();
        // fee str
        monero_vamount2str(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                           G_monero_vstate.ux_amount, 15);

        snprintf(G_monero_vstate.ux_amount + strlen(G_monero_vstate.ux_amount),
                 sizeof(G_monero_vstate.ux_amount) - strlen(G_monero_vstate.ux_amount), " XMR");
        // ask user
        monero_io_discard(1);
        ui_menu_fee_validation_display(0);
        return 0;
    }

    error = monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                                   G_monero_vstate.io_length - G_monero_vstate.io_offset);
    if (error) {
        return error;
    }
    monero_io_discard(1);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_update() {
    unsigned char is_subaddress;
    unsigned char *Aout;
    unsigned char *Bout;
    unsigned char is_change;
    unsigned char AKout[KEY_SIZE];
    unsigned char AKout_raw[KEY_SIZE];
    unsigned char C[32];
    unsigned char v[32];
    unsigned char v_raw[32];
    unsigned char k[32];
    unsigned char k_raw[32];
    uint64_t amount;
    unsigned int i;

#define aH AKout
    unsigned char kG[32];
    int err = 0;

    // fetch destination
    is_subaddress = monero_io_fetch_u8();
    if (G_monero_vstate.io_protocol_version >= 2) {
        is_change = monero_io_fetch_u8();
    } else {
        is_change = 0;
    }
    Aout = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    Bout = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(32);
    err = monero_io_fetch_decrypt(AKout, KEY_SIZE, TYPE_AMOUNT_KEY);
    if (err) {
        goto end;
    }
    monero_io_fetch(C, 32);
    monero_io_fetch(k, 32);
    monero_io_fetch(v, 32);
    memcpy(AKout_raw, AKout, KEY_SIZE);
    memcpy(k_raw, k, 32);
    memcpy(v_raw, v, 32);

    monero_io_discard(0);

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        // check C = aH+kG
        err = monero_unblind(v, k, AKout, G_monero_vstate.options & 0x03, sizeof(v), sizeof(k),
                             sizeof(AKout));
        if (err) {
            goto end;
        }

        // short amounts must be canonical before being displayed as uint64
        if ((G_monero_vstate.options & 0x03) == 0x02) {
            for (i = 8; i < 32; i++) {
                if (v[i] != 0) {
                    err = SW_SECURITY_AMOUNT_CHAIN_CONTROL;
                    goto end;
                }
            }
        }

        amount = monero_bamount2uint64(v, sizeof(v));

        // sweep_all/sweep_single may include a dummy amount=0 change output
        if (is_change && !cx_math_is_zero(v, 32)) {
            err = monero_check_change_address(Aout, Bout);
            if (err) {
                goto end;
            }
        }

        err = monero_ecmul_G(kG, k, sizeof(kG), sizeof(k));
        if (err) {
            goto end;
        }

        if (!cx_math_is_zero(v, 32)) {
            err = monero_ecmul_H(aH, v, sizeof(aH), sizeof(v));
            if (err) {
                goto end;
            }

            err = monero_ecadd(aH, kG, aH, sizeof(aH), sizeof(kG), sizeof(aH));
            if (err) {
                goto end;
            }
        } else {
            memcpy(aH, kG, 32);
        }
        if (memcmp(C, aH, 32) != 0) {
#ifndef BYPASS_COMMITMENT_FOR_TESTS
            err = SW_SECURITY_COMMITMENT_CHAIN_CONTROL;
            goto end;
#endif
        }
        if (is_change == 0) {
            // encode dest adress
            err = monero_base58_public_key(&G_monero_vstate.ux_address[0], Aout, Bout,
                                           is_subaddress, NULL);
            if (err) {
                goto end;
            }
        }
    }

    // update MLSAG prehash
    if ((G_monero_vstate.options & 0x03) == 0x02) {
        err = monero_keccak_update_H(v_raw, 8);
        if (err) {
            goto end;
        }

    } else {
        err = monero_keccak_update_H(k_raw, 32);
        if (err) {
            goto end;
        }

        err = monero_keccak_update_H(v_raw, 32);
        if (err) {
            goto end;
        }
    }

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        // update destination hash control
        if (G_monero_vstate.io_protocol_version >= 2) {
            err = monero_sha256_outkeys_update(Aout, KEY_SIZE);
            if (err) {
                goto end;
            }
            err = monero_sha256_outkeys_update(Bout, KEY_SIZE);
            if (err) {
                goto end;
            }
            err = monero_sha256_outkeys_update(&is_change, 1);
            if (err) {
                goto end;
            }
            err = monero_sha256_outkeys_update(AKout_raw, KEY_SIZE);
            if (err) {
                goto end;
            }
        }

        // update commitment hash control
        err = monero_sha256_commitment_update(C, 32);
        if (err) {
            goto end;
        }

        if ((G_monero_vstate.options & IN_OPTION_MORE_COMMAND) == 0) {
            if (G_monero_vstate.io_protocol_version >= 2) {
                // finalize and check destination hash_control
                err = monero_sha256_outkeys_final(k);
                if (err) {
                    goto end;
                }
                if (memcmp(k, G_monero_vstate.OUTK, KEY_SIZE) != 0) {
                    err = SW_SECURITY_COMMITMENT_CHAIN_CONTROL;
                    goto end;
                }
            }
            // finalize commitment hash control
            err = monero_sha256_commitment_final(NULL);
            if (err) {
                goto end;
            }
            monero_sha256_commitment_init();
        }

        // ask user
        /* Rejecting signature for a non-change output with amount equal to 0.
         * Otherwise showing review sequence.
         */
        if ((amount == 0) && (!is_change)) {
            err = SW_SECURITY_AMOUNT_CHAIN_CONTROL;
            goto end;
        }

        monero_amount2str(amount, G_monero_vstate.ux_amount, 15);
        snprintf(G_monero_vstate.ux_amount + strlen(G_monero_vstate.ux_amount),
                 sizeof(G_monero_vstate.ux_amount) - strlen(G_monero_vstate.ux_amount), " XMR");

        if ((G_monero_vstate.options & IN_OPTION_MORE_COMMAND) == 0) {
            if (!is_change) {
                ui_menu_validation_display_last(0);
            } else {
                ui_menu_change_validation_display_last(0);
            }
        } else {
            if (!is_change) {
                ui_menu_validation_display(0);
            } else {
                ui_menu_change_validation_display(0);
            }
        }
        err = 0;
        goto end;
    }
    err = SW_OK;

end:
    explicit_bzero(AKout, sizeof(AKout));
    explicit_bzero(AKout_raw, sizeof(AKout_raw));
    explicit_bzero(v, sizeof(v));
    explicit_bzero(v_raw, sizeof(v_raw));
    explicit_bzero(k, sizeof(k));
    explicit_bzero(k_raw, sizeof(k_raw));
    return err;

#undef aH
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_finalize() {
    unsigned char message[32];
    unsigned char proof[32];
    unsigned char H[32];
    int error;

    if (G_monero_vstate.options & IN_OPTION_MORE_COMMAND) {
        // accumulate
        monero_io_fetch(H, 32);
        monero_io_discard(1);
        error = monero_keccak_update_H(H, 32);
        if (error) {
            return error;
        }

        error = monero_sha256_commitment_update(H, 32);
        if (error) {
            return error;
        }
    } else {
        // Finalize and check commitment hash control
        if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
            error = monero_sha256_commitment_final(H);
            if (error) {
                return error;
            }
            if (memcmp(H, G_monero_vstate.C, 32) != 0) {
#ifndef BYPASS_COMMITMENT_FOR_TESTS
                return SW_SECURITY_COMMITMENT_CHAIN_CONTROL;
#endif
            }
        }
        // compute last H
        error = monero_keccak_final_H(H);
        if (error) {
            return error;
        }
        // compute last prehash
        monero_io_fetch(message, 32);
        monero_io_fetch(proof, 32);
        monero_io_discard(1);
        error = monero_keccak_init_H();
        if (error) {
            return error;
        }

        if (G_monero_vstate.io_protocol_version >= 3) {
            if (memcmp(message, G_monero_vstate.prefixH, 32) != 0) {
#ifndef BYPASS_COMMITMENT_FOR_TESTS
                return SW_SECURITY_PREFIX_HASH;
#endif
            }
        }
        error = monero_keccak_update_H(message, 32);
        if (error) {
            return error;
        }

        error = monero_keccak_update_H(H, 32);
        if (error) {
            return error;
        }

        error = monero_keccak_update_H(proof, 32);
        if (error) {
            return error;
        }

        error = monero_keccak_final_H(G_monero_vstate.mlsagH);
        if (error) {
            return error;
        }

        monero_io_insert(G_monero_vstate.mlsagH, 32);

        if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
            ui_menu_transaction_signed();
        }
    }

    return SW_OK;
}
