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
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        if (G_monero_vstate.io_p2 == 1) {
            monero_sha256_outkeys_final(G_monero_vstate.OUTK);
            monero_sha256_outkeys_init();
            monero_sha256_commitment_init();
            monero_keccak_init_H();
        }
    }
    monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                           G_monero_vstate.io_length - G_monero_vstate.io_offset);
    if ((G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) && (G_monero_vstate.io_p2 == 1)) {
        // skip type
        monero_io_fetch_u8();
        // fee str
        monero_vamount2str(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                           G_monero_vstate.ux_amount, 15);
        // ask user
        monero_io_discard(1);
        ui_menu_fee_validation_display(0);
        return 0;
    } else {
        monero_io_discard(1);
        return SW_OK;
    }
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_update() {
    unsigned char is_subaddress;
    unsigned char *Aout;
    unsigned char *Bout;
    unsigned char is_change;
    unsigned char AKout[32];
    unsigned char C[32];
    unsigned char v[32];
    unsigned char k[32];

#define aH AKout
    unsigned char kG[32];

    // fetch destination
    is_subaddress = monero_io_fetch_u8();
    if (G_monero_vstate.io_protocol_version >= 2) {
        is_change = monero_io_fetch_u8();
    } else {
        is_change = 0;
    }
    Aout = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    Bout = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_fetch(NULL, 32);
    monero_io_fetch_decrypt(AKout, 32, TYPE_AMOUNT_KEY);
    monero_io_fetch(C, 32);
    monero_io_fetch(k, 32);
    monero_io_fetch(v, 32);

    monero_io_discard(0);

    // update MLSAG prehash
    if ((G_monero_vstate.options & 0x03) == 0x02) {
        monero_keccak_update_H(v, 8);
    } else {
        monero_keccak_update_H(k, 32);
        monero_keccak_update_H(v, 32);
    }

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        if (is_change == 0) {
            // encode dest adress
            monero_base58_public_key(&G_monero_vstate.ux_address[0], Aout, Bout, is_subaddress,
                                     NULL);
        }
        // update destination hash control
        if (G_monero_vstate.io_protocol_version >= 2) {
            monero_sha256_outkeys_update(Aout, 32);
            monero_sha256_outkeys_update(Bout, 32);
            monero_sha256_outkeys_update(&is_change, 1);
            monero_sha256_outkeys_update(AKout, 32);
        }

        // check C = aH+kG
        monero_unblind(v, k, AKout, G_monero_vstate.options & 0x03);
        monero_ecmul_G(kG, k);
        if (!cx_math_is_zero(v, 32)) {
            monero_ecmul_H(aH, v);
            monero_ecadd(aH, kG, aH);
        } else {
            os_memmove(aH, kG, 32);
        }
        if (os_memcmp(C, aH, 32)) {
            monero_lock_and_throw(SW_SECURITY_COMMITMENT_CONTROL);
        }
        // update commitment hash control
        monero_sha256_commitment_update(C, 32);

        if ((G_monero_vstate.options & IN_OPTION_MORE_COMMAND) == 0) {
            if (G_monero_vstate.io_protocol_version >= 2) {
                // finalize and check destination hash_control
                monero_sha256_outkeys_final(k);
                if (os_memcmp(k, G_monero_vstate.OUTK, 32)) {
                    monero_lock_and_throw(SW_SECURITY_OUTKEYS_CHAIN_CONTROL);
                }
            }
            // finalize commitment hash control
            monero_sha256_commitment_final(NULL);
            monero_sha256_commitment_init();
        }

        // ask user
        uint64_t amount;
        amount = monero_bamount2uint64(v);
        if (amount) {
            monero_amount2str(amount, G_monero_vstate.ux_amount, 15);
            if (!is_change) {
                ui_menu_validation_display(0);
            } else {
                ui_menu_change_validation_display(0);
            }
            return 0;
        }
    }
    return SW_OK;

#undef aH
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_mlsag_prehash_finalize() {
    unsigned char message[32];
    unsigned char proof[32];
    unsigned char H[32];

    if (G_monero_vstate.options & IN_OPTION_MORE_COMMAND) {
        // accumulate
        monero_io_fetch(H, 32);
        monero_io_discard(1);
        monero_keccak_update_H(H, 32);
        monero_sha256_commitment_update(H, 32);
#ifdef DEBUG_HWDEVICE
        monero_io_insert(H, 32);
#endif

    } else {
        // Finalize and check commitment hash control
        if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
            monero_sha256_commitment_final(H);
            if (os_memcmp(H, G_monero_vstate.C, 32)) {
                monero_lock_and_throw(SW_SECURITY_COMMITMENT_CHAIN_CONTROL);
            }
        }
        // compute last H
        monero_keccak_final_H(H);
        // compute last prehash
        monero_io_fetch(message, 32);
        monero_io_fetch(proof, 32);
        monero_io_discard(1);
        monero_keccak_init_H();
        if (G_monero_vstate.io_protocol_version == 3) {
            if (os_memcmp(message, G_monero_vstate.prefixH, 32) != 0) {
                monero_lock_and_throw(SW_SECURITY_PREFIX_HASH);
            }
        }
        monero_keccak_update_H(message, 32);
        monero_keccak_update_H(H, 32);
        monero_keccak_update_H(proof, 32);
        monero_keccak_final_H(G_monero_vstate.mlsagH);
#ifdef DEBUG_HWDEVICE
        monero_io_insert(G_monero_vstate.mlsagH, 32);
        monero_io_insert(H, 32);
#endif
    }

    return SW_OK;
}
