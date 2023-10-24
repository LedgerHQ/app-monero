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
int monero_apdu_prefix_hash_init(void) {
    uint64_t timelock;
    int error = 0;

    monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                           G_monero_vstate.io_length - G_monero_vstate.io_offset);

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
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
    monero_keccak_update_H(G_monero_vstate.io_buffer + G_monero_vstate.io_offset,
                           G_monero_vstate.io_length - G_monero_vstate.io_offset);
    monero_io_discard(0);
    if ((G_monero_vstate.options & 0x80) == 0x00) {
        monero_keccak_final_H(G_monero_vstate.prefixH);
        monero_io_insert(G_monero_vstate.prefixH, 32);
    }

    return SW_OK;
}
