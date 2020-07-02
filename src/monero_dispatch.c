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

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

void update_protocol() {
    G_monero_vstate.tx_state_ins = G_monero_vstate.io_ins;
    G_monero_vstate.tx_state_p1 = G_monero_vstate.io_p1;
    G_monero_vstate.tx_state_p2 = G_monero_vstate.io_p2;
}

void clear_protocol() {
    G_monero_vstate.tx_state_ins = 0;
    G_monero_vstate.tx_state_p1 = 0;
    G_monero_vstate.tx_state_p2 = 0;
}

int check_potocol() {
    /* if locked and pin is veririfed, unlock */
    if ((G_monero_vstate.protocol_barrier == PROTOCOL_LOCKED_UNLOCKABLE) &&
        (os_global_pin_is_validated() == PIN_VERIFIED)) {
        G_monero_vstate.protocol_barrier = PROTOCOL_UNLOCKED;
    }

    /* if we are locked, deny all command! */
    if (G_monero_vstate.protocol_barrier != PROTOCOL_UNLOCKED) {
        return SW_SECURITY_LOCKED;
    }

    /* the first command enforce the protocol version until application quits */
    switch (G_monero_vstate.io_protocol_version) {
        case 0x00: /* the first one: PCSC epoch */
        case 0x03: /* protocol V3 */
            if (G_monero_vstate.protocol == 0xff) {
                G_monero_vstate.protocol = G_monero_vstate.io_protocol_version;
            }
            if (G_monero_vstate.protocol == G_monero_vstate.io_protocol_version) {
                break;
            }
            // unknown protocol or hot protocol switch is not allowed
            // FALL THROUGH

        default:
            return SW_PROTOCOL_NOT_SUPPORTED;
    }
    return SW_OK;
}

int check_ins_access() {
    if (G_monero_vstate.key_set != 1) {
        return SW_KEY_NOT_SET;
    }

    switch (G_monero_vstate.io_ins) {
        case INS_LOCK_DISPLAY:
        case INS_RESET:
        case INS_PUT_KEY:
        case INS_GET_KEY:
        case INS_DISPLAY_ADDRESS:
        case INS_VERIFY_KEY:
        case INS_GET_CHACHA8_PREKEY:
        case INS_GEN_KEY_DERIVATION:
        case INS_DERIVATION_TO_SCALAR:
        case INS_DERIVE_PUBLIC_KEY:
        case INS_DERIVE_SECRET_KEY:
        case INS_GEN_KEY_IMAGE:
        case INS_SECRET_KEY_TO_PUBLIC_KEY:
        case INS_SECRET_KEY_ADD:
        case INS_GENERATE_KEYPAIR:
        case INS_SECRET_SCAL_MUL_KEY:
        case INS_SECRET_SCAL_MUL_BASE:
        case INS_DERIVE_SUBADDRESS_PUBLIC_KEY:
        case INS_GET_SUBADDRESS:
        case INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY:
        case INS_GET_SUBADDRESS_SECRET_KEY:
        case INS_MANAGE_SEEDWORDS:
        case INS_UNBLIND:
        case INS_STEALTH:
        case INS_GET_TX_PROOF:
        case INS_CLOSE_TX:
            return SW_OK;

        case INS_OPEN_TX:
        case INS_SET_SIGNATURE_MODE:
            if (os_global_pin_is_validated() != PIN_VERIFIED) {
                return SW_SECURITY_PIN_LOCKED;
            }
            return SW_OK;

        case INS_GEN_TXOUT_KEYS:
        case INS_PREFIX_HASH:
        case INS_BLIND:
        case INS_VALIDATE:
        case INS_MLSAG:
        case INS_GEN_COMMITMENT_MASK:
            if (os_global_pin_is_validated() != PIN_VERIFIED) {
                return SW_SECURITY_PIN_LOCKED;
            }
            if (G_monero_vstate.tx_in_progress != 1) {
                return SW_COMMAND_NOT_ALLOWED;
            }
            return SW_OK;
    }

    return SW_INS_NOT_SUPPORTED;
}

int monero_dispatch() {
    int sw;

    if (((sw = check_potocol()) != SW_OK) || ((sw = check_ins_access() != SW_OK))) {
        monero_io_discard(0);
        return sw;
    }

    G_monero_vstate.options = monero_io_fetch_u8();

    if (G_monero_vstate.io_ins == INS_RESET) {
        sw = monero_apdu_reset();
        return sw;
    }

    if (G_monero_vstate.io_ins == INS_LOCK_DISPLAY) {
        sw = monero_apdu_lock();
        return sw;
    }

    sw = 0x6F01;

    switch (G_monero_vstate.io_ins) {
        /* --- KEYS --- */
        case INS_PUT_KEY:
            sw = monero_apdu_put_key();
            break;
        case INS_GET_KEY:
            sw = monero_apdu_get_key();
            break;
        case INS_DISPLAY_ADDRESS:
            sw = monero_apdu_display_address();
            break;
        case INS_MANAGE_SEEDWORDS:
            sw = monero_apdu_manage_seedwords();
            break;

            /* --- PROVISIONING--- */
        case INS_VERIFY_KEY:
            sw = monero_apdu_verify_key();
            break;
        case INS_GET_CHACHA8_PREKEY:
            sw = monero_apdu_get_chacha8_prekey();
            break;
        case INS_SECRET_KEY_TO_PUBLIC_KEY:
            sw = monero_apdu_secret_key_to_public_key();
            break;
        case INS_GEN_KEY_DERIVATION:
            sw = monero_apdu_generate_key_derivation();
            break;
        case INS_DERIVATION_TO_SCALAR:
            sw = monero_apdu_derivation_to_scalar();
            break;
        case INS_DERIVE_PUBLIC_KEY:
            sw = monero_apdu_derive_public_key();
            break;
        case INS_DERIVE_SECRET_KEY:
            sw = monero_apdu_derive_secret_key();
            break;
        case INS_GEN_KEY_IMAGE:
            sw = monero_apdu_generate_key_image();
            break;
        case INS_SECRET_KEY_ADD:
            sw = monero_apdu_sc_add();
            break;
        case INS_GENERATE_KEYPAIR:
            sw = monero_apdu_generate_keypair();
            break;
        case INS_SECRET_SCAL_MUL_KEY:
            sw = monero_apdu_scal_mul_key();
            break;
        case INS_SECRET_SCAL_MUL_BASE:
            sw = monero_apdu_scal_mul_base();
            break;

        /* --- ADRESSES --- */
        case INS_DERIVE_SUBADDRESS_PUBLIC_KEY:
            sw = monero_apdu_derive_subaddress_public_key();
            break;
        case INS_GET_SUBADDRESS:
            sw = monero_apdu_get_subaddress();
            break;
        case INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY:
            sw = monero_apdu_get_subaddress_spend_public_key();
            break;
        case INS_GET_SUBADDRESS_SECRET_KEY:
            sw = monero_apdu_get_subaddress_secret_key();
            break;

        /* --- PARSE --- */
        case INS_UNBLIND:
            sw = monero_apdu_unblind();
            break;

        /* --- PROOF --- */
        case INS_GET_TX_PROOF:
            sw = monero_apdu_get_tx_proof();
            break;

            /* =======================================================================
             *  Following command are only allowed during transaction and their
             *  sequence shall be enforced
             */

            /* --- START TX --- */
        case INS_OPEN_TX:
            // state machine check
            if (G_monero_vstate.tx_state_ins != 0) {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // 2. command process
            sw = monero_apdu_open_tx();
            update_protocol();
            break;

        case INS_CLOSE_TX:
            sw = monero_apdu_close_tx();
            clear_protocol();
            break;

            /* --- SIG MODE --- */
        case INS_SET_SIGNATURE_MODE:
            // 1. state machine check
            if (G_monero_vstate.tx_in_progress != 0) {
                // Change sig mode during transacation is not allowed
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // 2. command process
            sw = monero_apdu_set_signature_mode();
            break;

            /* --- STEATH PAYMENT --- */
        case INS_STEALTH:
            // 1. state machine check
            if (G_monero_vstate.tx_in_progress == 1) {
                if ((G_monero_vstate.tx_state_ins != INS_OPEN_TX) &&
                    (G_monero_vstate.tx_state_ins != INS_STEALTH)) {
                    THROW(SW_COMMAND_NOT_ALLOWED);
                }
                if ((G_monero_vstate.io_p1 != 0) || (G_monero_vstate.io_p2 != 0)) {
                    THROW(SW_WRONG_P1P2);
                }
            }
            // 2. command process
            sw = monero_apdu_stealth();
            if (G_monero_vstate.tx_in_progress == 1) {
                update_protocol();
            }
            break;

            /* --- TX OUT KEYS --- */
        case INS_GEN_TXOUT_KEYS:
            // 1. state machine check
            if ((G_monero_vstate.tx_state_ins != INS_OPEN_TX) &&
                (G_monero_vstate.tx_state_ins != INS_GEN_TXOUT_KEYS) &&
                (G_monero_vstate.tx_state_ins != INS_STEALTH)) {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            if (G_monero_vstate.protocol == 3) {
                if ((G_monero_vstate.tx_state_ins != INS_OPEN_TX) &&
                    (G_monero_vstate.tx_state_ins != INS_GEN_TXOUT_KEYS) &&
                    (G_monero_vstate.tx_state_ins != INS_STEALTH)) {
                    THROW(SW_COMMAND_NOT_ALLOWED);
                }
            }
            if ((G_monero_vstate.io_p1 != 0) || (G_monero_vstate.io_p2 != 0)) {
                THROW(SW_WRONG_P1P2);
            }
            // 2. command process
            sw = monero_apu_generate_txout_keys();
            update_protocol();
            break;

        /* --- PREFIX HASH  --- */
        case INS_PREFIX_HASH:
            // 1. state machine check
            if ((G_monero_vstate.tx_state_ins != INS_GEN_TXOUT_KEYS) &&
                (G_monero_vstate.tx_state_ins != INS_PREFIX_HASH)) {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // init prefixhash state machine
            if (G_monero_vstate.tx_state_ins == INS_GEN_TXOUT_KEYS) {
                G_monero_vstate.tx_state_ins = INS_PREFIX_HASH;
                G_monero_vstate.tx_state_p1 = 0;
                G_monero_vstate.tx_state_p2 = 0;
            }
            // check new state is allowed
            if (G_monero_vstate.tx_state_p1 == 0) {
                if (1 != G_monero_vstate.io_p1) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            } else if (G_monero_vstate.tx_state_p1 == 1) {
                if ((G_monero_vstate.io_p1 != 2) || (G_monero_vstate.io_p2 != 1)) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            } else if (G_monero_vstate.tx_state_p1 == 2) {
                if ((G_monero_vstate.io_p1 != 2) ||
                    (G_monero_vstate.io_p2 - 1 != G_monero_vstate.tx_state_p2)) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            } else {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // 2. command process
            if (G_monero_vstate.io_p1 == 1) {
                sw = monero_apdu_prefix_hash_init();
            } else if (G_monero_vstate.io_p1 == 2) {
                sw = monero_apdu_prefix_hash_update();
            } else {
                THROW(SW_WRONG_P1P2);
            }
            update_protocol();
            break;

            /*--- COMMITMENT MASK --- */
        case INS_GEN_COMMITMENT_MASK:
            // 1. state machine check
            if (G_monero_vstate.protocol == 3) {
                if ((G_monero_vstate.tx_state_ins != INS_PREFIX_HASH) &&
                    (G_monero_vstate.tx_state_ins != INS_GEN_COMMITMENT_MASK)) {
                    THROW(SW_COMMAND_NOT_ALLOWED);
                }
            }

            if ((G_monero_vstate.io_p1 != 0) || (G_monero_vstate.io_p2 != 0)) {
                THROW(SW_WRONG_P1P2);
            }
            // 2. command process
            sw = monero_apdu_gen_commitment_mask();
            update_protocol();
            break;

            /* --- BLIND --- */
        case INS_BLIND:
            // 1. state machine check
            if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_FAKE) {
                if (G_monero_vstate.protocol == 3) {
                    if ((G_monero_vstate.tx_state_ins != INS_PREFIX_HASH) &&
                        (G_monero_vstate.tx_state_ins != INS_BLIND)) {
                        THROW(SW_COMMAND_NOT_ALLOWED);
                    }
                }
            } else if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
                if ((G_monero_vstate.tx_state_ins != INS_GEN_COMMITMENT_MASK) &&
                    (G_monero_vstate.tx_state_ins != INS_BLIND)) {
                    THROW(SW_COMMAND_NOT_ALLOWED);
                }
            } else {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // 2. command process
            if ((G_monero_vstate.io_p1 != 0) || (G_monero_vstate.io_p2 != 0)) {
                THROW(SW_WRONG_P1P2);
            }
            sw = monero_apdu_blind();
            update_protocol();
            break;

            /* --- VALIDATE/PREHASH --- */
        case INS_VALIDATE:
            // 1. state machine check
            if ((G_monero_vstate.tx_state_ins != INS_BLIND) &&
                (G_monero_vstate.tx_state_ins != INS_VALIDATE)) {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // init PREHASH state machine
            if (G_monero_vstate.tx_state_ins == INS_BLIND) {
                G_monero_vstate.tx_state_ins = INS_VALIDATE;
                G_monero_vstate.tx_state_p1 = 1;
                G_monero_vstate.tx_state_p2 = 0;
                if ((G_monero_vstate.io_p1 != 1) || (G_monero_vstate.io_p2 != 1)) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            }
            // check new state is allowed
            if (G_monero_vstate.tx_state_p1 == G_monero_vstate.io_p1) {
                if (G_monero_vstate.tx_state_p2 != G_monero_vstate.io_p2 - 1) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            } else if (G_monero_vstate.tx_state_p1 == G_monero_vstate.io_p1 - 1) {
                if (1 != G_monero_vstate.io_p2) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            } else {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            // 2. command process
            if (G_monero_vstate.io_p1 == 1) {
                sw = monero_apdu_mlsag_prehash_init();
            } else if (G_monero_vstate.io_p1 == 2) {
                sw = monero_apdu_mlsag_prehash_update();
            } else if (G_monero_vstate.io_p1 == 3) {
                sw = monero_apdu_mlsag_prehash_finalize();
            } else {
                THROW(SW_WRONG_P1P2);
            }
            update_protocol();
            break;

        /* --- MLSAG --- */
        case INS_MLSAG:
            // 1. state machine check
            if ((G_monero_vstate.tx_state_ins != INS_VALIDATE) &&
                (G_monero_vstate.tx_state_ins != INS_MLSAG)) {
                THROW(SW_COMMAND_NOT_ALLOWED);
            }
            if (G_monero_vstate.tx_state_ins == INS_VALIDATE) {
                if ((G_monero_vstate.tx_state_p1 != 3) || (G_monero_vstate.io_p1 != 1) ||
                    (G_monero_vstate.io_p2 != 0)) {
                    THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                }
            } else {
                if (G_monero_vstate.tx_state_p1 == 1) {
                    if (2 != G_monero_vstate.io_p1) {
                        THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                    }
                } else if (G_monero_vstate.tx_state_p1 == 2) {
                    if ((2 != G_monero_vstate.io_p1) && (3 != G_monero_vstate.io_p1)) {
                        THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                    }
                } else if (G_monero_vstate.tx_state_p1 == 3) {
                    if (1 != G_monero_vstate.io_p1) {
                        THROW(SW_SUBCOMMAND_NOT_ALLOWED);
                    }
                } else {
                    THROW(SW_COMMAND_NOT_ALLOWED);
                }
            }

            // 2. command process
            if (G_monero_vstate.io_p1 == 1) {
                sw = monero_apdu_mlsag_prepare();
            } else if (G_monero_vstate.io_p1 == 2) {
                sw = monero_apdu_mlsag_hash();
            } else if (G_monero_vstate.io_p1 == 3) {
                sw = monero_apdu_mlsag_sign();
            } else {
                THROW(SW_WRONG_P1P2);
            }
            update_protocol();
            break;

            /* --- KEYS --- */

        default:
            THROW(SW_INS_NOT_SUPPORTED);
            break;
    }
    return sw;
}
