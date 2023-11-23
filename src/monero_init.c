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

/* ----------------------*/
/* -- A Kind of Magic -- */
/* ----------------------*/
const unsigned char C_MAGIC[8] = {'M', 'O', 'N', 'E', 'R', 'O', 'H', 'W'};

const unsigned char C_FAKE_SEC_VIEW_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const unsigned char C_FAKE_SEC_SPEND_KEY[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ----------------------------------------------------------------------- */
/* --- Boot                                                            --- */
/* ----------------------------------------------------------------------- */
unsigned int monero_init() {
    memset(&G_monero_vstate, 0, sizeof(monero_v_state_t));

    // first init ?
    if (memcmp((void*)N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC)) != 0) {
#if defined(MONERO_ALPHA) || defined(MONERO_BETA)
        monero_install(STAGENET);
#else
        monero_install(MAINNET);
#endif
    }

    G_monero_vstate.protocol = 0xff;

    // load key
    unsigned error = monero_init_private_key();
    if (error) {
        return error;
    }
    // ux conf
    error = monero_init_ux();
    if (error) {
        return error;
    }
    // Let's go!
    G_monero_vstate.state = STATE_IDLE;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* --- init private keys                                               --- */
/* ----------------------------------------------------------------------- */
int monero_init_private_key(void) {
    unsigned int path[5];
    unsigned char seed[64];
    unsigned char chain[32];
    int error;

    // generate account keys

    // m / purpose' / coin_type' / account' / change / address_index
    // m / 44'      / 128'       / 0'       / 0      / 0
    path[0] = 0x8000002C;
    path[1] = 0x80000080;
    path[2] = 0x80000000 | N_monero_pstate->account_id;
    path[3] = 0x00000000;
    path[4] = 0x00000000;
    if (os_derive_bip32_no_throw(CX_CURVE_SECP256K1, path, 5, seed, chain)) {
        return SW_SECURITY_INTERNAL;
    }

    switch (N_monero_pstate->key_mode) {
        case KEY_MODE_SEED:

            error = monero_keccak_F(seed, 32, G_monero_vstate.b);
            if (error) {
                return error;
            }

            error = monero_reduce(G_monero_vstate.b, G_monero_vstate.b, sizeof(G_monero_vstate.b),
                                  sizeof(G_monero_vstate.b));
            if (error) {
                return error;
            }

            error = monero_keccak_F(G_monero_vstate.b, 32, G_monero_vstate.a);
            if (error) {
                return error;
            }

            error = monero_reduce(G_monero_vstate.a, G_monero_vstate.a, sizeof(G_monero_vstate.a),
                                  sizeof(G_monero_vstate.a));
            if (error) {
                return error;
            }
            break;

        case KEY_MODE_EXTERNAL:
            memcpy(G_monero_vstate.a, (void*)N_monero_pstate->a, 32);
            memcpy(G_monero_vstate.b, (void*)N_monero_pstate->b, 32);
            break;

        default:
            return SW_SECURITY_LOAD_KEY;
    }
    error = monero_ecmul_G(G_monero_vstate.A, G_monero_vstate.a, sizeof(G_monero_vstate.A),
                           sizeof(G_monero_vstate.a));
    if (error) {
        return error;
    }
    error = monero_ecmul_G(G_monero_vstate.B, G_monero_vstate.b, sizeof(G_monero_vstate.B),
                           sizeof(G_monero_vstate.b));
    if (error) {
        return error;
    }

    // generate key protection
    error = monero_aes_derive(&G_monero_vstate.spk, chain, G_monero_vstate.a, G_monero_vstate.b);
    if (error) {
        return error;
    }

    G_monero_vstate.key_set = 1;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---  Set up ui/ux                                                   --- */
/* ----------------------------------------------------------------------- */
int monero_init_ux() {
    int error = monero_base58_public_key(G_monero_vstate.ux_address, G_monero_vstate.A,
                                         G_monero_vstate.B, 0, NULL);
    if (error) {
        return error;
    }

    memset(G_monero_vstate.ux_wallet_public_short_address, '.',
           sizeof(G_monero_vstate.ux_wallet_public_short_address));

#ifndef TARGET_NANOS
    snprintf(G_monero_vstate.ux_wallet_account_name, sizeof(G_monero_vstate.ux_wallet_account_name),
             "XMR / %d", N_monero_pstate->account_id);
    memcpy(G_monero_vstate.ux_wallet_public_short_address, G_monero_vstate.ux_address, 5);
    memcpy(G_monero_vstate.ux_wallet_public_short_address + 7, G_monero_vstate.ux_address + 95 - 5,
           5);
    G_monero_vstate.ux_wallet_public_short_address[12] = 0;
#else
    snprintf(G_monero_vstate.ux_wallet_account_name, sizeof(G_monero_vstate.ux_wallet_account_name),
             "     XMR / %d", N_monero_pstate->account_id);
    memcpy(G_monero_vstate.ux_wallet_public_short_address, G_monero_vstate.ux_address, 4);
    memcpy(G_monero_vstate.ux_wallet_public_short_address + 6, G_monero_vstate.ux_address + 95 - 4,
           4);
    G_monero_vstate.ux_wallet_public_short_address[10] = 0;
#endif

    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---  Install/ReInstall Monero app                                   --- */
/* ----------------------------------------------------------------------- */
void monero_install(unsigned char netId) {
    unsigned char c;

    // full reset data
    monero_nvm_write((void*)N_monero_pstate, NULL, sizeof(monero_nv_state_t));

    // set mode key
    c = KEY_MODE_SEED;
    nvm_write((void*)&N_monero_pstate->key_mode, &c, 1);

    // set net id
    monero_nvm_write((void*)&N_monero_pstate->network_id, &netId, 1);

    // write magic
    monero_nvm_write((void*)N_monero_pstate->magic, (void*)C_MAGIC, sizeof(C_MAGIC));
}

/* ----------------------------------------------------------------------- */
/* --- Reset                                                           --- */
/* ----------------------------------------------------------------------- */
// Accept the following versions and their derivates
const char* const supported_clients[] = {"0.18."};
#define MONERO_SUPPORTED_CLIENT_SIZE (sizeof(supported_clients) / sizeof(supported_clients[0]))

// Explicitly refuse the following versions
const char* const refused_clients[] = {"0.18.0.0."};
#define MONERO_REFUSED_CLIENT_SIZE (sizeof(refused_clients) / sizeof(refused_clients[0]))

static bool is_client_version_valid(const char* client_version) {
    // Check if version is explicitly refused
    for (uint32_t i = 0; i < MONERO_REFUSED_CLIENT_SIZE; ++i) {
        if (strcmp(PIC(refused_clients[i]), client_version) == 0) {
            return false;
        }
    }
    // Check if version is supported
    for (uint32_t i = 0; i < MONERO_SUPPORTED_CLIENT_SIZE; ++i) {
        // Use strncmp to allow supported version prefixing client version
        unsigned int supported_clients_len = strlen(PIC(supported_clients[i]));
        if (strncmp(PIC(supported_clients[i]), client_version, supported_clients_len) == 0) {
            return true;
        }
    }
    return false;
}

int monero_apdu_reset() {
    unsigned int client_version_len;
    char client_version[16];
    memset(client_version, '\0', 16);
    client_version_len = G_monero_vstate.io_length - G_monero_vstate.io_offset;
    if (client_version_len > 14) {
        return SW_CLIENT_NOT_SUPPORTED + 1;
    }
    monero_io_fetch((unsigned char*)&client_version[0], client_version_len);
    // Add '.' suffix to avoid 'X.1' prefixing 'X.10'
    client_version[client_version_len] = '.';

    if (!is_client_version_valid(client_version)) {
        return SW_CLIENT_NOT_SUPPORTED;
    }

    monero_io_discard(0);
    unsigned int error = monero_init();
    if (error) {
        return error;
    }
    monero_io_insert_u8(MONERO_VERSION_MAJOR);
    monero_io_insert_u8(MONERO_VERSION_MINOR);
    monero_io_insert_u8(MONERO_VERSION_MICRO);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* --- LOCK                                                           --- */
/* ----------------------------------------------------------------------- */
void monero_lock(int sw) {
    snprintf(G_monero_vstate.ux_info1, sizeof(G_monero_vstate.ux_info1), "Security Err");
    snprintf(G_monero_vstate.ux_info2, sizeof(G_monero_vstate.ux_info2), "%x", sw);
    ui_menu_show_security_error();
}
