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

#ifndef MONERO_TYPES_H
#define MONERO_TYPES_H

#include "os_io_seproxyhal.h"

#if CX_APILEVEL == 8
#define PIN_VERIFIED (!0)
#elif CX_APILEVEL == 9 || CX_APILEVEL == 10

#define PIN_VERIFIED BOLOS_UX_OK
#else
#error CX_APILEVEL not  supported
#endif

/* cannot send more that F0 bytes in CCID, why? do not know for now
 *  So set up length to F0 minus 2 bytes for SW
 */
#define MONERO_APDU_LENGTH 0xFE

/* big private DO */
#define MONERO_EXT_PRIVATE_DO_LENGTH 512
/* will be fixed..1024 is not enougth */
#define MONERO_EXT_CARD_HOLDER_CERT_LENTH 2560
/* random choice */
#define MONERO_EXT_CHALLENGE_LENTH 254

/* --- ... --- */
#define MAINNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX            18
#define MAINNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX 19
#define MAINNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX         42

#define STAGENET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX            24
#define STAGENET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX 25
#define STAGENET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX         36

#define TESTNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX            53
#define TESTNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX 54
#define TESTNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX         63

enum network_type {
#ifndef MONERO_ALPHA
    MAINNET = 0,
#endif
    TESTNET = 1,
    STAGENET = 2,
    FAKECHAIN = 3
};

struct monero_nv_state_s {
    /* magic */
    unsigned char magic[8];

    /* network */
    unsigned char network_id;

/* key mode */
#define KEY_MODE_EXTERNAL 0x21
#define KEY_MODE_SEED     0x42
    unsigned char key_mode;

    /* acount id for bip derivation */
    unsigned int account_id;

    /* spend key */
    unsigned char b[32];
    /* view key */
    unsigned char a[32];

/*words*/
#define WORDS_MAX_LENGTH 20
    union {
        char words[26][WORDS_MAX_LENGTH];
        char words_list[25 * WORDS_MAX_LENGTH + 25];
    };
};

typedef struct monero_nv_state_s monero_nv_state_t;

#define MONERO_IO_BUFFER_LENGTH (300)
enum device_mode { NONE, TRANSACTION_CREATE_REAL, TRANSACTION_CREATE_FAKE, TRANSACTION_PARSE };

#define EXPORT_VIEW_KEY 0xC001BEEF

#define DISP_MAIN       0x51
#define DISP_SUB        0x52
#define DISP_INTEGRATED 0x53

struct monero_v_state_s {
    unsigned char state;
    unsigned char protocol;

    /* ------------------------------------------ */
    /* ---                  IO                --- */
    /* ------------------------------------------ */

    /* io state*/
    unsigned char io_protocol_version;
    unsigned char io_ins;
    unsigned char io_p1;
    unsigned char io_p2;
    unsigned char io_lc;
    unsigned char io_le;
    unsigned short io_length;
    unsigned short io_offset;
    unsigned short io_mark;
    unsigned char io_buffer[MONERO_IO_BUFFER_LENGTH];

    unsigned int options;

    /* ------------------------------------------ */
    /* ---            State Machine           --- */
    /* ------------------------------------------ */
    unsigned int export_view_key;
    unsigned char key_set;

/* protocol guard */
#define PROTOCOL_LOCKED            0x42
#define PROTOCOL_LOCKED_UNLOCKABLE 0x84
#define PROTOCOL_UNLOCKED          0x24
    unsigned char protocol_barrier;

    /* Tx state machine */
    unsigned char tx_in_progress;
    unsigned char tx_cnt;
    unsigned char tx_sig_mode;
    unsigned char tx_state_ins;
    unsigned char tx_state_p1;
    unsigned char tx_state_p2;
    unsigned char tx_output_cnt;
    unsigned int tx_sign_cnt;

    /* sc_add control */
    unsigned char last_derive_secret_key[32];
    unsigned char last_get_subaddress_secret_key[32];

    /* ------------------------------------------ */
    /* ---               Crypo                --- */
    /* ------------------------------------------ */
    unsigned char b[32];
    unsigned char a[32];
    unsigned char A[32];
    unsigned char B[32];

    /* SPK */
    cx_aes_key_t spk;
    unsigned char hmac_key[32];

    /* Tx key */
    unsigned char R[32];
    unsigned char r[32];

    /* prefix/mlsag hash */
    cx_sha3_t keccakF;
    cx_sha3_t keccakH;
    unsigned char prefixH[32];
    unsigned char mlsagH[32];
    unsigned char c[32];

    /* -- track tx-in/out and commitment -- */
    cx_sha256_t sha256_out_keys;
    unsigned char OUTK[32];

    cx_sha256_t sha256_commitment;
    unsigned char C[32];

    /* ------------------------------------------ */
    /* ---               UI/UX                --- */
    /* ------------------------------------------ */
    char ux_wallet_public_short_address[5 + 2 + 5 + 1];
    char ux_wallet_account_name[14];

    union {
        struct {
            char ux_info1[14];
            char ux_info2[14];
            /* menu */
            char ux_menu[16];
            // address to display: 95/106-chars + null
            char ux_address[160];
            // xmr to display: max pow(2,64) unit, aka 20-chars + '0' + dot + null
            char ux_amount[23];
            // addr mode
            unsigned char disp_addr_mode;
            // M.m address
            unsigned int disp_addr_M;
            unsigned int disp_addr_m;
            // payment id
            char payment_id[16];
        };
        struct {
            unsigned char tmp[340];
        };
    };
};
typedef struct monero_v_state_s monero_v_state_t;

#define SIZEOF_TX_VSTATE (sizeof(monero_v_state_t) - OFFSETOF(monero_v_state_t, state))

#define STATE_IDLE 0xC0

/* --- ... --- */
#define TYPE_SCALAR     1
#define TYPE_DERIVATION 2
#define TYPE_AMOUNT_KEY 3
#define TYPE_ALPHA      4

/* ---  ...  --- */
#define IO_OFFSET_END  (unsigned int)-1
#define IO_OFFSET_MARK (unsigned int)-2

#define ENCRYPTED_PAYMENT_ID_TAIL 0x8d

/* ---  Errors  --- */
#define ERROR(x) ((x) << 16)

#define ERROR_IO_OFFSET ERROR(1)
#define ERROR_IO_FULL   ERROR(2)

/* ---  INS  --- */

#define INS_NONE         0x00
#define INS_RESET        0x02
#define INS_LOCK_DISPLAY 0x04

#define INS_GET_KEY            0x20
#define INS_DISPLAY_ADDRESS    0x21
#define INS_PUT_KEY            0x22
#define INS_GET_CHACHA8_PREKEY 0x24
#define INS_VERIFY_KEY         0x26
#define INS_MANAGE_SEEDWORDS   0x28

#define INS_SECRET_KEY_TO_PUBLIC_KEY 0x30
#define INS_GEN_KEY_DERIVATION       0x32
#define INS_DERIVATION_TO_SCALAR     0x34
#define INS_DERIVE_PUBLIC_KEY        0x36
#define INS_DERIVE_SECRET_KEY        0x38
#define INS_GEN_KEY_IMAGE            0x3A
#define INS_SECRET_KEY_ADD           0x3C
#define INS_GENERATE_KEYPAIR         0x40
#define INS_SECRET_SCAL_MUL_KEY      0x42
#define INS_SECRET_SCAL_MUL_BASE     0x44

#define INS_DERIVE_SUBADDRESS_PUBLIC_KEY    0x46
#define INS_GET_SUBADDRESS                  0x48
#define INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY 0x4A
#define INS_GET_SUBADDRESS_SECRET_KEY       0x4C

#define INS_OPEN_TX             0x70
#define INS_SET_SIGNATURE_MODE  0x72
#define INS_GET_ADDITIONAL_KEY  0x74
#define INS_STEALTH             0x76
#define INS_GEN_COMMITMENT_MASK 0x77
#define INS_BLIND               0x78
#define INS_UNBLIND             0x7A
#define INS_GEN_TXOUT_KEYS      0x7B
#define INS_PREFIX_HASH         0x7D
#define INS_VALIDATE            0x7C
#define INS_MLSAG               0x7E
#define INS_CLSAG               0x7F
#define INS_CLOSE_TX            0x80

#define INS_GET_TX_PROOF       0xA0
#define INS_GEN_SIGNATURE      0xA2
#define INS_GEN_RING_SIGNATURE 0xA4

#define INS_GET_RESPONSE 0xc0

/* --- OPTIONS --- */
#define IN_OPTION_MASK  0x000000FF
#define OUT_OPTION_MASK 0x0000FF00

#define IN_OPTION_MORE_COMMAND 0x00000080

/* ---  IO constants  --- */
#define OFFSET_CLA       0
#define OFFSET_INS       1
#define OFFSET_P1        2
#define OFFSET_P2        3
#define OFFSET_P3        4
#define OFFSET_CDATA     5
#define OFFSET_EXT_CDATA 7

#define SW_OK 0x9000

#define SW_WRONG_LENGTH 0x6700

#define SW_SECURITY_PIN_LOCKED               0x6910
#define SW_SECURITY_LOAD_KEY                 0x6911
#define SW_SECURITY_COMMITMENT_CONTROL       0x6912
#define SW_SECURITY_AMOUNT_CHAIN_CONTROL     0x6913
#define SW_SECURITY_COMMITMENT_CHAIN_CONTROL 0x6914
#define SW_SECURITY_OUTKEYS_CHAIN_CONTROL    0x6915
#define SW_SECURITY_MAXOUTPUT_REACHED        0x6916
#define SW_SECURITY_HMAC                     0x6917
#define SW_SECURITY_RANGE_VALUE              0x6918
#define SW_SECURITY_INTERNAL                 0x6919
#define SW_SECURITY_MAX_SIGNATURE_REACHED    0x691A
#define SW_SECURITY_PREFIX_HASH              0x691B
#define SW_SECURITY_LOCKED                   0x69EE

#define SW_COMMAND_NOT_ALLOWED    0x6980
#define SW_SUBCOMMAND_NOT_ALLOWED 0x6981
#define SW_DENY                   0x6982
#define SW_KEY_NOT_SET            0x6983
#define SW_WRONG_DATA             0x6984
#define SW_WRONG_DATA_RANGE       0x6985
#define SW_IO_FULL                0x6986

#define SW_CLIENT_NOT_SUPPORTED 0x6A30

#define SW_WRONG_P1P2             0x6b00
#define SW_INS_NOT_SUPPORTED      0x6d00
#define SW_PROTOCOL_NOT_SUPPORTED 0x6e00

#define SW_UNKNOWN 0x6f00

#endif
