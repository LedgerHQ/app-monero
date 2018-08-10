/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MONERO_TYPES_H
#define MONERO_TYPES_H

#include "os_io_seproxyhal.h"
/* cannot send more that F0 bytes in CCID, why? do not know for now
 *  So set up length to F0 minus 2 bytes for SW
 */
#define MONERO_APDU_LENGTH                       0xFE


/* big private DO */
#define MONERO_EXT_PRIVATE_DO_LENGTH             512
/* will be fixed..1024 is not enougth */
#define MONERO_EXT_CARD_HOLDER_CERT_LENTH        2560
/* random choice */
#define MONERO_EXT_CHALLENGE_LENTH               254

/* --- ... --- */
#define MAINNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             18
#define MAINNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  19
#define MAINNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          42

#define STAGENET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX            24
#define STAGENET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX 25
#define STAGENET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX         36

#define TESTNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX             53
#define TESTNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX  54
#define TESTNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX          63

enum network_type {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN
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


  /* view key */
  unsigned char a[32];

  /* spend key */
  unsigned char b[32];

  /*words*/
  #define WORDS_MAX_LENGTH 20
  char words[26][20];

} ;

typedef struct monero_nv_state_s monero_nv_state_t;

#define MONERO_IO_BUFFER_LENGTH (300)
enum device_mode {
  NONE,
  TRANSACTION_CREATE_REAL,
  TRANSACTION_CREATE_FAKE,
  TRANSACTION_PARSE
};

struct monero_v_state_s {
  unsigned char   state; 

  /* ------------------------------------------ */
  /* ---                  IO                --- */
  /* ------------------------------------------ */

  /* io state*/
  unsigned char   io_cla;
  unsigned char   io_ins;
  unsigned char   io_p1;
  unsigned char   io_p2;
  unsigned char   io_lc;
  unsigned char   io_le;
  unsigned short  io_length;
  unsigned short  io_offset;
  unsigned short  io_mark;
  unsigned char   io_buffer[MONERO_IO_BUFFER_LENGTH];


  unsigned int    options;

  /* ------------------------------------------ */
  /* ---            State Machine           --- */
  /* ------------------------------------------ */


  unsigned int   sig_mode;

  /* ------------------------------------------ */
  /* ---               Crypo                --- */
  /* ------------------------------------------ */

  unsigned char a[32];
  unsigned char A[32];
  unsigned char b[32];
  unsigned char B[32];

  /* SPK */
  cx_aes_key_t spk;

  /* Tx state machine */
  unsigned int    tx_state; 

  /* Tx key */
  unsigned char R[32];
  unsigned char r[32];

  /* mlsag hash */
  cx_sha3_t     keccakF;
  cx_sha3_t     keccakH;
  unsigned char H[32];
  unsigned char c[32];

  /* -- track tx-in/out and commitment -- */
  cx_sha256_t   sha256_amount;
  unsigned char KV[32];

  cx_sha256_t   sha256_commitment;
  unsigned char C[32];

  /* ------------------------------------------ */
  /* ---               UI/UX                --- */
  /* ------------------------------------------ */
  union {
    struct {
      /* menu 0: 95-chars + "<monero: >"  + null */
      char            ux_menu[112];
      // address to display: 95-chars + null
      char            ux_address[96];
      // xmr to display: max pow(2,64) unit, aka 20-chars + '0' + dot + null
      char            ux_amount[23];
    };
    struct {
      char words[340];
    };
  };
};
typedef struct  monero_v_state_s monero_v_state_t;




#define SIZEOF_TX_VSTATE   (sizeof(monero_v_state_t) - OFFSETOF(monero_v_state_t, state))

/* ---  ...  --- */
#define IO_OFFSET_END                       (unsigned int)-1
#define IO_OFFSET_MARK                      (unsigned int)-2

#define ENCRYPTED_PAYMENT_ID_TAIL            0x8d

/* ---  Errors  --- */
#define ERROR(x)                            ((x)<<16)

#define ERROR_IO_OFFSET                     ERROR(1)
#define ERROR_IO_FULL                       ERROR(2)

/* ---  INS  --- */

#define INS_NONE                            0x00
#define INS_RESET                           0x02

#define INS_GET_KEY                         0x20
#define INS_PUT_KEY                         0x22
#define INS_GET_CHACHA8_PREKEY              0x24
#define INS_VERIFY_KEY                      0x26
#define INS_MANAGE_SEEDWORDS                0x28

#define INS_SECRET_KEY_TO_PUBLIC_KEY        0x30
#define INS_GEN_KEY_DERIVATION              0x32
#define INS_DERIVATION_TO_SCALAR            0x34
#define INS_DERIVE_PUBLIC_KEY               0x36
#define INS_DERIVE_SECRET_KEY               0x38
#define INS_GEN_KEY_IMAGE                   0x3A
#define INS_SECRET_KEY_ADD                  0x3C
#define INS_SECRET_KEY_SUB                  0x3E
#define INS_GENERATE_KEYPAIR                0x40
#define INS_SECRET_SCAL_MUL_KEY             0x42
#define INS_SECRET_SCAL_MUL_BASE            0x44

#define INS_DERIVE_SUBADDRESS_PUBLIC_KEY    0x46
#define INS_GET_SUBADDRESS                  0x48
#define INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY 0x4A
#define INS_GET_SUBADDRESS_SECRET_KEY       0x4C

#define INS_OPEN_TX                         0x70
#define INS_SET_SIGNATURE_MODE              0x72
#define INS_GET_ADDITIONAL_KEY              0x74
#define INS_STEALTH                         0x76
#define INS_BLIND                           0x78
#define INS_UNBLIND                         0x7A
#define INS_VALIDATE                        0x7C
#define INS_MLSAG                           0x7E
#define INS_CLOSE_TX                        0x80



#define INS_GET_RESPONSE                    0xc0

/* --- OPTIONS --- */
#define IN_OPTION_MASK                      0x000000FF
#define OUT_OPTION_MASK                     0x0000FF00

#define IN_OPTION_MORE_COMMAND              0x00000080

/* ---  IO constants  --- */
#define OFFSET_CLA                          0
#define OFFSET_INS                          1
#define OFFSET_P1                           2
#define OFFSET_P2                           3
#define OFFSET_P3                           4
#define OFFSET_CDATA                        5
#define OFFSET_EXT_CDATA                    7


#define SW_OK                                0x9000
#define SW_ALGORITHM_UNSUPPORTED             0x9484

#define SW_BYTES_REMAINING_00                0x6100

#define SW_WARNING_STATE_UNCHANGED           0x6200
#define SW_STATE_TERMINATED                  0x6285

#define SW_MORE_DATA_AVAILABLE               0x6310

#define SW_WRONG_LENGTH                      0x6700

#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED     0x6881
#define SW_SECURE_MESSAGING_NOT_SUPPORTED    0x6882
#define SW_LAST_COMMAND_EXPECTED             0x6883
#define SW_COMMAND_CHAINING_NOT_SUPPORTED    0x6884


#define SW_SECURITY_LOAD_KEY                 0x6900
#define SW_SECURITY_COMMITMENT_CONTROL       0x6911
#define SW_SECURITY_AMOUNT_CHAIN_CONTROL     0x6912
#define SW_SECURITY_COMMITMENT_CHAIN_CONTROL 0x6913

#define SW_SECURITY_STATUS_NOT_SATISFIED     0x6982
#define SW_FILE_INVALID                      0x6983
#define SW_PIN_BLOCKED                       0x6983
#define SW_DATA_INVALID                      0x6984
#define SW_CONDITIONS_NOT_SATISFIED          0x6985
#define SW_COMMAND_NOT_ALLOWED               0x6986
#define SW_APPLET_SELECT_FAILED              0x6999

#define SW_WRONG_DATA                        0x6a80
#define SW_FUNC_NOT_SUPPORTED                0x6a81
#define SW_FILE_NOT_FOUND                    0x6a82
#define SW_RECORD_NOT_FOUND                  0x6a83
#define SW_FILE_FULL                         0x6a84
#define SW_INCORRECT_P1P2                    0x6a86
#define SW_REFERENCED_DATA_NOT_FOUND         0x6a88

#define SW_WRONG_P1P2                        0x6b00
#define SW_CORRECT_LENGTH_00                 0x6c00
#define SW_INS_NOT_SUPPORTED                 0x6d00
#define SW_CLA_NOT_SUPPORTED                 0x6e00

#define SW_UNKNOWN                           0x6f00


#endif
