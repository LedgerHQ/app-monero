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

#ifndef MONERO_API_H
#define MONERO_API_H

#include "monero_vars.h"

void __attribute__((noreturn)) send_error_and_kill_app(int sw);
int monero_apdu_reset(void);
int monero_apdu_lock(void);
void monero_lock(int sw);

void monero_install(unsigned char netId);
unsigned int monero_init(void);
int monero_init_private_key(void);

void monero_init_ux(void);
int monero_dispatch(void);

int monero_apdu_put_key(void);
int monero_apdu_get_key(void);
int monero_apdu_display_address(void);
int monero_apdu_manage_seedwords(void);
int monero_apdu_verify_key(void);
int monero_apdu_get_chacha8_prekey(void);
int monero_apdu_sc_add(void);
int monero_apdu_scal_mul_key(void);
int monero_apdu_scal_mul_base(void);
int monero_apdu_generate_keypair(void);
int monero_apdu_secret_key_to_public_key(void);
int monero_apdu_generate_key_derivation(void);
int monero_apdu_derivation_to_scalar(void);
int monero_apdu_derive_public_key(void);
int monero_apdu_derive_secret_key(void);
int monero_apdu_generate_key_image(void);
int monero_apdu_derive_view_tag(void);
int monero_apdu_derive_subaddress_public_key(void);
int monero_apdu_get_subaddress(void);
int monero_apdu_get_subaddress_spend_public_key(void);
int monero_apdu_get_subaddress_secret_key(void);

int monero_apdu_get_tx_proof(void);

int monero_apdu_open_tx(void);
int monero_apdu_open_tx_cont(void);
void monero_reset_tx(int reset_tx_cnt);
int monero_apdu_open_subtx(void);
int monero_apdu_set_signature_mode(void);
int monero_apdu_stealth(void);
int monero_apdu_blind(void);
int monero_apdu_unblind(void);
int monero_apdu_gen_commitment_mask(void);

int monero_apdu_mlsag_prehash_init(void);
int monero_apdu_mlsag_prehash_update(void);
int monero_apdu_mlsag_prehash_finalize(void);

int monero_apdu_clsag_prepare(void);
int monero_apdu_clsag_hash(void);
int monero_apdu_clsag_sign(void);

int monero_apu_generate_txout_keys(void);

int monero_apdu_prefix_hash_init(void);
int monero_apdu_prefix_hash_update(void);

int monero_apdu_mlsag_prepare(void);
int monero_apdu_mlsag_hash(void);
int monero_apdu_mlsag_sign(void);
int monero_apdu_close_tx(void);

void ui_init(void);
void ui_menu_lock_display(void);
void ui_menu_main_display(void);
void ui_menu_show_security_error(void);
void ui_menu_show_tx_aborted(void);
void ui_export_viewkey_display(unsigned int value);
int ui_menu_any_pubaddr_display(unsigned int value, unsigned char *pub_view,
                                 unsigned char *pub_spend, unsigned char is_subbadress,
                                 unsigned char *paymanetID);
void ui_menu_pubaddr_display(unsigned int value);

unsigned int ui_menu_transaction_start(void);
unsigned int ui_menu_transaction_signed(void);
/* ----------------------------------------------------------------------- */
/* ---                               MISC                             ---- */
/* ----------------------------------------------------------------------- */
#define OFFSETOF(type, field) ((unsigned int)&(((type *)NULL)->field))

int monero_base58_public_key(char *str_b58, unsigned char *view, unsigned char *spend,
                             unsigned char is_subbadress, unsigned char *paymanetID);

/** unsigned varint amount to uint64 */
uint64_t monero_vamount2uint64(unsigned char *binary);
/** binary little endian unsigned  int amount to uint64 */
uint64_t monero_bamount2uint64(unsigned char *binary, size_t binary_len);
/** unsigned varint amount to str */
int monero_vamount2str(unsigned char *binary, char *str, unsigned int str_len);
/** binary little endian unsigned  int amount to str */
int monero_bamount2str(unsigned char *binary, char *str, size_t binary_len, unsigned int str_len);
/** uint64  amount to str */
int monero_amount2str(uint64_t xmr, char *str, unsigned int str_len);

/** uint64  amount to str */
unsigned int monero_uint642str(uint64_t val, char *str, unsigned int str_len);

int monero_abort_tx(void);
int monero_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout,
                   unsigned int short_amount, size_t v_len, size_t k_len, size_t AKout_len);
void ui_menu_validation_display(unsigned int value);
void ui_menu_validation_display_last(unsigned int value);
void ui_menu_fee_validation_display(unsigned int value);
void ui_menu_change_validation_display(unsigned int value);
void ui_menu_change_validation_display_last(unsigned int value);
void ui_menu_timelock_validation_display(unsigned int value);

void ui_menu_opentx_display(unsigned int value);

void display_account(void);
/* ----------------------------------------------------------------------- */
/* ---                          KEYS & ADDRESS                        ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_FAKE_SEC_VIEW_KEY[32];
extern const unsigned char C_FAKE_SEC_SPEND_KEY[32];

int is_fake_view_key(unsigned char *s);
int is_fake_spend_key(unsigned char *s);

void monero_ge_fromfe_frombytes(unsigned char *ge, unsigned char *bytes, size_t ge_len, size_t bytes_len);
void monero_sc_add(unsigned char *r, unsigned char *s1, unsigned char *s2);
void monero_hash_to_scalar(unsigned char *scalar, unsigned char *raw, size_t scalar_len, unsigned int len);
void monero_hash_to_ec(unsigned char *ec, unsigned char *ec_pub, size_t ec_len);
void monero_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv, size_t ec_pub_len, size_t ec_priv_len);
/*
 *  compute s = 8 * (k*P)
 *
 * s [out] 32 bytes derivation value
 * P [in]  point in 02 y or 04 x y format
 * k [in]  32 bytes scalar
 */
void monero_generate_key_derivation(unsigned char *drv_data, unsigned char *P,
                                    unsigned char *scalar, size_t drv_data_len, size_t P_len, size_t scalar_len);
int monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data,
                                 unsigned int out_idx, size_t scalar_len, size_t drv_data_len);
/*
 *  compute x = Hps(drv_data,out_idx) + ec_pv
 *
 * x        [out] 32 bytes private key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pv    [in]  32 bytes private key
 */
int monero_derive_secret_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                              unsigned char *ec_priv, size_t x_len, size_t drv_data_len, size_t ec_priv_len);
/*
 *  compute x = Hps(drv_data,out_idx)*G + ec_pub
 *
 * x        [out] 32 bytes public key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pub   [in]  32 bytes public key
 */
int monero_derive_public_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                              unsigned char *ec_pub, size_t x_len, size_t drv_data_len, size_t ec_pub_len);
void monero_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv, size_t ec_pub_len, size_t ec_priv_len);
void monero_generate_key_image(unsigned char *img, unsigned char *P, unsigned char *x, size_t img_len, size_t x_len);
int monero_derive_view_tag(unsigned char *view_tag, const unsigned char drv_data[static 32],
                            unsigned int out_idx);

void monero_derive_subaddress_public_key(unsigned char *x, unsigned char *pub,
                                         unsigned char *drv_data, unsigned int index,
                                         size_t x_len, size_t pub_len, size_t drv_data_len);
void monero_get_subaddress_spend_public_key(unsigned char *x, unsigned char *index, size_t x_len, size_t index_len);
void monero_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index, size_t C_len, size_t D_len, size_t index_len);
void monero_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s, unsigned char *index, size_t sub_s_len, size_t s_len, size_t index_len);

void monero_clear_words(void);
/* ----------------------------------------------------------------------- */
/* ---                              CRYPTO                            ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_ED25519_ORDER[];

int monero_aes_derive(cx_aes_key_t *sk, unsigned char *seed32, unsigned char *a, unsigned char *b);
void monero_aes_generate(cx_aes_key_t *sk);

/* Compute Monero-Hash of data*/
int monero_hash_init_keccak(cx_hash_t *hasher);
void monero_hash_init_sha256(cx_hash_t *hasher);
int monero_hash_update(cx_hash_t *hasher, const unsigned char *buf, unsigned int len);
int monero_hash_final(cx_hash_t *hasher, unsigned char *out);
int monero_hash(unsigned int algo, cx_hash_t *hasher, const unsigned char *buf, unsigned int len,
                unsigned char *out);

static inline int monero_keccak_F(unsigned char *buf, size_t len, unsigned char *out) {
    return monero_hash(CX_KECCAK, (cx_hash_t *)&G_monero_vstate.keccakF, buf, len, out);
}

static inline int monero_keccak_init_H(void) {
    return monero_hash_init_keccak((cx_hash_t *)&G_monero_vstate.keccakH);
}

static inline int monero_keccak_update_H(const unsigned char *buf, size_t len) {
    return monero_hash_update((cx_hash_t *)&G_monero_vstate.keccakH, buf, len);
}

static inline int monero_keccak_final_H(unsigned char *out) {
    return monero_hash_final((cx_hash_t *)&G_monero_vstate.keccakH, out);
}

static inline int monero_keccak_H(const unsigned char *buf, size_t len, unsigned char *out) {
    return monero_hash(CX_KECCAK, (cx_hash_t *)&G_monero_vstate.keccakH, buf, len, out);
}

static inline void monero_sha256_commitment_init(void) {
    monero_hash_init_sha256((cx_hash_t *)&G_monero_vstate.sha256_commitment);
}

static inline int monero_sha256_commitment_update(const unsigned char *buf, size_t len) {
    return monero_hash_update((cx_hash_t *)&G_monero_vstate.sha256_commitment, buf, len);
}

static inline int monero_sha256_commitment_final(unsigned char *out) {
    unsigned char *digest = out ? out : G_monero_vstate.C;
    return monero_hash_final((cx_hash_t *)&G_monero_vstate.sha256_commitment, digest);
}

static inline void monero_sha256_outkeys_init(void) {
    monero_hash_init_sha256((cx_hash_t *)&G_monero_vstate.sha256_out_keys);
}

static inline int monero_sha256_outkeys_update(const unsigned char *buf, size_t len) {
    return monero_hash_update((cx_hash_t *)&G_monero_vstate.sha256_out_keys, buf, len);
}

static inline int monero_sha256_outkeys_final(unsigned char *out) {
    return monero_hash_final((cx_hash_t *)&G_monero_vstate.sha256_out_keys, out);
}

/*
 *  check 1<s<N, else throw
 */
unsigned int monero_check_scalar_range_1N(unsigned char *s, size_t s_len);

/*
 *  check 1<s, else throw
 */
unsigned int monero_check_scalar_not_null(unsigned char *s);

/**
 * LE-7-bits encoding. High bit set says one more byte to decode.
 */
unsigned int monero_encode_varint(unsigned char *varint, unsigned int max_len, uint64_t v, unsigned int *out_len);

/**
 * LE-7-bits decoding. High bit set says one more byte to decode.
 */
unsigned int monero_decode_varint(const unsigned char *varint, size_t max_len, uint64_t *value, unsigned int *out_len);

/** */
void monero_reverse32(unsigned char *rscal, unsigned char *scal, size_t rscal_len, size_t scal_len);

/**
 * Hps: keccak(drv_data|varint(out_idx))
 */
int monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data,
                                 unsigned int out_idx, size_t scalar_len, size_t drv_data_len);

/*
 * W = k.P
 */
void monero_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32, size_t W_len, size_t P_len, size_t scalar32_len);
/*
 * W = 8k.P
 */
void monero_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32, size_t W_len, size_t P_len, size_t scalar32_len);

/*
 * W = 8.P
 */
void monero_ecmul_8(unsigned char *W, unsigned char *P, size_t W_len, size_t P_len);

/*
 * W = k.G
 */
void monero_ecmul_G(unsigned char *W, unsigned char *scalar32, size_t W_len, size_t scalar32_len);

/*
 * W = k.H
 */
void monero_ecmul_H(unsigned char *W, unsigned char *scalar32, size_t W_len, size_t scalar32_len);

/**
 *  keccak("amount"|sk)
 */
void monero_ecdhHash(unsigned char *x, unsigned char *k, size_t k_len);

/**
 * keccak("commitment_mask"|sk) %order
 */
void monero_genCommitmentMask(unsigned char *c, unsigned char *sk, size_t c_len, size_t sk_len);

/*
 * W = P+Q
 */
void monero_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q, size_t W_len, size_t P_len, size_t Q_len);
/*
 * W = P-Q
 */
void monero_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q, size_t W_len, size_t P_len, size_t Q_len);

/* r = (a+b) %order */
void monero_addm(unsigned char *r, unsigned char *a, unsigned char *b, size_t r_len, size_t a_len, size_t b_len);

/* r = (a-b) %order */
void monero_subm(unsigned char *r, unsigned char *a, unsigned char *b, size_t r_len, size_t a_len, size_t b_len);

/* r = (a*b) %order */
void monero_multm(unsigned char *r, unsigned char *a, unsigned char *b, size_t r_len, size_t a_len, size_t b_len);

/* r = (a*8) %order */
void monero_multm_8(unsigned char *r, unsigned char *a, size_t r_len, size_t a_len);

/* */
void monero_reduce(unsigned char *r, unsigned char *a, size_t r_len, size_t a_len);

void monero_rng_mod_order(unsigned char *r, size_t r_len);
/* ----------------------------------------------------------------------- */
/* ---                                IO                              ---- */
/* ----------------------------------------------------------------------- */

void monero_io_discard(int clear);
void monero_io_clear(void);
void monero_io_mark(void);
void monero_io_rewind(void);
void monero_io_hole(unsigned int sz);
void monero_io_inserted(unsigned int len);
void monero_io_insert(unsigned char const *buffer, unsigned int len);
void monero_io_insert_encrypt(unsigned char *buffer, size_t len, int type);
void monero_io_insert_hmac_for(unsigned char *buffer, int len, int type);

void monero_io_insert_u32(unsigned int v32);
void monero_io_insert_u24(unsigned int v24);
void monero_io_insert_u16(unsigned int v16);
void monero_io_insert_u8(unsigned int v8);
void monero_io_insert_t(unsigned int T);
void monero_io_insert_tl(unsigned int T, unsigned int L);
void monero_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V);

int monero_io_fetch_available(void);
void monero_io_fetch_buffer(unsigned char *buffer, unsigned int len);
int monero_io_fetch_varint(uint64_t* out_v64);
unsigned int monero_io_fetch_u32(void);
unsigned int monero_io_fetch_u24(void);
unsigned int monero_io_fetch_u16(void);
unsigned int monero_io_fetch_u8(void);
int monero_io_fetch_t(unsigned int *T);
int monero_io_fetch_l(unsigned int *L);
int monero_io_fetch_tl(unsigned int *T, unsigned int *L);
int monero_io_fetch_nv(unsigned char *buffer, int len);
void monero_io_skip(int len);
int monero_io_fetch(unsigned char *buffer, int len);
int monero_io_fetch_decrypt(unsigned char *buffer, size_t len, int type);
int monero_io_fetch_decrypt_key(unsigned char *buffer, size_t len);

int monero_io_do(unsigned int io_flags);
/* ----------------------------------------------------------------------- */
/* ---                                DEBUG                           ---- */
/* ----------------------------------------------------------------------- */
#ifdef MONERO_DEBUG

#include "monero_debug.h"

#else

#define monero_nvm_write   nvm_write
#define monero_io_exchange io_exchange

#endif

#endif
