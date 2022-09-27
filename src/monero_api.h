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

int monero_apdu_reset(void);
int monero_apdu_lock(void);
void monero_lock_and_throw(int sw);

void monero_install(unsigned char netId);
void monero_init(void);
void monero_init_private_key(void);
void monero_wipe_private_key(void);

void monero_init_ux(void);
int monero_dispatch(void);

int monero_apdu_put_key(void);
int monero_apdu_get_key(void);
int monero_apdu_display_address(void);
int monero_apdu_manage_seedwords();
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

int monero_apdu_prefix_hash_init();
int monero_apdu_prefix_hash_update();

int monero_apdu_mlsag_prepare(void);
int monero_apdu_mlsag_hash(void);
int monero_apdu_mlsag_sign(void);
int monero_apdu_close_tx(void);

void ui_init(void);
void ui_menu_lock_display(void);
void ui_menu_main_display(unsigned int value);
void ui_menu_info_display(unsigned int value);
void ui_menu_info_display2(unsigned int value, char *line1, char *line2);
void ui_export_viewkey_display(unsigned int value);
void ui_menu_any_pubaddr_display(unsigned int value, unsigned char *pub_view,
                                 unsigned char *pub_spend, unsigned char is_subbadress,
                                 unsigned char *paymanetID);
void ui_menu_pubaddr_display(unsigned int value);

/* ----------------------------------------------------------------------- */
/* ---                               MISC                             ---- */
/* ----------------------------------------------------------------------- */
#define OFFSETOF(type, field) ((unsigned int)&(((type *)NULL)->field))

int monero_base58_public_key(char *str_b58, unsigned char *view, unsigned char *spend,
                             unsigned char is_subbadress, unsigned char *paymanetID);

/** unsigned varint amount to uint64 */
uint64_t monero_vamount2uint64(unsigned char *binary);
/** binary little endian unsigned  int amount to uint64 */
uint64_t monero_bamount2uint64(unsigned char *binary);
/** unsigned varint amount to str */
int monero_vamount2str(unsigned char *binary, char *str, unsigned int str_len);
/** binary little endian unsigned  int amount to str */
int monero_bamount2str(unsigned char *binary, char *str, unsigned int str_len);
/** uint64  amount to str */
int monero_amount2str(uint64_t xmr, char *str, unsigned int str_len);

/** uint64  amount to str */
void monero_uint642str(uint64_t val, char *str, unsigned int str_len);

int monero_abort_tx();
int monero_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout,
                   unsigned int short_amount);
void ui_menu_validation_display(unsigned int value);
void ui_menu_fee_validation_display(unsigned int value);
void ui_menu_change_validation_display(unsigned int value);
void ui_menu_timelock_validation_display(unsigned int value);

void ui_menu_opentx_display(unsigned int value);
/* ----------------------------------------------------------------------- */
/* ---                          KEYS & ADDRESS                        ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_FAKE_SEC_VIEW_KEY[32];
extern const unsigned char C_FAKE_SEC_SPEND_KEY[32];

int is_fake_view_key(unsigned char *s);
int is_fake_spend_key(unsigned char *s);

void monero_ge_fromfe_frombytes(unsigned char *ge, unsigned char *bytes);
void monero_sc_add(unsigned char *r, unsigned char *s1, unsigned char *s2);
void monero_hash_to_scalar(unsigned char *scalar, unsigned char *raw, unsigned int len);
void monero_hash_to_ec(unsigned char *ec, unsigned char *ec_pub);
void monero_generate_keypair(unsigned char *ec_pub, unsigned char *ec_priv);
/*
 *  compute s = 8 * (k*P)
 *
 * s [out] 32 bytes derivation value
 * P [in]  point in 02 y or 04 x y format
 * k [in]  32 bytes scalar
 */
void monero_generate_key_derivation(unsigned char *drv_data, unsigned char *P,
                                    unsigned char *scalar);
void monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data,
                                 unsigned int out_idx);
/*
 *  compute x = Hps(drv_data,out_idx) + ec_pv
 *
 * x        [out] 32 bytes private key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pv    [in]  32 bytes private key
 */
void monero_derive_secret_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                              unsigned char *ec_priv);
/*
 *  compute x = Hps(drv_data,out_idx)*G + ec_pub
 *
 * x        [out] 32 bytes public key
 * drv_data [in]  32 bytes derivation data (point)
 * ec_pub   [in]  32 bytes public key
 */
void monero_derive_public_key(unsigned char *x, unsigned char *drv_data, unsigned int out_idx,
                              unsigned char *ec_pub);
void monero_secret_key_to_public_key(unsigned char *ec_pub, unsigned char *ec_priv);
void monero_generate_key_image(unsigned char *img, unsigned char *P, unsigned char *x);
void monero_derive_view_tag(unsigned char *view_tag, unsigned char *drv_data, unsigned int out_idx);

void monero_derive_subaddress_public_key(unsigned char *x, unsigned char *pub,
                                         unsigned char *drv_data, unsigned int index);
void monero_get_subaddress_spend_public_key(unsigned char *x, unsigned char *index);
void monero_get_subaddress(unsigned char *C, unsigned char *D, unsigned char *index);
void monero_get_subaddress_secret_key(unsigned char *sub_s, unsigned char *s, unsigned char *index);

void monero_clear_words();
/* ----------------------------------------------------------------------- */
/* ---                              CRYPTO                            ---- */
/* ----------------------------------------------------------------------- */
extern const unsigned char C_ED25519_ORDER[];

void monero_aes_derive(cx_aes_key_t *sk, unsigned char *seed32, unsigned char *a, unsigned char *b);
void monero_aes_generate(cx_aes_key_t *sk);

/* Compute Monero-Hash of data*/
void monero_hash_init_keccak(cx_hash_t *hasher);
void monero_hash_init_sha256(cx_hash_t *hasher);
void monero_hash_update(cx_hash_t *hasher, unsigned char *buf, unsigned int len);
int monero_hash_final(cx_hash_t *hasher, unsigned char *out);
int monero_hash(unsigned int algo, cx_hash_t *hasher, unsigned char *buf, unsigned int len,
                unsigned char *out);

#define monero_keccak_init_F() monero_hash_init_keccak((cx_hash_t *)&G_monero_vstate.keccakF)
#define monero_keccak_update_F(buf, len) \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.keccakF, (buf), (len))
#define monero_keccak_final_F(out) monero_hash_final((cx_hash_t *)&G_monero_vstate.keccakF, (out))
#define monero_keccak_F(buf, len, out) \
    monero_hash(CX_KECCAK, (cx_hash_t *)&G_monero_vstate.keccakF, (buf), (len), (out))

#define monero_keccak_init_H() monero_hash_init_keccak((cx_hash_t *)&G_monero_vstate.keccakH)
#define monero_keccak_update_H(buf, len) \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.keccakH, (buf), (len))
#define monero_keccak_final_H(out) monero_hash_final((cx_hash_t *)&G_monero_vstate.keccakH, (out))
#define monero_keccak_H(buf, len, out) \
    monero_hash(CX_KECCAK, (cx_hash_t *)&G_monero_vstate.keccakH, (buf), (len), (out))

#define monero_sha256_commitment_init() \
    monero_hash_init_sha256((cx_hash_t *)&G_monero_vstate.sha256_commitment)
#define monero_sha256_commitment_update(buf, len) \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.sha256_commitment, (buf), (len))
#define monero_sha256_commitment_final(out)                            \
    monero_hash_final((cx_hash_t *)&G_monero_vstate.sha256_commitment, \
                      (out) ? (out) : G_monero_vstate.C)

#define monero_sha256_outkeys_init() \
    monero_hash_init_sha256((cx_hash_t *)&G_monero_vstate.sha256_out_keys)
#define monero_sha256_outkeys_update(buf, len) \
    monero_hash_update((cx_hash_t *)&G_monero_vstate.sha256_out_keys, (buf), (len))
#define monero_sha256_outkeys_final(out) \
    monero_hash_final((cx_hash_t *)&G_monero_vstate.sha256_out_keys, (out))

/*
 *  check 1<s<N, else throw
 */
void monero_check_scalar_range_1N(unsigned char *s);

/*
 *  check 1<s, else throw
 */
void monero_check_scalar_not_null(unsigned char *s);

/**
 * LE-7-bits encoding. High bit set says one more byte to decode.
 */
unsigned int monero_encode_varint(unsigned char *varint, unsigned int max_len, uint64_t v);

/**
 * LE-7-bits decoding. High bit set says one more byte to decode.
 */
unsigned int monero_decode_varint(unsigned char *varint, unsigned int max_len, uint64_t *v);

/** */
void monero_reverse32(unsigned char *rscal, unsigned char *scal);

/**
 * Hps: keccak(drv_data|varint(out_idx))
 */
void monero_derivation_to_scalar(unsigned char *scalar, unsigned char *drv_data,
                                 unsigned int out_idx);

/*
 * W = k.P
 */
void monero_ecmul_k(unsigned char *W, unsigned char *P, unsigned char *scalar32);
/*
 * W = 8k.P
 */
void monero_ecmul_8k(unsigned char *W, unsigned char *P, unsigned char *scalar32);

/*
 * W = 8.P
 */
void monero_ecmul_8(unsigned char *W, unsigned char *P);

/*
 * W = k.G
 */
void monero_ecmul_G(unsigned char *W, unsigned char *scalar32);

/*
 * W = k.H
 */
void monero_ecmul_H(unsigned char *W, unsigned char *scalar32);

/**
 *  keccak("amount"|sk)
 */
void monero_ecdhHash(unsigned char *x, unsigned char *k);

/**
 * keccak("commitment_mask"|sk) %order
 */
void monero_genCommitmentMask(unsigned char *c, unsigned char *sk);

/*
 * W = P+Q
 */
void monero_ecadd(unsigned char *W, unsigned char *P, unsigned char *Q);
/*
 * W = P-Q
 */
void monero_ecsub(unsigned char *W, unsigned char *P, unsigned char *Q);

/* r = (a+b) %order */
void monero_addm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a-b) %order */
void monero_subm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a*b) %order */
void monero_multm(unsigned char *r, unsigned char *a, unsigned char *b);

/* r = (a*8) %order */
void monero_multm_8(unsigned char *r, unsigned char *a);

/* */
void monero_reduce(unsigned char *r, unsigned char *a);

void monero_rng_mod_order(unsigned char *r);
/* ----------------------------------------------------------------------- */
/* ---                                IO                              ---- */
/* ----------------------------------------------------------------------- */

void monero_io_discard(int clear);
void monero_io_clear(void);
void monero_io_set_offset(unsigned int offset);
void monero_io_mark(void);
void monero_io_rewind(void);
void monero_io_hole(unsigned int sz);
void monero_io_inserted(unsigned int len);
void monero_io_insert(unsigned char const *buffer, unsigned int len);
void monero_io_insert_encrypt(unsigned char *buffer, int len, int type);
void monero_io_insert_hmac_for(unsigned char *buffer, int len, int type);

void monero_io_insert_u32(unsigned int v32);
void monero_io_insert_u24(unsigned int v24);
void monero_io_insert_u16(unsigned int v16);
void monero_io_insert_u8(unsigned int v8);
void monero_io_insert_t(unsigned int T);
void monero_io_insert_tl(unsigned int T, unsigned int L);
void monero_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V);

int monero_io_fetch_available();
void monero_io_fetch_buffer(unsigned char *buffer, unsigned int len);
uint64_t monero_io_fetch_varint(void);
unsigned int monero_io_fetch_u32(void);
unsigned int monero_io_fetch_u24(void);
unsigned int monero_io_fetch_u16(void);
unsigned int monero_io_fetch_u8(void);
int monero_io_fetch_t(unsigned int *T);
int monero_io_fetch_l(unsigned int *L);
int monero_io_fetch_tl(unsigned int *T, unsigned int *L);
int monero_io_fetch_nv(unsigned char *buffer, int len);
int monero_io_fetch(unsigned char *buffer, int len);
int monero_io_fetch_decrypt(unsigned char *buffer, int len, int type);
int monero_io_fetch_decrypt_key(unsigned char *buffer);

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
