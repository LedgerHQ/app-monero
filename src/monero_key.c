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

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
static void monero_payment_id_to_str(const unsigned char *payment_id, char *str) {
    for (int i = 0; i < 8; i++) {
        if (payment_id[i] <= 0xF) {
            snprintf(str + i * 2, 3, "0%x", payment_id[i]);
        } else {
            snprintf(str + i * 2, 3, "%x", payment_id[i]);
        }
    }
}

int monero_apdu_display_address() {
    unsigned int major;
    unsigned int minor;
    unsigned char index[8];
    unsigned char payment_id[8];
    unsigned char C[KEY_SIZE];
    unsigned char D[KEY_SIZE];
    int error = 0;

    // fetch
    monero_io_fetch(index, 8);
    monero_io_fetch(payment_id, 8);
    monero_io_discard(0);

    major = (index[0] << 0) | (index[1] << 8) | (index[2] << 16) | (index[3] << 24);
    minor = (index[4] << 0) | (index[5] << 8) | (index[6] << 16) | (index[7] << 24);
    if ((minor | major) && (G_monero_vstate.io_p1 == 1)) {
        return SW_WRONG_DATA;
    }

    // retrieve pub keys
    if (minor | major) {
        error = monero_get_subaddress(C, D, index, sizeof(C), sizeof(D), sizeof(index));
        if (error) {
            return error;
        }
    } else {
        memcpy(C, G_monero_vstate.A, KEY_SIZE);
        memcpy(D, G_monero_vstate.B, KEY_SIZE);
    }

    // prepare UI
    if (minor | major) {
        G_monero_vstate.disp_addr_M = major;
        G_monero_vstate.disp_addr_m = minor;
        G_monero_vstate.disp_addr_mode = DISP_SUB;
    } else {
        if (G_monero_vstate.io_p1 == 1) {
            monero_payment_id_to_str(payment_id, G_monero_vstate.payment_id);
            G_monero_vstate.disp_addr_mode = DISP_INTEGRATED;
        } else {
            G_monero_vstate.disp_addr_mode = DISP_MAIN;
        }
    }

    error = ui_menu_any_pubaddr_display(0, C, D, (minor | major) ? 1 : 0,
                                        (G_monero_vstate.io_p1 == 1) ? payment_id : NULL);
    return error;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int is_fake_view_key(unsigned char *s) {
    return memcmp(s, C_FAKE_SEC_VIEW_KEY, KEY_SIZE) == 0;
}

int is_fake_spend_key(unsigned char *s) {
    return memcmp(s, C_FAKE_SEC_SPEND_KEY, KEY_SIZE) == 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_put_key() {
#ifdef DEBUG_HWDEVICE
    unsigned char raw[KEY_SIZE];
    unsigned char pub[KEY_SIZE];
    unsigned char sec[KEY_SIZE];
    int err;

    // option + priv/pub view key + priv/pub spend key + base58 address
    if (G_monero_vstate.io_length != (1 + KEY_SIZE * 2 + KEY_SIZE * 2 + 95)) {
        return SW_WRONG_LENGTH;
    }

    // view key
    monero_io_fetch(sec, KEY_SIZE);
    monero_io_fetch(pub, KEY_SIZE);
    err = monero_ecmul_G(raw, sec, sizeof(raw), sizeof(sec));
    if (err) {
        return err;
    }

    if (memcmp(pub, raw, KEY_SIZE) != 0) {
        return SW_WRONG_DATA;
    }
    nvm_write((void *)N_monero_pstate->a, sec, KEY_SIZE);

    // spend key
    monero_io_fetch(sec, KEY_SIZE);
    monero_io_fetch(pub, KEY_SIZE);
    err = monero_ecmul_G(raw, sec, sizeof(raw), sizeof(sec));
    if (err) {
        return err;
    }

    if (memcmp(pub, raw, KEY_SIZE) != 0) {
        return SW_WRONG_DATA;
    }
    nvm_write((void *)N_monero_pstate->b, sec, KEY_SIZE);

    // change mode
    unsigned char key_mode = KEY_MODE_EXTERNAL;
    nvm_write((void *)&N_monero_pstate->key_mode, &key_mode, 1);

    monero_io_discard(1);

    return SW_OK;
#else
    return SW_INS_NOT_SUPPORTED;
#endif
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_key() {
    monero_io_discard(1);
    switch (G_monero_vstate.io_p1) {
        // get pub
        case 1:
            // view key
            monero_io_insert(G_monero_vstate.A, KEY_SIZE);
            // spend key
            monero_io_insert(G_monero_vstate.B, KEY_SIZE);
            // public base address
            int error = monero_base58_public_key(
                (char *)G_monero_vstate.io_buffer + G_monero_vstate.io_offset, G_monero_vstate.A,
                G_monero_vstate.B, 0, NULL);
            if (error) {
                return 0;
            }
            monero_io_inserted(95);
            break;

        // get private
        case 2:
            // view key
            ui_export_viewkey_display(0);
            return 0;

#ifdef DEBUG_HWDEVICE
        // get info
        case 3: {
            unsigned int path[5];
            unsigned char seed[64];

            // m/44'/128'/0'/0/0
            path[0] = 0x8000002C;
            path[1] = 0x80000080;
            path[2] = 0x80000000;
            path[3] = 0x00000000;
            path[4] = 0x00000000;

            if (os_derive_bip32_no_throw(CX_CURVE_SECP256K1, path, 5, seed, G_monero_vstate.a)) {
                return SW_WRONG_DATA;
            }
            monero_io_insert(seed, KEY_SIZE);

            monero_io_insert(G_monero_vstate.b, KEY_SIZE);
            monero_io_insert(G_monero_vstate.a, KEY_SIZE);

            break;
        }

            // get info
        case 4:
            monero_io_insert(G_monero_vstate.a, KEY_SIZE);
            monero_io_insert(G_monero_vstate.b, KEY_SIZE);
            break;
#endif

        default:
            return SW_WRONG_P1P2;
    }
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_verify_key() {
    unsigned char pub[KEY_SIZE];
    unsigned char computed_pub[KEY_SIZE];
    unsigned int verified = 0;
    int err = 0;

    switch (G_monero_vstate.io_p1) {
        case 0: {
            unsigned char priv[KEY_SIZE];
            err = monero_io_fetch_decrypt_key(priv, sizeof(priv));
            if (err) {
                explicit_bzero(priv, sizeof(priv));
                return err;
            }

            err = monero_secret_key_to_public_key(computed_pub, priv, sizeof(computed_pub),
                                                  sizeof(priv));
            explicit_bzero(priv, sizeof(priv));

            if (err) {
                return err;
            }
            break;
        }
        case 1:
            monero_io_skip(KEY_SIZE);
            memcpy(computed_pub, G_monero_vstate.A, KEY_SIZE);
            break;
        case 2:
            monero_io_skip(KEY_SIZE);
            memcpy(computed_pub, G_monero_vstate.B, KEY_SIZE);
            break;
        default:
            return SW_WRONG_P1P2;
    }

    monero_io_fetch(pub, sizeof(pub));

    if (memcmp(computed_pub, pub, sizeof(pub)) == 0) {
        verified = 1;
    }

    monero_io_discard(1);
    monero_io_insert_u32(verified);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
#define CHACHA8_LABEL       "MONERO_CHACHA8_PREKEY"
#define CHACHA8_LABEL_LEN   (sizeof(CHACHA8_LABEL) - 1U)
#define CHACHA8_PREKEY_SIZE 200
int monero_apdu_get_chacha8_prekey(/*char  *prekey*/) {
    unsigned char abt[CHACHA8_LABEL_LEN + KEY_SIZE];
    unsigned char pre[CHACHA8_PREKEY_SIZE];

    monero_io_discard(0);
    memcpy(abt, CHACHA8_LABEL, CHACHA8_LABEL_LEN);
    memcpy(abt + CHACHA8_LABEL_LEN, G_monero_vstate.a, KEY_SIZE);
    cx_err_t error = cx_shake256_hash(abt, CHACHA8_LABEL_LEN + KEY_SIZE, pre, CHACHA8_PREKEY_SIZE);
    explicit_bzero(abt, sizeof(abt));
    if (CX_OK != error) {
        explicit_bzero(pre, sizeof(pre));
        return SW_SECURITY_INTERNAL;
    }
    monero_io_insert(pre, CHACHA8_PREKEY_SIZE);
    explicit_bzero(pre, sizeof(pre));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_sc_add(/*unsigned char *r, unsigned char *s1, unsigned char *s2*/) {
    unsigned char s1[KEY_SIZE];
    unsigned char s2[KEY_SIZE];
    unsigned char r[KEY_SIZE];
    int err;
    // fetch
    err = monero_io_fetch_decrypt(s1, KEY_SIZE, TYPE_SCALAR);
    if (err) {
        explicit_bzero(s1, sizeof(s1));
        return err;
    }
    err = monero_io_fetch_decrypt(s2, KEY_SIZE, TYPE_SCALAR);
    if (err) {
        explicit_bzero(s1, sizeof(s1));
        explicit_bzero(s2, sizeof(s2));
        return err;
    }
    monero_io_discard(0);
    if (G_monero_vstate.tx_in_progress) {
        // During a transaction, only "last_derive_secret_key+last_get_subaddress_secret_key"
        // is allowed, in order to match the call at
        // https://github.com/monero-project/monero/blob/v0.15.0.5/src/cryptonote_basic/cryptonote_format_utils.cpp#L331
        //
        //      hwdev.sc_secret_add(scalar_step2, scalar_step1,subaddr_sk);
        if ((memcmp(s1, G_monero_vstate.last_derive_secret_key, KEY_SIZE) != 0) ||
            (memcmp(s2, G_monero_vstate.last_get_subaddress_secret_key, KEY_SIZE) != 0)) {
            explicit_bzero(s1, sizeof(s1));
            explicit_bzero(s2, sizeof(s2));
            return SW_WRONG_DATA;
        }
    }
    err = monero_addm(r, s1, s2, sizeof(r), sizeof(s1), sizeof(s2));
    if (err) {
        explicit_bzero(s1, sizeof(s1));
        explicit_bzero(s2, sizeof(s2));
        explicit_bzero(r, sizeof(r));
        return err;
    }
    monero_io_insert_encrypt(r, KEY_SIZE, TYPE_SCALAR);
    explicit_bzero(s1, sizeof(s1));
    explicit_bzero(s2, sizeof(s2));
    explicit_bzero(r, sizeof(r));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_scal_mul_key(/*const rct::key &pub, const rct::key &sec, rct::key mulkey*/) {
    unsigned char pub[KEY_SIZE];
    unsigned char sec[KEY_SIZE];
    unsigned char r[KEY_SIZE];
    int err = 0;

    // fetch
    monero_io_fetch(pub, KEY_SIZE);
    err = monero_io_fetch_decrypt_key(sec, sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_discard(0);

    err = monero_ecmul_k(r, pub, sec, sizeof(r), sizeof(pub), sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_insert(r, KEY_SIZE);
    explicit_bzero(sec, sizeof(sec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_scal_mul_base(/*const rct::key &sec, rct::key mulkey*/) {
    unsigned char sec[KEY_SIZE];
    unsigned char r[KEY_SIZE];
    int err;
    // fetch
    err = monero_io_fetch_decrypt(sec, KEY_SIZE, TYPE_SCALAR);
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_discard(0);

    err = monero_ecmul_G(r, sec, sizeof(r), sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }

    monero_io_insert(r, KEY_SIZE);
    explicit_bzero(sec, sizeof(sec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_keypair(/*crypto::public_key &pub, crypto::secret_key &sec*/) {
    unsigned char sec[KEY_SIZE];
    unsigned char pub[KEY_SIZE];

    monero_io_discard(0);
    int error = monero_generate_keypair(pub, sec, sizeof(pub), sizeof(sec));
    if (error) {
        explicit_bzero(sec, sizeof(sec));
        return error;
    }
    monero_io_insert(pub, KEY_SIZE);
    monero_io_insert_encrypt(sec, KEY_SIZE, TYPE_SCALAR);
    explicit_bzero(sec, sizeof(sec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_secret_key_to_public_key(
    /*const crypto::secret_key &sec, crypto::public_key &pub*/) {
    unsigned char sec[KEY_SIZE];
    unsigned char pub[KEY_SIZE];
    // fetch
    int err = monero_io_fetch_decrypt(sec, KEY_SIZE, TYPE_SCALAR);
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_discard(0);
    // pub
    err = monero_ecmul_G(pub, sec, sizeof(pub), sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }

    // pub key
    monero_io_insert(pub, KEY_SIZE);
    explicit_bzero(sec, sizeof(sec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_key_derivation(/*const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation*/) {
    unsigned char pub[KEY_SIZE];
    unsigned char sec[KEY_SIZE];
    unsigned char drv[KEY_SIZE];
    int err = 0;

    // fetch
    monero_io_fetch(pub, KEY_SIZE);
    err = monero_io_fetch_decrypt_key(sec, sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }

    monero_io_discard(0);

    // Derive  and keep
    err = monero_generate_key_derivation(drv, pub, sec, sizeof(drv), sizeof(pub), sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        explicit_bzero(drv, sizeof(drv));
        return err;
    }

    monero_io_insert_encrypt(drv, KEY_SIZE, TYPE_DERIVATION);
    explicit_bzero(sec, sizeof(sec));
    explicit_bzero(drv, sizeof(drv));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derivation_to_scalar(
    /*const crypto::key_derivation &derivation, const size_t output_index, ec_scalar &res*/) {
    unsigned char derivation[KEY_SIZE];
    unsigned int output_index;
    unsigned char res[KEY_SIZE];

    // fetch
    int err = monero_io_fetch_decrypt(derivation, KEY_SIZE, TYPE_DERIVATION);
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }
    output_index = monero_io_fetch_u32();
    monero_io_discard(0);

    // pub
    err =
        monero_derivation_to_scalar(res, derivation, output_index, sizeof(res), sizeof(derivation));
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        explicit_bzero(res, sizeof(res));
        return err;
    }

    // pub key
    monero_io_insert_encrypt(res, KEY_SIZE, TYPE_SCALAR);
    explicit_bzero(derivation, sizeof(derivation));
    explicit_bzero(res, sizeof(res));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_public_key(/*const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub, public_key &derived_pub*/) {
    unsigned char derivation[KEY_SIZE];
    unsigned int output_index;
    unsigned char pub[KEY_SIZE];
    unsigned char drvpub[KEY_SIZE];

    // fetch
    int err = monero_io_fetch_decrypt(derivation, KEY_SIZE, TYPE_DERIVATION);
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }
    output_index = monero_io_fetch_u32();
    monero_io_fetch(pub, KEY_SIZE);
    monero_io_discard(0);

    // pub
    int error = monero_derive_public_key(drvpub, derivation, output_index, pub, sizeof(drvpub),
                                         sizeof(derivation), sizeof(pub));
    if (error) {
        explicit_bzero(derivation, sizeof(derivation));
        return error;
    }

    // pub key
    monero_io_insert(drvpub, KEY_SIZE);
    explicit_bzero(derivation, sizeof(derivation));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_secret_key(/*const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec, secret_key &derived_sec*/){
    unsigned char derivation[KEY_SIZE];
    unsigned int output_index;
    unsigned char sec[KEY_SIZE];
    unsigned char drvsec[KEY_SIZE];
    int err = 0;

    // fetch
    err = monero_io_fetch_decrypt(derivation, KEY_SIZE, TYPE_DERIVATION);
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }
    output_index = monero_io_fetch_u32();
    err = monero_io_fetch_decrypt_key(sec, sizeof(sec));
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_discard(0);

    // pub
    err = monero_derive_secret_key(drvsec, derivation, output_index, sec, sizeof(drvsec),
                                   sizeof(derivation), sizeof(sec));
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        explicit_bzero(sec, sizeof(sec));
        explicit_bzero(drvsec, sizeof(drvsec));
        return err;
    }

    // sec key
    memcpy(G_monero_vstate.last_derive_secret_key, drvsec, KEY_SIZE);
    monero_io_insert_encrypt(drvsec, KEY_SIZE, TYPE_SCALAR);

    explicit_bzero(derivation, sizeof(derivation));
    explicit_bzero(sec, sizeof(sec));
    explicit_bzero(drvsec, sizeof(drvsec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_generate_key_image(
    /*const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image*/) {
    unsigned char pub[KEY_SIZE];
    unsigned char sec[KEY_SIZE];
    unsigned char image[KEY_SIZE];

    // fetch
    monero_io_fetch(pub, KEY_SIZE);
    int err = monero_io_fetch_decrypt(sec, KEY_SIZE, TYPE_SCALAR);
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_discard(0);

    // pub
    err = monero_generate_key_image(image, pub, sec, sizeof(image), sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }

    // pub key
    monero_io_insert(image, KEY_SIZE);
    explicit_bzero(sec, sizeof(sec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_view_tag(
    /*const crypto::key_derivation &derivation, const size_t output_index, crypto::view_tag &view_tag*/) {
    unsigned char derivation[KEY_SIZE];
    unsigned int output_index;
    unsigned char res[1];
    int err;

    // fetch
    err = monero_io_fetch_decrypt(derivation, KEY_SIZE, TYPE_DERIVATION);
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }
    output_index = monero_io_fetch_u32();
    monero_io_discard(0);

    // derive and keep
    err = monero_derive_view_tag(res, derivation, output_index);
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }

    monero_io_insert(res, 1);
    explicit_bzero(derivation, sizeof(derivation));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_derive_subaddress_public_key(/*const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index, public_key &derived_pub*/) {
    unsigned char pub[KEY_SIZE];
    unsigned char derivation[KEY_SIZE];
    unsigned int output_index;
    unsigned char sub_pub[KEY_SIZE];

    // fetch
    monero_io_fetch(pub, KEY_SIZE);
    int err = monero_io_fetch_decrypt(derivation, KEY_SIZE, TYPE_DERIVATION);
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }
    output_index = monero_io_fetch_u32();
    monero_io_discard(0);

    // pub
    err = monero_derive_subaddress_public_key(sub_pub, pub, derivation, output_index,
                                              sizeof(sub_pub), sizeof(pub), sizeof(derivation));
    if (err) {
        explicit_bzero(derivation, sizeof(derivation));
        return err;
    }
    // pub key
    monero_io_insert(sub_pub, KEY_SIZE);
    explicit_bzero(derivation, sizeof(derivation));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_subaddress(
    /*const cryptonote::subaddress_index& index, cryptonote::account_public_address &address*/) {
    unsigned char index[8];
    unsigned char C[KEY_SIZE];
    unsigned char D[KEY_SIZE];

    // fetch
    monero_io_fetch(index, 8);
    monero_io_discard(0);

    // pub
    int error = monero_get_subaddress(C, D, index, sizeof(C), sizeof(D), sizeof(index));
    if (error) {
        return error;
    }

    // pub key
    monero_io_insert(C, KEY_SIZE);
    monero_io_insert(D, KEY_SIZE);
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_subaddress_spend_public_key(
    /*const cryptonote::subaddress_index& index, crypto::public_key D*/) {
    unsigned char index[8];
    unsigned char D[KEY_SIZE];

    // fetch
    monero_io_fetch(index, 8);
    monero_io_discard(1);

    // pub
    int error = monero_get_subaddress_spend_public_key(D, index, sizeof(D), sizeof(index));
    if (error) {
        return error;
    }

    // pub key
    monero_io_insert(D, KEY_SIZE);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_get_subaddress_secret_key(/*const crypto::secret_key& sec, const cryptonote::subaddress_index& index, crypto::secret_key &sub_sec*/) {
    unsigned char sec[KEY_SIZE];
    unsigned char index[8];
    unsigned char sub_sec[KEY_SIZE];
    int err = 0;

    err = monero_io_fetch_decrypt_key(sec, sizeof(sec));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        return err;
    }
    monero_io_fetch(index, 8);
    monero_io_discard(0);

    err = monero_get_subaddress_secret_key(sub_sec, sec, index, sizeof(sub_sec), sizeof(sec),
                                           sizeof(index));
    if (err) {
        explicit_bzero(sec, sizeof(sec));
        explicit_bzero(sub_sec, sizeof(sec));
        return err;
    }

    memcpy(G_monero_vstate.last_get_subaddress_secret_key, sub_sec, KEY_SIZE);

    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        unsigned int major = (unsigned int)index[0] | ((unsigned int)index[1] << 8) |
                             ((unsigned int)index[2] << 16) | ((unsigned int)index[3] << 24);
        unsigned int minor = (unsigned int)index[4] | ((unsigned int)index[5] << 8) |
                             ((unsigned int)index[6] << 16) | ((unsigned int)index[7] << 24);
        unsigned char already_seen = 0;
        for (unsigned char i = 0; i < G_monero_vstate.tx_change_cnt; i++) {
            if (G_monero_vstate.tx_change_major_indices[i] == major &&
                G_monero_vstate.tx_change_minor_indices[i] == minor) {
                already_seen = 1;
                break;
            }
        }
        if (!already_seen && (major != 0 || minor != 0) && G_monero_vstate.tx_change_cnt < 8) {
            G_monero_vstate.tx_change_major_indices[G_monero_vstate.tx_change_cnt] = major;
            G_monero_vstate.tx_change_minor_indices[G_monero_vstate.tx_change_cnt] = minor;
            G_monero_vstate.tx_change_cnt++;
        }
    }

    monero_io_insert_encrypt(sub_sec, KEY_SIZE, TYPE_SCALAR);
    explicit_bzero(sec, sizeof(sec));
    explicit_bzero(sub_sec, sizeof(sec));
    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_check_change_address(const unsigned char *Aout, const unsigned char *Bout) {
    unsigned char C[KEY_SIZE];
    unsigned char D[KEY_SIZE];
    unsigned char index[8];
    int err;

    /* primary address (major=0, minor=0) */
    if ((memcmp(Aout, G_monero_vstate.A, KEY_SIZE) == 0) &&
        (memcmp(Bout, G_monero_vstate.B, KEY_SIZE) == 0)) {
        return 0;
    }

    for (unsigned char i = 0; i < G_monero_vstate.tx_change_cnt; i++) {
        unsigned int M = G_monero_vstate.tx_change_major_indices[i];
        unsigned int m = G_monero_vstate.tx_change_minor_indices[i];
        /* candidates: exact (M,m), then account root (M,0) if m!=0 && M!=0 */
        unsigned char candidates = (m != 0 && M != 0) ? 2 : 1;

        index[0] = (unsigned char)(M & 0xFF);
        index[1] = (unsigned char)((M >> 8) & 0xFF);
        index[2] = (unsigned char)((M >> 16) & 0xFF);
        index[3] = (unsigned char)((M >> 24) & 0xFF);

        for (unsigned char j = 0; j < candidates; j++) {
            unsigned int m_check = (j == 0) ? m : 0;
            index[4] = (unsigned char)(m_check & 0xFF);
            index[5] = (unsigned char)((m_check >> 8) & 0xFF);
            index[6] = (unsigned char)((m_check >> 16) & 0xFF);
            index[7] = (unsigned char)((m_check >> 24) & 0xFF);
            err = monero_get_subaddress(C, D, index, KEY_SIZE, KEY_SIZE, sizeof(index));
            if (err) {
                return err;
            }
            if ((memcmp(Aout, C, KEY_SIZE) == 0) && (memcmp(Bout, D, KEY_SIZE) == 0)) {
                return 0;
            }
        }
    }

    return SW_SECURITY_CHANGE_ADDRESS;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */

int monero_apu_generate_txout_keys(/*size_t tx_version, crypto::secret_key tx_sec, crypto::public_key Aout, crypto::public_key Bout, size_t output_index, bool is_change, bool is_subaddress, bool need_additional_key, bool use_view_tags*/) {
    // IN
    unsigned char tx_key[KEY_SIZE];
    unsigned char *txkey_pub;
    unsigned char *Aout;
    unsigned char *Bout;
    unsigned int output_index;
    unsigned char is_change;
    unsigned char is_subaddress;
    unsigned char need_additional_txkeys;
    unsigned char additional_txkey_sec[KEY_SIZE];
    unsigned char use_view_tags;
    // OUT
    unsigned char additional_txkey_pub[KEY_SIZE];
#define amount_key         tx_key
#define out_eph_public_key additional_txkey_sec
    unsigned char view_tag[1];
    // TMP
    unsigned char derivation[KEY_SIZE];
    int err = 0;

    monero_io_fetch_u32();  // skip tx_version
    err = monero_io_fetch_decrypt_key(tx_key, sizeof(tx_key));
    if (err) {
        explicit_bzero(tx_key, sizeof(tx_key));
        return err;
    }
    txkey_pub = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(KEY_SIZE);
    Aout = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(KEY_SIZE);
    Bout = G_monero_vstate.io_buffer + G_monero_vstate.io_offset;
    monero_io_skip(KEY_SIZE);
    output_index = monero_io_fetch_u32();
    is_change = monero_io_fetch_u8();
    is_subaddress = monero_io_fetch_u8();
    need_additional_txkeys = monero_io_fetch_u8();
    if (need_additional_txkeys) {
        err = monero_io_fetch_decrypt_key(additional_txkey_sec, sizeof(additional_txkey_sec));
        if (err) {
            explicit_bzero(tx_key, sizeof(tx_key));
            explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
            return err;
        }
    } else {
        monero_io_skip(KEY_SIZE);
    }
    use_view_tags = monero_io_fetch_u8();

    // reject spoofed change address before any state is mutated
    if (is_change && (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL)) {
        err = monero_check_change_address(Aout, Bout);
        if (err) {
            explicit_bzero(tx_key, sizeof(tx_key));
            explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
            return err;
        }
    }

    // update outkeys hash control
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        if (G_monero_vstate.io_protocol_version >= 2) {
            err = monero_sha256_outkeys_update(Aout, KEY_SIZE);
            if (err) {
                explicit_bzero(tx_key, sizeof(tx_key));
                explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
                return err;
            }
            err = monero_sha256_outkeys_update(Bout, KEY_SIZE);
            if (err) {
                explicit_bzero(tx_key, sizeof(tx_key));
                explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
                return err;
            }
            err = monero_sha256_outkeys_update(&is_change, 1);
            if (err) {
                explicit_bzero(tx_key, sizeof(tx_key));
                explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
                return err;
            }
        }
    }

    // make additional tx pubkey if necessary
    if (need_additional_txkeys) {
        if (is_subaddress) {
            err = monero_ecmul_k(additional_txkey_pub, Bout, additional_txkey_sec,
                                 sizeof(additional_txkey_pub), KEY_SIZE,
                                 sizeof(additional_txkey_sec));
            if (err) {
                explicit_bzero(tx_key, sizeof(tx_key));
                explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
                return err;
            }
        } else {
            err = monero_ecmul_G(additional_txkey_pub, additional_txkey_sec,
                                 sizeof(additional_txkey_pub), sizeof(additional_txkey_sec));
            if (err) {
                explicit_bzero(tx_key, sizeof(tx_key));
                explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
                return err;
            }
        }
    } else {
        explicit_bzero(additional_txkey_pub, KEY_SIZE);
    }

    // derivation
    if (is_change) {
        err =
            monero_generate_key_derivation(derivation, txkey_pub, G_monero_vstate.a,
                                           sizeof(derivation), KEY_SIZE, sizeof(G_monero_vstate.a));
        if (err) {
            explicit_bzero(tx_key, sizeof(tx_key));
            explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
            return err;
        }
    } else {
        err = monero_generate_key_derivation(
            derivation, Aout,
            (is_subaddress && need_additional_txkeys) ? additional_txkey_sec : tx_key,
            sizeof(derivation), KEY_SIZE, KEY_SIZE);
        if (err) {
            explicit_bzero(tx_key, sizeof(tx_key));
            explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
            return err;
        }
    }

    // compute amount key AKout (scalar1), version is always greater than 1
    err = monero_derivation_to_scalar(amount_key, derivation, output_index, sizeof(amount_key),
                                      sizeof(derivation));
    if (err) {
        explicit_bzero(tx_key, sizeof(tx_key));
        explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
        explicit_bzero(amount_key, sizeof(amount_key));
        return err;
    }
    if (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL) {
        if (G_monero_vstate.io_protocol_version >= 2) {
            err = monero_sha256_outkeys_update(amount_key, KEY_SIZE);
            if (err) {
                explicit_bzero(tx_key, sizeof(tx_key));
                explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
                explicit_bzero(amount_key, sizeof(amount_key));
                return err;
            }
        }
    }

    // compute ephemeral output key
    err = monero_derive_public_key(out_eph_public_key, derivation, output_index, Bout,
                                   sizeof(out_eph_public_key), sizeof(derivation), KEY_SIZE);
    if (err) {
        explicit_bzero(tx_key, sizeof(tx_key));
        explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
        explicit_bzero(amount_key, sizeof(amount_key));
        return err;
    }

    // compute view tag
    if (use_view_tags) {
        err = monero_derive_view_tag(view_tag, derivation, output_index);
        if (err) {
            explicit_bzero(tx_key, sizeof(tx_key));
            explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
            explicit_bzero(amount_key, sizeof(amount_key));
            return err;
        }
    }

    // send all
    monero_io_discard(0);
    monero_io_insert_encrypt(amount_key, KEY_SIZE, TYPE_AMOUNT_KEY);
    monero_io_insert(out_eph_public_key, KEY_SIZE);
    if (need_additional_txkeys) {
        monero_io_insert(additional_txkey_pub, KEY_SIZE);
    }
    if (use_view_tags) {
        monero_io_insert(view_tag, 1);
    }
    G_monero_vstate.tx_output_cnt++;
    explicit_bzero(tx_key, sizeof(tx_key));
    explicit_bzero(additional_txkey_sec, sizeof(additional_txkey_sec));
    explicit_bzero(amount_key, sizeof(amount_key));
    return SW_OK;
}
