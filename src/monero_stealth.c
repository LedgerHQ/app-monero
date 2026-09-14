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

#include "cx.h"
#include "monero_api.h"
#include "monero_types.h"
#include "monero_vars.h"
#include "os.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_stealth() {
    int i;
    unsigned char pub[KEY_SIZE];
    unsigned char sec[KEY_SIZE];
    unsigned char drv[33];
    unsigned char payID[8];
    int err = 0;
    // Keep the payment ID only for a real transaction. Nothing checks or shows
    // a fake one.
    int retain = G_monero_vstate.tx_in_progress &&
                 (G_monero_vstate.tx_sig_mode == TRANSACTION_CREATE_REAL);

    // fetch pub
    monero_io_fetch(pub, KEY_SIZE);
    // fetch sec
    err = monero_io_fetch_decrypt_key(sec, sizeof(sec));
    if (err) {
        goto end;
    }
    // The host picks both derivation operands, so tie them down here: only
    // this transaction's secret, and keep the point for the output review to
    // check against the destination it shows. It has to be here rather than
    // with the payment ID below, because the keccak reuses sec as its output
    // buffer and the scalar is gone by then.
    if (retain) {
        if (G_monero_vstate.tx_payment_id_set ||
            memcmp(sec, G_monero_vstate.r, KEY_SIZE) != 0) {
            err = SW_SECURITY_PAYMENT_ID;
            goto end;
        }
        memcpy(G_monero_vstate.tx_payment_id_pub, pub, KEY_SIZE);
    }
    // fetch paymentID
    monero_io_fetch(payID, 8);

    monero_io_discard(0);

    // Compute Dout
    err = monero_generate_key_derivation(drv, pub, sec, sizeof(drv),
                                         sizeof(pub), sizeof(sec));
    if (err) {
        goto end;
    }

    // compute mask
    drv[KEY_SIZE] = ENCRYPTED_PAYMENT_ID_TAIL;
    err = monero_keccak_F(drv, 33, sec);
    if (err) {
        goto end;
    }

    // One payment ID per transaction. Allow a second call and the host picks
    // which value is checked and shown.
    if (retain) {
        // Copy the plaintext now. The loop below overwrites payID.
        memcpy(G_monero_vstate.tx_payment_id, payID, 8);
    }

    // stealth!
    for (i = 0; i < 8; i++) {
        payID[i] = payID[i] ^ sec[i];
    }

    // Now the nonce, in the shape the prefix must carry.
    if (retain) {
        G_monero_vstate.tx_payment_id_nonce[0] =
            TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID;
        memcpy(G_monero_vstate.tx_payment_id_nonce + 1, payID, 8);
        G_monero_vstate.tx_payment_id_set = 1;
    }

    monero_io_insert(payID, 8);

    err = SW_OK;

end:
    explicit_bzero(sec, sizeof(sec));
    explicit_bzero(drv, sizeof(drv));
    return err;
}