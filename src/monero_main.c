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

#ifndef MONERO_DEBUG_MAIN

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"
#include "io.h"

#include "ux.h"

/* ----------------------------------------------------------------------- */
/* ---                            Application Entry                    --- */
/* ----------------------------------------------------------------------- */
void __attribute__((noreturn)) app_exit(void);

void __attribute__((noreturn)) send_error_and_kill_app(int sw) {
    monero_io_insert_u16(sw);
    monero_io_do(IO_RETURN_AFTER_TX);
    memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
    app_exit();
}

void app_main(void) {
    unsigned int io_flags;
    unsigned int error;
    io_flags = 0;

    error = monero_init();
    if (error) {
        memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
        app_exit();
    }

    // set up initial screen
    ui_init();

    for (;;) {
        volatile unsigned short sw = 0;
        monero_io_do(io_flags);
        sw = monero_dispatch();
        if (sw == 0) {
            io_flags = IO_ASYNCH_REPLY;
        } else if (sw == SW_OK) {
            monero_io_insert_u16(sw);
            io_flags = 0;
        } else {
            send_error_and_kill_app(sw);
        }
    }
}

#endif
