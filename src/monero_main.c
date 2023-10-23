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

#ifdef HAVE_UX_FLOW
#include "ux.h"
#endif

/* ----------------------------------------------------------------------- */
/* ---                            Application Entry                    --- */
/* ----------------------------------------------------------------------- */
extern uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
void __attribute__((noreturn)) app_exit(void);

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
        if (sw) {
            monero_io_insert_u16(sw);
            io_flags = 0;
        } else {
            io_flags = IO_ASYNCH_REPLY;
        }

        if (sw != 0 && sw != SW_OK) {
            monero_io_do(io_flags);
            memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
            app_exit();
        }
    }
}

unsigned char io_event(unsigned char channel __attribute__((unused))) {
    unsigned int s_before;
    unsigned int s_after;

    s_before = os_global_pin_is_validated();

    // nothing done with the event, throw an error on the transport layer if
    // needed
    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_FINGER_EVENT:
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;
        // power off if long push, else pass to the application callback if any
        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:  // for Nano S
#ifdef HAVE_BAGL
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif
            break;

        // other events are propagated to the UX just in case
        default:
            UX_DEFAULT_EVENT();
            break;

        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
            UX_DISPLAYED_EVENT({});
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL
            UX_DEFAULT_EVENT();
#endif  // HAVE_NBGL
            break;
        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
#ifdef HAVE_BAGL
                // only allow display when not locked of overlayed by an OS UX.
                if (UX_ALLOWED) {
                    UX_REDISPLAY();
                }
#endif
            });
            break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    s_after = os_global_pin_is_validated();

    if (s_before != s_after) {
        if (s_after == PIN_VERIFIED) {
            if (!monero_init_private_key()) {
                memset(&G_monero_vstate, 0, sizeof(G_monero_vstate));
                app_exit();
            }
        } else {
            ;  // do nothing, allowing TX parsing in lock mode
            // monero_wipe_private_key();
        }
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

#endif
