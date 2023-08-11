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

void monero_main(void) {
    unsigned int io_flags, cont;
    io_flags = 0;
    cont = 1;
    while (cont) {
        volatile unsigned short sw = 0;
        BEGIN_TRY {
            TRY {
                monero_io_do(io_flags);
                sw = monero_dispatch();
            }
            CATCH(EXCEPTION_IO_RESET) {
                sw = 0;
                cont = 0;
                monero_io_discard(1);
            }
            CATCH_OTHER(e) {
                monero_reset_tx(1);
                if (((e & 0xF000) == 0x9000) || ((e & 0xFF00) == 0x6400)) {
                    sw = e;
                } else {
                    monero_io_discard(1);
                    if ((e & 0xFFFF0000) || ((e & 0xF000) != 0x6000)) {
                        monero_io_insert_u32(e);
                        sw = 0x6f42;
                    } else {
                        sw = e;
                    }
                }
            }
            FINALLY {
                if (sw) {
                    monero_io_insert_u16(sw);
                    io_flags = 0;
                } else {
                    io_flags = IO_ASYNCH_REPLY;
                }
            }
        }
        END_TRY;
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
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        // other events are propagated to the UX just in case
        default:
            UX_DEFAULT_EVENT();
            break;

        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
            UX_DISPLAYED_EVENT({});
            break;
        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
                // only allow display when not locked of overlayed by an OS UX.
                if (UX_ALLOWED) {
                    UX_REDISPLAY();
                }
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
            monero_init_private_key();
        } else {
            ;  // do nothing, allowing TX parsing in lock mode
            // monero_wipe_private_key();
        }
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;

            // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    reset();
                }
                return 0;  // nothing received from the master so far (it's a tx
                           // transaction)
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
            }

        default:
            THROW(INVALID_PARAMETER);
            return 0;
    }
    return 0;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

/* -------------------------------------------------------------- */

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");
    unsigned int cont = 1;

    // ensure exception will work as planned
    os_boot();
    while (cont) {
        UX_INIT();

        BEGIN_TRY {
            TRY {
                // start communication with MCU
                io_seproxyhal_init();

                USB_power(0);
                USB_power(1);

#ifdef HAVE_USB_CLASS_CCID
                io_usb_ccid_set_card_inserted(1);
#endif

#ifdef TARGET_NANOX
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
                BLE_power(0, NULL);
                BLE_power(1, "Nano X - Monero");
#endif

                monero_init();

                // set up initial screen
                ui_init();

                // start the application
                // the first exchange will:
                // - display the  initial screen
                // - send the ATR
                // - receive the first command
                monero_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                ;
            }
            CATCH_OTHER(e) {
                cont = 0;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
}

#endif
