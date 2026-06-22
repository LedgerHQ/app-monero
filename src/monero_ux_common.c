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

/* UI string helpers shared by the BAGL (monero_ux_nano.c) and NBGL
 * (monero_ux_nbgl.c) builds, which are mutually exclusive. */

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"

// Format the change-review title: "Change" for the primary account, or
// "Change account <N>" so a non-primary change account is shown to the user.
void monero_format_change_title(char *str, size_t str_len, unsigned int major) {
    if (major == 0) {
        snprintf(str, str_len, "Change");
    } else {
        snprintf(str, str_len, "Change account %u", major);
    }
}
