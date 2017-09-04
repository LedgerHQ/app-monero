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

#ifndef MONERO_VARS_H
#define MONERO_VARS_H

#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "monero_types.h"
#include "monero_api.h"


extern monero_v_state_t  G_monero_vstate;
extern monero_nv_state_t N_state_pic;
#define N_monero_pstate  ((WIDE  monero_nv_state_t *)PIC(&N_state_pic))


#ifdef MONERO_DEBUG_MAIN
extern int apdu_n;
#endif

extern ux_state_t ux;
#endif
