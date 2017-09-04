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

#ifndef MONERO_API_H
#define  MONERO_API_H

int  monero_oid2curve(unsigned char* oid, unsigned int len);

void monero_init(void);
void monero_init_ux(void);
int  monero_install(unsigned char app_state) ;
int  monero_dispatch(void);


int monero_open_tx(void);
int monero_open_subtx(void) ;
int monero_stealth();
int monero_get_derivation_data(void) ;
int monero_get_input_key(void);
int monero_get_output_key(void);
int monero_blind(void);
int monero_init_mlsag(void) ;
int monero_update_mlsag(void) ;
int monero_finalize_mlsag(void);

/* ----------------------------------------------------------------------- */
/* ---                                  IO                            ---- */
/* ----------------------------------------------------------------------- */
void monero_io_discard(int clear) ;
void monero_io_clear(void);
void monero_io_set_offset(unsigned int offset) ;
void monero_io_mark(void) ;
void monero_io_rewind(void) ;
void monero_io_hole(unsigned int sz) ;
void monero_io_inserted(unsigned int len);
void monero_io_insert(unsigned char const * buffer, unsigned int len) ;
void monero_io_insert_u32(unsigned  int v32) ;
void monero_io_insert_u24(unsigned  int v24) ;
void monero_io_insert_u16(unsigned  int v16) ;
void monero_io_insert_u8(unsigned int v8) ;
void monero_io_insert_t(unsigned int T) ;
void monero_io_insert_tl(unsigned int T, unsigned int L) ;
void monero_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) ;

void monero_io_fetch_buffer(unsigned char  * buffer, unsigned int len) ;
unsigned int monero_io_fetch_u32(void) ;
unsigned int monero_io_fetch_u24(void) ;
unsigned int monero_io_fetch_u16(void) ;
unsigned int monero_io_fetch_u8(void) ;
int monero_io_fetch_t(unsigned int *T) ;
int monero_io_fetch_l(unsigned int *L) ;
int monero_io_fetch_tl(unsigned int *T, unsigned int *L) ;
int monero_io_fetch_nv(unsigned char* buffer, int len) ;
int monero_io_fetch(unsigned char* buffer, int len) ;

int monero_io_do(unsigned int io_flags) ;

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
