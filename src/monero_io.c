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

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

#if defined(IODUMMYCRYPT)
  #warning IODUMMYCRYPT activated
#endif
#if defined(IONOCRYPT)
  #warning IONOCRYPT activated
#endif


/*
 * io_buff: contains current message part
 * io_off: offset in current message part
 * io_length: length of current message part
 */

/* ----------------------------------------------------------------------- */
/* MISC                                                                    */
/* ----------------------------------------------------------------------- */

void monero_io_set_offset(unsigned int offset) {
  if (offset == IO_OFFSET_END) {
    G_monero_vstate.io_offset = G_monero_vstate.io_length;
  }
  else if (offset == IO_OFFSET_MARK) {
    G_monero_vstate.io_offset = G_monero_vstate.io_mark;
  }
  else if (offset < G_monero_vstate.io_length) {
    G_monero_vstate.io_offset = offset;
  }
  else {
    THROW(ERROR_IO_OFFSET);
    return ;
  }
}


void monero_io_mark() {
  G_monero_vstate.io_mark = G_monero_vstate.io_offset;
}


void monero_io_inserted(unsigned int len) {
  G_monero_vstate.io_offset += len;
  G_monero_vstate.io_length += len;
}

void monero_io_discard(int clear) {
  G_monero_vstate.io_length = 0;
  G_monero_vstate.io_offset = 0;
  G_monero_vstate.io_mark = 0;
  if (clear) {
    monero_io_clear();
  }
}

void monero_io_clear() {
  os_memset(G_monero_vstate.io_buffer, 0 , MONERO_IO_BUFFER_LENGTH);
}

/* ----------------------------------------------------------------------- */
/* INSERT data to be sent                                                  */
/* ----------------------------------------------------------------------- */

void monero_io_hole(unsigned int sz) {
  if ((G_monero_vstate.io_length + sz) > MONERO_IO_BUFFER_LENGTH) {
    THROW(ERROR_IO_FULL);
    return ;
  }
  os_memmove(G_monero_vstate.io_buffer+G_monero_vstate.io_offset+sz,
             G_monero_vstate.io_buffer+G_monero_vstate.io_offset,
             G_monero_vstate.io_length-G_monero_vstate.io_offset);
  G_monero_vstate.io_length += sz;
}

void monero_io_insert(unsigned char const *buff, unsigned int len) {
  monero_io_hole(len);
  os_memmove(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, buff, len);
  G_monero_vstate.io_offset += len;
}

void monero_io_insert_encrypt(unsigned char* buffer, int len) {
  monero_io_hole(len);

  //for now, only 32bytes block are allowed
  if (len != 32) {
    THROW(SW_SECURE_MESSAGING_NOT_SUPPORTED);
    return ;
  }


#if defined(IODUMMYCRYPT)
  for (int i = 0; i<len; i++) {
       G_monero_vstate.io_buffer[G_monero_vstate.io_offset+i] = buffer[i] ^ 0x55;
    }
#elif defined(IONOCRYPT)
  os_memmove(G_monero_vstate.io_buffer+G_monero_vstate.io_offset, buffer, len);
#else 
  cx_aes(&G_monero_vstate.spk, CX_ENCRYPT|CX_CHAIN_CBC|CX_LAST|CX_PAD_NONE,
         buffer, len,
         G_monero_vstate.io_buffer+G_monero_vstate.io_offset, len);
#endif
  G_monero_vstate.io_offset += len;
}

void monero_io_insert_u32(unsigned  int v32) {
  monero_io_hole(4);
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] = v32>>24;
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+1] = v32>>16;
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+2] = v32>>8;
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+3] = v32>>0;
  G_monero_vstate.io_offset += 4;
}

void monero_io_insert_u24(unsigned  int v24) {
  monero_io_hole(3);
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] = v24>>16;
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+1] = v24>>8;
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+2] = v24>>0;
  G_monero_vstate.io_offset += 3;
}

void monero_io_insert_u16(unsigned  int v16) {
  monero_io_hole(2);
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] = v16>>8;
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+1] = v16>>0;
  G_monero_vstate.io_offset += 2;
}

void monero_io_insert_u8(unsigned int v8) {
  monero_io_hole(1);
  G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] = v8;
  G_monero_vstate.io_offset += 1;
}

void monero_io_insert_t(unsigned int T) {
  if (T &0xFF00) {
     monero_io_insert_u16(T);
  } else {
     monero_io_insert_u8(T);
  }
}

void monero_io_insert_tl(unsigned int T, unsigned int L) {
  monero_io_insert_t(T);
  if (L < 128) {
    monero_io_insert_u8(L);
  } else if (L < 256) {
    monero_io_insert_u16(0x8100|L);
  } else {
    monero_io_insert_u8(0x82);
    monero_io_insert_u16(L);
  }
}

void monero_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) {
  monero_io_insert_tl(T,L);
  monero_io_insert(V, L);
}

/* ----------------------------------------------------------------------- */
/* FECTH data from received buffer                                         */
/* ----------------------------------------------------------------------- */
void monero_io_assert_availabe(int sz) {
  if ((G_monero_vstate.io_length-G_monero_vstate.io_offset) < sz) {
    THROW(SW_WRONG_LENGTH + (sz&0xFF));
  }
}

int monero_io_fetch(unsigned char* buffer, int len) {
  monero_io_assert_availabe(len);
  if (buffer) {
    os_memmove(buffer, G_monero_vstate.io_buffer+G_monero_vstate.io_offset, len);
  }
  G_monero_vstate.io_offset += len;
  return len;
}

int monero_io_fetch_decrypt(unsigned char* buffer, int len) {
  monero_io_assert_availabe(len);

  //for now, only 32bytes block allowed
  if (len != 32) {
    THROW(SW_SECURE_MESSAGING_NOT_SUPPORTED);
    return 0;
  }

  if (buffer) {
#if defined(IODUMMYCRYPT)
    for (int i = 0; i<len; i++) {
      buffer[i] = G_monero_vstate.io_buffer[G_monero_vstate.io_offset+i] ^ 0x55;
    }
#elif defined(IONOCRYPT)
     os_memmove(buffer, G_monero_vstate.io_buffer+G_monero_vstate.io_offset, len);
#else //IOCRYPT
    cx_aes(&G_monero_vstate.spk, CX_DECRYPT|CX_CHAIN_CBC|CX_LAST|CX_PAD_NONE,
           G_monero_vstate.io_buffer+G_monero_vstate.io_offset, len,
           buffer, len);
#endif
  }
  G_monero_vstate.io_offset += len;
  return len;
}

int monero_io_fetch_decrypt_key(unsigned char* buffer) {
  int i;
  unsigned char* k;
  monero_io_assert_availabe(32);

  k = G_monero_vstate.io_buffer+G_monero_vstate.io_offset;
  //view?
  for (i =0; i <32; i++) {
    if (k[i] != 0x00) break;
  }
  if(i==32) {
    os_memmove(buffer, G_monero_vstate.a,32);
    G_monero_vstate.io_offset += 32;
    return 32;
  }
  //spend?
  for (i =0; i <32; i++) {
    if (k [i] != 0xff) break;
  }
  if(i==32) {
    os_memmove(buffer, G_monero_vstate.b,32);
    G_monero_vstate.io_offset += 32;
    return 32;
  }
  return monero_io_fetch_decrypt(buffer, 32);
}

unsigned int monero_io_fetch_u32() {
  unsigned int  v32;
  monero_io_assert_availabe(4);
  v32 =  ( (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] << 24) |
           (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+1] << 16) |
           (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+2] << 8) |
           (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+3] << 0) );
  G_monero_vstate.io_offset += 4;
  return v32;
}

unsigned int monero_io_fetch_u24() {
  unsigned int  v24;
  monero_io_assert_availabe(3);
  v24 =  ( (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] << 16) |
           (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+1] << 8) |
           (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+2] << 0) );
  G_monero_vstate.io_offset += 3;
  return v24;
}

unsigned int monero_io_fetch_u16() {
  unsigned int  v16;
  monero_io_assert_availabe(2);
  v16 =  ( (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+0] << 8) |
           (G_monero_vstate.io_buffer[G_monero_vstate.io_offset+1] << 0) );
  G_monero_vstate.io_offset += 2;
  return v16;
}

unsigned int monero_io_fetch_u8() {
  unsigned int  v8;
  monero_io_assert_availabe(1);
  v8 = G_monero_vstate.io_buffer[G_monero_vstate.io_offset] ;
  G_monero_vstate.io_offset += 1;
  return v8;
}

int monero_io_fetch_t(unsigned int *T) {
  *T = monero_io_fetch_u8();
  if ((*T & 0x1F) == 0x1F) {
    *T = (*T << 8) | monero_io_fetch_u8();
  }
  return 0;
}

int monero_io_fetch_l(unsigned int *L) {
  *L = monero_io_fetch_u8();

  if ((*L & 0x80) != 0) {
    *L &= 0x7F;
    if (*L == 1) {
      *L =  monero_io_fetch_u8();
    } else if (*L == 2) {
      *L =  monero_io_fetch_u16() ;
    } else {
      *L = -1;
    }
  }
  return 0;
}

int monero_io_fetch_tl(unsigned int *T, unsigned int *L) {
  monero_io_fetch_t(T);
  monero_io_fetch_l(L);
  return 0;
}

int monero_io_fetch_nv(unsigned char* buffer, int len) {
  monero_io_assert_availabe(len);
  monero_nvm_write(buffer, G_monero_vstate.io_buffer+G_monero_vstate.io_offset, len);
  G_monero_vstate.io_offset += len;
  return len;
}




/* ----------------------------------------------------------------------- */
/* REAL IO                                                                 */
/* ----------------------------------------------------------------------- */

#define MAX_OUT MONERO_APDU_LENGTH

int monero_io_do(unsigned int io_flags) {

  //if pending input chaining
  if (G_monero_vstate.io_cla & 0x01) {
    goto in_chaining;
  }


  if (io_flags & IO_ASYNCH_REPLY) {
    // if IO_ASYNCH_REPLY has been  set,
    //  monero_io_exchange will return when  IO_RETURN_AFTER_TX will set in ui
    monero_io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
  } else {
    // --- full out chaining ---
    G_monero_vstate.io_offset = 0;
    while(G_monero_vstate.io_length > MAX_OUT) {
      unsigned int tx,xx;
      //send chunk
      tx =  MAX_OUT-2;
      os_memmove(G_io_apdu_buffer, G_monero_vstate.io_buffer+G_monero_vstate.io_offset, tx);
      G_monero_vstate.io_length -= tx;
      G_monero_vstate.io_offset += tx;
      G_io_apdu_buffer[tx] = 0x61;
      if (G_monero_vstate.io_length > MAX_OUT-2) {
        xx = MAX_OUT-2;
      } else {
        xx = G_monero_vstate.io_length-2;
      }
      G_io_apdu_buffer[tx+1] = xx;
      monero_io_exchange(CHANNEL_APDU, tx+2);
      //check get response
      if ((G_io_apdu_buffer[0] != 0x00) ||
        (G_io_apdu_buffer[1] != 0xc0) ||
        (G_io_apdu_buffer[2] != 0x00) ||
        (G_io_apdu_buffer[3] != 0x00) ) {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return 0;
      }
    }
    os_memmove(G_io_apdu_buffer,  G_monero_vstate.io_buffer+G_monero_vstate.io_offset, G_monero_vstate.io_length);

    if (io_flags & IO_RETURN_AFTER_TX) {
      monero_io_exchange(CHANNEL_APDU |IO_RETURN_AFTER_TX, G_monero_vstate.io_length);
      return 0;
    } else {
       monero_io_exchange(CHANNEL_APDU,  G_monero_vstate.io_length);
    }
  }

  //--- full in chaining ---
  G_monero_vstate.io_offset = 0;
  G_monero_vstate.io_length = 0;
  G_monero_vstate.io_cla = G_io_apdu_buffer[0];
  G_monero_vstate.io_ins = G_io_apdu_buffer[1];
  G_monero_vstate.io_p1  = G_io_apdu_buffer[2];
  G_monero_vstate.io_p2  = G_io_apdu_buffer[3];
  G_monero_vstate.io_lc  = 0;
  G_monero_vstate.io_le  = 0;

  switch (G_monero_vstate.io_ins) {

  case INS_GET_RESPONSE:
    G_monero_vstate.io_le  = G_io_apdu_buffer[4];
    break;

  default:
    G_monero_vstate.io_lc  = G_io_apdu_buffer[4];
    os_memmove(G_monero_vstate.io_buffer, G_io_apdu_buffer+5, G_monero_vstate.io_lc);
    G_monero_vstate.io_length =  G_monero_vstate.io_lc;
    break;
  }

  while(G_monero_vstate.io_cla  & 0x10) {

    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
    monero_io_exchange(CHANNEL_APDU, 2);
  in_chaining:
    if (((G_io_apdu_buffer[0] & 0xEF) !=   (G_monero_vstate.io_cla& 0xEF)) ||
        (G_io_apdu_buffer[1] != G_monero_vstate.io_ins) ||
        (G_io_apdu_buffer[2] != G_monero_vstate.io_p1) ||
        (G_io_apdu_buffer[3] != G_monero_vstate.io_p2) ) {
      THROW(SW_COMMAND_NOT_ALLOWED);
      return SW_COMMAND_NOT_ALLOWED;
    }
    G_monero_vstate.io_cla = G_io_apdu_buffer[0];
    G_monero_vstate.io_lc  = G_io_apdu_buffer[4];
    if ((G_monero_vstate.io_length + G_monero_vstate.io_lc) > MONERO_IO_BUFFER_LENGTH) {
      return 1;
    }
    os_memmove(G_monero_vstate.io_buffer+G_monero_vstate.io_length, G_io_apdu_buffer+5,  G_monero_vstate.io_lc);
    G_monero_vstate.io_length +=  G_monero_vstate.io_lc;
  }


  return 0;
}
