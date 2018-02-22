/*
 * Initial source from Monero Project
 * Adpated by  Cedric Mesnil <cslashm@gmail.com> <cedric@ledger.fr>, Ledger SAS 
 */
#include "os.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"



// Copyright (c) 2014-2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


const char         alphabet[]              = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
#define            alphabet_size           (sizeof(alphabet) - 1)
const unsigned int encoded_block_sizes[]   = {0, 2, 3, 5, 6, 7, 9, 10, 11};
#define  full_block_size                   8 //(sizeof(encoded_block_sizes) / sizeof(encoded_block_sizes[0]) - 1)
#define  full_encoded_block_size           11 //encoded_block_sizes[full_block_size];
#define  addr_checksum_size                4


static uint64_t uint_8be_to_64(const unsigned char* data, size_t size) {
    uint64_t res = 0;
    switch (9 - size) {
    case 1:            res |= *data++;
    case 2: res <<= 8; res |= *data++;
    case 3: res <<= 8; res |= *data++;
    case 4: res <<= 8; res |= *data++;
    case 5: res <<= 8; res |= *data++;
    case 6: res <<= 8; res |= *data++;
    case 7: res <<= 8; res |= *data++;
    case 8: res <<= 8; res |= *data; 
    break;
    }

    return res;
}

static void encode_block(const unsigned char* block, unsigned int  size,  char* res) {
    uint64_t num = uint_8be_to_64(block, size);
    int i = encoded_block_sizes[size] - 1;
    while (0 < num) {
        uint64_t remainder = num % alphabet_size;
        num /= alphabet_size;
        res[i] = alphabet[remainder];
        --i;
    }
}

int monero_base58_public_key(char* str_b58, unsigned char *view, unsigned char *spend) {
    #define DATA_SIZE 69
    unsigned char data[69];

    data[0] = N_monero_pstate->network_id;
    os_memmove(data+1,spend,32);
    os_memmove(data+1+32,view,32);
    monero_keccak_F(data, 65, G_monero_vstate.H);
    os_memmove(data+1+32+32, G_monero_vstate.H, 4);

    unsigned int full_block_count = DATA_SIZE / full_block_size;
    unsigned int last_block_size = DATA_SIZE % full_block_size;
    for (size_t i = 0; i < full_block_count; ++i) {
        encode_block(data + i * full_block_size, full_block_size, &str_b58[i * full_encoded_block_size]);
    }

    if (0 < last_block_size) {
        encode_block(data + full_block_count * full_block_size, last_block_size, &str_b58[full_block_count * full_encoded_block_size]);
    }

    return 0;
}

