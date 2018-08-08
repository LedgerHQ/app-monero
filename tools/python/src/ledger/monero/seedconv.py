 # Copyright 2018 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.


import sys
import unicodedata
import readline
import binascii

import hashlib
import hmac

from ecpy import curves
from Cryptodome.Hash import keccak

from .dictionaries.languages import monero_langs

MAJOR = 0
MINOR = 8


def printerr(*args):
    # print(args)
    return

def NKFDbytes(str):
    return  unicodedata.normalize('NFKD', str).encode()


def retrieve_language():
    print("* Select Language")
    i = 0
    dflt = 0
    for l in monero_langs:
        print("  %2d : %s (%s)"%(i, l['language_name'], l['english_language_name']))
        if  l['english_language_name'] == 'English':
            dflt = i
        i += 1
    n = input("Enter the number corresponding to the language of your choice (%d): "%dflt)
    if len(n) == 0:
        n = dflt
    return monero_langs[int(n)]

def retrieve_credentials():
    print()
    w = input("* Enter your NanoS 12/18/24 words: ")
    w = w.split()
    if len(w) not in (12,24,18):
        error("Your mnemonic does not contain 12, 18 or 24 words, but %d"%len(w))
    w = ' '.join(w)

    print()
    p = input("* Enter your NanoS passphrase (may be empty): ")

    return w,p


def mnemonic_to_seed(mnemonic, passphrase=""):    
    seed = hashlib.pbkdf2_hmac('sha512', NKFDbytes(mnemonic), NKFDbytes(u"mnemonic"+passphrase), 2048)
    return seed


def seed_to_master_key(seed):
    """ return (mkey, mchain) """
    I = hmac.new(NKFDbytes(u"Bitcoin seed"), seed, 'sha512' ).digest()
    return I[0:32], I[32:]

def master_key_to_child_key(key,path):
    G = curves.Curve.get_curve("secp256k1").generator
    O = curves.Curve.get_curve("secp256k1").order
    path = path.split('/')
    kpar = key[0]
    cpar = key[1]
    assert path[0] == 'm'
    for child in path[1:]:
        hardened = child[len(child)-1]=="'"

        printerr("\nprocess %s"%child)
        printerr("kpar %s"%binascii.hexlify(kpar))
        printerr("cpar %s"%binascii.hexlify(cpar))
        printerr("hardened %d"%hardened)


        if hardened:
            child  = int(child[:len(child)-1])
            child += 0x80000000 
            data = b'\x00'+kpar+child.to_bytes(4,'big')
        else:
            child  = int(child)
            k = int.from_bytes(kpar,'big')
            kG = k*G
            Wpar = kG.x.to_bytes(32,'big')
            if kG.y == 0:
                Wpar = b"\x02" + Wpar
            else:
                Wpar = b"\x03" + Wpar
            data = Wpar+int(child).to_bytes(4,'big')

        printerr("hmac key: %s"%binascii.hexlify(cpar))
        printerr("hmac input: %s"%binascii.hexlify(data))
        I = hmac.new(cpar, data, 'sha512').digest()
        printerr("hmac output: %s"%binascii.hexlify(I))

        Il, Ir = I[:32], I[32:]
        Il = int.from_bytes(Il,'big')
        kpar = int.from_bytes(kpar,'big')
        Il = (Il +kpar) % O
        Il = Il.to_bytes(32,'big')
        kpar,cpar = Il,Ir
        printerr("ki %s"%binascii.hexlify(kpar))
        printerr("ci %s"%binascii.hexlify(cpar))

    return kpar,cpar


def monero_seed_to_monero_keys(seed):
  l = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
  printerr('monero_seed_to_monero_keys: seed %s'%seed)
  kh = keccak.new(digest_bits=256)
  kh.update(seed)
  b = kh.digest()  
  printerr('monero_seed_to_monero_keys: b %s'%b)
  ble = int.from_bytes(b,'little')%l
  b = ble.to_bytes(32, 'little')

  kh = keccak.new(digest_bits=256)
  kh.update(b)
  a = kh.digest()
  ale = int.from_bytes(a,'little')%l
  a = ale.to_bytes(32, 'little')
  printerr('monero_seed_to_monero_keys: a %s'%a)

  return a,b


def spendkey_to_words(seed, language):
    if (len(seed) %4) != 0 or len(seed) == 0:
        return None

    # 4 bytes -> 3 words.  8 digits base 16 -> 3 digits base 1626
    unique_prefix_length = language['prefix_length']
    word_list = language['words']
    word_list_length = len(word_list)
    words_store = []
    for i in range(0, len(seed)//4):
        val = (seed[i*4+0]<<0) | (seed[i*4+1]<<8) | (seed[i*4+2]<<16) | (seed[i*4+3]<<24)

        w1 = val % word_list_length;
        w2 = ((val // word_list_length) + w1) % word_list_length;
        w3 = (((val // word_list_length) // word_list_length) + w2) % word_list_length;

        words_store.append(word_list[w1]);
        words_store.append(word_list[w2]);
        words_store.append(word_list[w3]);
    
    trimmed_words = u''
    for w in words_store:
        trimmed_words += w[0:unique_prefix_length]
    checksum = binascii.crc32(trimmed_words.encode('utf8'))
    checksum = checksum % 24
    words_store.append(words_store[checksum])

    return words_store



def convert_mnemonic(language, ledger_mnemonic, passphrase):
    s = mnemonic_to_seed(ledger_mnemonic, passphrase)
    mkey = seed_to_master_key(s)
    monero_ki, monero_ci = master_key_to_child_key(mkey, u"m/44'/128'/0'/0/0")
    monero_seed = monero_ki
    monero_view_key, monero_spend_key = monero_seed_to_monero_keys(monero_seed)
    monero_words = spendkey_to_words(monero_spend_key, language)

    printerr("seed: %s"%binascii.hexlify(s))
    printerr("Km : %s"%binascii.hexlify(mkey[0]))
    printerr("Cm:  %s"%binascii.hexlify(mkey[0]))
    printerr("monero_seed: %s"%binascii.hexlify(monero_seed))
    printerr("monero view  keys: %s"%binascii.hexlify(monero_view_key))
    printerr("monero spend keys: %s"%binascii.hexlify(monero_spend_key))
    printerr("monero words: %d %s"%(len(monero_words), ' '.join(monero_words)))

    return monero_words, monero_view_key, monero_spend_key



def error(msg):
    print ("Ooops: %s"%msg)
    print ("Aborting, sorry.")
    sys.exit(1)

def usage():
    print("""
Usage:
    python -m ledger.monero.seedconv

    """)


def banner():
    print("""
=============================================================
Monero Seed Converter v%s.%s. Copyright (c) Ledger SAS 20018.
Licensed under the Apache License, Version 2.0
=============================================================
WARNING: Be sure to use a TRUSTED and SAFE computer.
 
        """%(MAJOR,MINOR))

def test():
    # Ledger: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
    # Monero: tiger building listen sack payment debut cunning howls sieve fight ledge rally assorted toyed slower jetting dizzy industrial fully baffles awakened island bowling cube slower
    # seed  DB9E57474BE8B64118B6ACF6ECEBD13F8F7C326B3BC1B19F4546573D6BAC9DCF
    # spend 3B094CA7218F175E91FA2402B4AE239A2FE8262792A3E718533A1A357A1E4109
    # view  0F3FE25D0C6D4C94DDE0C0BCC214B233E9C72927F813728B0F01F28F9D5E1201
    monero_view_key, monero_spend_key = monero_seed_to_monero_keys(binascii.unhexlify(u'DB9E57474BE8B64118B6ACF6ECEBD13F8F7C326B3BC1B19F4546573D6BAC9DCF'))
    print("monero view  keys: %s"%binascii.hexlify(monero_view_key))
    print("monero spend keys: %s"%binascii.hexlify(monero_spend_key))
    sys.exit(1);


banner()

lang  = retrieve_language()
mnemonic, passphrase = retrieve_credentials()
electrum_words,  monero_view_key, monero_spend_key = convert_mnemonic(lang, mnemonic, passphrase)
print(u"""
* Result:
  ---------------------------------------------------------------------------------------------------
  | Monero Electrum words :  {0:<70} |
  |                          {1:<70} |
  |                          {2:<70} |
  |                                                                                                 |
  | Spend key             :  {3:<70} |
  | View key              :  {4:<70} |
  ---------------------------------------------------------------------------------------------------
""" .format (' '.join(electrum_words[0:8]),' '.join(electrum_words[8:16]),' '.join(electrum_words[16:]),
        binascii.hexlify(monero_spend_key).decode(),
        binascii.hexlify(monero_view_key).decode()))
