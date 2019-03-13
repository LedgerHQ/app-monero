# blue-app-monero tools


## Seed Recovery

### Goals

Convert the 24 Ledger words to 25 Electrum/Monero words.

### Requirements

libusb-1.0-0-dev
libudev-dev

     sudo apt install libusb-1.0-0-dev libudev-dev

The following python package are required:

- Ecpy
- pycrytodome
- ledgerblue
```
 pip3 install pycryptodomex
 pip3 install ECPy
 pip3 install ledgerblue
```
### Usage

In tools/python/ directory:

     PYTHONPATH="$(pwd)/src" python3 -m ledger.monero.seedconv

Example:

    $ PYTHONPATH="$(pwd)/src" python3 -m ledger.monero.seedconv offline

    =============================================================
    Monero Seed Converter v0.8. Copyright (c) Ledger SAS 2018.
    Licensed under the Apache License, Version 2.0
    =============================================================
    WARNING: Be sure to use a TRUSTED and SAFE computer.


    * Select Language
       0 : 简体中文 (中国) (Chinese (simplified))
       1 : Nederlands (Dutch)
       2 : English (English)
       3 : Esperanto (Esperanto)
       4 : Français (French)
       5 : Italiano (Italian)
       6 : 日本語 (Japanese)
       7 : Lobjan (Lobjan)
       8 : Português (Portuguese)
       9 : русский язык (Russian)
      10 : Español (Spanish)
    Enter the number corresponding to the language of your choice (2): 2

    * Enter your NanoS 12/18/24 words: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

    * Enter your NanoS passphrase (may be empty): 

    * Result:
      ---------------------------------------------------------------------------------------------------
      | Monero Electrum words :  tavern judge beyond bifocals deepest mural onward dummy                |
      |                          eagle diode gained vacation rally cause firm idled                     |
      |                          jerseys moat vigilant upload bobsled jobs cunning doing jobs           |
      |                                                                                                 |
      | seed                  :  db9e57474be8b64118b6acf6ecebd13f8f7c326b3bc1b19f4546573d6bac9dcf       |
      | Spend key             :  3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109       |
      | View key              :  0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201       |
      ---------------------------------------------------------------------------------------------------

