# blue-app-monero tools


## Seed Recovery

### Goals

Convert the 24 Ledger words to 25 Electrum/Monero words.

### Requirements

libusb-dev
libudev-dev

     sudo apt install libusb-dev libudev-dev

The following python package are required:

- Ecpy
- pycrytodome
- ledgerblue

    pip3 install pycryptodomex
    pip3 install ECPy
    pip3 install ledgerblue

### Usage

In tools/python/ directory:

     PYTHONPATH=`pwd`/src python3 -m ledger.monero.seedconv

Example:

    $ PYTHONPATH=`pwd`/src python3 -m ledger.monero.seedconv offline

    =============================================================
    Monero Seed Converter v0.8. Copyright (c) Ledger SAS 20018.
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
      | Monero Electrum words :  moisture gleeful erected railway venomous fuel items match             |
      |                          guide rapid eternal entrance gulp ornament inactive aloof              |
      |                          cuisine drying shyness mailed onto uphill judge lemon shyness          |
      |                                                                                                 |
      | Spend key             :  3071e0ebf774956134a98bd58e1247fe22eec0c9910fd70ba42d8b1880197008       |
      | View key              :  27f45d107192bcc5b04a380a1032f57044b89694d8d25d6ba74216dea2aae003       |
      ---------------------------------------------------------------------------------------------------

