# blue-app-monero tools


## Seed Recovery

### Goals

The 24 master seed words (BIP39/BIP32) of your device is enough to keep safe your Monero
in case you loose or break your device:  get a new device, set it with your 24 words, 
install Monero application: your funds are here!

Now imagine you need to access your funds in emergency and cannot wait for a new device. 
The solution is to restore your wallet as a standard wallet with the 25 seed electrum words.

For that, this tools is what you need: It convert the 24 seed words to 25 Electrum/Monero seed words.

This convertion can be made in tow manner: offline and online.

**Offline:**

You do not need your device, just your 24 words. This way is insecure as you will have to enter
your 24 master words on the computer and the 25 Electrum seed will be display on the same computer.

**Online:** 

You need your device. This way is secure as you will have not to enter your 24 master words on the computer
and your 25 Electrum seed will be display only on your device.

Once got, you can write down those 25 words alongside with your 24 master seed words.



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
 
On Windows

``` 
 pip3 install pyreadline
```

On Mac/Linux

``` 
 pip3 install readline


### Usage

#### Offline

In tools/python/ directory run the command:

     PYTHONPATH=`pwd`/src  python3 -m ledger.monero.seedconv.py offline

Example:

    $ PYTHONPATH="$(pwd)/src" python3 -m ledger.monero.seedconv offline

        =============================================================
        Monero Seed Converter v0.9. Copyright (c) Ledger SAS 20018.
        Licensed under the Apache License, Version 2.0
        =============================================================
                
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

        WARNING: Be sure to use a TRUSTED and SAFE computer.
        * Continue? (yes/no): yes

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


#### Online

In tools/python/ directory run the command:

     PYTHONPATH=`pwd`/src  python3 -m ledger.monero.seedconv.py online

Example:

        $ PYTHONPATH=`pwd`/src  python3 -m ledger.monero.seedconv.py online

        =============================================================
        Monero Seed Converter v0.9. Copyright (c) Ledger SAS 20018.
        Licensed under the Apache License, Version 2.0
        =============================================================
                
        * Select Language
           2 : English (English)
           3 : Esperanto (Esperanto)
           4 : Français (French)
           5 : Italiano (Italian)
           7 : Lobjan (Lobjan)
           8 : Português (Portuguese)
        Enter the number corresponding to the language of your choice (2): 
        Open device...
        Erase old key words...
        Load dictionnary................................................................................................
        Done.
        Your key words are avalaible on your device under 'Settings/Show 25 words' menu.
        You can delete it at the end of keyword list.

Now on the device, in Monero application, go to `settings ~  show 25 words`, your 25 words are displayed. 
You can write down this words on safe paper. Then you can delete them.

Not that by default the list is empty.
