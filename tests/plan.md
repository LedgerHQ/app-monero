
Incomplete Draft of test to perform.



Setup
=====


Note:
-----

Setup has to be done only once, or to restart from fresh config.

Take care to note all your monero seeds when generating standard wallet.

`>:` denotes the shell prompt

`[...]: ` denotes the Monero client prompt


Daemon setup
------------

You can use a local daemons, but it needs you keep them up-to-date and it takes
around 3 days for getting the initial synchronization.

Or you can use the ones running on altcoin02.node.production.gra.ledger.fr.


**Ledger Daemon setup**


A restricted monero daemon runs on ledger server, you can use it with

**Login:**

    >: XMR_LOGIN="--daemon-login <user>:<password>"

Request the LOGIN info to cedric@ledger.fr

**Stagenet:**

    >: XMR_DAEMON="--stagenet --daemon-address 149.202.94.158:38081"

**Mainnet:**

    >: XMR_DAEMON="149.202.94.158:18081"


Client setup
------------

Download client CLI from getmonero.org

Unzip the content in a directory of your choice.

Open a Terminal and jump in this directory.

You should have a directory named monero-v0.x.y.z, eg: `monero-v0.14.0.2`

you can set a variable to that version:

    >: MONERO=./monero-v0.14.0.2/monero-wallet-cli


Create two wallets
------------------


Launch the ledger Monero appocation the device. In `settings->Change Network`, select `stagenet` or `mainnet`
depending the network you are on.

Create a ledger wallet,  in a shell type:

    >:  mkdir -p wallets/device

    >: ${MONERO} \
        ${DAEMON} \
        ${LOGIN} \
        --log-level 4 \
        --restore-height  1 \
        --log-file wallets/device/hwwallet.log  \
        --generate-from-device wallets/device/hwwallet \
        --subaddress-lookahead 2:5


Create a std-wallet, in a shell type:

    >: mkdir -p wallets/std

    >: ${MONERO} \
        ${DAEMON} \
        ${LOGIN} \
        --log-level 4 \
        --restore-height  1 \
        --log-file wallets/std/stdwallet.log  \
        --generate-new-wallet  wallets/std/stdwallet


When asked, accept to Export the view key.

Restoring wallet
----------------

Restoring a device wallet is the same as creating it.

For restoring a std wallet add  `--restore-deterministic-wallet`  option to the creation command.


Create sub address
------------------

At monero prompt type:

    [...]: address new
    [...]: address new

(yes twice)

Then:

    [...]: address all

You should get something like that:

    [...]: address all
    0  524GmkF7ZcwZGjvsQ2MZUh5i1YcdufiE5ToeSs6wixVS296wJDMQwQxhgDRDfwxb3c1Bv34AWTsjjazNEnQT9S58RKCH9vh  Primary address (used)
    1  76Ta9BiGA9fUPRJQWorbWHCuybq79m43pPubR77GjGRADTBQfo3iF5tMxCpaC91x9qYQ9CWVtMDWn4s1KDv77tE84DJsU88  (Untitled address)
    2  75pu1mzieBj8WNaAVYa8mhUgYjTh5BBerNgHsdMjc3wd5oLZRXf9dGmS4kQx2RuXrKBRwJEUvrbCSTzhPrFUrrDDA38YMe2  (Untitled address)

Entry zero is the main address. The two next are sub-addresses.


Finalize Config and Save All
----------------------------

    [...]: set ask-password 0
    [...]: save
    [...]: exit


Open existing wallet
====================

    >: ${MONERO} \
         ${XMR_DAEMON} \
         ${XMR_LOGIN} \
         --log-level 4 \
         --log-file wallets/std/stdwallet.log  \
         --wallet-file  wallets/std/stdwallet

or

    >: ${MONERO} \
         ${XMR_DAEMON} \
         ${XMR_LOGIN} \
         --log-level 4 \
         --log-file wallets/device/hwwallet.log  \
         --wallet-file  wallets/device/hwwallet


Test Plan
=========


To get initial funds on stagenet, contact cedric@ledger.fr

To get initial funds on mainnet, ....


Test 1: transfer
----------------

**Perform**

1. From device wallet to std wallet.

- Make a transfer to only main address
- Make a transfer to only one sub-address
- Make a transfer to two sub-addresses
- Make a transfer to main main address and only one sub-address
- Make a transfer to main main address and two sub-addresses

2. Do the same from std wallet to device wallet


**Check**

For each transfer
 - check the amount is correctly received by the receiver
 - check the change is correctly received by the sender


**Notes**

Transfers are performed with command:

    [...]: transfer <dest_address> amount [ dest_address amount, ...]

Once transfer done you get it status and the change value with:

    [...]: show_transfer <txid>
    or
    [...]: show_transfers


Test 2: sweep to mainaddress
============================

**Perform**

Sweep all from device to std main address

**Check**

- check the amount is correctly received by the receiver


Test 3: sweep to subaddress
===========================

**Perform**

Sweep all from device to std sub-address

**Check**

- check the amount is correctly received by the receiver

