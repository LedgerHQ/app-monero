# Monero Ledger App

Monero wallet application for Ledger Nano S and Nano X.

## Install

### Prerequisite

Be sure to have your environment correctly set up (see [Getting Started](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html)) and [ledgerblue](https://pypi.org/project/ledgerblue/) installed.


### Compilation

In order to use the app with the Monero client, you need to compile in debug mode:

```
make DEBUG=1
make load  # load the app on the Nano using ledgerblue
```

Note that it's for testing only.
For production usage, use the application provided by the [Ledger Live](https://www.ledger.com/ledger-live/download/) manager.

## Useful links

* Monero client CLI or GUI - [https://web.getmonero.org/downloads/](https://web.getmonero.org/downloads/)

* Ledger's developer documentation - [https://ledger.readthedocs.io](https://ledger.readthedocs.io)
