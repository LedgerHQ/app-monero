# ledger-app-monero

Monero wallet application for Ledger Blue and Nano S

# Install from sources

In order to install from sources for testing purpose you need to uncomment the two following lines in Makefile

    DEFINES   += DEBUG_HWDEVICE
    DEFINES   += IODUMMYCRYPT

Note this is only for testing. For production usage, use the application provided by the Live Manager.
