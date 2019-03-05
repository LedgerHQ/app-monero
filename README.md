# ledger-app-monero


Monero wallet application for Ledger Blue and Nano S

# Install from sources

In order to install from sources for testing purpose you need to uncomment the two following lines in Makefile

    DEFINES   += DEBUG_HWDEVICE
    DEFINES   += IODUMMYCRYPT

Note this is only for testing. For production usage, use the application provided by the Live Manager.

# Revision

## v1.2.0

Targeted Client: Monero 0.14.0.0+

- V11 fork integration
- Fix change address issue.

## v1.1.3

- Remove rolling address display
- Allow STEALTH instruction outside TX
- Doc fix

## v1.1.2

Fix stack overflow for 1.5.5 SDK

## v1.1.1

Allow transaction parsing when screen is locked

## v1.1.0

Initial Release

Targeted Client: Monero 0.13.0.0+

- Security fix: Screen lock management
- Optimisation: New protocol V2 for future
- Fix bug in large amount display that was truncated
- Remove confirmation for zero amount (fake sweep change)
- Better handling for change address to not display them
- Dual id (PIN based) management
- Add onscreen seed words display


## v1.0.0

Initial Release

Targeted Client: Monero 0.13.0.0+


## v 0.12.4 / Beta 5

Targeted Client: Monero 0.12.1

- U2F support
- Fix Windows detection problem
- activate Mainnet 'Beta stage: USE AT YOUR OWN RISK'

## v 0.12.3 / Beta 4

Targeted Client: Monero 0.12.1

- SDK 1.4.2.1 port

## v 0.12.2 / Beta 3

Targeted Client: Monero 0.12.1

- Activate security command chain control


## v 0.12.1 / Beta 2

Targeted Client: Monero 0.12.1

- Add second PIN support
- Remove key storage  in NVRAM, always recompute secret key at boot
- Export secret viewkey, with agreement of user, to speed up tx scan
- Clean-up RAM usage
- Change some naming according to Monero client convention

## Beta 1

Targeted Client: Monero 0.12.0

- Initial Beta.
