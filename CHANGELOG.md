# Changelog

All notable changes to this project will be documented in this file.


## 1.6.0 - 2020-06-04

 Add Timelock verification on device

## 1.5.1 - 2020-02-28

 Security Enhancement

## 1.4.2

 Compatibility check with client version now discards the fourth sub-version number.

 Release for client 0.15.0+
 firmware LNS 1.6.0 et LNX 1.2.4

## 1.4.1

 Release for client 0.15
 firmware LNS 1.6.0 et LNX 1.2.4

## 1.4.0

- Add address display
- Enhance protocol security
- Remove double ask for view key

## 1.3.2

--

## 1.3.1

Add Tx proof support Monero post 0.14.0.2

## 1.3.0

Targeted Client: Monero post 0.14.0.2

## 1.2.2

Targeted Client: Monero 0.14.0.2

Partial bug Fixes in change destination address computation: Only one destination
is allowed in transfer command

## 1.2.0

Targeted Client: Monero 0.14.0.0+

- V11 fork integration
- Fix change address issue.

## 1.1.3

- Remove rolling address display
- Allow STEALTH instruction outside TX
- Doc fix

## 1.1.2

Fix stack overflow for 1.5.5 SDK

## 1.1.1

Allow transaction parsing when screen is locked

## 1.1.0

Initial Release

Targeted Client: Monero 0.13.0.0+

- Security fix: Screen lock management
- Optimisation: New protocol V2 for future
- Fix bug in large amount display that was truncated
- Remove confirmation for zero amount (fake sweep change)
- Better handling for change address to not display them
- Dual id (PIN based) management
- Add onscreen seed words display


## 1.0.0

Initial Release

Targeted Client: Monero 0.13.0.0+


## 0.12.4 / Beta 5

Targeted Client: Monero 0.12.1

- U2F support
- Fix Windows detection problem
- activate Mainnet 'Beta stage: USE AT YOUR OWN RISK'

## 0.12.3 / Beta 4

Targeted Client: Monero 0.12.1

- SDK 1.4.2.1 port

## 0.12.2 / Beta 3

Targeted Client: Monero 0.12.1

- Activate security command chain control


## 0.12.1 / Beta 2

Targeted Client: Monero 0.12.1

- Add second PIN support
- Remove key storage  in NVRAM, always recompute secret key at boot
- Export secret viewkey, with agreement of user, to speed up tx scan
- Clean-up RAM usage
- Change some naming according to Monero client convention

## Beta 1

Targeted Client: Monero 0.12.0

- Initial Beta.

