#*******************************************************************************
#    Ledger App Monero
#    (c) 2023-2025 Ledger SAS.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "Monero"

# Application version
APPVERSION_M = 2
APPVERSION_N = 1
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

SPECVERSION = "1.0"

# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOS = icons/app_monero_16px.gif
ICON_NANOX = icons/app_monero_14px.gif
ICON_NANOSP = icons/app_monero_14px.gif
ICON_STAX = icons/app_monero_32px.gif
ICON_FLEX = icons/app_monero_40px.gif

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS = "44'/128'"

VARIANT_PARAM = COIN
VARIANT_VALUES = monero

ENABLE_BLUETOOTH = 1
ENABLE_NBGL_QRCODE = 1

DEFINES   += $(MONERO_CONFIG)
DEFINES   += MONERO_VERSION_MAJOR=$(APPVERSION_M) MONERO_VERSION_MINOR=$(APPVERSION_N) MONERO_VERSION_MICRO=$(APPVERSION_P)
DEFINES   += MONERO_VERSION=$(APPVERSION)
DEFINES   += MONERO_NAME=$(APPNAME)

DEFINES   += SPEC_VERSION=$(SPECVERSION)

# Enable StageNet by default
#DEFINES += MONERO_ALPHA // This will also disable mainnet
#DEFINES += MONERO_BETA


############
# Platform #
############

DEFINES   += CUSTOM_IO_APDU_BUFFER_SIZE=\(255+5+64\)
DEFINES   += HAVE_LEGACY_PID

DEFINES   += U2F_PROXY_MAGIC=\"MOON\"
DEFINES   += HAVE_IO_U2F HAVE_U2F

# Enabling debug PRINTF
ifneq ($(DEBUG),0)
  # Debug options
  DEFINES += DEBUG_HWDEVICE
  DEFINES += BYPASS_COMMITMENT_FOR_TESTS
  DEFINES += IODUMMYCRYPT  # or IONOCRYPT
  # Stagenet network by default
  DEFINES += MONERO_BETA
endif


### variables processed by the common makefile.rules of the SDK to grab source files and include dirs
SDK_SOURCE_PATH  += lib_u2f

include $(BOLOS_SDK)/Makefile.standard_app
