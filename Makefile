# Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
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
#

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

#Monero /44'/128'
APPNAME = "Monero"
APP_LOAD_PARAMS=--appFlags 0x40  --path "2147483692/2147483776" --curve secp256k1 $(COMMON_LOAD_PARAMS)

APPVERSION_M=0
APPVERSION_N=1
APPVERSION_P=0

APPVERSION=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)
SPECVERSION="0.7b"
ICONNAME=images/icon_monero.gif


################
# Default rule #
################
all: default

############
# Platform #
############
DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES   += HAVE_BAGL HAVE_PRINTF HAVE_SPRINTF
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += HAVE_USB_CLASS_CCID

## App Conf
DEFINES   += $(MONERO_CONFIG) MONERO_VERSION=$(APPVERSION) MONERO_NAME=$(APPNAME) SPEC_VERSION=$(SPECVERSION)

## Debug options
DEFINES   += DEBUGLEDGER
DEFINES   += IODUMMYCRYPT
#DEFINES  += IONOCRYPT
DEFINES   += TESTKEY
DEFINES   += TESTNET

##############
#  Compiler  #
##############
#GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
#CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
CC       := $(CLANGPATH)clang

#CFLAGS   += -O0 -gdwarf-2  -gstrict-dwarf
CFLAGS   += -O3 -Os

AS     := $(GCCPATH)arm-none-eabi-gcc

LD       := $(GCCPATH)arm-none-eabi-gcc
#LDFLAGS  += -O0 -gdwarf-2  -gstrict-dwarf
LDFLAGS  += -O3 -Os
LDLIBS   += -lm -lgcc -lc

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### computed variables
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl


load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile.genericwallet

