cmake_minimum_required(VERSION 3.28)
project(UNIT_TESTS
    VERSION 0.1
    DESCRIPTION "Unit tests for the Ledger Monero application"
    LANGUAGES C
)

#######################################################################
#                        Setup SDK & LedgerUT                         #
#######################################################################
if(NOT DEFINED ENV{BOLOS_SDK})
    message(FATAL_ERROR "BOLOS_SDK environment variable is not set. Please set it to the path of the Ledger Secure SDK.")
endif()

set(SDK_DIR $ENV{BOLOS_SDK})
list(APPEND CMAKE_MODULE_PATH "${SDK_DIR}/cmake")
include(LedgerUT)

#######################################################################
#             Setup app specific includes & compile defs              #
#######################################################################
set(UT_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs/
)

# From the app Makefile (line 61). Only monero_init.c needs them, and only
# because the coverage lib below compiles every source, not just the ones under
# test.
set(UT_COMPILE_DEFS
    MONERO_VERSION_MAJOR=2
    MONERO_VERSION_MINOR=2
    MONERO_VERSION_MICRO=2
    # From the Makefile (line 76), sizes G_io_tx_buffer.
    CUSTOM_IO_APDU_BUFFER_SIZE=\(255+5+64\)
)

#######################################################################
#                           LedgerUT Setup                            #
#######################################################################
ledger_unit_tests_init()

ledger_unit_tests_find_sources()

# Drop the UI sources from the coverage baseline. They cannot be unit tested --
# what they do is draw, which only the ragger snapshots can check -- and keeping
# them would mean declaring every generated icon here just to compile files no
# test links. Coverage is over the code these tests can actually reach.
list(FILTER APP_SOURCES EXCLUDE REGEX "/monero_ux_[a-z_]*\\.c$")

ledger_unit_tests_build_app_sources_as_lib(
    SOURCES      ${APP_SOURCES}
    INCLUDE_DIRS ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

#######################################################################
#                        LedgerUT test suites                         #
#######################################################################
# monero_monero.c holds one public function, monero_base58_public_key, and two
# statics it uses. Its only outside needs are a varint encoder, a keccak and the
# network id, all supplied by stubs/, so nothing else of the app is linked.
ledger_unit_tests_add_test(
    NAME          test_monero_base58
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/monero_monero.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/stubs/stub_monero.c
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

# monero_crypto.c: destination lengths validated after the write. The cx_
# stubs are not crypto, they just write the same number of bytes the real ones
# do, which is what these tests measure.
ledger_unit_tests_add_test(
    NAME          test_monero_crypto
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/monero_crypto.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/stubs/stub_crypto.c
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_monero_blind
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/monero_blind.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/stubs/stub_blind.c
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_monero_io
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/monero_io.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/stubs/stub_io.c
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS_SDK} ${UT_INCLUDE_DIRS}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)
