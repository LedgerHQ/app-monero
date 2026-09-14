"""Status words the tests assert on.

Values verified against src/monero_types.h, except SWO_COMMAND_NOT_ACCEPTED,
which is the SDK's (ledger-secure-sdk include/status_words.h). They were
declared inline in 16 test files before, 23 times.

Note monero_io.c passes ERROR_IO_FULL (0x20000) to send_error_and_kill_app,
which monero_io_insert_u16 truncates to 0x0000 on the wire, so there is no
constant for it here.
"""

SW_OK = 0x9000

SW_WRONG_LENGTH = 0x6700

#: the SDK's pending-APDU latch, which pre-empts the app's own gate
SWO_COMMAND_NOT_ACCEPTED = 0x6901

SW_SECURITY_COMMITMENT_CHAIN_CONTROL = 0x6914
SW_SECURITY_OUTKEYS_CHAIN_CONTROL = 0x6915
SW_SECURITY_HMAC = 0x6917
SW_SECURITY_INTERNAL = 0x6919
SW_SECURITY_PREFIX_HASH = 0x691B
SW_SECURITY_CHANGE_ADDRESS = 0x691C
SW_SECURITY_USER_NOT_APPROVED = 0x691D
SW_SECURITY_PREHASH_NOT_FINALIZED = 0x691E
SW_SECURITY_PREFIX_NOT_FINALIZED = 0x691F
SW_SECURITY_OUTPUTS_NOT_REVIEWED = 0x6920
SW_SECURITY_PAYMENT_ID = 0x6921

SW_COMMAND_NOT_ALLOWED = 0x6980
SW_DENY = 0x6982
SW_WRONG_DATA = 0x6984
SW_WRONG_DATA_RANGE = 0x6985
SW_PROTOCOL_NOT_SUPPORTED = 0x6E00
