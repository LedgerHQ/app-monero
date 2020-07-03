import enum
from typing import Dict, Any, Optional

from . import *


class DeviceError:
    exc: Dict[int, Any] = {
        0x6700: WrongLength,
        0x6a30: ClientNotSupported,
        0x6910: SecurityPinLocked,
        0x6911: SecurityLoadKey,
        0x6912: SecurityCommitmentControl,
        0x6913: SecurityAmountChainControl,
        0x6914: SecurityCommitmentChainControl,
        0x6915: SecurityOutKeysChainControl,
        0x6916: SecurityMaxOutputReached,
        0x6917: SecurityHMAC,
        0x6918: SecurityRangeValue,
        0x6919: SecurityInternal,
        0x691a: SecurityMaxSignatureReached,
        0x691b: SecurityPrefixHash,
        0x69ee: SecurityLocked,
        0x6980: CommandNotAllowed,
        0x6981: SubCommandNotAllowed,
        0x6982: Deny,
        0x6983: KeyNotSet,
        0x6984: WrongData,
        0x6985: WrongDataRange,
        0x6986: IOFull,
        0x6b00: WrongP1P2,
        0x6d00: InsNotSupported,
        0x6e00: ProtocolNotSupported,
        0x6f00: Unknown
    }

    def __new__(cls,
                value: int,
                ins: Optional[enum.IntEnum] = None,
                *args,
                **kwargs) -> Any:
        if value in DeviceError.exc:
            msg: str = f"Error in {ins!r} command" if ins else "Error in command"

            return DeviceError.exc[value](hex(value), msg, *args, **kwargs)

        return UnknownDeviceError(hex(value), *args, **kwargs)
