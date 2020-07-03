__all__ = [
    "UnknownDeviceError",
    "WrongLength",
    "ClientNotSupported",
    "SecurityPinLocked",
    "SecurityLoadKey",
    "SecurityCommitmentControl",
    "SecurityAmountChainControl",
    "SecurityCommitmentChainControl",
    "SecurityOutKeysChainControl",
    "SecurityMaxOutputReached",
    "SecurityHMAC",
    "SecurityRangeValue",
    "SecurityInternal",
    "SecurityMaxSignatureReached",
    "SecurityPrefixHash",
    "SecurityLocked",
    "CommandNotAllowed",
    "SubCommandNotAllowed",
    "Deny",
    "KeyNotSet",
    "WrongData",
    "WrongDataRange",
    "IOFull",
    "WrongP1P2",
    "InsNotSupported",
    "ProtocolNotSupported",
    "Unknown"
]


class UnknownDeviceError(Exception):
    pass


class WrongLength(UnknownDeviceError):
    pass


class ClientNotSupported(UnknownDeviceError):
    pass


class SecurityPinLocked(UnknownDeviceError):
    pass


class SecurityLoadKey(UnknownDeviceError):
    pass


class SecurityCommitmentControl(UnknownDeviceError):
    pass


class SecurityAmountChainControl(UnknownDeviceError):
    pass


class SecurityCommitmentChainControl(UnknownDeviceError):
    pass


class SecurityOutKeysChainControl(UnknownDeviceError):
    pass


class SecurityMaxOutputReached(UnknownDeviceError):
    pass


class SecurityHMAC(UnknownDeviceError):
    pass


class SecurityRangeValue(UnknownDeviceError):
    pass


class SecurityInternal(UnknownDeviceError):
    pass


class SecurityMaxSignatureReached(UnknownDeviceError):
    pass


class SecurityPrefixHash(UnknownDeviceError):
    pass


class SecurityLocked(UnknownDeviceError):
    pass


class CommandNotAllowed(UnknownDeviceError):
    pass


class SubCommandNotAllowed(UnknownDeviceError):
    pass


class Deny(UnknownDeviceError):
    pass


class KeyNotSet(UnknownDeviceError):
    pass


class WrongData(UnknownDeviceError):
    pass


class WrongDataRange(UnknownDeviceError):
    pass


class IOFull(UnknownDeviceError):
    pass


class WrongP1P2(UnknownDeviceError):
    pass


class InsNotSupported(UnknownDeviceError):
    pass


class ProtocolNotSupported(UnknownDeviceError):
    pass


class Unknown(UnknownDeviceError):
    pass
