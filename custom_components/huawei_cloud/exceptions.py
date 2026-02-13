from __future__ import annotations


class HuaweiCloudError(Exception):
    pass


class ConfigError(HuaweiCloudError):
    pass


class AuthError(ConfigError):
    pass


class TemporaryError(HuaweiCloudError):
    pass


class EmptyDataError(TemporaryError):
    pass

