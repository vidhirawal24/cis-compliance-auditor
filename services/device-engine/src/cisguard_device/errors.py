"""Structured device-engine errors used by library and CLI boundaries."""

from __future__ import annotations

from typing import Any


class DeviceEngineError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        retryable: bool = False,
    ) -> None:
        self.code = code
        self.message = message
        self.details = details
        self.retryable = retryable
        super().__init__(message)


class FixtureInputError(DeviceEngineError):
    pass


class LiveWriteBlockedError(DeviceEngineError):
    pass
