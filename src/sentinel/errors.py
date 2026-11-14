"""Typed engine errors. Every security failure maps to a fail-closed outcome."""


class SentinelError(Exception):
    """Base class for all engine errors."""


class ValidationError(SentinelError):
    """Input failed validation at a trust boundary."""


class BlockedError(SentinelError):
    """A protected operation was denied by policy or authorisation (R-10: result is BLOCKED)."""

    def __init__(self, reason: str, code: str = "blocked") -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


class CapabilityUnavailable(SentinelError):
    """A required host capability is missing (D-32). The affected work is refused, never weakened."""

    def __init__(self, capability: str, reason: str) -> None:
        super().__init__(f"{capability}: {reason}")
        self.capability = capability
        self.reason = reason


class IntegrityError(SentinelError):
    """Evidence, manifest or log integrity check failed (R-13)."""


class LifecycleError(SentinelError):
    """An illegal audit or check state transition was attempted."""
