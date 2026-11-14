"""Core domain models with validation at trust boundaries.

Models are immutable dataclasses. Every `from_dict` rejects unknown keys, wrong types and values
outside their enumerations, so untrusted configuration can't smuggle extra behaviour in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from ..errors import ValidationError
from .enums import (
    COMPLETE_STATUSES,
    ActivityClass,
    AuditLevel,
    AuditMode,
    CheckStatus,
    Environment,
)

MAX_TEXT = 4096


def _require_keys(
    data: Any, required: set[str], optional: set[str] | None = None, *, what: str
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError(f"{what}: expected an object")
    optional = optional or set()
    missing = required - set(data)
    unknown = set(data) - required - optional
    if missing:
        raise ValidationError(f"{what}: missing keys {sorted(missing)}")
    if unknown:
        raise ValidationError(f"{what}: unknown keys {sorted(unknown)}")
    return data


def _text(value: Any, what: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{what}: expected a string")
    if "\x00" in value or len(value) > MAX_TEXT:
        raise ValidationError(f"{what}: invalid string")
    if not allow_empty and not value.strip():
        raise ValidationError(f"{what}: must not be empty")
    return value


def _enum[E: Enum](enum_cls: type[E], value: Any, what: str) -> E:
    try:
        return enum_cls(value)
    except ValueError as exc:
        allowed = [e.value for e in enum_cls]
        raise ValidationError(f"{what}: {value!r} is not one of {allowed}") from exc


@dataclass(frozen=True)
class Asset:
    """A target the operator names. `locator` is a local path, artifact hash or host, depending on kind."""

    asset_id: str
    kind: str  # "local_path" | "artifact" | "host"
    locator: str
    environment: Environment

    KINDS = frozenset({"local_path", "artifact", "host"})

    @classmethod
    def from_dict(cls, data: Any) -> Asset:
        d = _require_keys(data, {"id", "kind", "locator", "environment"}, what="asset")
        kind = _text(d["kind"], "asset.kind")
        if kind not in cls.KINDS:
            raise ValidationError(f"asset.kind: {kind!r} is not one of {sorted(cls.KINDS)}")
        env = _enum(Environment, d["environment"], "asset.environment")
        locator = _text(d["locator"], "asset.locator")
        if env == Environment.PRODUCTION and any(c in locator for c in "*?["):
            raise ValidationError("asset.locator: production assets must be exact (no wildcards, D-37)")
        if kind == "local_path" and ".." in PurePosixPath(locator).parts:
            raise ValidationError("asset.locator: '..' is not allowed in local paths")
        return cls(_text(d["id"], "asset.id"), kind, locator, env)


@dataclass(frozen=True)
class Scope:
    """Explicit allowlist (R-01). An empty scope allows nothing."""

    assets: tuple[Asset, ...]
    exclusions: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Any) -> Scope:
        d = _require_keys(data, {"assets"}, {"exclusions"}, what="scope")
        if not isinstance(d["assets"], list):
            raise ValidationError("scope.assets: expected a list")
        assets = tuple(Asset.from_dict(a) for a in d["assets"])
        ids = [a.asset_id for a in assets]
        if len(ids) != len(set(ids)):
            raise ValidationError("scope.assets: duplicate asset ids")
        excl = d.get("exclusions", [])
        if not isinstance(excl, list):
            raise ValidationError("scope.exclusions: expected a list")
        return cls(assets, tuple(_text(x, "scope.exclusions[]") for x in excl))

    def asset(self, asset_id: str) -> Asset | None:
        return next((a for a in self.assets if a.asset_id == asset_id), None)


@dataclass(frozen=True)
class AuditConfig:
    """What the operator asks for. Mode defaults to READ and level to L2 (D-07, D-08)."""

    mode: AuditMode
    level: AuditLevel
    scope: Scope
    activity_classes: tuple[ActivityClass, ...]
    authorization_ref: str | None = None

    @classmethod
    def from_dict(cls, data: Any) -> AuditConfig:
        d = _require_keys(
            data, {"scope"}, {"mode", "level", "activity_classes", "authorization_ref"}, what="audit config"
        )
        mode = _enum(AuditMode, d.get("mode", AuditMode.READ.value), "mode")
        level = _enum(AuditLevel, d.get("level", AuditLevel.L2.value), "level")
        raw_classes = d.get("activity_classes", ["S1"])
        if not isinstance(raw_classes, list) or not raw_classes:
            raise ValidationError("activity_classes: expected a non-empty list")
        classes = tuple(_enum(ActivityClass, c, "activity_classes[]") for c in raw_classes)
        if ActivityClass.B3 in classes:
            raise ValidationError("activity_classes: B3 (running analysed artifacts) is prohibited (D-15)")
        auth = d.get("authorization_ref")
        if auth is not None:
            auth = _text(auth, "authorization_ref")
        scope = Scope.from_dict(d["scope"])
        if not scope.assets:
            raise ValidationError("scope.assets: at least one asset is required")
        return cls(mode, level, scope, classes, auth)


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    adapter: str
    status: CheckStatus
    reason: str = ""
    evidence: tuple[str, ...] = ()
    duration_ms: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.status, CheckStatus):
            raise ValidationError("check status must be a CheckStatus")
        if self.status in (CheckStatus.NOT_RUN, CheckStatus.BLOCKED, CheckStatus.ERROR) and not self.reason:
            raise ValidationError(f"{self.status} requires a reason (§5: reasons go in 'checks not run')")

    @property
    def finished(self) -> bool:
        return self.status in COMPLETE_STATUSES

    def to_json(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "adapter": self.adapter,
            "status": self.status.value,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class ScannerExecution:
    """Provenance of one scanner run (§6.1 producer, D-12)."""

    adapter: str
    adapter_version: str
    scanner: str
    scanner_version: str
    binary_sha256: str
    config_sha256: str
    exit_code: int | None
    duration_ms: int
    truncated: bool = False

    def __post_init__(self) -> None:
        for name in ("binary_sha256", "config_sha256"):
            v = getattr(self, name)
            if v and (len(v) != 64 or any(c not in "0123456789abcdef" for c in v)):
                raise ValidationError(f"{name} must be a lowercase sha256 hex digest")


@dataclass(frozen=True)
class AuditSummary:
    audit_id: str
    state: str
    overall: str
    checks: tuple[CheckResult, ...]
    counts: dict[str, int] = field(default_factory=dict)

    @classmethod
    def build(cls, audit_id: str, state: str, overall: str, checks: list[CheckResult]) -> AuditSummary:
        counts: dict[str, int] = {s.value: 0 for s in CheckStatus}
        for c in checks:
            counts[c.status.value] += 1
        return cls(audit_id, state, overall, tuple(checks), counts)

    @property
    def not_finished(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.finished]
