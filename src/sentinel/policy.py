"""Engine policy: built-in defaults (D-07, D-19, D-21, D-25, D-35) plus an optional operator-approved
policy file. A policy file is a trust anchor: it applies only with a valid `policy.change` approval
whose subject is the file's sha256 (D-27, D-33). A present-but-invalid policy file blocks the audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import approvals, canonical, scanner_pins
from .domain.enums import ActivityClass, ApprovalAction, AuditLevel, AuditMode
from .errors import BlockedError, ValidationError
from .keys.operator import TrustStore
from .scanner_pins import Pins


def plugin_pins(data: dict[str, Any]) -> dict[str, Any]:
    from .plugins import parse_pins

    return parse_pins(data)


MODE_LEVELS: dict[AuditMode, frozenset[AuditLevel]] = {
    AuditMode.READ: frozenset({AuditLevel.L1, AuditLevel.L2}),
    AuditMode.VALIDATE: frozenset({AuditLevel.L3}),
}

#: Classes allowed with no authorisation record (§11 enforcement rules, D-25). A1 never; B3 never.
NO_RECORD_CLASSES = frozenset({ActivityClass.S1, ActivityClass.S2, ActivityClass.B1, ActivityClass.B2})
MODE_CLASSES: dict[AuditMode, frozenset[ActivityClass]] = {
    AuditMode.READ: NO_RECORD_CLASSES,
    AuditMode.VALIDATE: NO_RECORD_CLASSES | {ActivityClass.A1},
}


@dataclass(frozen=True)
class Limits:
    scanner_timeout_s: int = 15 * 60
    max_audit_duration_s: int = 4 * 3600
    max_concurrent_scanners: int = 2
    max_artifact_bytes: int = 500 * 1024 * 1024
    max_extracted_total_bytes: int = 1024 * 1024 * 1024
    max_extracted_entries: int = 10_000
    max_nested_archive_depth: int = 3
    max_path_depth: int = 32
    max_entry_ratio: int = 100
    max_total_ratio: int = 50
    max_extracted_file_bytes: int = 256 * 1024 * 1024
    evidence_retention_days: int = 90
    max_scanner_output_bytes: int = 64 * 1024 * 1024


@dataclass(frozen=True)
class Policy:
    limits: Limits = field(default_factory=Limits)
    #: name -> sha256 of allowlisted native scanner binaries / scripts (D-22, R-16).
    adapter_allowlist: dict[str, str] = field(default_factory=dict)
    #: assets the operator has authority over (separate from signature validity, D-16).
    owned_assets: tuple[str, ...] = ()
    #: SHA-256 of the approved Secure Enclave helper build (contract §6). None: no helper is trusted.
    se_helper_sha256: str | None = None
    #: Operator-approved custom redaction patterns: ({"name": str, "regex": str}, ...).
    redaction_patterns: tuple[dict[str, str], ...] = ()
    #: D-22/D-53/D-54/D-56: approved scanner binaries and images, Podman runtime, OSV database.
    pins: Pins = field(default_factory=Pins)
    #: M6: approved plugins, each pinned by manifest SHA-256.
    plugins: dict[str, Any] = field(default_factory=dict)
    source: str = "built-in defaults"

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "limits": self.limits.__dict__,
            "adapter_allowlist": self.adapter_allowlist,
            "owned_assets": list(self.owned_assets),
            "se_helper_sha256": self.se_helper_sha256,
            "redaction_patterns": [p["name"] for p in self.redaction_patterns],
            "pins": self.pins.describe(),
            "plugins": {n: p.manifest_sha256 for n, p in sorted(self.plugins.items())},
        }


def _applied_policy_path() -> Path:
    from .paths import state_dir

    return state_dir() / "policy" / "applied.json"


def builtin_allowlist() -> dict[str, str]:
    from .adapters.fixture import FIXTURE_SCRIPT, script_sha256
    from .adapters.native import builtin_native_allowlist

    return {"fixture": script_sha256(FIXTURE_SCRIPT), **builtin_native_allowlist()}


def default_policy() -> Policy:
    return Policy(adapter_allowlist=builtin_allowlist())


def _expected_previous(new_hash: str) -> tuple[dict[str, Any], str | None]:
    applied = _applied_policy_path()
    prev = (
        canonical.decode_strict(applied.read_bytes())
        if applied.exists()
        else {"current": None, "previous": None}
    )
    from .schema import validate

    validate(prev, "applied-policy")
    # §11.3: a policy change binds the new file hash and the hash of the file it replaces.
    expected_prev = prev["previous"] if prev.get("current") == new_hash else prev.get("current")
    return prev, expected_prev


def _verify_policy_approval(
    raw: bytes,
    approval_path: Path | None,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
    *,
    consume: bool,
) -> tuple[approvals.Approval, str, dict[str, Any]]:
    if approval_path is None or not approval_path.exists():
        raise BlockedError("policy file has no operator approval; refusing to use it", "policy_unsigned")
    approval = approvals.load_approval_file(approval_path)
    new_hash = canonical.sha256_hex(raw)
    prev, expected_prev = _expected_previous(new_hash)
    approvals.verify(
        approval,
        approvals.Expectation(
            action=ApprovalAction.POLICY_CHANGE,
            subject={"type": "policy_file", "sha256": new_hash},
            revision=f"policy-prev:{expected_prev or 'none'}",
        ),
        trust,
        ledger,
        now,
        consume=consume,
    )
    return approval, new_hash, prev


def _schema_precheck_policy(raw: bytes) -> None:
    """Strict decoding then the D-40 policy contract, before any approval or trust decision."""
    from .schema import validate

    validate(canonical.decode_strict(raw), "policy")


def _parse_policy(raw: bytes, source: str) -> Policy:
    data = canonical.decode_strict(raw)
    from .schema import validate

    validate(data, "policy")  # D-40: schema before the domain checks
    if not isinstance(data, dict):
        raise ValidationError("policy must be an object")

    allowed = {
        "limits",
        "adapter_allowlist",
        "owned_assets",
        "se_helper_sha256",
        "redaction_patterns",
        "scanners",
        "podman",
        "b2",
        "mobsf",
        "osv_database",
        "trivy_database",
        "grype_database",
        "plugins",
    }
    if set(data) - allowed:
        raise ValidationError(f"unknown policy keys: {sorted(set(data) - allowed)}")
    raw_limits = data.get("limits", {})
    if not isinstance(raw_limits, dict):
        raise ValidationError("policy limits must be an object")
    unknown = set(raw_limits) - set(Limits().__dict__)
    if unknown:
        raise ValidationError(f"unknown policy limits: {sorted(unknown)}")
    for k, v in raw_limits.items():
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ValidationError(f"limit {k} must be a positive integer")
    lim = Limits(**{**Limits().__dict__, **raw_limits})
    allow_raw = data.get("adapter_allowlist", {})
    owned_raw = data.get("owned_assets", [])
    if not isinstance(allow_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and len(v) == 64 for k, v in allow_raw.items()
    ):
        raise ValidationError("adapter_allowlist must map names to sha256 hex digests")
    if not isinstance(owned_raw, list) or not all(isinstance(x, str) and x for x in owned_raw):
        raise ValidationError("owned_assets must be a list of asset ids")
    allow = {**builtin_allowlist(), **allow_raw}
    pin = data.get("se_helper_sha256")
    if pin is not None and (
        not isinstance(pin, str) or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin)
    ):
        raise ValidationError("se_helper_sha256 must be 64 lowercase hex characters")
    from .redaction import compile_custom

    custom = data.get("redaction_patterns", [])
    if not isinstance(custom, list):
        raise ValidationError("redaction_patterns must be a list")
    compile_custom(custom)  # validates names, sizes, compilation and empty matches
    return Policy(
        limits=lim,
        adapter_allowlist=allow,
        owned_assets=tuple(owned_raw),
        se_helper_sha256=pin,
        redaction_patterns=tuple(dict(c) for c in custom),
        pins=scanner_pins.parse(data),
        plugins=plugin_pins(data),
        source=source,
    )


def load_policy(
    policy_path: Path | None,
    approval_path: Path | None,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> Policy:
    if policy_path is None:
        return default_policy()
    if not policy_path.exists():
        raise ValidationError(f"policy file not found: {policy_path}")
    raw = policy_path.read_bytes()
    _schema_precheck_policy(raw)  # D-40: before the approval is verified, its nonce consumed or state written
    approval, new_hash, prev = _verify_policy_approval(raw, approval_path, trust, ledger, now, consume=True)
    if prev.get("current") != new_hash:
        from .paths import atomic_write
        from .schema import check_output

        record = {"current": new_hash, "previous": prev.get("current")}
        check_output(record, "applied-policy")
        atomic_write(_applied_policy_path(), canonical.encode(record))
    return _parse_policy(raw, f"{policy_path} (approved, payload {approval.payload_hash[:16]})")


def validate_policy_file(
    policy_path: Path,
    approval_path: Path | None,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> Policy:
    """Same checks as load_policy, but read-only: the approval is verified without consuming its nonce,
    and the applied-policy record is not changed."""
    if not policy_path.exists():
        raise ValidationError(f"policy file not found: {policy_path}")
    raw = policy_path.read_bytes()
    _schema_precheck_policy(raw)  # D-40: before the approval is verified
    approval, _, _ = _verify_policy_approval(raw, approval_path, trust, ledger, now, consume=False)
    return _parse_policy(raw, f"{policy_path} (approved, payload {approval.payload_hash[:16]})")


def check_mode_authorization(mode: AuditMode, has_record: bool) -> None:
    """D-21: VALIDATE runs only with a verified authorisation record, whatever classes are requested."""
    if mode == AuditMode.VALIDATE and not has_record:
        raise BlockedError("VALIDATE requires a verified authorisation record (D-21)", "no_record")


def check_mode_level(mode: AuditMode, level: AuditLevel) -> None:
    if level not in MODE_LEVELS[mode]:
        raise BlockedError(f"level {level} is not available in mode {mode} (D-21)", "mode_level")


def check_activity(mode: AuditMode, cls: ActivityClass, has_record: bool) -> None:
    if cls == ActivityClass.B3:
        raise BlockedError("B3 (running analysed artifacts) is prohibited (D-15)", "b3_prohibited")
    if cls not in MODE_CLASSES[mode]:
        raise BlockedError(f"class {cls} not permitted in mode {mode}", "class_not_permitted")
    if cls not in NO_RECORD_CLASSES and not has_record:
        raise BlockedError(f"class {cls} requires an authorisation record", "no_record")
