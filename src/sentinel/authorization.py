"""Authorisation records (§11, D-16, D-21, D-27, D-33, D-37, R-01..R-10).

A record is approved by an `authorize_record` approval whose subject is the record's canonical hash
and whose scope repeats the record's assets, environments and activity classes. Authority over each
asset is checked separately from signature validity: the asset must be in the operator-approved
policy's `owned_assets`, or the record must cite `evidence_of_authority` for it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from . import approvals, canonical
from .domain.enums import ActivityClass, ApprovalAction, Environment
from .errors import BlockedError, ValidationError
from .keys.operator import TrustStore
from .policy import Policy

RECORD_FIELDS = {
    "id",
    "version",
    "owner",
    "approver",
    "assets",
    "permitted_activities",
    "operations",
    "limits",
    "exclusions",
    "valid_from",
    "expires_at",
    "evidence_of_authority",
}


def _validate_record(rec: Any) -> dict[str, Any]:
    from .schema import validate

    validate(rec, "authorization-record")  # D-40: schema before domain rules, signature subject or authority
    if not isinstance(rec, dict) or set(rec) != RECORD_FIELDS:
        raise ValidationError(f"authorisation record must have exactly {sorted(RECORD_FIELDS)}")
    if not isinstance(rec["assets"], list) or not rec["assets"]:
        raise ValidationError("record must list at least one asset (R-01)")
    for a in rec["assets"]:
        if not isinstance(a, dict) or set(a) != {"id", "locator", "environment"}:
            raise ValidationError("each asset needs exactly id, locator, environment")
        Environment(a["environment"])
        if a["environment"] == Environment.PRODUCTION and any(ch in a["locator"] for ch in "*?["):
            raise BlockedError(
                "production assets must be exact; wildcards are not allowed (D-37)", "prod_wildcard"
            )
    acts = [ActivityClass(x) for x in rec["permitted_activities"]]
    if ActivityClass.B3 in acts:
        raise BlockedError("B3 cannot be authorised (D-15)", "b3_prohibited")
    if any(a["environment"] == Environment.PRODUCTION for a in rec["assets"]) and ActivityClass.A1 in acts:
        raise BlockedError("A1 against production is excluded from V1 (D-21, D-37)", "prod_a1")
    if not isinstance(rec["operations"], list) or not all(isinstance(o, str) for o in rec["operations"]):
        raise ValidationError("operations must be a list of strings")
    for name in ("valid_from", "expires_at"):
        if not isinstance(rec[name], int) or isinstance(rec[name], bool):
            raise ValidationError(f"{name} must be an integer timestamp")
    if not isinstance(rec["exclusions"], list) or not all(isinstance(x, str) for x in rec["exclusions"]):
        raise ValidationError("exclusions must be a list of strings")
    return rec


def record_scope(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "assets": rec["assets"],
        "activity_classes": sorted(rec["permitted_activities"]),
        "operations": sorted(rec["operations"]),
    }


@dataclass(frozen=True)
class VerifiedRecord:
    record: dict[str, Any]
    approval: approvals.Approval

    @property
    def record_hash(self) -> str:
        return canonical.digest(self.record)


def verify_record(
    rec_raw: Any,
    approval: approvals.Approval,
    policy: Policy,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> VerifiedRecord:
    rec = _validate_record(rec_raw)
    if not (int(rec["valid_from"]) <= now < int(rec["expires_at"])):
        raise BlockedError("authorisation record is not currently valid", "record_expired")
    approvals.verify(
        approval,
        approvals.Expectation(
            action=ApprovalAction.AUTHORIZE_RECORD,
            subject={"type": "authorization_record", "sha256": canonical.digest(rec)},
            revision=f"record:{rec['id']}:{rec['version']}",
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    if approval.payload["scope"] != record_scope(rec):
        raise BlockedError("approval scope does not repeat the record scope exactly", "scope_mismatch")
    if int(approval.payload["expires_at"]) < int(rec["expires_at"]):
        # the record is only valid while its approval is
        rec = {**rec, "expires_at": int(approval.payload["expires_at"])}
    # Authority is established separately from signature validity (D-16). In M1 the only machine-
    # checkable source is the operator-approved policy's owned_assets. evidence_of_authority (for
    # third-party assets) is recorded but cannot be verified automatically, so it never suffices alone.
    for a in rec["assets"]:
        if a["id"] not in policy.owned_assets:
            raise BlockedError(
                f"no authority established for asset {a['id']}: it is not in the approved "
                "policy's owned_assets (a signature alone is not authority)",
                "no_authority",
            )
    return VerifiedRecord(rec, approval)


def authorize_operation(
    vr: VerifiedRecord,
    *,
    asset_locator: str,
    environment: Environment,
    activity: ActivityClass,
    operation: str,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> None:
    """Called immediately before each protected operation (R-03, D-36). Re-verifies everything."""
    if now >= int(vr.record["expires_at"]):
        raise BlockedError("authorisation expired", "record_expired")
    approvals.verify(
        vr.approval,
        approvals.Expectation(
            action=ApprovalAction.AUTHORIZE_RECORD,
            subject=vr.approval.payload["subject"],
            revision=vr.approval.payload["revision"],
        ),
        trust,
        ledger,
        now,
        consume=False,
    )
    if activity.value not in vr.record["permitted_activities"]:
        raise BlockedError(f"activity {activity} not permitted by record", "activity_not_permitted")
    if operation not in vr.record["operations"]:
        raise BlockedError(f"operation {operation!r} not permitted by record", "operation_not_permitted")
    for ex in vr.record["exclusions"]:
        if fnmatch.fnmatchcase(asset_locator, str(ex)):
            raise BlockedError("asset is excluded", "excluded")
    for a in vr.record["assets"]:
        if a["environment"] != environment.value:
            continue
        if environment == Environment.PRODUCTION:
            if asset_locator == a["locator"]:
                return
        elif fnmatch.fnmatchcase(asset_locator, a["locator"]):
            return
    raise BlockedError(
        f"asset {asset_locator} ({environment}) is not in the authorised scope", "out_of_scope"
    )
