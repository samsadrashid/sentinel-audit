"""Findings: fingerprints, states, promotion rules, dedup, suppression (§6.3, §7, D-26, D-27, R-12)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import approvals, canonical
from .domain.enums import SEVERITY_ORDER, ApprovalAction, Confidence, FindingOrigin, FindingState, Severity
from .errors import BlockedError
from .keys.operator import TrustStore


def fingerprint(domain: str, rule: str, location: str, component: str) -> str:
    """Deterministic identity (§7.4 dedup key). Excludes timestamps and run identifiers (R-12)."""
    return canonical.digest({"domain": domain, "rule": rule, "location": location, "component": component})


@dataclass
class Finding:
    fingerprint: str
    domain: str
    rule: str
    title: str
    location: dict[str, Any]
    component: str
    severity: Severity
    confidence: Confidence
    origin: FindingOrigin
    state: FindingState
    evidence: list[str] = field(default_factory=list)
    producers: list[str] = field(default_factory=list)
    review: dict[str, Any] | None = None
    suppression: dict[str, Any] | None = None
    #: AC-16: `live`, `test` or `unknown` for secret findings; None for everything else.
    liveness: str | None = None
    #: D-62: every contributing scanner, its own rule, evidence and database snapshot.
    sources: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        if d["liveness"] is None:
            del d["liveness"]
        if not d["sources"]:
            del d["sources"]
        for k in ("severity", "confidence", "origin", "state"):
            d[k] = str(d[k])
        return d


def new_finding(
    *,
    domain: str,
    rule: str,
    title: str,
    file: str,
    line: int,
    component: str,
    severity: str,
    origin: FindingOrigin,
    evidence_id: str,
    producer: str,
    liveness: str | None = None,
    location_key: str | None = None,
    source: dict[str, Any] | None = None,
) -> Finding:
    sev = Severity(severity) if severity in {s.value for s in Severity} else Severity.MEDIUM
    # §6.3 starting states: scanner -> suspected; agent/model -> unverified
    state = FindingState.SUSPECTED if origin == FindingOrigin.SCANNER else FindingState.UNVERIFIED
    loc = location_key if location_key is not None else f"{file}:{line}"
    return Finding(
        fingerprint(domain, rule, loc, component),
        domain,
        rule,
        title,
        {"file": file, "line": line},
        component,
        sev,
        Confidence.MEDIUM if origin == FindingOrigin.SCANNER else Confidence.LOW,
        origin,
        state,
        [evidence_id],
        [producer],
        liveness=liveness,
        sources=[source] if source else [],
    )


def canonical_advisory(ids: list[str]) -> str:
    """One advisory identity across scanners (D-62): the smallest CVE alias, else GHSA, else any ID."""
    clean = sorted({str(i) for i in ids if i})
    for prefix in ("CVE-", "GHSA-"):
        hit = [i for i in clean if i.startswith(prefix)]
        if hit:
            return hit[0]
    return clean[0] if clean else "unknown"


def deduplicate(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        m = merged.get(f.fingerprint)
        if m is None:
            merged[f.fingerprint] = f
            continue
        m.evidence = sorted(set(m.evidence) | set(f.evidence))
        m.producers = sorted(set(m.producers) | set(f.producers))
        keyed = {json.dumps(x, sort_keys=True): x for x in [*m.sources, *f.sources]}
        m.sources = [keyed[k] for k in sorted(keyed)]  # D-62: no contributing source is ever dropped
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[m.severity]:
            m.severity = f.severity
        if len(m.producers) > 1 and m.confidence != Confidence.HIGH:
            m.confidence = Confidence.HIGH  # independent producers agree (§7.4)
    return [merged[k] for k in sorted(merged)]


def promote_deterministic(f: Finding, confirming_evidence: str, confirmed_by_scanner: bool) -> None:
    """unverified->suspected or suspected->verified need deterministic evidence.

    Engine-internal: agents have no path to this function.
    """
    if not confirmed_by_scanner:
        raise BlockedError("promotion requires a deterministic producer", "no_deterministic_evidence")
    f.evidence = sorted(set(f.evidence) | {confirming_evidence})
    if f.state == FindingState.UNVERIFIED:
        f.state = FindingState.SUSPECTED
    elif f.state == FindingState.SUSPECTED:
        f.state = FindingState.VERIFIED


def apply_human_review(
    f: Finding,
    approval: approvals.Approval,
    revision: str,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> None:
    """D-26: signed decision moves a finding to HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE only."""
    approvals.verify(
        approval,
        approvals.Expectation(
            action=ApprovalAction.REVIEW_VERIFY_NO_EVIDENCE,
            subject={"type": "finding", "fingerprint": f.fingerprint},
            revision=revision,
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    if f.state == FindingState.VERIFIED:
        f.review = {"payload_hash": approval.payload_hash, "note": "additional assurance; state unchanged"}
        return
    if f.state not in (FindingState.UNVERIFIED, FindingState.SUSPECTED):
        raise BlockedError(f"cannot human-verify a finding in state {f.state}", "bad_state")
    f.state = FindingState.HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE
    f.review = {
        "payload_hash": approval.payload_hash,
        "key_id": approval.payload["key_id"],
        "rationale": approval.payload["rationale"],
    }


def apply_suppression(
    f: Finding,
    entry: dict[str, Any],
    approval: approvals.Approval,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> None:
    """§7.4: a suppression or accepted risk applies only through a signed entry whose sha256 is the
    approval subject. The finding stays in the result with the decision attached; severity is unchanged."""
    kind = entry.get("kind")
    if kind not in ("suppress", "accept_risk") or entry.get("finding") != f.fingerprint:
        raise BlockedError("suppression entry does not name this finding", "wrong_subject")
    action = ApprovalAction.REVIEW_ACCEPT_RISK if kind == "accept_risk" else ApprovalAction.SUPPRESS
    approvals.verify(
        approval,
        approvals.Expectation(
            action=action,
            subject={"type": "suppression_entry", "sha256": canonical.digest(entry)},
            revision=str(entry.get("revision")),
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    if now >= int(entry["expires_at"]):
        raise BlockedError("suppression entry has expired", "expired")
    f.suppression = {
        "type": action.value,
        "payload_hash": approval.payload_hash,
        "expires_at": min(int(entry["expires_at"]), int(approval.payload["expires_at"])),
        "rationale": approval.payload["rationale"],
        "author": entry.get("author"),
        "key_id": approval.payload["key_id"],
        **(
            {"approver": entry["approver"], "compensating_controls": entry["compensating_controls"]}
            if kind == "accept_risk"
            else {}
        ),
    }
    if kind == "accept_risk":
        f.state = FindingState.ACCEPTED_RISK


def summary(findings: list[Finding]) -> dict[str, Any]:
    by_state: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_state[f.state.value] = by_state.get(f.state.value, 0) + 1
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return {
        "total": len(findings),
        "by_state": dict(sorted(by_state.items())),
        "by_severity": dict(sorted(by_sev.items())),
        # AC-13: never summed together
        "verified": by_state.get(FindingState.VERIFIED.value, 0),
        "human_verified_no_deterministic_evidence": by_state.get(
            FindingState.HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE.value, 0
        ),
        "suppressed": sum(1 for f in findings if f.suppression and f.suppression["type"] == "suppress"),
        "accepted_risk": by_state.get(FindingState.ACCEPTED_RISK.value, 0),
    }
