"""Signed human review decisions, accepted risks and suppressions (§6.3, §7.4, §11.3, D-26, D-27, D-36, D-37).

Decisions live in an operator-controlled folder outside any target (write-once files). Each is a signed
approval plus, for suppressions and accepted risks, an entry whose sha256 is the approval subject:

- review (`review.verify_no_evidence`): subject is the finding fingerprint; bound to one source revision.
  It gives HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE, never `verified`.
- suppress: entry {kind, finding, revision, reason, author, created_at, expires_at}.
- accept_risk (`review.accept_risk`): the same plus approver and compensating_controls.

Rules: the approval rationale must equal the entry reason; the entry expiry can't outlive the approval;
at audit time every decision is verified again immediately before it is applied, and any decision that
fails, has expired, or names another revision is not applied and is listed in the result. Applying a
suppression never removes a finding, never changes its severity and never changes a check status.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import approvals, canonical
from .domain.enums import ApprovalAction
from .errors import BlockedError, IntegrityError, SentinelError, ValidationError
from .findings import Finding, apply_human_review, apply_suppression
from .keys.operator import TrustStore
from .paths import ensure_private_dir, state_dir, write_once
from .redaction import Redactor

KINDS = {
    "review": ApprovalAction.REVIEW_VERIFY_NO_EVIDENCE,
    "suppress": ApprovalAction.SUPPRESS,
    "accept_risk": ApprovalAction.REVIEW_ACCEPT_RISK,
}
ENTRY_FIELDS = {
    "suppress": {"kind", "finding", "revision", "reason", "author", "created_at", "expires_at"},
    "accept_risk": {
        "kind",
        "finding",
        "revision",
        "reason",
        "author",
        "created_at",
        "expires_at",
        "approver",
        "compensating_controls",
    },
}
MIN_REASON = 10
MAX_TEXT = 4096
MAX_DECISION_BYTES = 256 * 1024


def _hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _text(v: Any, what: str, minimum: int = 1) -> str:
    if not isinstance(v, str) or "\x00" in v or len(v) > MAX_TEXT or len(v.strip()) < minimum:
        raise ValidationError(f"{what} must be {minimum}-{MAX_TEXT} characters")
    return v


def _int(v: Any, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
        raise ValidationError(f"{what} must be a positive integer")
    return v


def validate_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict) or entry.get("kind") not in ENTRY_FIELDS:
        raise ValidationError("entry kind must be suppress or accept_risk")
    fields = ENTRY_FIELDS[entry["kind"]]
    if set(entry) != fields:
        raise ValidationError(f"{entry['kind']} entry must have exactly {sorted(fields)}")
    if not _hex64(entry["finding"]):
        raise ValidationError("entry finding must be a finding fingerprint")
    _text(entry["revision"], "entry revision")
    _text(entry["reason"], "entry reason", MIN_REASON)
    _text(entry["author"], "entry author")
    if _int(entry["expires_at"], "entry expires_at") <= _int(entry["created_at"], "entry created_at"):
        raise ValidationError("entry must expire after it is created")
    if entry["kind"] == "accept_risk":
        _text(entry["approver"], "entry approver")
        _text(entry["compensating_controls"], "entry compensating_controls", MIN_REASON)
    return entry


@dataclass(frozen=True)
class Decision:
    kind: str
    finding: str
    revision: str
    approval: approvals.Approval
    entry: dict[str, Any] | None = None

    @property
    def decision_id(self) -> str:
        return self.approval.payload_hash

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "entry": self.entry, "approval": self.approval.to_json()}

    def expectation(self) -> approvals.Expectation:
        if self.kind == "review":
            subject = {"type": "finding", "fingerprint": self.finding}
        else:
            subject = {"type": "suppression_entry", "sha256": canonical.digest(self.entry)}
        return approvals.Expectation(action=KINDS[self.kind], subject=subject, revision=self.revision)

    def summary(self) -> dict[str, Any]:
        p = self.approval.payload
        out = {
            "decision_id": self.decision_id,
            "kind": self.kind,
            "finding": self.finding,
            "revision": self.revision,
            "key_id": p["key_id"],
            "rationale": p["rationale"],
            "approval_expires_at": p["expires_at"],
        }
        if self.entry is not None:
            out["entry_expires_at"] = self.entry["expires_at"]
            out["author"] = self.entry["author"]
            if self.kind == "accept_risk":
                out["approver"] = self.entry["approver"]
                out["compensating_controls"] = self.entry["compensating_controls"]
        return out


def build(
    kind: str, approval: approvals.Approval, *, entry: Any = None, finding: str = "", revision: str = ""
) -> Decision:
    """Structural checks only; signature and nonce checks happen in `verify_decision`."""
    if Redactor.for_output().contains_secret({"payload": approval.payload, "entry": entry}):
        raise ValidationError(
            "decision contains content that looks like a secret; it would be stored unredacted"
        )
    if kind not in KINDS:
        raise ValidationError(f"decision kind must be one of {sorted(KINDS)}")
    p = approval.payload
    if kind == "review":
        if entry is not None:
            raise ValidationError("a review decision has no entry")
        if not _hex64(finding):
            raise ValidationError("finding must be a finding fingerprint")
        _text(revision, "revision")
        _text(p.get("rationale"), "review rationale", MIN_REASON)
        return Decision(kind, finding, revision, approval)
    e = validate_entry(entry)
    if e["kind"] != kind:
        raise ValidationError(f"entry kind is {e['kind']}, not {kind}")
    if p.get("rationale") != e["reason"]:
        raise ValidationError("approval rationale must equal the entry reason")
    if int(e["expires_at"]) > int(p.get("expires_at", 0)):
        raise ValidationError("entry expiry can't be later than its approval's expiry")
    return Decision(kind, e["finding"], e["revision"], approval, e)


def verify_decision(d: Decision, trust: TrustStore, ledger: approvals.NonceLedger, now: int) -> None:
    approvals.verify(d.approval, d.expectation(), trust, ledger, now, consume=True)
    if d.entry is not None and now >= int(d.entry["expires_at"]):
        raise BlockedError("decision entry has expired", "expired")


def revocation_subject(d: Decision) -> dict[str, str]:
    """A revocation names the exact decision (its approval payload hash) and the exact entry it signed."""
    return {
        "type": "decision",
        "decision_id": d.decision_id,
        "entry_sha256": canonical.digest(d.entry) if d.entry is not None else "none",
    }


class DecisionStore:
    def __init__(self, root: Path | None = None, revocations: Path | None = None) -> None:
        self.root = root or (state_dir() / "decisions")
        self.revocations = revocations or (self.root.parent / f"{self.root.name}-revocations")

    def find(self, decision_id: str) -> Decision:
        if not _hex64(decision_id):
            raise ValidationError("decision id must be a 64-character hex payload hash")
        ds, _ = self.load()
        match = [d for d in ds if d.decision_id == decision_id]
        if not match:
            raise BlockedError(f"no recorded decision {decision_id}", "unknown_decision")
        return match[0]

    def revocation_path(self, decision_id: str) -> Path:
        return self.revocations / f"{decision_id}.json"

    def revocation_state(self, d: Decision, trust: TrustStore) -> str:
        """'active', 'revoked', or 'unverifiable' (a revocation file exists but doesn't verify)."""
        p = self.revocation_path(d.decision_id)
        if not p.exists() and not p.is_symlink():
            return "active"
        try:
            if p.is_symlink() or p.stat().st_size > MAX_DECISION_BYTES:
                return "unverifiable"
            ap = approvals.Approval.from_json(
                canonical.decode_strict(p.read_bytes(), max_bytes=MAX_DECISION_BYTES)
            )
        except (SentinelError, OSError, KeyError, TypeError, ValueError):
            return "unverifiable"
        pl = ap.payload
        key = trust.get(str(pl.get("key_id")))
        ok = (
            key is not None
            and pl.get("context") == approvals.context_for(ApprovalAction.REVOKE_RECORD)
            and pl.get("action") == ApprovalAction.REVOKE_RECORD.value
            and pl.get("subject") == revocation_subject(d)
            and pl.get("revision") == d.revision
            # A revocation stays valid after its signing key is later revoked: it was accepted when
            # the key was active, and revoking a key must never resurrect decisions it revoked.
            and key.public.verify(ap.signature, ap.payload_bytes)
        )
        return "revoked" if ok else "unverifiable"

    def add(self, d: Decision) -> Path:
        path = ensure_private_dir(self.root) / f"{d.kind}-{d.decision_id}.json"
        if path.exists():
            raise BlockedError("this decision is already recorded", "duplicate_decision")
        from .schema import check_output

        check_output(d.to_json(), "decision")  # D-40: nothing malformed is persisted
        write_once(path, canonical.encode(d.to_json()))
        return path

    def load(self) -> tuple[list[Decision], list[dict[str, str]]]:
        """Return (decisions, problems). Malformed or renamed files are reported, never applied."""
        out: list[Decision] = []
        problems: list[dict[str, str]] = []
        if not self.root.is_dir():
            return out, problems
        for p in sorted(self.root.iterdir()):
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_DECISION_BYTES:
                    raise ValidationError("not a regular decision file")
                raw = canonical.decode_strict(p.read_bytes(), max_bytes=MAX_DECISION_BYTES)
                from .schema import validate

                validate(raw, "decision")  # D-40: schema before the approval is parsed or the decision built
                if not isinstance(raw, dict) or set(raw) != {"kind", "entry", "approval"}:
                    raise ValidationError("decision file has wrong fields")
                ap = approvals.Approval.from_json(raw["approval"])
                if raw["kind"] == "review":
                    subj = ap.payload.get("subject", {})
                    d = build(
                        "review",
                        ap,
                        finding=str(subj.get("fingerprint", "")),
                        revision=str(ap.payload.get("revision", "")),
                    )
                else:
                    d = build(str(raw["kind"]), ap, entry=raw["entry"])
                if p.name != f"{d.kind}-{d.decision_id}.json":
                    raise IntegrityError("decision file name does not match its content")
                out.append(d)
            except (SentinelError, OSError, KeyError, TypeError, ValueError) as exc:
                problems.append({"file": p.name, "problem": str(exc)[:200]})
        return out, problems


def record(
    d: Decision, store: DecisionStore, trust: TrustStore, ledger: approvals.NonceLedger, now: int
) -> Path:
    verify_decision(d, trust, ledger, now)
    return store.add(d)


def revoke(
    decision_id: str,
    approval: approvals.Approval,
    store: DecisionStore,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> Decision:
    """Revoke a standing decision with a one-time `revoke_record` approval bound to the decision ID, the
    entry hash and the decision's revision. The decision file is kept; a revocation record is appended."""
    d = store.find(decision_id)
    if store.revocation_state(d, trust) != "active":
        raise BlockedError("decision is already revoked", "already_revoked")
    approvals.verify(
        approval,
        approvals.Expectation(
            action=ApprovalAction.REVOKE_RECORD, subject=revocation_subject(d), revision=d.revision
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    write_once(
        ensure_private_dir(store.revocations) / f"{decision_id}.json", canonical.encode(approval.to_json())
    )
    ledger.revoked.add(d.decision_id)
    ledger.save(now)
    return d


def apply_decisions(
    findings: list[Finding],
    revision: str,
    store: DecisionStore,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
) -> dict[str, Any]:
    """Apply every decision for these findings at this revision, re-verified now. Report the rest."""
    decisions, problems = store.load()
    by_fp = {f.fingerprint: f for f in findings}
    applied: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = [{"decision_id": None, **p, "code": "malformed"} for p in problems]
    other_revision = 0
    # reviews first, then accepted risks, then suppressions: an accepted risk keeps the review on record
    order = {"review": 0, "accept_risk": 1, "suppress": 2}
    for d in sorted(decisions, key=lambda x: (order[x.kind], x.decision_id)):
        f = by_fp.get(d.finding)
        if f is None:
            continue
        if d.revision != revision:
            other_revision += 1
            continue
        state = store.revocation_state(d, trust)
        if state != "active":
            code = "decision_revoked" if state == "revoked" else "revocation_unverifiable"
            rejected.append(
                {"decision_id": d.decision_id, "kind": d.kind, "finding": d.finding, "code": code}
            )
            continue
        try:
            verify_decision(d, trust, ledger, now)
            if d.kind == "review":
                apply_human_review(f, d.approval, revision, trust, ledger, now)
            else:
                assert d.entry is not None
                apply_suppression(f, d.entry, d.approval, trust, ledger, now)
        except BlockedError as exc:
            rejected.append(
                {"decision_id": d.decision_id, "kind": d.kind, "finding": d.finding, "code": exc.code}
            )
            continue
        applied.append({"decision_id": d.decision_id, "kind": d.kind, "finding": d.finding})
    return {"applied": applied, "rejected": rejected, "other_revision": other_revision}


__all__ = ["DecisionStore", "Decision", "build", "record", "apply_decisions", "verify_decision"]
