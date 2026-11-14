"""Unsigned approval payload preparation (§11.3).

Builds the exact canonical payload that the consuming operation's verifier expects, so an operator can
review it and sign it with a presence-backed key outside Sentinel. Preparing is side-effect free:
nothing is signed, no nonce is registered or consumed, no ledger, trust store, policy record, decision or
log is written. A prepared payload has no signature, so no loader can mistake it for an approval.

Subjects and revisions are derived here from the same objects the verifier will recompute them from;
caller-supplied hashes are never trusted. There is no `allowlist.change` kind: that action was removed by
D-42, and adapter allowlist changes go through `policy.change`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import approvals, authorization, canonical, decisions, policy, release
from .admin import EMPTY_TRUST_FINGERPRINT, CandidateKey, key_subject
from .domain.enums import ApprovalAction
from .errors import BlockedError, ValidationError
from .keys.operator import TrustStore
from .redaction import Redactor

KINDS = (
    "key-enrol",
    "key-rotate",
    "key-revoke",
    "review",
    "accept-risk",
    "suppress",
    "decision-revoke",
    "policy-change",
    "authorize-record",
    "release-publish",
)
UNSIGNED_NOTE = (
    "UNSIGNED. This is not an approval. Review every field, then sign the canonical bytes "
    "(field `canonical`, SHA-256 = payload_sha256) with your presence-backed operator key."
)


def _signer(trust: TrustStore, key_id: str, now: int) -> None:
    trust.usable(key_id, now)  # unknown, revoked or expired signer keys are refused before preparing


def _rationale(text: str) -> str:
    if (
        not isinstance(text, str)
        or len(text.strip()) < decisions.MIN_REASON
        or len(text) > decisions.MAX_TEXT
    ):
        raise ValidationError(f"rationale must be {decisions.MIN_REASON}-{decisions.MAX_TEXT} characters")
    return text


def prepare(
    kind: str,
    *,
    trust: TrustStore,
    now: int,
    key_id: str,
    lifetime: int,
    rationale: str | None = None,
    key: CandidateKey | None = None,
    target_key_id: str | None = None,
    finding: str | None = None,
    revision: str | None = None,
    entry: Any = None,
    decision_id: str | None = None,
    store: decisions.DecisionStore | None = None,
    policy_bytes: bytes | None = None,
    record: Any = None,
    dist: Path | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    """Return {payload, payload_sha256, display, note}. Raises on any missing, extra or ambiguous input."""
    given = {
        "key": key,
        "target_key_id": target_key_id,
        "finding": finding,
        "revision": revision,
        "entry": entry,
        "decision_id": decision_id,
        "policy_bytes": policy_bytes,
        "record": record,
        "dist": dist,
        "commit": commit,
    }
    needs = {
        "key-enrol": {"key"},
        "key-rotate": {"key"},
        "key-revoke": {"target_key_id"},
        "review": {"finding", "revision"},
        "accept-risk": {"entry"},
        "suppress": {"entry"},
        "decision-revoke": {"decision_id"},
        "policy-change": {"policy_bytes"},
        "authorize-record": {"record"},
        "release-publish": {"dist", "commit"},
    }
    if kind not in needs:
        raise ValidationError(f"unsupported approval kind {kind!r}; supported: {', '.join(KINDS)}")
    supplied = {k for k, v in given.items() if v is not None}
    if supplied != needs[kind]:
        raise ValidationError(f"{kind} needs exactly {sorted(needs[kind])}, got {sorted(supplied)}")
    if not isinstance(lifetime, int) or isinstance(lifetime, bool):
        raise ValidationError("lifetime must be an integer number of seconds")
    scope: dict[str, Any] = {}

    if kind == "key-enrol":
        assert key is not None
        if trust.fingerprint() != EMPTY_TRUST_FINGERPRINT:
            raise BlockedError(
                "trust store already initialised; prepare key-rotate instead", "enrol_after_init"
            )
        if key_id != key.public.key_id:
            raise ValidationError("an enrolment must be signed by the key being enrolled")
        action, subject, rev = ApprovalAction.KEY_ROTATE, key_subject(key), f"trust:{EMPTY_TRUST_FINGERPRINT}"
        text = _rationale(rationale or "")
    elif kind == "key-rotate":
        assert key is not None
        _signer(trust, key_id, now)
        if key_id == key.public.key_id or trust.get(key.public.key_id) is not None:
            raise ValidationError("the new key must be new and signed by a different, active key")
        action, subject, rev = ApprovalAction.KEY_ROTATE, key_subject(key), f"trust:{trust.fingerprint()}"
        text = _rationale(rationale or "")
    elif kind == "key-revoke":
        assert target_key_id is not None
        _signer(trust, key_id, now)
        if trust.get(target_key_id) is None:
            raise BlockedError(f"unknown operator key {target_key_id}", "unknown_key")
        action = ApprovalAction.KEY_REVOKE
        subject, rev = {"type": "operator_key", "key_id": target_key_id}, f"trust:{trust.fingerprint()}"
        text = _rationale(rationale or "")
    elif kind == "review":
        assert finding is not None and revision is not None
        _signer(trust, key_id, now)
        if not decisions._hex64(finding) or not revision.strip():
            raise ValidationError("review needs a finding fingerprint and a revision")
        action, subject, rev = (
            ApprovalAction.REVIEW_VERIFY_NO_EVIDENCE,
            {"type": "finding", "fingerprint": finding},
            revision,
        )
        text = _rationale(rationale or "")
    elif kind in ("accept-risk", "suppress"):
        _signer(trust, key_id, now)
        e = decisions.validate_entry(entry)
        want = "accept_risk" if kind == "accept-risk" else "suppress"
        if e["kind"] != want:
            raise ValidationError(f"entry kind is {e['kind']}, not {want}")
        if rationale is not None and rationale != e["reason"]:
            raise ValidationError("the rationale of a suppression or accepted risk is the entry reason")
        if e["expires_at"] > now + lifetime:
            raise ValidationError(
                "entry expiry is later than the approval's; shorten the entry or lengthen lifetime"
            )
        action = ApprovalAction.REVIEW_ACCEPT_RISK if want == "accept_risk" else ApprovalAction.SUPPRESS
        subject, rev, text = (
            {"type": "suppression_entry", "sha256": canonical.digest(e)},
            e["revision"],
            e["reason"],
        )
    elif kind == "decision-revoke":
        assert decision_id is not None
        _signer(trust, key_id, now)
        d = (store or decisions.DecisionStore()).find(decision_id)
        action, subject, rev = ApprovalAction.REVOKE_RECORD, decisions.revocation_subject(d), d.revision
        text = _rationale(rationale or "")
    elif kind == "policy-change":
        assert policy_bytes is not None
        _signer(trust, key_id, now)
        policy._parse_policy(policy_bytes, "prepared")  # must be a valid policy before anyone signs it
        new_hash = canonical.sha256_hex(policy_bytes)
        _, prev = policy._expected_previous(new_hash)
        action, subject = ApprovalAction.POLICY_CHANGE, {"type": "policy_file", "sha256": new_hash}
        rev = f"policy-prev:{prev or 'none'}"
        text = _rationale(rationale or "")
    elif kind == "release-publish":
        # D-74: everything is recomputed from the files; SHA256SUMS must describe exactly what's there.
        assert dist is not None and commit is not None
        _signer(trust, key_id, now)
        subject, rev, scope = release.release_parts(dist, commit)
        action = ApprovalAction.RELEASE_PUBLISH
        text = _rationale(rationale or "")
    else:  # authorize-record
        _signer(trust, key_id, now)
        rec = authorization._validate_record(record)
        action = ApprovalAction.AUTHORIZE_RECORD
        subject = {"type": "authorization_record", "sha256": canonical.digest(rec)}
        rev, scope = f"record:{rec['id']}:{rec['version']}", authorization.record_scope(rec)
        text = _rationale(rationale or "")

    payload = approvals.build_payload(
        action=action,
        subject=subject,
        revision=rev,
        scope=scope,
        issued_at=now,
        lifetime=lifetime,
        key_id=key_id,
        rationale=text,
    )
    if Redactor.for_output().contains_secret(payload):
        # A signed payload can't be redacted afterwards, so secret-like content is refused up front.
        raise ValidationError("payload contains content that looks like a secret; remove it before preparing")
    return describe(payload)


def describe(payload: dict[str, Any]) -> dict[str, Any]:
    """Re-canonicalise a payload and show every field plus the full hash. Reproducible for equal payloads."""
    if not isinstance(payload, dict) or set(payload) != set(approvals.REQUIRED_FIELDS):
        raise ValidationError(f"payload must have exactly {sorted(approvals.REQUIRED_FIELDS)}")
    return {
        "payload": payload,
        "canonical": canonical.encode(payload).decode(),
        "payload_sha256": canonical.digest(payload),
        "display": approvals.display_text(payload),
        "note": UNSIGNED_NOTE,
    }
