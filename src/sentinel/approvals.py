"""Canonical approval payloads (§11.3, D-33), nonce semantics (§11.3.1, D-36), expiry (§11.3.2, D-37).

Verification order is fail-closed: any failed check raises BlockedError, which callers turn into
BLOCKED. Signatures are verified against the operator trust store only; run keys are never accepted.

Replay limitation (D-34, D-36): the nonce ledger is local, same-user-writable state. A rollback of
the ledger can re-enable an approval until its expiry. Sentinel claims no protection beyond that.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import canonical
from .domain.enums import ONE_TIME_ACTIONS, STANDING_ACTIONS, ApprovalAction, Environment
from .errors import BlockedError, ValidationError
from .keys.operator import TrustStore
from .paths import atomic_write, state_dir

HOUR = 3600
DAY = 86400
CLOCK_SKEW = 120

#: D-37 maximum lifetimes. Changing them is itself a policy.change approval.
MAX_EXPIRY: dict[str, int] = {
    "authorize_record:local": 30 * DAY,
    "authorize_record:staging": 30 * DAY,
    "authorize_record:production": 24 * HOUR,
    ApprovalAction.REVOKE_RECORD: HOUR,
    ApprovalAction.KEY_ROTATE: HOUR,
    ApprovalAction.KEY_REVOKE: HOUR,
    ApprovalAction.REVIEW_VERIFY_NO_EVIDENCE: 90 * DAY,
    ApprovalAction.REVIEW_ACCEPT_RISK: 90 * DAY,
    ApprovalAction.SUPPRESS: 90 * DAY,
    ApprovalAction.POLICY_CHANGE: 90 * DAY,
    ApprovalAction.RELEASE_PUBLISH: HOUR,  # D-74: a signing window, not how long the signature is valid
}

REQUIRED_FIELDS = (
    "context",
    "action",
    "subject",
    "revision",
    "scope",
    "issued_at",
    "expires_at",
    "nonce",
    "key_id",
    "rationale",
)


def context_for(action: ApprovalAction) -> str:
    return f"sentinel/v1/approval/{action.value}"


def max_expiry_for(action: ApprovalAction, scope: dict[str, Any]) -> int:
    if action == ApprovalAction.AUTHORIZE_RECORD:
        envs = {str(a.get("environment")) for a in scope.get("assets", [])} or {"local"}
        if not envs <= {e.value for e in Environment}:
            raise BlockedError("unknown environment in scope", "bad_scope")
        return min(MAX_EXPIRY[f"authorize_record:{e}"] for e in envs)
    return MAX_EXPIRY[action]


def _map_approval_schema_error(data: Any, exc: Exception) -> Exception:
    """Explicit D-40 error mapping: keep the established D-42/D-33 classifications for schema failures.

    Reads only the two plain strings ``action`` and ``context``; nothing is trusted or verified."""
    from .schema import SchemaError

    payload = data.get("payload") if isinstance(data, dict) else None
    action = payload.get("action") if isinstance(payload, dict) else None
    context = payload.get("context") if isinstance(payload, dict) else None
    known = {a.value for a in ApprovalAction}
    if isinstance(action, str) and action not in known:
        return SchemaError(f"unknown approval action {action!r}")
    if isinstance(action, str) and context != context_for(ApprovalAction(action)):
        return SchemaError("approval context does not match its action")
    return exc


@dataclass(frozen=True)
class Approval:
    payload: dict[str, Any]
    signature: bytes

    @property
    def payload_bytes(self) -> bytes:
        return canonical.encode(self.payload)

    @property
    def payload_hash(self) -> str:
        return canonical.sha256_hex(self.payload_bytes)

    def to_json(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": base64.b64encode(self.signature).decode()}

    @classmethod
    def from_json(cls, data: Any) -> Approval:
        from .schema import SchemaError, validate

        payload0 = data.get("payload") if isinstance(data, dict) else None
        ctx = payload0.get("context") if isinstance(payload0, dict) else None
        if isinstance(ctx, str) and ctx.startswith("sentinel/v") and not ctx.startswith("sentinel/v1/"):
            raise SchemaError(f"unsupported approval context version {ctx!r}", "unsupported_version")
        try:
            validate(data, "approval")  # D-40: schema before any domain check, signature or trust decision
        except SchemaError as exc:
            raise _map_approval_schema_error(data, exc) from exc
        if not isinstance(data, dict) or set(data) != {"payload", "signature"}:
            raise ValidationError("approval must have exactly payload and signature")
        payload = data["payload"]
        if not isinstance(payload, dict) or set(payload) != set(REQUIRED_FIELDS):
            raise ValidationError(f"approval payload must have exactly the fields {REQUIRED_FIELDS}")
        types = {
            "context": str,
            "action": str,
            "subject": dict,
            "revision": str,
            "scope": dict,
            "issued_at": int,
            "expires_at": int,
            "nonce": str,
            "key_id": str,
            "rationale": str,
        }
        for name, typ in types.items():
            v = payload[name]
            if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
                raise ValidationError(f"approval payload field {name!r} must be {typ.__name__}")
        # Only the defined actions exist; anything else (including the removed `allowlist.change`,
        # D-42) is refused at load time, and the context must be that action's own (D-33).
        if payload["action"] not in {a.value for a in ApprovalAction}:
            raise ValidationError(f"unknown approval action {payload['action']!r}")
        if payload["context"] != context_for(ApprovalAction(payload["action"])):
            raise ValidationError("approval context does not match its action")
        if len(payload["nonce"]) != 32 or any(c not in "0123456789abcdef" for c in payload["nonce"]):
            raise ValidationError("approval nonce must be 128-bit lowercase hex")
        if not isinstance(data["signature"], str):
            raise ValidationError("approval signature must be a base64 string")
        try:
            sig = base64.b64decode(data["signature"], validate=True)
        except ValueError as exc:
            raise ValidationError("approval signature is not valid base64") from exc
        canonical.encode(payload)  # rejects floats, bad keys and deep nesting
        return cls(payload, sig)


def build_payload(
    *,
    action: ApprovalAction,
    subject: dict[str, str],
    revision: str,
    scope: dict[str, Any],
    issued_at: int,
    lifetime: int,
    key_id: str,
    rationale: str,
) -> dict[str, Any]:
    """Build the canonical payload. Callers sign `canonical.encode(payload)` only via a PresenceProvider."""
    limit = max_expiry_for(action, scope)
    if lifetime <= 0 or lifetime > limit:
        raise BlockedError(
            f"requested lifetime {lifetime}s exceeds maximum {limit}s for {action}", "expiry_too_long"
        )
    return {
        "context": context_for(action),
        "action": action.value,
        "subject": subject,
        "revision": revision,
        "scope": scope,
        "issued_at": issued_at,
        "expires_at": issued_at + lifetime,
        "nonce": secrets.token_hex(16),
        "key_id": key_id,
        "rationale": rationale,
    }


def display_text(payload: dict[str, Any]) -> str:
    """Exactly what will be signed, in readable form (§11.3: prompt shows the exact payload)."""
    return (
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
        + "\nsha256: "
        + canonical.digest(payload)
    )


class NonceLedger:
    """D-36 ledger. One-time nonces are consumed; standing nonces are bound to one payload hash."""

    def __init__(self, path: Path | None = None) -> None:
        self.path: Path = path or (state_dir() / "ledger" / "nonces.json")
        self.entries: dict[str, dict[str, Any]] = {}
        self.revoked: set[str] = set()
        if self.path.exists():
            raw = canonical.decode_strict(self.path.read_bytes())
            from .schema import validate

            validate(raw, "nonce-ledger")  # D-40: a malformed ledger fails closed before any check
            self.entries = dict(raw.get("nonces", {}))
            self.revoked = set(raw.get("revoked", []))

    def save(self, now: int) -> None:
        self.entries = {n: e for n, e in self.entries.items() if int(e["expires_at"]) > now - CLOCK_SKEW}
        from .schema import check_output

        body = {"nonces": self.entries, "revoked": sorted(self.revoked)}
        check_output(body, "nonce-ledger")
        atomic_write(self.path, canonical.encode(body))

    def check(self, nonce: str, payload_hash: str, one_time: bool) -> None:
        e = self.entries.get(nonce)
        if e is None:
            return
        if one_time:
            raise BlockedError("one-time approval nonce already consumed", "nonce_reused")
        if e["payload_hash"] != payload_hash:
            raise BlockedError("nonce is registered to a different payload", "nonce_rebound")

    def register(self, nonce: str, payload_hash: str, one_time: bool, expires_at: int) -> None:
        self.entries[nonce] = {"payload_hash": payload_hash, "one_time": one_time, "expires_at": expires_at}


@dataclass(frozen=True)
class Expectation:
    """What the consuming operation requires. Anything not matching is rejected (no cross-use)."""

    action: ApprovalAction
    subject: dict[str, str]
    revision: str
    required_scope: dict[str, Any] | None = None


def _scope_covers(granted: dict[str, Any], required: dict[str, Any]) -> bool:
    for key, needed in required.items():
        have = granted.get(key)
        if isinstance(needed, list):
            if not isinstance(have, list):
                return False
            enc = {canonical.digest(x) for x in have}
            if any(canonical.digest(x) not in enc for x in needed):
                return False
        elif have != needed:
            return False
    return True


def verify(
    approval: Approval,
    expect: Expectation,
    trust: TrustStore,
    ledger: NonceLedger,
    now: int,
    *,
    consume: bool,
) -> None:
    """Verify an approval immediately before use. Raises BlockedError on any failure.

    consume=True records the nonce (first acceptance / one-time consumption). Re-verifying a standing
    approval with consume=True is idempotent and never changes expiry or scope.
    """
    p = approval.payload
    action = expect.action
    if p.get("context") != context_for(action) or p.get("action") != action.value:
        raise BlockedError("approval context/action does not match the operation", "wrong_context")
    # D-45/D-47: only an operator-role key that lists this action may sign it; recovery keys never
    # produce ordinary signatures (their assertions go through sentinel.recovery only).
    key = trust.authorise(str(p.get("key_id")), action.value, now, role="operator")
    if not key.public.verify(approval.signature, approval.payload_bytes):
        raise BlockedError("approval signature invalid or payload altered", "bad_signature")
    check_binding_and_replay(p, approval.payload_hash, expect, ledger, now, consume=consume)


def check_binding_and_replay(
    p: dict[str, Any],
    payload_hash: str,
    expect: Expectation,
    ledger: NonceLedger,
    now: int,
    *,
    consume: bool,
) -> None:
    """Subject, revision, time window, D-37 lifetime, scope, revocation and D-36 nonce rules, shared by
    the operator-signature path (`verify`) and the recovery-assertion path (`sentinel.recovery`)."""
    action = expect.action
    approval_hash = payload_hash
    if p.get("subject") != expect.subject:
        raise BlockedError("approval subject does not match", "wrong_subject")
    if p.get("revision") != expect.revision:
        raise BlockedError("approval revision does not match", "wrong_revision")
    issued, expires = int(p["issued_at"]), int(p["expires_at"])
    if issued > now + CLOCK_SKEW:
        raise BlockedError("approval issued in the future", "future_issue")
    if now >= expires:
        raise BlockedError("approval expired", "expired")
    if expires - issued > max_expiry_for(action, p["scope"]):
        raise BlockedError("approval lifetime exceeds the D-37 maximum", "expiry_too_long")
    if expect.required_scope is not None and not _scope_covers(p["scope"], expect.required_scope):
        raise BlockedError("operation is outside the approved scope", "out_of_scope")
    if approval_hash in ledger.revoked:
        raise BlockedError("approval has been revoked", "revoked")
    one_time = action in ONE_TIME_ACTIONS
    ledger.check(str(p["nonce"]), approval_hash, one_time)
    if consume:
        ledger.register(str(p["nonce"]), approval_hash, one_time, expires)
        ledger.save(now)


def apply_revocation(
    revocation: Approval, target: Approval, trust: TrustStore, ledger: NonceLedger, now: int
) -> None:
    """Revoke a standing approval (or an authorisation record's approval) with a one-time
    `revoke_record` approval (§11.3.1, D-36).

    AUD-16: the revocation is bound to the target's payload hash (its ID) **and** to the target's own
    revision; a revocation signed for another revision, or carrying any placeholder revision, is refused.
    The target must itself be a well-formed approval signed by a registered operator key (any status:
    revoking something a since-revoked key approved must still be possible). Signed decisions use
    `decisions.revoke`, which additionally binds the entry hash.
    """
    if target.payload.get("action") not in {a.value for a in STANDING_ACTIONS}:
        raise BlockedError("only standing approvals can be revoked", "not_revocable")
    target_rev = target.payload.get("revision")
    if not isinstance(target_rev, str) or not target_rev.strip():
        raise BlockedError("target approval has no revision", "malformed_target")
    signer = trust.get(str(target.payload.get("key_id")))
    if signer is None or not signer.public.verify(target.signature, target.payload_bytes):
        raise BlockedError(
            "target is not an approval signed by a registered operator key", "malformed_target"
        )
    verify(
        revocation,
        Expectation(
            action=ApprovalAction.REVOKE_RECORD,
            subject={"type": "approval", "sha256": target.payload_hash},
            revision=target_rev,
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    ledger.revoked.add(target.payload_hash)
    ledger.save(now)


def load_approval_file(path: Path) -> Approval:
    return Approval.from_json(canonical.decode_strict(path.read_bytes()))


def save_approval_file(path: Path, approval: Approval) -> None:
    from .schema import check_output

    check_output(approval.to_json(), "approval")
    atomic_write(path, json.dumps(approval.to_json(), indent=1, sort_keys=True).encode())
