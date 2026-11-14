"""Trust administration: operator key enrolment, rotation and revocation (§11.2, D-16, D-27, D-36-D-38).

Every change needs a pre-signed approval made through operator presence. This module only verifies and
applies; it never creates an operator signature. Rules:

- Enrolment (bootstrap) only when the trust store is empty, with a `key.rotate` approval signed by the
  new key itself over its own identity (proof of possession). The owner must compare the printed public
  key fingerprint with an out-of-band record: a first key can't be authorised by anything else.
- Rotation adds a key, authorised by a one-time `key.rotate` approval from an active key. Revocation uses
  a one-time `key.revoke` approval. Both bind the current trust-store fingerprint, and the caller must
  state the fingerprint it expects, so a changed trust store is detected before anything is applied.
- The last active key can't be revoked (no further administration would be possible).
- Changes are refused when the caller is non-interactive or declares or shows an AI-agent environment.
  This is necessary but not sufficient (an agent can fake a terminal); the real control is the
  presence-backed signature, which an agent can't produce.
- Every attempt, accepted or refused, is appended to a hash-chained admin log whose entries are
  checkpointed with the run key (integrity relative to that key only, D-34).
"""

from __future__ import annotations

import base64
import binascii
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import approvals, canonical, recovery
from .crypto.signing import OPERATOR_ALGORITHMS, P256, Ed25519Signer, PublicKey
from .disclosure import AGENT_ENV_MARKERS
from .domain.enums import ApprovalAction
from .errors import BlockedError, ValidationError
from .evidence import AuditLog
from .keys.operator import (
    COSE_ES256,
    MAX_CREDENTIAL_ID,
    OPERATOR_ROLE,
    RECOVERY_ROLE,
    RECOVERY_RP_ID,
    ROLE_ACTIONS,
    OperatorKey,
    RecoveryCredential,
    TrustStore,
)
from .paths import ensure_private_dir, state_dir
from .recovery import RecoveryApproval

EMPTY_TRUST_FINGERPRINT = canonical.digest({"keys": []})
RECOVERY_KEY_FILE_FIELDS = {
    "key_id",
    "algorithm",
    "public_hex",
    "role",
    "credential_id_b64",
    "rp_id",
    "cose_alg",
}
MAX_OPERATOR_NAME = 128


def admin_log_path() -> Path:
    return ensure_private_dir(state_dir() / "history") / "admin-log.jsonl"


def require_human_channel(interactive: bool, env: Mapping[str, str], caller: str | None = None) -> None:
    """T16/D-27: trust-anchor changes are refused from agents and non-interactive sessions."""
    agents = sorted({name for var, name in AGENT_ENV_MARKERS.items() if env.get(var)})
    if caller is not None and caller not in ("operator",):
        agents.append(caller)
    if agents:
        raise BlockedError(
            f"trust-anchor changes are refused from an agent ({', '.join(agents)})", "agent_caller"
        )
    if not interactive:
        raise BlockedError("trust-anchor changes need an interactive operator session", "non_interactive")


@dataclass
class AdminContext:
    trust: TrustStore
    ledger: approvals.NonceLedger
    run_signer: Ed25519Signer
    now: int
    log_path: Path | None = None

    @property
    def log(self) -> AuditLog:
        return AuditLog(self.log_path or admin_log_path())

    def record(self, event: str, data: dict[str, Any]) -> None:
        self.log.append(event, data, self.run_signer, checkpoint=True)


@dataclass(frozen=True)
class CandidateKey:
    public: PublicKey
    role: str = OPERATOR_ROLE
    recovery: RecoveryCredential | None = None

    def as_trusted(self, operator: str, expires_at: int) -> OperatorKey:
        """D-45: the role's full permission set; recovery keys start with counter mode `unset` (OD-3)."""
        return OperatorKey(
            self.public.key_id,
            operator,
            self.public,
            "active",
            expires_at,
            self.role,
            ROLE_ACTIONS[self.role],
            self.recovery,
        )

    @property
    def public_sha256(self) -> str:
        return canonical.sha256_hex(self.public.public_raw)


def parse_key_file(data: Any) -> CandidateKey:
    """Public-only operator key file: exactly {key_id, algorithm, public_hex}.

    The legacy Secure Enclave metadata form (``handle_b64``, the rejected handle-on-disk design) is
    refused. Its private handle is never decoded, stored, imported or used."""
    from .schema import SchemaError, validate

    if isinstance(data, dict) and "handle_b64" in data:
        # Explicit classification only; the handle value is not read.
        raise SchemaError(
            "legacy Secure Enclave key metadata (handle-on-disk) is no longer accepted; convert it to "
            "{key_id, algorithm, public_hex} with public_hex = public_x963_hex (docs/m1/schemas.md)",
            "legacy_key_format",
        )
    validate(data, "operator-public-key")  # D-40: schema before any domain check, enrolment or rotation
    recovery: RecoveryCredential | None = None
    if isinstance(data, dict) and data.get("role") == RECOVERY_ROLE:
        if set(data) != RECOVERY_KEY_FILE_FIELDS or data["algorithm"] != P256:
            raise ValidationError(f"recovery key file must have exactly {sorted(RECOVERY_KEY_FILE_FIELDS)}")
        if data["rp_id"] != RECOVERY_RP_ID or data["cose_alg"] != COSE_ES256:
            raise ValidationError("recovery credentials must be ES256 for rp_id sentinel-recovery.invalid")
        try:
            cred = base64.b64decode(str(data["credential_id_b64"]), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValidationError("recovery credential id is not base64") from exc
        if not cred or len(cred) > MAX_CREDENTIAL_ID:
            raise ValidationError("recovery credential id has a bad length")
        recovery = RecoveryCredential(cred)
    elif not isinstance(data, dict) or set(data) != {"key_id", "algorithm", "public_hex"}:
        raise ValidationError("key file must have exactly key_id, algorithm and public_hex")
    if data["algorithm"] not in OPERATOR_ALGORITHMS:
        raise ValidationError("algorithm not allowed for operator keys")
    try:
        pub = PublicKey.from_raw(bytes.fromhex(str(data["public_hex"])), str(data["algorithm"]))
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"invalid public key: {exc}") from exc
    if pub.key_id != data["key_id"]:
        raise ValidationError("key_id does not match the public key")
    if recovery is not None:
        return CandidateKey(pub, RECOVERY_ROLE, recovery)
    return CandidateKey(pub)


def key_subject(key: CandidateKey) -> dict[str, str]:
    return {"type": "operator_key", "key_id": key.public.key_id, "public_sha256": key.public_sha256}


def _verify_any(
    ctx: AdminContext, approval: approvals.Approval | RecoveryApproval, expect: approvals.Expectation
) -> None:
    """Two separate verification paths (D-47): operator signatures and recovery assertions."""
    if isinstance(approval, RecoveryApproval):
        recovery.verify(approval, expect, ctx.trust, ctx.ledger, ctx.now, consume=True)
    else:
        approvals.verify(approval, expect, ctx.trust, ctx.ledger, ctx.now, consume=True)


def _check_name_and_expiry(operator: str, expires_at: int, now: int) -> None:
    if not operator.strip() or len(operator) > MAX_OPERATOR_NAME or "\x00" in operator:
        raise ValidationError("operator name must be 1-128 characters")
    if expires_at <= now:
        raise ValidationError("key expiry must be in the future")


def _check_trust_fingerprint(trust: TrustStore, expected: str) -> None:
    actual = trust.fingerprint()
    if expected != actual:
        raise BlockedError(
            f"trust store fingerprint is {actual}, not the expected {expected}", "trust_fingerprint_mismatch"
        )


def _refused(ctx: AdminContext, event: str, exc: BlockedError, data: dict[str, Any]) -> None:
    ctx.record(f"{event}.refused", {**data, "code": exc.code, "reason": exc.reason})


def enrol(
    ctx: AdminContext,
    key: CandidateKey,
    approval: approvals.Approval | RecoveryApproval,
    *,
    operator: str,
    expires_at: int,
) -> OperatorKey:
    data = {"key_id": key.public.key_id, "public_sha256": key.public_sha256}
    try:
        _check_name_and_expiry(operator, expires_at, ctx.now)
        if isinstance(approval, RecoveryApproval):
            raise BlockedError("enrolment needs a self-signed operator approval", "wrong_key_role")
        if ctx.trust.fingerprint() != EMPTY_TRUST_FINGERPRINT:
            raise BlockedError(
                "trust store already initialised; add keys only via key.rotate", "enrol_after_init"
            )
        if key.role != OPERATOR_ROLE:
            raise BlockedError(
                "the first key must be an operator key; recovery keys are added by key.rotate (D-45)",
                "action_not_permitted",
            )
        if approval.payload.get("key_id") != key.public.key_id:
            raise BlockedError("enrolment must be signed by the key being enrolled", "not_self_signed")
        candidate = key.as_trusted(operator, expires_at)
        with tempfile.TemporaryDirectory() as tmp:
            probe = TrustStore(Path(tmp) / "probe.json")
            probe.enrol(candidate)
            approvals.verify(
                approval,
                approvals.Expectation(
                    action=ApprovalAction.KEY_ROTATE,
                    subject=key_subject(key),
                    revision=f"trust:{EMPTY_TRUST_FINGERPRINT}",
                ),
                probe,
                ctx.ledger,
                ctx.now,
                consume=True,
            )
        ctx.trust.enrol(candidate)
    except BlockedError as exc:
        _refused(ctx, "key.enrol", exc, data)
        raise
    ctx.trust.save()
    ctx.record("key.enrol", {**data, "approval": approval.payload_hash, "trust": ctx.trust.fingerprint()})
    return candidate


def rotate(
    ctx: AdminContext,
    key: CandidateKey,
    approval: approvals.Approval | RecoveryApproval,
    *,
    operator: str,
    expires_at: int,
    expected_trust_fingerprint: str,
) -> OperatorKey:
    data = {"key_id": key.public.key_id, "public_sha256": key.public_sha256}
    try:
        _check_name_and_expiry(operator, expires_at, ctx.now)
        _check_trust_fingerprint(ctx.trust, expected_trust_fingerprint)
        if ctx.trust.get(key.public.key_id) is not None:
            raise BlockedError("key is already in the trust store", "duplicate_key")
        if approval.payload.get("key_id") == key.public.key_id:
            raise BlockedError("a new key can't authorise its own addition", "self_rotation")
        if isinstance(approval, RecoveryApproval) and key.role != OPERATOR_ROLE:
            raise BlockedError(
                "a recovery key may only enrol a replacement operator key (D-45)", "action_not_permitted"
            )
        _verify_any(
            ctx,
            approval,
            approvals.Expectation(
                action=ApprovalAction.KEY_ROTATE,
                subject=key_subject(key),
                revision=f"trust:{ctx.trust.fingerprint()}",
            ),
        )
    except BlockedError as exc:
        _refused(ctx, "key.rotate", exc, data)
        raise
    new = key.as_trusted(operator, expires_at)
    ctx.trust.apply_rotation(new)
    ctx.trust.save()
    ctx.record(
        "key.rotate",
        {
            **data,
            "approval": approval.payload_hash,
            "by": approval.payload["key_id"],
            "trust": ctx.trust.fingerprint(),
        },
    )
    return new


def revoke(
    ctx: AdminContext,
    key_id: str,
    approval: approvals.Approval | RecoveryApproval,
    *,
    expected_trust_fingerprint: str,
) -> None:
    data = {"key_id": key_id}
    try:
        _check_trust_fingerprint(ctx.trust, expected_trust_fingerprint)
        target = ctx.trust.get(key_id)
        if target is None:
            raise BlockedError(f"unknown operator key {key_id}", "unknown_key")
        if target.status != "active":
            raise BlockedError("key is already revoked", "already_revoked")
        # At least one active operator-role key must remain, so ordinary approvals stay possible.
        others = [k for k in ctx.trust.active_operator_keys(ctx.now) if k.key_id != key_id]
        if not others:
            raise BlockedError("refusing to revoke the last active operator key", "last_active_key")
        if approval.payload.get("key_id") == key_id:
            raise BlockedError("a key can't revoke itself (D-45, protocol R3.5)", "self_revocation")
        _verify_any(
            ctx,
            approval,
            approvals.Expectation(
                action=ApprovalAction.KEY_REVOKE,
                subject={"type": "operator_key", "key_id": key_id},
                revision=f"trust:{ctx.trust.fingerprint()}",
            ),
        )
    except BlockedError as exc:
        _refused(ctx, "key.revoke", exc, data)
        raise
    ctx.trust.apply_revocation(key_id)
    ctx.trust.save()
    ctx.record(
        "key.revoke",
        {
            **data,
            "approval": approval.payload_hash,
            "by": approval.payload["key_id"],
            "trust": ctx.trust.fingerprint(),
        },
    )
