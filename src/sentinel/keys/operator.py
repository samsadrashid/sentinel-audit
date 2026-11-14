"""Operator keys, trust store and user-presence providers (§11.2, D-16, D-27, D-38).

An operator signature is only ever produced by a PresenceProvider that obtains genuine user
presence from the host. The engine never holds an operator private key, and there is no software
fallback (D-38). If no provider is available, signing is refused (fail closed).

Provider status in M1:
- Apple Secure Enclave P-256 with a user-presence ACL is approved (D-38). The helper that drives it
  is not implemented yet, so `available_provider()` still fails closed on every host.
- FIDO2 Ed25519 authenticators: not implemented.

The trust store lists operator public keys with their algorithm. It is same-user writable (residual
risk, see docs/m1/implementation-audit.md AUD-05): reports should show its fingerprint so the owner
can compare it with an out-of-band record.
"""

from __future__ import annotations

import base64
import binascii
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from .. import canonical
from ..crypto.signing import OPERATOR_ALGORITHMS, P256, PublicKey
from ..errors import BlockedError, CapabilityUnavailable, ValidationError
from ..paths import atomic_write, state_dir

#: D-45 permitted actions per role, with `release.publish` added by D-74 (operator only). `signer.release`
#: and `registry.checkpoint` exist only on the signing device and are never accepted by the engine, so
#: they are not listed here.
OPERATOR_ROLE = "operator"
RECOVERY_ROLE = "recovery"
OPERATOR_ACTIONS: tuple[str, ...] = tuple(
    sorted(
        (
            "authorize_record",
            "revoke_record",
            "review.verify_no_evidence",
            "review.accept_risk",
            "suppress",
            "policy.change",
            "key.rotate",
            "key.revoke",
            "release.publish",
        )
    )
)
RECOVERY_ACTIONS: tuple[str, ...] = ("key.revoke", "key.rotate")
ROLE_ACTIONS = {OPERATOR_ROLE: OPERATOR_ACTIONS, RECOVERY_ROLE: RECOVERY_ACTIONS}
RECOVERY_RP_ID = "sentinel-recovery.invalid"  # OD-2: a reserved name that never resolves
COSE_ES256 = -7
COUNTER_MODES = ("unset", "zero", "increasing")
MAX_CREDENTIAL_ID = 1023


@dataclass(frozen=True)
class RecoveryCredential:
    """D-47 FIDO2 recovery credential (ES256 WebAuthn assertions only; never an operator signature)."""

    credential_id: bytes
    rp_id: str = RECOVERY_RP_ID
    cose_alg: int = COSE_ES256
    counter_mode: str = "unset"  # OD-3
    last_count: int = 0


@dataclass(frozen=True)
class OperatorKey:
    key_id: str
    operator: str
    public: PublicKey
    status: str  # "active" | "revoked" | "suspect" (recovery keys only, OD-3)
    expires_at: int  # unix seconds
    role: str = OPERATOR_ROLE
    permitted_actions: tuple[str, ...] = OPERATOR_ACTIONS
    recovery: RecoveryCredential | None = None

    def with_status(self, status: str) -> OperatorKey:
        return replace(self, status=status)


_BASE_FIELDS = {"key_id", "operator", "algorithm", "public", "status", "expires_at"}
_ROLE_FIELDS = _BASE_FIELDS | {"role", "permitted_actions"}
_RECOVERY_FIELDS = _ROLE_FIELDS | {"credential_id_b64", "rp_id", "cose_alg", "counter_mode", "last_count"}


def _recovery_from_json(k: dict[str, Any]) -> RecoveryCredential:
    try:
        cred = base64.b64decode(str(k["credential_id_b64"]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError("trust store: recovery credential id is not base64") from exc
    if not cred or len(cred) > MAX_CREDENTIAL_ID:
        raise ValidationError("trust store: bad recovery credential id length")
    if k["rp_id"] != RECOVERY_RP_ID or k["cose_alg"] != COSE_ES256:
        raise ValidationError("trust store: recovery keys must be ES256 for rp_id sentinel-recovery.invalid")
    if k["counter_mode"] not in COUNTER_MODES:
        raise ValidationError("trust store: bad recovery counter mode")
    n = k["last_count"]
    if not isinstance(n, int) or isinstance(n, bool) or not 0 <= n < 2**32:
        raise ValidationError("trust store: bad recovery counter")
    return RecoveryCredential(cred, RECOVERY_RP_ID, COSE_ES256, str(k["counter_mode"]), n)


def _key_from_json(k: Any) -> OperatorKey:
    if not isinstance(k, dict) or set(k) not in (_BASE_FIELDS, _ROLE_FIELDS, _RECOVERY_FIELDS):
        raise ValidationError("trust store entry has wrong fields")
    if k["algorithm"] not in OPERATOR_ALGORITHMS:
        raise ValidationError(f"trust store: algorithm {k['algorithm']!r} not allowed for operator keys")
    if not isinstance(k["expires_at"], int) or not isinstance(k["operator"], str):
        raise ValidationError("trust store: bad field types")
    try:
        pub = PublicKey.from_raw(bytes.fromhex(k["public"]), k["algorithm"])
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"trust store: invalid public key: {exc}") from exc
    if pub.key_id != k["key_id"]:
        raise ValidationError("trust store: key_id does not match public key")
    # Pre-D-45 entries (no role) are operator keys with the full operator permission set; they are
    # written back in the explicit form, which is what the fingerprint covers.
    role = k.get("role", OPERATOR_ROLE)
    if role not in ROLE_ACTIONS:
        raise ValidationError("trust store: unknown key role")
    actions = k.get("permitted_actions", list(ROLE_ACTIONS[role]))
    if (
        not isinstance(actions, list)
        or not actions
        or actions != sorted(set(actions))
        or not set(actions) <= set(ROLE_ACTIONS[role])
    ):
        raise ValidationError("trust store: permitted_actions must be a sorted subset of the role's actions")
    recovery = None
    if role == RECOVERY_ROLE:
        if set(k) != _RECOVERY_FIELDS or pub.algorithm != P256:
            raise ValidationError("trust store: recovery keys need ES256 credential fields")
        recovery = _recovery_from_json(k)
    elif set(k) == _RECOVERY_FIELDS:
        raise ValidationError("trust store: credential fields are only for recovery keys")
    allowed_status = ("active", "revoked", "suspect") if role == RECOVERY_ROLE else ("active", "revoked")
    if k["status"] not in allowed_status:
        raise ValidationError("trust store: bad key status")
    return OperatorKey(
        pub.key_id, k["operator"], pub, k["status"], k["expires_at"], role, tuple(actions), recovery
    )


def key_to_json(k: OperatorKey) -> dict[str, Any]:
    out: dict[str, Any] = {
        "key_id": k.key_id,
        "operator": k.operator,
        "algorithm": k.public.algorithm,
        "public": k.public.public_raw.hex(),
        "status": k.status,
        "expires_at": k.expires_at,
        "role": k.role,
        "permitted_actions": list(k.permitted_actions),
    }
    if k.recovery is not None:
        out |= {
            "credential_id_b64": base64.b64encode(k.recovery.credential_id).decode(),
            "rp_id": k.recovery.rp_id,
            "cose_alg": k.recovery.cose_alg,
            "counter_mode": k.recovery.counter_mode,
            "last_count": k.recovery.last_count,
        }
    return out


class TrustStore:
    """Operator public keys.

    After enrolment, changes happen only through key.rotate / key.revoke approvals.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path: Path = path or (state_dir() / "keys" / "operator-trust.json")
        self._keys: dict[str, OperatorKey] = {}
        if self.path.exists():
            raw = canonical.decode_strict(self.path.read_bytes())
            from ..schema import validate

            validate(raw, "trust-store")  # D-40: schema before any key is parsed or used
            if not isinstance(raw, dict) or set(raw) != {"keys"} or not isinstance(raw["keys"], list):
                raise ValidationError("trust store malformed")
            for entry in raw["keys"]:
                key = _key_from_json(entry)
                if key.key_id in self._keys:
                    raise ValidationError("trust store: duplicate key")
                self._keys[key.key_id] = key

    def _as_json(self) -> dict[str, Any]:
        """Explicit D-45 form: role and permitted actions are part of every entry and so of the
        fingerprint (D-49 item 2)."""
        return {"keys": [key_to_json(k) for k in sorted(self._keys.values(), key=lambda x: x.key_id)]}

    def fingerprint(self) -> str:
        return canonical.digest(self._as_json())

    def save(self) -> None:
        from ..schema import check_output

        check_output(self._as_json(), "trust-store")
        atomic_write(self.path, canonical.encode(self._as_json()))

    def get(self, key_id: str) -> OperatorKey | None:
        return self._keys.get(key_id)

    def enrol(self, key: OperatorKey) -> None:
        if self._keys:
            raise BlockedError(
                "trust store already initialised; add keys only via key.rotate", "enrol_after_init"
            )
        if key.public.algorithm not in OPERATOR_ALGORITHMS:
            raise BlockedError("algorithm not allowed for operator keys", "bad_algorithm")
        self._keys[key.key_id] = key

    def apply_rotation(self, new: OperatorKey) -> None:
        if new.public.algorithm not in OPERATOR_ALGORITHMS:
            raise BlockedError("operator keys must be ECDSA P-256 (D-47)", "bad_algorithm")
        self._keys[new.key_id] = new

    def apply_revocation(self, key_id: str) -> None:
        k = self._keys.get(key_id)
        if k:
            self._keys[key_id] = k.with_status("revoked")

    def update_recovery(self, key_id: str, credential: RecoveryCredential, *, suspect: bool = False) -> None:
        """Record the OD-3 counter state of a recovery key (and mark it suspect on rollback)."""
        k = self._keys[key_id]
        status = "suspect" if suspect else k.status
        self._keys[key_id] = replace(k, recovery=credential, status=status)

    def active_operator_keys(self, now: int) -> list[OperatorKey]:
        return [
            k
            for k in self._keys.values()
            if k.role == OPERATOR_ROLE and k.status == "active" and now < k.expires_at
        ]

    def authorise(self, key_id: str, action: str, now: int, *, role: str) -> OperatorKey:
        """D-45: the key must be usable, have the role this verification path serves, and list the action."""
        k = self.usable(key_id, now)
        if k.public.algorithm not in OPERATOR_ALGORITHMS:  # defence in depth; the loader refuses it too
            raise BlockedError("operator keys must be ECDSA P-256 (D-47)", "bad_algorithm")
        if k.role != role:
            raise BlockedError(
                f"key {key_id} has role {k.role!r}; this operation needs a {role!r} signature "
                "(operator signatures and recovery assertions are never interchangeable, D-47)",
                "wrong_key_role",
            )
        if action not in k.permitted_actions:
            raise BlockedError(
                f"action {action!r} is not permitted for key {key_id} (D-45)", "action_not_permitted"
            )
        return k

    def usable(self, key_id: str, now: int) -> OperatorKey:
        k = self._keys.get(key_id)
        if k is None:
            raise BlockedError(f"unknown operator key {key_id}", "unknown_key")
        if k.status == "suspect":
            raise BlockedError(
                f"recovery key {key_id} is suspect (OD-3); resolve it on the signing device", "suspect_key"
            )
        if k.status != "active":
            raise BlockedError(f"operator key {key_id} is revoked", "revoked_key")
        if now >= k.expires_at:
            raise BlockedError(f"operator key {key_id} has expired", "expired_key")
        return k


class PresenceProvider(Protocol):
    """Produces an operator signature after genuine user presence, showing `display` to the user."""

    name: str

    def sign_with_presence(self, message: bytes, display: str) -> tuple[str, bytes]:
        """Return (key_id, signature). Must raise if presence is not obtained."""
        ...


def available_provider() -> PresenceProvider:
    """Return an approved user-presence provider, or raise CapabilityUnavailable (fail closed, D-38).

    Delegates to the Secure Enclave production factory, which refuses until the native helper exists.
    """
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CapabilityUnavailable("operator-presence", "operator signing requires an interactive terminal")
    from .secure_enclave import production_provider

    return production_provider()
