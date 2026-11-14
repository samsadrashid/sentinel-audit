"""D-47 recovery WebAuthn assertion verification (engine side, D-49 item 3).

A recovery credential is a FIDO2 ES256 key used only through the signing device. It produces a WebAuthn
*assertion*, never a plain signature over the payload. This module is the only place that verifies one,
and it is deliberately separate from `approvals.verify`:

* an operator signature is never accepted here, and a recovery assertion is never accepted there;
* the key must have role `recovery` (D-45) and the action must be `key.rotate` or `key.revoke`;
* every check of signing-protocol-final-review §1.3 (exact client-data key set, type, challenge,
  origin, crossOrigin, rpIdHash, UP and UV set, AT and ED clear, 37-byte authenticator data), the
  credential ID, the OD-3 counter policy and the DER ECDSA P-256 signature over
  `authenticatorData || SHA-256(clientDataJSON)` must pass. Origin and RP ID are never relaxed.

The challenge is recomputed from the verifier's own copy of the payload:
``SHA-256("sentinel/v1/recovery-assertion" || 0x00 || canonical.encode(payload))``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any

from . import approvals, canonical
from .domain.enums import ApprovalAction
from .errors import BlockedError, ValidationError
from .keys.operator import RECOVERY_ROLE, OperatorKey, RecoveryCredential, TrustStore

CHALLENGE_PREFIX = b"sentinel/v1/recovery-assertion\x00"
AUTH_DATA_LEN = 37
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80
CLIENT_DATA_KEYSETS = ({"type", "challenge", "origin"}, {"type", "challenge", "origin", "crossOrigin"})
MAX_CLIENT_DATA = 1024
MAX_SIGNATURE = 80
WEBAUTHN_FIELDS = {"authenticator_data_b64", "client_data_json_b64", "credential_id_b64", "signature_der_b64"}
RECOVERY_ACTIONS = frozenset({ApprovalAction.KEY_ROTATE, ApprovalAction.KEY_REVOKE})


def challenge_for(payload: dict[str, Any]) -> bytes:
    return hashlib.sha256(CHALLENGE_PREFIX + canonical.encode(payload)).digest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64(value: Any, what: str, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2:
        raise ValidationError(f"recovery assertion: {what} must be a base64 string")
    try:
        out = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError(f"recovery assertion: {what} is not valid base64") from exc
    if not out or len(out) > limit:
        raise ValidationError(f"recovery assertion: {what} has a bad length")
    return out


@dataclass(frozen=True)
class RecoveryApproval:
    """A payload plus the WebAuthn assertion that the recovery credential produced over its challenge."""

    payload: dict[str, Any]
    authenticator_data: bytes
    client_data_json: bytes
    credential_id: bytes
    signature: bytes

    @property
    def payload_bytes(self) -> bytes:
        return canonical.encode(self.payload)

    @property
    def payload_hash(self) -> str:
        return canonical.sha256_hex(self.payload_bytes)

    def webauthn_json(self) -> dict[str, str]:
        return {
            "authenticator_data_b64": base64.b64encode(self.authenticator_data).decode(),
            "client_data_json_b64": base64.b64encode(self.client_data_json).decode(),
            "credential_id_b64": base64.b64encode(self.credential_id).decode(),
            "signature_der_b64": base64.b64encode(self.signature).decode(),
        }

    def to_json(self) -> dict[str, Any]:
        return {"payload": self.payload, "webauthn": self.webauthn_json()}

    @classmethod
    def from_parts(cls, payload: Any, webauthn: Any) -> RecoveryApproval:
        if not isinstance(webauthn, dict) or set(webauthn) != WEBAUTHN_FIELDS:
            raise ValidationError(f"recovery assertion must have exactly {sorted(WEBAUTHN_FIELDS)}")
        # The payload passes the same strict approval loader as any approval (schema, D-42, nonce form).
        approvals.Approval.from_json({"payload": payload, "signature": "AA=="})
        return cls(
            dict(payload),
            _b64(webauthn["authenticator_data_b64"], "authenticator data", 64),
            _b64(webauthn["client_data_json_b64"], "client data", MAX_CLIENT_DATA),
            _b64(webauthn["credential_id_b64"], "credential id", 1023),
            _b64(webauthn["signature_der_b64"], "signature", MAX_SIGNATURE),
        )

    @classmethod
    def from_json(cls, data: Any) -> RecoveryApproval:
        from .schema import validate

        validate(data, "recovery-approval")  # D-40: schema before any domain check
        return cls.from_parts(data["payload"], data["webauthn"])


def load_any(data: Any) -> approvals.Approval | RecoveryApproval:
    """Dispatch on the exact key set: an operator approval or a recovery approval, never both."""
    if isinstance(data, dict) and set(data) == {"payload", "webauthn"}:
        return RecoveryApproval.from_json(data)
    return approvals.Approval.from_json(data)


def _client_data(raw: bytes, payload: dict[str, Any], rp_id: str) -> None:
    try:
        text = raw.decode("utf-8")
        cd = json.loads(text, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BlockedError("recovery client data is not strict UTF-8 JSON", "bad_client_data") from exc
    if not isinstance(cd, dict) or set(cd) not in CLIENT_DATA_KEYSETS:
        raise BlockedError("recovery client data has unexpected keys", "bad_client_data")
    if cd["type"] != "webauthn.get":
        raise BlockedError("recovery client data type must be webauthn.get", "bad_client_data")
    if cd["challenge"] != b64url(challenge_for(payload)):
        raise BlockedError("recovery assertion challenge does not bind this payload", "bad_challenge")
    if cd["origin"] != "https://" + rp_id:
        raise BlockedError("recovery assertion origin is not exactly https://" + rp_id, "bad_origin")
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        raise BlockedError("recovery assertion must not be cross-origin", "bad_origin")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _authenticator_data(raw: bytes, rp_id: str) -> int:
    if len(raw) != AUTH_DATA_LEN:
        raise BlockedError("recovery authenticator data must be exactly 37 bytes", "bad_authenticator_data")
    if raw[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise BlockedError("recovery authenticator data is for another RP ID", "bad_rp_id")
    flags = raw[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise BlockedError("recovery assertion needs user presence and verification", "presence_missing")
    if flags & (FLAG_AT | FLAG_ED):
        raise BlockedError("recovery assertion must not carry attested data or extensions", "bad_flags")
    return int(struct.unpack(">I", raw[33:37])[0])


def next_counter(cred: RecoveryCredential, n: int) -> tuple[RecoveryCredential, str | None]:
    """OD-3. Returns the new credential state and a rejection code (None if accepted)."""
    s = cred.last_count
    if cred.counter_mode == "unset":
        mode = "zero" if n == 0 else "increasing"
        return RecoveryCredential(cred.credential_id, cred.rp_id, cred.cose_alg, mode, n), None
    if cred.counter_mode == "zero":
        if n == 0:
            return cred, None
        return cred, "counter_mode_changed"
    if n > s:
        return RecoveryCredential(cred.credential_id, cred.rp_id, cred.cose_alg, "increasing", n), None
    return cred, ("counter_not_increasing" if n == s else "counter_rollback")


SUSPECT_CODES = frozenset({"counter_rollback", "counter_mode_changed"})


def check_assertion(ap: RecoveryApproval, key: OperatorKey) -> int:
    """Static WebAuthn checks (no state change). Returns the assertion's signature counter."""
    cred = key.recovery
    if key.role != RECOVERY_ROLE or cred is None:
        raise BlockedError("a recovery assertion needs a recovery-role key (D-45, D-47)", "wrong_key_role")
    if ap.credential_id != cred.credential_id:
        raise BlockedError("recovery assertion names another credential", "wrong_credential")
    _client_data(ap.client_data_json, ap.payload, cred.rp_id)
    count = _authenticator_data(ap.authenticator_data, cred.rp_id)
    signed = ap.authenticator_data + hashlib.sha256(ap.client_data_json).digest()
    if not key.public.verify(ap.signature, signed):
        raise BlockedError("recovery assertion signature does not verify", "bad_signature")
    return count


def verify(
    ap: RecoveryApproval,
    expect: approvals.Expectation,
    trust: TrustStore,
    ledger: approvals.NonceLedger,
    now: int,
    *,
    consume: bool,
) -> None:
    """Verify a recovery approval immediately before use. The caller saves the trust store afterwards
    (the OD-3 counter state is updated in memory); a counter rollback marks the key suspect and saves."""
    p = ap.payload
    action = expect.action
    if action not in RECOVERY_ACTIONS:
        raise BlockedError(f"recovery keys may not authorise {action} (D-45)", "action_not_permitted")
    if p.get("context") != approvals.context_for(action) or p.get("action") != action.value:
        raise BlockedError("approval context/action does not match the operation", "wrong_context")
    key = trust.authorise(str(p.get("key_id")), action.value, now, role=RECOVERY_ROLE)
    count = check_assertion(ap, key)
    assert key.recovery is not None
    updated, problem = next_counter(key.recovery, count)
    if problem is not None:
        if problem in SUSPECT_CODES:
            trust.update_recovery(key.key_id, key.recovery, suspect=True)
            trust.save()
        raise BlockedError(f"recovery assertion counter check failed ({problem}, OD-3)", problem)
    approvals.check_binding_and_replay(p, ap.payload_hash, expect, ledger, now, consume=consume)
    if consume:
        trust.update_recovery(key.key_id, updated)
