"""Signing protocol v1, engine (development Mac) side: request emission and response reception (D-49 (4)).

The engine never signs operator payloads. It writes a canonical *sign request* for an unsigned payload to
a transfer volume, remembers the request as pending, and later reads the signing device's *response*.
A response carries no authority (protocol §1.3): the engine verifies the returned signature or recovery
assertion over **its own pending payload**, with the enrolled public key, and only then stores an
approval file. Every use of that approval is verified again at use time (`approvals.verify` or
`recovery.verify`), exactly like any other approval.

Transport (protocol §6): ``<volume>/sentinel-v1/to-signer/req-<request_id>.json`` and
``<volume>/sentinel-v1/from-signer/resp-<request_id>.json``. Files are written atomically and read with
symlink, special-file, hard-link and size refusal. Nothing on the volume is trusted.

This module does not implement the signing device, its registry, its display or its hardware; those are
outside M1 (D-49). Production signing stays disabled.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import approvals, canonical, recovery
from .domain.enums import ApprovalAction
from .errors import BlockedError, IntegrityError, ValidationError
from .keys.operator import OPERATOR_ROLE, RECOVERY_ROLE, TrustStore
from .paths import atomic_write, ensure_private_dir, state_dir

REQUEST_ENVELOPE = "sentinel/v1/sign-request"
RESPONSE_ENVELOPE = "sentinel/v1/sign-response"
ROOT_DIR = "sentinel-v1"
TO_SIGNER = "to-signer"
FROM_SIGNER = "from-signer"
MAX_REQUEST = 16_384
MAX_RESPONSE = 2_048
MAX_RESPONSES_PER_RECEIVE = 16
REQUEST_NAME = re.compile(r"^req-([0-9a-f]{32})\.json$")
RESPONSE_NAME = re.compile(r"^resp-([0-9a-f]{32})\.json$")
RESPONSE_KEYS_OPERATOR = {"envelope", "key_id", "payload_sha256", "request_id", "signature_der_b64"}
RESPONSE_KEYS_RECOVERY = {"envelope", "key_id", "payload_sha256", "request_id", "webauthn"}


def pending_dir() -> Path:
    return ensure_private_dir(state_dir() / "signing" / "pending")


def received_dir() -> Path:
    return ensure_private_dir(state_dir() / "signing" / "approvals")


def _printable_ascii(value: Any, where: str = "payload") -> None:
    """Protocol §2: every string is printable ASCII (0x20-0x7E); the device refuses anything else."""
    if isinstance(value, str):
        if any(not 0x20 <= ord(c) <= 0x7E for c in value):
            raise ValidationError(f"{where}: strings must be printable ASCII for the signing device")
    elif isinstance(value, dict):
        for k, v in value.items():
            _printable_ascii(k, where)
            _printable_ascii(v, f"{where}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _printable_ascii(v, f"{where}[{i}]")


def _strict_canonical(raw: bytes, what: str) -> Any:
    """Protocol §2 validity test: decode, then re-encode must reproduce the bytes exactly."""
    data = canonical.decode_strict(raw, max_bytes=MAX_REQUEST)
    if canonical.encode(data) != raw:
        raise IntegrityError(f"{what} is not canonical JSON")
    return data


def _safe_dir(path: Path, what: str) -> Path:
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise ValidationError(f"{what} not found: {path}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise IntegrityError(f"{what} must be a real directory, not a link or file")
    return path


def _volume_dir(volume: Path, sub: str, *, create: bool) -> Path:
    root = _safe_dir(Path(volume), "transfer volume")
    base = root / ROOT_DIR
    if create and not os.path.lexists(base):
        os.mkdir(base, 0o755)
    _safe_dir(base, ROOT_DIR)
    d = base / sub
    if create and not os.path.lexists(d):
        os.mkdir(d, 0o755)
    return _safe_dir(d, f"{ROOT_DIR}/{sub}")


def _write_exclusive(directory: Path, name: str, body: bytes) -> Path:
    """Atomic, no-overwrite write: O_EXCL temp file, fsync, rename (refused if the name exists)."""
    final = directory / name
    if os.path.lexists(final):
        raise BlockedError(f"{name} already exists on the transfer volume", "duplicate_request")
    tmp = directory / f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.path.lexists(final):
        os.unlink(tmp)
        raise BlockedError(f"{name} already exists on the transfer volume", "duplicate_request")
    os.rename(tmp, final)
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return final


def read_untrusted(path: Path, limit: int) -> bytes:
    """Protocol §6.2/§6.4: no symlinks, regular file only, one link, size within the limit."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise IntegrityError(f"refusing {path.name}: not a plain readable file ({exc.strerror})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise IntegrityError(f"refusing {path.name}: not a regular single-link file")
        if st.st_size == 0 or st.st_size > limit:
            raise IntegrityError(f"refusing {path.name}: size {st.st_size} outside 1..{limit} bytes")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if not data or len(data) > limit:
        raise IntegrityError(f"refusing {path.name}: truncated or oversized")
    return data


@dataclass(frozen=True)
class Pending:
    request_id: str
    payload: dict[str, Any]
    payload_sha256: str
    emitted_at: int
    state: str
    #: First enrolment only: the candidate key's public X9.63 bytes (hex). The trust store is empty, so the
    #: response is checked against this key; `key enrol` then verifies the approval again, in full.
    enrol_public_hex: str | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "request_id": self.request_id,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "emitted_at": self.emitted_at,
            "state": self.state,
        }
        if self.enrol_public_hex is not None:
            out["enrol_public_hex"] = self.enrol_public_hex
        return out


def _pending_path(request_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ValidationError("bad request id")
    return pending_dir() / f"{request_id}.json"


def load_pending(request_id: str) -> Pending | None:
    from .schema import validate

    p = _pending_path(request_id)
    if not p.exists():
        return None
    raw = canonical.decode_strict(p.read_bytes())
    validate(raw, "pending-request")
    assert isinstance(raw, dict)
    if canonical.sha256_hex(canonical.encode(raw["payload"])) != raw["payload_sha256"]:
        raise IntegrityError("pending request record does not match its payload")
    return Pending(
        raw["request_id"],
        raw["payload"],
        raw["payload_sha256"],
        raw["emitted_at"],
        raw["state"],
        raw.get("enrol_public_hex"),
    )


def _save_pending(p: Pending) -> None:
    from .schema import check_output

    check_output(p.to_json(), "pending-request")
    atomic_write(_pending_path(p.request_id), canonical.encode(p.to_json()))


def _check_enrolment(payload: dict[str, Any], key: Any, trust: TrustStore) -> None:
    """The one request a not-yet-trusted key may sign: its own enrolment into an empty trust store."""
    from .admin import EMPTY_TRUST_FINGERPRINT, key_subject

    if trust.fingerprint() != EMPTY_TRUST_FINGERPRINT:
        raise BlockedError(
            "trust store already initialised; enrolment requests are refused", "enrol_after_init"
        )
    if key.role != OPERATOR_ROLE:
        raise BlockedError("the first key must be an operator key (D-45)", "action_not_permitted")
    if (
        payload.get("action") != ApprovalAction.KEY_ROTATE.value
        or payload.get("key_id") != key.public.key_id
        or payload.get("subject") != key_subject(key)
        or payload.get("revision") != f"trust:{EMPTY_TRUST_FINGERPRINT}"
    ):
        raise BlockedError(
            "an enrolment request must be the key's own self-signed key.rotate into the empty trust store",
            "not_self_signed",
        )


def emit_request(
    payload: Any, volume: Path, trust: TrustStore, now: int, enrol_key: Any = None
) -> dict[str, Any]:
    """Write a sign request for an unsigned payload. Nothing is signed; no nonce is registered.

    `enrol_key` (an `admin.CandidateKey`) is only for the first enrolment (ceremony step 6): the key isn't
    trusted yet, so the request records its public key for checking the response."""
    from .schema import check_output, validate

    validate({"payload": payload, "signature": "AA=="}, "approval")  # D-40: same payload contract
    approvals.Approval.from_json({"payload": payload, "signature": "AA=="})  # D-42 / nonce form checks
    assert isinstance(payload, dict)
    _printable_ascii(payload)
    action = ApprovalAction(payload["action"])
    # Engine-side D-45 pre-check, so a request the device must refuse is never emitted.
    if enrol_key is not None:
        _check_enrolment(payload, enrol_key, trust)
        role = OPERATOR_ROLE
    else:
        key = trust.get(str(payload["key_id"]))
        role = key.role if key is not None else OPERATOR_ROLE
        trust.authorise(str(payload["key_id"]), action.value, now, role=role)
    if int(payload["expires_at"]) <= now:
        raise BlockedError("payload has already expired", "expired")
    request_id = secrets.token_hex(16)
    digest = canonical.sha256_hex(canonical.encode(payload))
    request = {
        "envelope": REQUEST_ENVELOPE,
        "payload": payload,
        "payload_sha256": digest,
        "request_id": request_id,
    }
    check_output(request, "sign-request")
    body = canonical.encode(request)
    if len(body) > MAX_REQUEST:
        raise ValidationError(f"sign request exceeds {MAX_REQUEST} bytes")
    pending = Pending(
        request_id,
        payload,
        digest,
        now,
        "pending",
        enrol_key.public.public_raw.hex() if enrol_key is not None else None,
    )
    _save_pending(pending)  # recorded before the file leaves, so a response can always be matched
    out = _write_exclusive(_volume_dir(volume, TO_SIGNER, create=True), f"req-{request_id}.json", body)
    return {"request_id": request_id, "payload_sha256": digest, "file": str(out), "role": role}


def _parse_response(raw: bytes) -> dict[str, Any]:
    from .schema import validate

    data = _strict_canonical(raw, "sign response")
    validate(data, "sign-response")  # D-40: exact key set, exactly one signature form
    assert isinstance(data, dict)
    if set(data) not in (RESPONSE_KEYS_OPERATOR, RESPONSE_KEYS_RECOVERY):
        raise IntegrityError("sign response has an unexpected key set")
    return data


def _approval_from_response(
    resp: dict[str, Any], pending: Pending, trust: TrustStore, now: int
) -> approvals.Approval | recovery.RecoveryApproval:
    action = ApprovalAction(pending.payload["action"])
    if resp["key_id"] != pending.payload["key_id"]:
        raise BlockedError("response is signed by a different key than the request names", "key_mismatch")
    if pending.enrol_public_hex is not None:
        return _enrolment_approval(resp, pending, trust)
    if "webauthn" in resp:
        key = trust.authorise(resp["key_id"], action.value, now, role=RECOVERY_ROLE)
        rap = recovery.RecoveryApproval.from_parts(pending.payload, resp["webauthn"])
        recovery.check_assertion(rap, key)  # counter (OD-3) is applied when the approval is used
        return rap
    key = trust.authorise(resp["key_id"], action.value, now, role=OPERATOR_ROLE)
    try:
        sig = base64.b64decode(resp["signature_der_b64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IntegrityError("response signature is not valid base64") from exc
    if not sig or len(sig) > 128 or not key.public.verify(sig, canonical.encode(pending.payload)):
        raise BlockedError("response signature does not verify over the pending payload", "bad_signature")
    return approvals.Approval(pending.payload, sig)


def _enrolment_approval(resp: dict[str, Any], pending: Pending, trust: TrustStore) -> approvals.Approval:
    """Check a first-enrolment response against the candidate key recorded at emission. This stores the
    approval only; `key enrol` verifies it again, in full, before anything is trusted."""
    from .admin import CandidateKey
    from .crypto.signing import P256, PublicKey

    if "webauthn" in resp:
        raise BlockedError("an enrolment is signed by the operator key itself", "wrong_key_role")
    try:
        key = CandidateKey(PublicKey.from_raw(bytes.fromhex(str(pending.enrol_public_hex)), P256))
    except (ValueError, TypeError) as exc:
        raise IntegrityError("pending enrolment key is invalid") from exc
    _check_enrolment(pending.payload, key, trust)
    try:
        sig = base64.b64decode(resp["signature_der_b64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IntegrityError("response signature is not valid base64") from exc
    verified = bool(sig) and len(sig) <= 128 and key.public.verify(sig, canonical.encode(pending.payload))
    if not verified:
        raise BlockedError("enrolment response does not verify with the candidate key", "bad_signature")
    return approvals.Approval(pending.payload, sig)


def _remove_transferred(from_dir: Path, name: str, rid: str) -> None:
    """Protocol §6.4 cleanup. Only plain files inside verified (non-link) volume directories are removed;
    a link anywhere on the path leaves everything in place."""
    targets = [from_dir / name]
    to_dir = from_dir.parent / TO_SIGNER
    try:
        _safe_dir(to_dir, f"{ROOT_DIR}/{TO_SIGNER}")
        targets.append(to_dir / f"req-{rid}.json")
    except (IntegrityError, ValidationError):
        pass
    for f in targets:
        if os.path.lexists(f) and not os.path.islink(f) and os.path.isfile(f):
            os.unlink(f)


def receive_responses(volume: Path, trust: TrustStore, now: int) -> list[dict[str, Any]]:
    """Read every response on the volume. Each is verified against its own pending request; valid ones
    become approval files in engine state; the matching request and response files are then removed
    from the volume. Invalid responses are reported and left untouched."""
    directory = _volume_dir(volume, FROM_SIGNER, create=False)
    names = sorted(n for n in os.listdir(directory) if RESPONSE_NAME.match(n))
    if len(names) > MAX_RESPONSES_PER_RECEIVE:
        raise BlockedError(
            f"more than {MAX_RESPONSES_PER_RECEIVE} responses on the volume", "too_many_responses"
        )
    results: list[dict[str, Any]] = []
    for name in names:
        m = RESPONSE_NAME.match(name)
        assert m is not None
        rid = m.group(1)
        try:
            resp = _parse_response(read_untrusted(directory / name, MAX_RESPONSE))
            if resp["request_id"] != rid:
                raise IntegrityError("response file name does not match its request_id")
            pending = load_pending(rid)
            if pending is None or pending.state != "pending":
                raise BlockedError("response for an unknown or already received request", "unknown_request")
            if resp["payload_sha256"] != pending.payload_sha256:
                raise BlockedError("response is for different payload bytes", "payload_mismatch")
            ap = _approval_from_response(resp, pending, trust, now)
            out = received_dir() / f"{rid}.approval.json"
            body = ap.to_json()
            from .schema import check_output

            check_output(
                body, "recovery-approval" if isinstance(ap, recovery.RecoveryApproval) else "approval"
            )
            atomic_write(out, canonical.encode(body))
            _save_pending(
                Pending(
                    rid,
                    pending.payload,
                    pending.payload_sha256,
                    pending.emitted_at,
                    "received",
                    pending.enrol_public_hex,
                )
            )
            _remove_transferred(directory, name, rid)
            results.append(
                {
                    "request_id": rid,
                    "status": "received",
                    "approval": str(out),
                    "action": pending.payload["action"],
                }
            )
        except (BlockedError, IntegrityError, ValidationError) as exc:
            code = getattr(exc, "code", None) or type(exc).__name__
            results.append(
                {"request_id": rid, "status": "refused", "code": str(code), "reason": str(exc)[:300]}
            )
    return results
