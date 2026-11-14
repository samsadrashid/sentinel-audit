"""Secure Enclave operator-signing integration boundary (D-38). Python side only.

Status: the native helper does not exist yet (see docs/m1/se-helper-contract.md). The production
factory therefore always fails closed. Nothing in this module produces a signature by itself:
signatures come only from a `SigningBackend`, and only a backend whose `genuine_hardware` is True
may be used outside tests.

Trust rules enforced here, independent of what a backend returns:
- the backend's key handle must belong to registered, validated metadata whose key ID is recomputed
  from the algorithm and public key;
- the key must be active, unexpired and present in the operator trust store with the same public key;
- the backend must report the SHA-256 of the exact bytes it signed, and it must match the canonical
  payload the operator was shown;
- the returned signature is verified against the registered public key before it is accepted;
- every approval asks the backend again: nothing is cached or reused;
- operator signing refuses to run without an interactive terminal (a necessary but not sufficient
  check; the genuine control is the hardware user-presence prompt, which a fake backend cannot give).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .. import approvals, canonical
from ..crypto.signing import P256, PublicKey, key_id_for
from ..domain.enums import ApprovalAction
from ..errors import BlockedError, CapabilityUnavailable, ValidationError
from ..paths import atomic_write, state_dir
from .operator import OperatorKey, TrustStore

BACKEND_NAME = "apple-secure-enclave"
MAX_HANDLE_BYTES = 4096
MAX_SIGNATURE_BYTES = 80  # DER ECDSA P-256 is at most 72 bytes
SIGN_TIMEOUT_S = 120
MAX_MESSAGE_BYTES = 65536  # helper refuses larger stdin (contract §4)
MAX_HELPER_OUTPUT = 8192

#: Error codes a backend may report (contract §4). Anything else is treated as malformed.
BACKEND_ERRORS = {
    "cancelled": "operator cancelled the user-presence prompt",
    "timeout": "user-presence prompt timed out",
    "auth_failed": "user-presence authentication failed",
    "no_secure_enclave": "Secure Enclave unavailable on this host",
    "key_unusable": "the Secure Enclave key handle could not be used on this device",
    "not_interactive": "no interactive session available for the user-presence prompt",
}


@dataclass(frozen=True)
class SecureEnclaveKeyMetadata:
    key_id: str
    algorithm: str
    public_x963: bytes
    handle: bytes
    backend: str
    created_at: int

    @property
    def public(self) -> PublicKey:
        return PublicKey(self.key_id, self.algorithm, self.public_x963)

    @classmethod
    def from_json(cls, data: Any) -> SecureEnclaveKeyMetadata:
        fields = {"key_id", "algorithm", "public_x963_hex", "handle_b64", "backend", "created_at"}
        if not isinstance(data, dict) or set(data) != fields:
            raise ValidationError(f"key metadata must have exactly {sorted(fields)}")
        if data["algorithm"] != P256:
            raise ValidationError("Secure Enclave operator keys must be ECDSA P-256 (D-38)")
        if data["backend"] != BACKEND_NAME:
            raise ValidationError("key metadata names an unknown backend")
        if not isinstance(data["created_at"], int) or isinstance(data["created_at"], bool):
            raise ValidationError("created_at must be an integer")
        try:
            pub = PublicKey.from_raw(bytes.fromhex(data["public_x963_hex"]), P256)
            handle = base64.b64decode(data["handle_b64"], validate=True)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ValidationError(f"invalid key metadata: {exc}") from exc
        if pub.key_id != data["key_id"]:
            raise ValidationError("key_id does not match the public key")
        if not handle or len(handle) > MAX_HANDLE_BYTES:
            raise ValidationError("invalid key handle size")
        return cls(pub.key_id, P256, pub.public_raw, handle, BACKEND_NAME, data["created_at"])

    def to_json(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_x963_hex": self.public_x963.hex(),
            "handle_b64": base64.b64encode(self.handle).decode(),
            "backend": self.backend,
            "created_at": self.created_at,
        }


class KeyMetadataStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or (state_dir() / "keys" / "secure-enclave")

    def _path(self, key_id: str) -> Path:
        if (
            not key_id.startswith("p256:")
            or len(key_id) != 37
            or not all(c in "0123456789abcdef" for c in key_id[5:])
        ):
            raise ValidationError("bad key id")
        return self.root / (key_id.replace(":", "-") + ".json")

    def save(self, meta: SecureEnclaveKeyMetadata) -> None:
        atomic_write(self._path(meta.key_id), canonical.encode(meta.to_json()))

    def load(self, key_id: str) -> SecureEnclaveKeyMetadata:
        p = self._path(key_id)
        if not p.exists():
            raise BlockedError(f"no metadata for operator key {key_id}", "unknown_key")
        meta = SecureEnclaveKeyMetadata.from_json(canonical.decode_strict(p.read_bytes()))
        if meta.key_id != key_id:
            raise ValidationError("metadata file holds a different key")
        return meta


class SigningBackend(Protocol):
    """A user-presence signing backend. `genuine_hardware` is True only for the real native helper."""

    genuine_hardware: bool

    def sign(self, handle: bytes, message: bytes, reason: str, timeout_s: int) -> dict[str, Any]: ...


def register_key(
    meta: SecureEnclaveKeyMetadata,
    trust: TrustStore,
    store: KeyMetadataStore,
    *,
    operator: str,
    expires_at: int,
) -> None:
    """Bootstrap enrolment of the first operator key (trust store must be empty)."""
    expected = key_id_for(P256, meta.public_x963)
    if meta.key_id != expected or meta.algorithm != P256:
        raise ValidationError("key identity binding failed")
    trust.enrol(OperatorKey(meta.key_id, operator, meta.public, "active", expires_at))
    store.save(meta)
    trust.save()


class SecureEnclaveProvider:
    name = "secure-enclave"

    def __init__(
        self,
        meta: SecureEnclaveKeyMetadata,
        trust: TrustStore,
        backend: SigningBackend,
        *,
        now: Callable[[], int],
        interactive: Callable[[], bool] | None = None,
        allow_test_backend: bool = False,
    ) -> None:
        if not backend.genuine_hardware and not allow_test_backend:
            raise CapabilityUnavailable("operator-presence", "refusing a non-hardware signing backend (D-38)")
        self.meta, self.trust, self.backend, self.now = meta, trust, backend, now
        self.interactive = interactive or (lambda: sys.stdin.isatty() and sys.stdout.isatty())

    @property
    def hardware_backed(self) -> bool:
        return self.backend.genuine_hardware

    def sign_with_presence(self, message: bytes, display: str) -> tuple[str, bytes]:
        if not self.interactive():
            raise CapabilityUnavailable(
                "operator-presence", "operator signing requires an interactive terminal"
            )
        key = self.trust.usable(self.meta.key_id, self.now())
        if key.public.algorithm != P256 or key.public.public_raw != self.meta.public_x963:
            raise BlockedError(
                "trust store key does not match the Secure Enclave key metadata", "key_mismatch"
            )
        digest = canonical.sha256_hex(message)
        reason = f"Sentinel: approve operator action. Payload SHA-256 {digest[:16]}"
        resp = self.backend.sign(self.meta.handle, message, reason, SIGN_TIMEOUT_S)
        if not isinstance(resp, dict):
            raise BlockedError("malformed backend response", "backend_malformed")
        if set(resp) == {"error"} or "error" in resp:
            code = resp.get("error")
            if code not in BACKEND_ERRORS or set(resp) - {"error", "message"}:
                raise BlockedError("malformed backend error response", "backend_malformed")
            raise BlockedError(BACKEND_ERRORS[str(code)], f"presence_{code}")
        if set(resp) != {"signature_der_b64", "message_sha256", "key_id"}:
            raise BlockedError("malformed backend response", "backend_malformed")
        if resp["key_id"] != self.meta.key_id:
            raise BlockedError("backend signed with a different key", "key_mismatch")
        if resp["message_sha256"] != digest:
            raise BlockedError("backend signed different bytes than the payload shown", "payload_mismatch")
        try:
            sig = base64.b64decode(str(resp["signature_der_b64"]), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BlockedError("malformed signature encoding", "backend_malformed") from exc
        if not sig or len(sig) > MAX_SIGNATURE_BYTES or not key.public.verify(sig, message):
            raise BlockedError("signature does not verify against the registered public key", "bad_signature")
        return self.meta.key_id, sig


def sign_payload(
    provider: SecureEnclaveProvider, payload: dict[str, Any], show: Callable[[str], None]
) -> approvals.Approval:
    """Show the exact canonical payload, then obtain a fresh user-presence signature over those bytes."""
    if payload.get("key_id") != provider.meta.key_id:
        raise BlockedError("payload names a different key", "key_mismatch")
    message = canonical.encode(payload)
    show(approvals.display_text(payload))
    _, sig = provider.sign_with_presence(message, approvals.display_text(payload))
    return approvals.Approval(payload, sig)


def rotate_key(
    approval: approvals.Approval,
    new: SecureEnclaveKeyMetadata,
    trust: TrustStore,
    store: KeyMetadataStore,
    ledger: approvals.NonceLedger,
    now: int,
    *,
    operator: str,
    expires_at: int,
) -> None:
    """Add a new operator key, authorised by a one-time key.rotate approval from an active key."""
    if new.key_id != key_id_for(P256, new.public_x963):
        raise ValidationError("key identity binding failed")
    approvals.verify(
        approval,
        approvals.Expectation(
            action=ApprovalAction.KEY_ROTATE,
            subject={
                "type": "operator_key",
                "key_id": new.key_id,
                "public_sha256": canonical.sha256_hex(new.public_x963),
            },
            revision=f"trust:{trust.fingerprint()}",
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    trust.apply_rotation(OperatorKey(new.key_id, operator, new.public, "active", expires_at))
    store.save(new)
    trust.save()


def revoke_key(
    approval: approvals.Approval, key_id: str, trust: TrustStore, ledger: approvals.NonceLedger, now: int
) -> None:
    """Revoke an operator key with a one-time key.revoke approval from an active key."""
    if trust.get(key_id) is None:
        raise BlockedError(f"unknown operator key {key_id}", "unknown_key")
    approvals.verify(
        approval,
        approvals.Expectation(
            action=ApprovalAction.KEY_REVOKE,
            subject={"type": "operator_key", "key_id": key_id},
            revision=f"trust:{trust.fingerprint()}",
        ),
        trust,
        ledger,
        now,
        consume=True,
    )
    trust.apply_revocation(key_id)
    trust.save()


class NativeHelperBackend:
    """Invokes the native helper (contract §4, §6). Process plumbing only: every trust decision stays in
    SecureEnclaveProvider. The helper binary must match a pinned SHA-256; a verified private copy is
    executed so the file can't be swapped between the hash check and exec."""

    genuine_hardware = True

    def __init__(self, helper_path: Path, pinned_sha256: str) -> None:
        if len(pinned_sha256) != 64 or any(c not in "0123456789abcdef" for c in pinned_sha256):
            raise ValidationError("pinned helper hash must be 64 lowercase hex characters")
        self.helper_path, self.pinned = helper_path, pinned_sha256

    def _run(self, args: list[str], stdin: bytes, timeout_s: int, files: dict[str, bytes]) -> dict[str, Any]:
        data = self.helper_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != self.pinned:
            raise CapabilityUnavailable(
                "operator-presence", "Secure Enclave helper hash does not match the pin"
            )
        work = Path(tempfile.mkdtemp(prefix="sentinel-se-"))
        try:
            os.chmod(work, 0o700)
            exe = work / "helper"
            fd = os.open(exe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            subs = {}
            for name, content in files.items():
                fp = work / name
                fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(content)
                subs[name] = str(fp)
            argv = [str(exe)] + [subs.get(a, a) for a in args]
            try:
                proc = subprocess.run(
                    argv,
                    input=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin"},
                    timeout=timeout_s + 15,
                    shell=False,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {"error": "timeout", "message": "helper did not finish"}
        finally:
            shutil.rmtree(work, ignore_errors=True)
        return parse_helper_output(proc.returncode, proc.stdout)

    def status(self) -> bool:
        resp = self._run(["status"], b"", 10, {})
        if set(resp) != {"secure_enclave"} or not isinstance(resp["secure_enclave"], bool):
            raise BlockedError("malformed helper status", "backend_malformed")
        return resp["secure_enclave"]

    def create(self, now: int) -> SecureEnclaveKeyMetadata:
        resp = self._run(["create"], b"", 30, {})
        if set(resp) != {"public_x963_hex", "handle_b64"}:
            if "error" in resp and resp.get("error") in BACKEND_ERRORS:
                raise BlockedError(BACKEND_ERRORS[str(resp["error"])], f"presence_{resp['error']}")
            raise BlockedError("malformed helper create response", "backend_malformed")
        try:
            pub = PublicKey.from_raw(bytes.fromhex(str(resp["public_x963_hex"])), P256)
        except (ValueError, TypeError) as exc:
            raise BlockedError("helper returned an invalid public key", "backend_malformed") from exc
        return SecureEnclaveKeyMetadata.from_json(
            {
                "key_id": pub.key_id,  # computed by Sentinel, never taken from the helper
                "algorithm": P256,
                "public_x963_hex": pub.public_raw.hex(),
                "handle_b64": resp["handle_b64"],
                "backend": BACKEND_NAME,
                "created_at": now,
            }
        )

    def sign(self, handle: bytes, message: bytes, reason: str, timeout_s: int) -> dict[str, Any]:
        # `reason` is deliberately not forwarded: the helper builds its prompt from its own digest.
        if not message or len(message) > MAX_MESSAGE_BYTES:
            raise BlockedError("payload size outside helper limits", "payload_mismatch")
        return self._run(
            ["sign", "handle", str(timeout_s)], message, timeout_s, {"handle": base64.b64encode(handle)}
        )


def parse_helper_output(returncode: int, stdout: bytes) -> dict[str, Any]:
    """Exactly one JSON object; exit 0 only with a non-error object, non-zero only with an error object.
    Anything else becomes an unknown error code, which the provider maps to backend_malformed."""
    malformed: dict[str, Any] = {"error": "malformed", "message": "unparseable helper output"}
    if len(stdout) > MAX_HELPER_OUTPUT:
        return malformed
    try:
        obj = canonical.decode_strict(stdout, max_bytes=MAX_HELPER_OUTPUT)
    except ValidationError:
        return malformed
    if not isinstance(obj, dict):
        return malformed
    is_error = "error" in obj
    if (returncode == 0) == is_error or returncode not in (0, 1, 2):
        return malformed
    return obj


def helper_path() -> Path:
    """Fixed location of the helper binary (contract §6). The path alone confers no trust."""
    return state_dir() / "bin" / "sentinel-se-helper"


def helper_backend(pinned_sha256: str | None) -> NativeHelperBackend:
    """The helper as trusted by operator-approved policy. No pin, or no binary: refused, no fallback.
    The binary is hashed against the pin before every execution (NativeHelperBackend._run)."""
    if pinned_sha256 is None:
        raise CapabilityUnavailable(
            "operator-presence", "no Secure Enclave helper pin in the approved policy (se_helper_sha256)"
        )
    path = helper_path()
    if path.is_symlink() or not path.is_file():
        raise CapabilityUnavailable("operator-presence", f"Secure Enclave helper not found at {path}")
    return NativeHelperBackend(path, pinned_sha256)


def helper_status(pinned_sha256: str | None) -> dict[str, Any]:
    """Read-only status for `sentinel status`. Never executes the helper."""
    path = helper_path()
    present = path.is_file() and not path.is_symlink()
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if present else None
    return {
        "path": str(path),
        "present": present,
        "pinned": pinned_sha256 is not None,
        "hash_matches_pin": bool(pinned_sha256 and actual == pinned_sha256),
        "production_signing": "not activated (needs H1-H11 and an activation decision record)",
    }


def production_provider(pinned_sha256: str | None = None) -> SecureEnclaveProvider:
    """The only factory production code may use. It validates the approved pin first, then still fails
    closed: activation needs all manual hardware tests H1-H11 to pass and a separate decision record."""
    if pinned_sha256 is not None:
        helper_backend(pinned_sha256)
    raise CapabilityUnavailable(
        "operator-presence",
        "Secure Enclave signing is not activated: H1-H11 must pass and an activation decision record is "
        "required (no software fallback, D-38)",
    )
