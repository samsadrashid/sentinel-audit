"""Per-run filesystem storage (D-18): content-addressed, write-once evidence; hash-chained audit log
with run-key-signed checkpoints; run-key-signed manifest.

Guarantee boundary (D-34, §13.8): every hash and run-key signature is verified on read (R-13).
That detects accidental and out-of-band changes. It does NOT detect a same-user process that can
both rewrite the files and use the run key to re-sign them. Signed evidence is not a verified finding.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import canonical
from .crypto.signing import RUN_KEY_ALGORITHM, Ed25519Signer, PublicKey
from .errors import IntegrityError, ValidationError
from .paths import atomic_write, ensure_private_dir, resolve_within, write_once
from .redaction import RedactionError, Redactor
from .redaction import summary as redaction_summary
from .schema import SchemaError, check_output, check_version, validate

CHECKPOINT_EVERY = 50


def uuid7() -> str:
    ms = int(time.time() * 1000)
    rand = secrets.token_bytes(10)
    b = (
        ms.to_bytes(6, "big")
        + bytes([0x70 | (rand[0] & 0x0F), rand[1], 0x80 | (rand[2] & 0x3F)])
        + rand[3:10]
    )
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    audit_id: str
    check_id: str
    producer: dict[str, Any]
    input: dict[str, Any]
    authorization_ref: str
    isolation_ref: str
    collected_at: int
    redaction: dict[str, Any]
    parent: str | None
    size: int
    truncated: bool

    def to_json(self) -> dict[str, Any]:
        return dict(self.__dict__)


class RunStore:
    def __init__(self, root: Path, redactor: Redactor | None = None) -> None:
        self.root = root
        #: Required to write evidence (§6.4): there is no path that stores unredacted content.
        self.redactor = redactor
        self.evidence_dir = root / "evidence"
        self.log_path = root / "audit-log.jsonl"
        self.manifest_path = root / "manifest.json"
        self.signature_path = root / "manifest.sig.json"

    @classmethod
    def create(cls, runs_dir: Path, audit_id: str, redactor: Redactor | None = None) -> RunStore:
        if not all(c in "0123456789abcdef-" for c in audit_id):
            raise ValidationError("bad audit id")
        root = ensure_private_dir(runs_dir) / audit_id
        root.mkdir(mode=0o700)
        ensure_private_dir(root / "evidence")
        return cls(root, redactor)

    # ── evidence ───────────────────────────────────────────────────────────
    def put_evidence(self, data: bytes, meta: dict[str, Any]) -> EvidenceRecord:
        """Redact, then store write-once. The raw bytes are never written (§6.4). RedactionError: nothing
        is stored and the caller must hold the artifact back."""
        if self.redactor is None:
            raise RedactionError("no redactor configured; refusing to store evidence")
        data, counts = self.redactor.redact_bytes(data)
        meta = {**meta, "redaction": redaction_summary(counts)}
        eid = canonical.sha256_hex(data)
        rec = EvidenceRecord(evidence_id=eid, size=len(data), **meta)
        check_output(rec.to_json(), "evidence-record")  # D-40: before any evidence byte is persisted
        path = resolve_within(self.evidence_dir, eid)
        if not path.exists():
            write_once(path, data)
        atomic_write(self.evidence_dir / f"{eid}.meta.json", canonical.encode(rec.to_json()))
        return rec

    def read_evidence(self, evidence_id: str) -> bytes:
        """R-13: hash verified on every read."""
        if len(evidence_id) != 64 or not all(c in "0123456789abcdef" for c in evidence_id):
            raise ValidationError("bad evidence id")
        data = resolve_within(self.evidence_dir, evidence_id).read_bytes()
        if canonical.sha256_hex(data) != evidence_id:
            raise IntegrityError(f"evidence {evidence_id[:12]} content does not match its hash")
        return data

    def evidence_index(self) -> dict[str, int]:
        return {
            p.name: p.stat().st_size
            for p in sorted(self.evidence_dir.iterdir())
            if len(p.name) == 64 and "." not in p.name
        }

    # ── manifest ───────────────────────────────────────────────────────────
    def write_manifest(self, manifest: dict[str, Any], signer: Ed25519Signer) -> str:
        check_output(manifest, "run-manifest")  # D-40: never sign or write a malformed manifest
        body = canonical.encode(manifest)
        atomic_write(self.manifest_path, body)
        sig = {
            "key_id": signer.key_id,
            "role": "run",
            "context": "sentinel/v1/run/manifest",
            "signature": base64.b64encode(signer.sign(b"sentinel/v1/run/manifest\n" + body)).decode(),
        }
        check_output(sig, "manifest-signature")
        atomic_write(self.signature_path, json.dumps(sig).encode())
        return canonical.sha256_hex(body)

    def verify_manifest(self, run_pub: PublicKey) -> dict[str, Any]:
        if run_pub.algorithm != RUN_KEY_ALGORITHM:
            raise IntegrityError("run key must be Ed25519 (D-16, D-38)")
        body = self.manifest_path.read_bytes()
        sig = canonical.decode_strict(self.signature_path.read_bytes())
        try:
            validate(sig, "manifest-signature")
        except SchemaError as exc:
            raise IntegrityError(f"manifest signature file malformed: {exc}") from exc
        manifest = canonical.decode_strict(body)
        check_version(manifest)  # unsupported_version is reported as such
        try:
            validate(manifest, "run-manifest")  # D-40: schema before signature verification or any trust
        except SchemaError as exc:
            raise IntegrityError(f"manifest malformed: {exc}") from exc
        if sig.get("key_id") != run_pub.key_id or sig.get("context") != "sentinel/v1/run/manifest":
            raise IntegrityError("manifest signed by an unexpected key or context")
        if not run_pub.verify(base64.b64decode(sig["signature"]), b"sentinel/v1/run/manifest\n" + body):
            raise IntegrityError("manifest signature invalid")
        index = manifest.get("evidence_index", {})
        actual = self.evidence_index()
        if set(index) != set(actual):
            raise IntegrityError("evidence set differs from manifest")
        for eid in index:
            self.read_evidence(eid)
        AuditLog(self.log_path).verify(run_pub)
        if manifest.get("audit_log_head") != AuditLog(self.log_path).head():
            raise IntegrityError("audit log head differs from manifest")
        if not isinstance(manifest, dict):
            raise IntegrityError("manifest is not an object")
        return manifest


class AuditLog:
    """Append-only, hash-chained JSONL log with run-key-signed checkpoints (R-11, D-34 limits).
    Event data is redacted before it is written."""

    def __init__(self, path: Path, redactor: Redactor | None = None) -> None:
        self.path = path
        self.redactor = redactor

    def _entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text().splitlines():
            if not line:
                continue
            entry = canonical.decode_strict(line.encode())
            try:
                validate(entry, "log-entry")  # D-40: schema first; a malformed entry is an integrity failure
            except SchemaError as exc:
                raise IntegrityError(f"audit log entry malformed: {exc}") from exc
            if not isinstance(entry, dict):
                raise IntegrityError("audit log entry is not an object")
            out.append(entry)
        return out

    def head(self) -> str:
        e = self._entries()
        return str(e[-1]["hash"]) if e else "0" * 64

    def append(
        self, event: str, data: dict[str, Any], signer: Ed25519Signer | None = None, checkpoint: bool = False
    ) -> dict[str, Any]:
        entries = self._entries()
        seq = len(entries)
        prev = entries[-1]["hash"] if entries else "0" * 64
        redactor = self.redactor or Redactor.default()
        data = redactor.redact_obj(data)
        event = redactor.redact_text(event)[0]
        body = {"seq": seq, "ts": int(time.time()), "prev": prev, "event": event, "data": data}
        entry_hash = canonical.digest(body)
        entry: dict[str, Any] = {**body, "hash": entry_hash}
        if signer and (checkpoint or (seq + 1) % CHECKPOINT_EVERY == 0):
            msg = b"sentinel/v1/run/checkpoint\n" + entry_hash.encode()
            entry["checkpoint"] = {
                "key_id": signer.key_id,
                "signature": base64.b64encode(signer.sign(msg)).decode(),
            }
        check_output(entry, "log-entry")  # D-40: before anything is appended
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(canonical.encode(entry).decode() + "\n")
        return entry

    def verify(self, run_pub: PublicKey) -> int:
        prev = "0" * 64
        checkpoints = 0
        for i, e in enumerate(self._entries()):
            body = {k: e[k] for k in ("seq", "ts", "prev", "event", "data")}
            if e["seq"] != i or e["prev"] != prev or canonical.digest(body) != e["hash"]:
                raise IntegrityError(f"audit log chain broken at entry {i}")
            cp = e.get("checkpoint")
            if cp:
                ok = cp.get("key_id") == run_pub.key_id and run_pub.verify(
                    base64.b64decode(cp["signature"]), b"sentinel/v1/run/checkpoint\n" + e["hash"].encode()
                )
                if not ok:
                    raise IntegrityError(f"audit log checkpoint {i} signature invalid")
                checkpoints += 1
            prev = e["hash"]
        if checkpoints == 0 and prev != "0" * 64:
            raise IntegrityError("audit log has no signed checkpoint")
        return checkpoints
