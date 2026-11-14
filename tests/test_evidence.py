"""Evidence store, manifest and audit log integrity (§6, R-11, R-13, R-14, D-18, D-34)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sentinel import canonical
from sentinel.crypto.signing import P256, Ed25519Signer, PublicKey
from sentinel.errors import IntegrityError, ValidationError
from sentinel.evidence import AuditLog, RunStore, uuid7

from .conftest import FakeOperator

# A complete §6.1 evidence record (D-40 evidence-record contract); RunStore fills in redaction.
META = {
    "audit_id": "a",
    "check_id": "c",
    "producer": {
        "adapter": "fixture",
        "adapter_version": "1",
        "scanner": "fixture",
        "scanner_version": "1",
        "binary_sha256": "0" * 64,
    },
    "input": {"asset": "app", "revision": "r"},
    "authorization_ref": "read-only-default",
    "isolation_ref": "none",
    "collected_at": 1,
    "redaction": {"rules": []},
    "parent": None,
    "truncated": False,
}
_MANIFEST_TEMPLATE = json.loads(
    (Path(__file__).parent / "fixtures/schemas/historical/signed/run/manifest.json").read_text()
)


def make_run(tmp_path: Path) -> tuple[RunStore, Ed25519Signer]:
    from sentinel.redaction import Redactor

    run = RunStore.create(tmp_path / "runs", uuid7(), Redactor.default())
    return run, Ed25519Signer.generate()


def finalise(run: RunStore, signer: Ed25519Signer) -> None:
    log = AuditLog(run.log_path)
    log.append("audit.start", {}, signer)
    log.append("audit.end", {}, signer, checkpoint=True)
    manifest = {
        **_MANIFEST_TEMPLATE,
        "audit_id": run.root.name,
        "evidence_index": run.evidence_index(),
        "audit_log_head": log.head(),
        "run_key_id": signer.key_id,
    }
    run.write_manifest(manifest, signer)


def test_uuid7_shape_and_order():
    a, b = uuid7(), uuid7()
    assert len(a) == 36 and a[14] == "7" and a[:8] <= b[:8]


def test_evidence_roundtrip_and_write_once(tmp_path):
    run, _ = make_run(tmp_path)
    rec = run.put_evidence(b"scanner output", META)
    assert rec.evidence_id == canonical.sha256_hex(b"scanner output") and rec.size == 14
    assert run.read_evidence(rec.evidence_id) == b"scanner output"
    assert (run.evidence_dir / rec.evidence_id).stat().st_mode & 0o777 == 0o400
    run.put_evidence(b"scanner output", META)  # idempotent for identical content


def test_tampered_evidence_detected_on_read(tmp_path):
    run, _ = make_run(tmp_path)
    rec = run.put_evidence(b"original", META)
    p = run.evidence_dir / rec.evidence_id
    os.chmod(p, 0o600)
    p.write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        run.read_evidence(rec.evidence_id)


@pytest.mark.parametrize("bad", ["../x", "a" * 63, "Z" * 64, ""])
def test_bad_evidence_ids_rejected(tmp_path, bad):
    run, _ = make_run(tmp_path)
    with pytest.raises(ValidationError):
        run.read_evidence(bad)


def test_bad_audit_id_rejected(tmp_path):
    with pytest.raises(ValidationError):
        RunStore.create(tmp_path, "../escape")


def test_manifest_verifies(tmp_path):
    run, signer = make_run(tmp_path)
    run.put_evidence(b"e1", META)
    finalise(run, signer)
    m = run.verify_manifest(signer.public)
    assert len(m["evidence_index"]) == 1


def test_manifest_tamper_and_wrong_key_detected(tmp_path):
    run, signer = make_run(tmp_path)
    run.put_evidence(b"e1", META)
    finalise(run, signer)
    with pytest.raises(IntegrityError):
        run.verify_manifest(Ed25519Signer.generate().public)  # wrong key id
    body = json.loads(run.manifest_path.read_text())
    body["evidence_index"] = {}
    run.manifest_path.write_bytes(canonical.encode(body))
    with pytest.raises(IntegrityError, match="signature"):
        run.verify_manifest(signer.public)


def test_added_or_removed_evidence_detected(tmp_path):
    run, signer = make_run(tmp_path)
    run.put_evidence(b"e1", META)
    finalise(run, signer)
    run.put_evidence(b"smuggled", META)
    with pytest.raises(IntegrityError, match="evidence set"):
        run.verify_manifest(signer.public)


def test_run_key_must_be_ed25519(tmp_path):
    run, signer = make_run(tmp_path)
    finalise(run, signer)
    p256 = FakeOperator.make(P256).public
    with pytest.raises(IntegrityError, match="Ed25519"):
        run.verify_manifest(PublicKey(signer.key_id, p256.algorithm, p256.public_raw))


def test_audit_log_chain_break_detected(tmp_path):
    run, signer = make_run(tmp_path)
    log = AuditLog(run.log_path)
    for i in range(3):
        log.append("e", {"i": i}, signer, checkpoint=(i == 2))
    assert log.verify(signer.public) == 1
    lines = run.log_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["data"] = {"i": 99}
    lines[1] = canonical.encode(entry).decode()
    run.log_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(IntegrityError, match="chain broken"):
        log.verify(signer.public)


def test_audit_log_deleted_entry_detected(tmp_path):
    run, signer = make_run(tmp_path)
    log = AuditLog(run.log_path)
    for i in range(3):
        log.append("e", {"i": i}, signer, checkpoint=(i == 2))
    lines = run.log_path.read_text().splitlines()
    run.log_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    with pytest.raises(IntegrityError):
        log.verify(signer.public)


def test_audit_log_requires_valid_checkpoint(tmp_path):
    run, signer = make_run(tmp_path)
    log = AuditLog(run.log_path)
    log.append("e", {})
    with pytest.raises(IntegrityError, match="no signed checkpoint"):
        log.verify(signer.public)
    log.append("e2", {}, signer, checkpoint=True)
    with pytest.raises(IntegrityError, match="checkpoint"):
        log.verify(Ed25519Signer.generate().public)


def test_checkpoints_are_periodic(tmp_path):
    run, signer = make_run(tmp_path)
    log = AuditLog(run.log_path)
    for i in range(100):
        log.append("e", {"i": i}, signer)
    assert log.verify(signer.public) == 2  # every 50 entries


def test_known_limitation_same_user_resign_is_not_detected(tmp_path):
    """D-34, demonstrated: a process with the run key can rewrite evidence and re-sign everything.
    Verification then passes. Run-key signatures prove integrity relative to the key only."""
    run, signer = make_run(tmp_path)
    run.put_evidence(b"real finding", META)
    finalise(run, signer)
    for p in run.evidence_dir.iterdir():
        os.chmod(p, 0o600)
        p.unlink()
    run.log_path.unlink()
    run.put_evidence(b"forged", META)
    finalise(run, signer)  # attacker re-signs with the same run key
    assert run.verify_manifest(signer.public)  # NOT detected: documented residual risk
