"""D-73: protocol-v1 interoperability between the engine (DM side) and the real Swift SignerCore.

A TEST-ONLY driver (`signer-interop`, never part of the signer product) runs SignerCore's real `Device`
logic (registry, R3.1 state machine, validation, transport, recovery self-check, checkpoints, releases)
with disposable software keys and a software FIDO2 authenticator. The engine side is unchanged engine
code: `emit_request`, `receive_responses`, `admin.enrol|rotate|revoke`, `recovery.verify`.

This proves wire and state compatibility only. Secure Enclave, Touch ID, the approval window, a real
FIDO2 key (SD-T35) and SD-T01..SD-T55 need the real signing device and are not claimed here.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sentinel import admin, approvals, canonical, prepare, recovery, release, signing_protocol
from sentinel.crypto.signing import P256, Ed25519Signer, PublicKey
from sentinel.domain.enums import ApprovalAction
from sentinel.errors import IntegrityError
from sentinel.keys.operator import OperatorKey, TrustStore

PKG = Path(__file__).resolve().parents[1] / "native" / "macos" / "sentinel-signer"
# The signer is macOS-only by design (CryptoKit, Secure Enclave, LocalAuthentication); on Linux the
# package can't build, so these tests skip there. On macOS a build failure is a failure, not a skip.
pytestmark = [
    pytest.mark.skipif(sys.platform != "darwin", reason="sentinel-signer is macOS-only (not a pass)"),
    pytest.mark.skipif(shutil.which("swift") is None, reason="Swift toolchain unavailable (not a pass)"),
]
YEAR = 365 * 86400


@pytest.fixture(scope="module")
def interop() -> Path:
    r = subprocess.run(
        ["swift", "build", "--product", "signer-interop"],
        cwd=PKG,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if r.returncode != 0:
        pytest.fail(f"swift build failed: {r.stderr[-2000:]}")
    out = subprocess.run(
        ["swift", "build", "--show-bin-path"], cwd=PKG, capture_output=True, text=True
    ).stdout.strip()
    return Path(out) / "signer-interop"


class SD:
    """The signing device, driven through the TEST-ONLY interop binary."""

    def __init__(self, tool: Path, root: Path) -> None:
        self.tool, self.dir, self.vol = tool, root / "sd", root / "SENTINEL-XFER"
        self.vol.mkdir()
        self("init")

    def __call__(self, *args: str, ok: bool = True) -> str:
        r = subprocess.run(
            [str(self.tool), args[0], str(self.dir), *args[1:]], capture_output=True, text=True, timeout=60
        )
        if ok:
            assert r.returncode == 0, r.stdout + r.stderr
        return r.stdout.strip()

    def key_file(self, key_id: str) -> admin.CandidateKey:
        self("export-pub", key_id, str(self.vol))
        p = self.vol / "sentinel-v1" / "from-signer" / f"pub-{key_id}.json"
        data = json.loads(p.read_bytes())
        p.unlink()  # the DM removes it after reading
        return admin.parse_key_file(data)


class DM:
    """The development machine: engine trust store, ledger and admin context."""

    def __init__(self, root: Path) -> None:
        self.trust_path = root / "dm" / "trust.json"
        self.trust_path.parent.mkdir()
        self.trust = TrustStore(self.trust_path)
        self.ledger = approvals.NonceLedger(root / "dm" / "nonces.json")
        self.run = Ed25519Signer.generate()

    def ctx(self) -> admin.AdminContext:
        return admin.AdminContext(
            self.trust, self.ledger, self.run, int(time.time()), self.trust_path.parent / "log"
        )

    def payload(
        self, action: ApprovalAction, subject: dict[str, str], key_id: str, revision: str | None = None
    ) -> dict:  # type: ignore[type-arg]
        return approvals.build_payload(
            action=action,
            subject=subject,
            revision=revision or f"trust:{self.trust.fingerprint()}",
            scope={},
            issued_at=int(time.time()),
            lifetime=600,
            key_id=key_id,
            rationale="interop ceremony",
        )

    def exchange(
        self, sd: SD, payload: dict, enrol_key: admin.CandidateKey | None = None
    ) -> tuple[str, list[dict]]:  # type: ignore[type-arg]
        signing_protocol.emit_request(payload, sd.vol, self.trust, int(time.time()), enrol_key=enrol_key)
        signed = sd("sign", str(sd.vol))
        return signed, signing_protocol.receive_responses(
            sd.vol, self.trust, int(time.time())
        ) if "signed" in signed else []

    def approval(self, result: dict):  # type: ignore[no-untyped-def,type-arg]
        return recovery.load_any(json.loads(Path(result["approval"]).read_bytes()))

    def trust_bytes(self, tmp: Path) -> str:
        out = tmp / f"trust-{time.monotonic_ns()}.json"
        out.write_bytes(self.trust_path.read_bytes())
        return str(out)


def test_full_ceremony_rotation_recovery_and_audit_round_trip(interop, tmp_path):
    """Ceremony steps 2-10, a rotation, recovery enrolment and a recovery-signed replacement and
    revocation: every trust state on the SD equals the engine's, fingerprint for fingerprint."""
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR

    # Ceremony: the SD creates its key; the DM prepares and emits the self-signed enrolment.
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    p = dm.payload(
        ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
    )
    signed, results = dm.exchange(sd, p, enrol_key=cand_a)
    assert signed.startswith("signed") and [r["status"] for r in results] == ["received"], (signed, results)
    assert sd("state").startswith("PENDING")
    admin.enrol(dm.ctx(), cand_a, dm.approval(results[0]), operator="owner", expires_at=exp)
    audit = sd("audit", dm.trust_bytes(tmp_path))
    assert audit.startswith("MISMATCH") and "present true" in audit  # not committed on the SD yet
    sd("commit")
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"
    assert sd("state") == f"IDLE {dm.trust.fingerprint()}"

    # Rotation: a second operator key, signed by the first. A second key operation is refused while PENDING.
    b = sd("create-key", "owner", str(exp))
    c = sd("create-key", "owner", str(exp))
    cand_b, cand_c = sd.key_file(b), sd.key_file(c)
    signed, results = dm.exchange(sd, dm.payload(ApprovalAction.KEY_ROTATE, admin.key_subject(cand_b), a))
    assert [r["status"] for r in results] == ["received"]
    signed2, _ = dm.exchange(sd, dm.payload(ApprovalAction.KEY_ROTATE, admin.key_subject(cand_c), a))
    assert "registry_pending" in signed2  # SD-T42: nothing signed, nothing written (O-P1)
    fp = dm.trust.fingerprint()
    admin.rotate(
        dm.ctx(),
        cand_b,
        dm.approval(results[0]),
        operator="owner",
        expires_at=exp,
        expected_trust_fingerprint=fp,
    )
    sd("commit")
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"

    # Recovery credential (software FIDO2 authenticator), enrolled by the operator key.
    r = sd("register-recovery", "owner-recovery", str(exp), "1")
    cand_r = sd.key_file(r)
    assert cand_r.role == "recovery"
    _, results = dm.exchange(sd, dm.payload(ApprovalAction.KEY_ROTATE, admin.key_subject(cand_r), a))
    admin.rotate(
        dm.ctx(),
        cand_r,
        dm.approval(results[0]),
        operator="owner-recovery",
        expires_at=exp,
        expected_trust_fingerprint=dm.trust.fingerprint(),
    )
    sd("commit")
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"

    # Recovery session: a replacement key generated in the session, enrolled by a recovery assertion.
    sd("recovery", "start")
    d = sd("create-key", "owner", str(exp))
    cand_d = sd.key_file(d)
    signed, results = dm.exchange(sd, dm.payload(ApprovalAction.KEY_ROTATE, admin.key_subject(cand_d), r))
    assert [x["status"] for x in results] == ["received"], (signed, results)
    resp_approval = dm.approval(results[0])
    assert isinstance(resp_approval, recovery.RecoveryApproval)
    admin.rotate(
        dm.ctx(),
        cand_d,
        resp_approval,
        operator="owner",
        expires_at=exp,
        expected_trust_fingerprint=dm.trust.fingerprint(),
    )
    sd("commit")
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"  # includes the recovery counter state
    assert "counter=increasing:1" in sd("status", r)

    # Recovery revocation of the "lost" key A (others stay active), then the session ends.
    _, results = dm.exchange(
        sd, dm.payload(ApprovalAction.KEY_REVOKE, {"type": "operator_key", "key_id": a}, r)
    )
    assert [x["status"] for x in results] == ["received"]
    admin.revoke(dm.ctx(), a, dm.approval(results[0]), expected_trust_fingerprint=dm.trust.fingerprint())
    sd("commit")
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"
    assert "counter=increasing:2" in sd("status", r)
    sd("recovery", "end")
    assert dm.trust.get(a).status == "revoked"  # type: ignore[union-attr]


def test_recovery_cannot_self_revoke_or_sign_ordinary_approvals(interop, tmp_path):
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    _, res = dm.exchange(
        sd,
        dm.payload(
            ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
        ),
        enrol_key=cand_a,
    )
    admin.enrol(dm.ctx(), cand_a, dm.approval(res[0]), operator="owner", expires_at=exp)
    sd("commit")
    r = sd("register-recovery", "rec", str(exp), "0")
    cand_r = sd.key_file(r)
    _, res = dm.exchange(sd, dm.payload(ApprovalAction.KEY_ROTATE, admin.key_subject(cand_r), a))
    admin.rotate(
        dm.ctx(),
        cand_r,
        dm.approval(res[0]),
        operator="rec",
        expires_at=exp,
        expected_trust_fingerprint=dm.trust.fingerprint(),
    )
    sd("commit")
    # The engine refuses to emit these (D-45 pre-check), so build the requests directly on the volume.
    for p in (
        dm.payload(ApprovalAction.KEY_REVOKE, {"type": "operator_key", "key_id": r}, r),
        dm.payload(
            ApprovalAction.POLICY_CHANGE, {"type": "policy_file", "sha256": "b" * 64}, r, "policy-prev:none"
        ),
    ):
        rid = "e" * 31 + str(len(p["action"]) % 10)
        body = canonical.encode(
            {
                "envelope": "sentinel/v1/sign-request",
                "payload": p,
                "payload_sha256": canonical.sha256_hex(canonical.encode(p)),
                "request_id": rid,
            }
        )
        to = sd.vol / "sentinel-v1" / "to-signer"
        to.mkdir(parents=True, exist_ok=True)
        (to / f"req-{rid}.json").write_bytes(body)
        out = sd("sign", str(sd.vol))
        assert "refused" in out and ("self_revocation" in out or "action_not_permitted" in out), out
        (to / f"req-{rid}.json").unlink()
    assert not (sd.vol / "sentinel-v1" / "from-signer").exists() or not list(
        (sd.vol / "sentinel-v1" / "from-signer").glob("resp-*")
    )


def test_abandon_needs_expiry_and_an_audit(interop, tmp_path):
    """R3.1, SD-T47: a change the DM never applied is abandoned only after expiry, on audit evidence."""
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    _, res = dm.exchange(
        sd,
        dm.payload(
            ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
        ),
        enrol_key=cand_a,
    )
    admin.enrol(dm.ctx(), cand_a, dm.approval(res[0]), operator="owner", expires_at=exp)
    sd("commit")
    b = sd("create-key", "owner", str(exp))
    dm.exchange(sd, dm.payload(ApprovalAction.KEY_ROTATE, admin.key_subject(sd.key_file(b)), a))
    sd("abandon")
    trust = dm.trust_bytes(tmp_path)  # the DM never applied it
    assert "not_expired" in sd("resolve", trust, str(int(time.time())), ok=False)
    assert sd("resolve", trust, str(int(time.time()) + 700)) == "ABANDONED"
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"


def test_checkpoint_restores_the_registry_on_a_replacement_device(interop, tmp_path):
    """D-46: restore only with the paper anchor; the restored state still matches the DM."""
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    _, res = dm.exchange(
        sd,
        dm.payload(
            ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
        ),
        enrol_key=cand_a,
    )
    admin.enrol(dm.ctx(), cand_a, dm.approval(res[0]), operator="owner", expires_at=exp)
    sd("commit")
    ck = tmp_path / "ckpt-1.json"
    seq, h, anchored = sd("checkpoint", str(ck)).split()
    assert seq == "1" and anchored == "anchored=true"
    fp = sd("fingerprint", a)
    (tmp_path / "replacement").mkdir()
    new = SD(interop, tmp_path / "replacement")
    assert "anchor_mismatch" in new("restore", str(ck), fp, "1", "0" * 64, ok=False)
    assert "fingerprint_mismatch" in new("restore", str(ck), "f" * 64, "1", h, ok=False)
    assert new("restore", str(ck), fp, "1", h).startswith("restored")
    assert new("audit", dm.trust_bytes(tmp_path)) == "MATCH"


def test_release_install_needs_an_operator_signed_successor_record(interop, tmp_path):
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    _, res = dm.exchange(
        sd,
        dm.payload(
            ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
        ),
        enrol_key=cand_a,
    )
    admin.enrol(dm.ctx(), cand_a, dm.approval(res[0]), operator="owner", expires_at=exp)
    sd("commit")
    binary = tmp_path / "sentinel-signer"
    binary.write_bytes(b"signer build")
    rec = tmp_path / "release.json"
    sd("release-sign", "a" * 40, str(PKG / "Sources"), str(binary), str(rec))
    other = tmp_path / "other"
    other.write_bytes(b"tampered build")
    assert "binary_mismatch" in sd("release-install", str(rec), str(other), ok=False)
    assert sd("release-install", str(rec), str(binary)) == "a" * 40
    assert "release_not_successor" in sd("release-install", str(rec), str(binary), ok=False)


def test_tampered_swift_response_is_refused_by_the_engine(interop, tmp_path):
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    p = dm.payload(
        ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
    )
    emitted = signing_protocol.emit_request(p, sd.vol, dm.trust, int(time.time()), enrol_key=cand_a)
    sd("sign", str(sd.vol))
    resp = sd.vol / "sentinel-v1" / "from-signer" / f"resp-{emitted['request_id']}.json"
    data = json.loads(resp.read_bytes())
    sig = bytearray(base64.b64decode(data["signature_der_b64"]))
    sig[-1] ^= 1
    data["signature_der_b64"] = base64.b64encode(bytes(sig)).decode()
    resp.chmod(0o644)
    resp.write_bytes(canonical.encode(data))
    results = signing_protocol.receive_responses(sd.vol, dm.trust, int(time.time()))
    assert results[0]["status"] != "received"


def test_signer_refuses_a_request_for_a_key_it_does_not_hold(interop, tmp_path):
    sd = SD(interop, tmp_path)
    priv, pub = subprocess.run(
        [str(interop), "keygen", "-"], capture_output=True, text=True, check=True
    ).stdout.split()
    key = PublicKey.from_raw(bytes.fromhex(pub), P256)
    ts = TrustStore(tmp_path / "foreign-trust.json")
    ts.enrol(OperatorKey(key.key_id, "owner", key, "active", int(time.time()) + 86400))
    now = int(time.time())
    p = approvals.build_payload(
        action=ApprovalAction.POLICY_CHANGE,
        subject={"type": "policy_file", "sha256": "b" * 64},
        revision="policy-prev:none",
        scope={},
        issued_at=now,
        lifetime=3600,
        key_id=key.key_id,
        rationale="x",
    )
    emitted = signing_protocol.emit_request(p, sd.vol, ts, now)
    out = sd("sign", str(sd.vol))
    assert f"refused {emitted['request_id']} foreign_key" in out
    assert (
        not list((sd.vol / "sentinel-v1" / "from-signer").glob("resp-*"))
        if (sd.vol / "sentinel-v1" / "from-signer").exists()
        else True
    )
    del priv


def test_enrolment_request_is_refused_unless_it_is_the_keys_own_first_enrolment(interop, tmp_path):
    """Engine side of the enrolment fix: only a self-signed key.rotate into an empty trust store."""
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a, b = sd("create-key", "owner", str(exp)), sd("create-key", "owner", str(exp))
    cand_a, cand_b = sd.key_file(a), sd.key_file(b)
    from sentinel.errors import BlockedError

    wrong_signer = dm.payload(
        ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), b, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
    )
    with pytest.raises(BlockedError, match="enrolment"):
        signing_protocol.emit_request(wrong_signer, sd.vol, dm.trust, int(time.time()), enrol_key=cand_a)
    good = dm.payload(
        ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
    )
    _, res = dm.exchange(sd, good, enrol_key=cand_a)
    admin.enrol(dm.ctx(), cand_a, dm.approval(res[0]), operator="owner", expires_at=exp)
    late = dm.payload(
        ApprovalAction.KEY_ROTATE, admin.key_subject(cand_b), b, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
    )
    with pytest.raises(BlockedError, match="already initialised"):
        signing_protocol.emit_request(late, sd.vol, dm.trust, int(time.time()), enrol_key=cand_b)


def _enrolled(interop: Path, tmp_path: Path) -> tuple[SD, DM, str]:
    sd, dm = SD(interop, tmp_path), DM(tmp_path)
    exp = int(time.time()) + YEAR
    a = sd("create-key", "owner", str(exp))
    cand_a = sd.key_file(a)
    p = dm.payload(
        ApprovalAction.KEY_ROTATE, admin.key_subject(cand_a), a, f"trust:{admin.EMPTY_TRUST_FINGERPRINT}"
    )
    _, res = dm.exchange(sd, p, enrol_key=cand_a)
    admin.enrol(dm.ctx(), cand_a, dm.approval(res[0]), operator="owner", expires_at=exp)
    sd("commit")
    assert sd("audit", dm.trust_bytes(tmp_path)) == "MATCH"  # the D-74 permission list is identical
    return sd, dm, a


def _dist(root: Path) -> Path:
    d = root / "dist"
    d.mkdir()
    (d / "sentinel_audit-1.2.3-py3-none-any.whl").write_bytes(b"wheel")
    (d / "sentinel_audit-1.2.3.tar.gz").write_bytes(b"sdist")
    (d / "sentinel-sbom.cdx.json").write_text("{}\n")
    (d / release.SUMS_NAME).write_bytes(release.sha256sums(d))
    return d


def test_release_publish_is_signed_on_the_signer_and_verifies(interop, tmp_path):
    """D-74 round trip: engine prepare -> protocol request -> SignerCore validation, recomputed SHA256SUMS
    and signature -> engine receive -> `release verify` against the files."""
    sd, dm, a = _enrolled(interop, tmp_path)
    dist = _dist(tmp_path)
    commit = "0123456789abcdef0123456789abcdef01234567"
    p = prepare.prepare(
        "release-publish",
        trust=dm.trust,
        now=int(time.time()),
        key_id=a,
        lifetime=3600,
        rationale="interop release",
        dist=dist,
        commit=commit,
    )["payload"]
    signed, res = dm.exchange(sd, p)
    assert signed.startswith("signed") and [r["status"] for r in res] == ["received"], (signed, res)
    raw = json.loads(Path(res[0]["approval"]).read_bytes())
    k = dm.trust.get(a)
    assert k is not None
    out = release.verify_release(dist, raw, k.public, trusted=k)
    assert (out["status"], out["version"], out["commit"]) == ("verified", "1.2.3", commit)
    (dist / "sentinel_audit-1.2.3.tar.gz").write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        release.verify_release(dist, raw, k.public, trusted=k)


def test_signer_recomputes_sums_and_refuses_a_forged_release_request(interop, tmp_path):
    """The engine emits what the DM gives it; the SD's own SHA256SUMS recomputation is the check."""
    sd, dm, a = _enrolled(interop, tmp_path)
    subject, _, scope = release.release_parts(_dist(tmp_path), "0123456789abcdef0123456789abcdef01234567")
    p = approvals.build_payload(
        action=ApprovalAction.RELEASE_PUBLISH,
        subject=subject,
        revision="sums:" + "0" * 64,
        scope=scope,
        issued_at=int(time.time()),
        lifetime=3600,
        key_id=a,
        rationale="forged release",
    )
    signed, res = dm.exchange(sd, p)
    assert "release_sums_mismatch" in signed and res == [], signed
