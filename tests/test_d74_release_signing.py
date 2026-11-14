"""D-74: release signing on the signing device (`release.publish`).

The engine side: the D-45 permission (operator only), the payload recomputed from the release files, and
`release verify` / `release attach`, which fail closed on any key, signature or content mismatch. All keys
are software test keys: this is engine-side evidence, not hardware validation (D-49, D-73).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sentinel import admin, approvals, canonical, prepare, release, signing_protocol
from sentinel.crypto.signing import P256
from sentinel.domain.enums import ONE_TIME_ACTIONS, STANDING_ACTIONS, ApprovalAction
from sentinel.errors import BlockedError, IntegrityError, ValidationError
from sentinel.keys.operator import OPERATOR_ACTIONS, RECOVERY_ACTIONS, OperatorKey, TrustStore
from sentinel.schema import validate

from .conftest import NOW, FakeOperator
from .signing_fixtures import FakeRecoveryAuthenticator
from .test_trust_admin import deps, home, run  # noqa: F401

YEAR = 365 * 86400
COMMIT = "0123456789abcdef0123456789abcdef01234567"
R = ApprovalAction.RELEASE_PUBLISH


def make_dist(root: Path, version: str = "1.2.3") -> Path:
    d = root / "dist"
    d.mkdir()
    (d / f"sentinel_audit-{version}-py3-none-any.whl").write_bytes(b"wheel bytes")
    (d / f"sentinel_audit-{version}.tar.gz").write_bytes(b"sdist bytes")
    (d / "sentinel-sbom.cdx.json").write_text('{"bomFormat": "CycloneDX"}\n')
    (d / release.SUMS_NAME).write_bytes(release.sha256sums(d))
    return d


def sign_release(op: FakeOperator, dist: Path, issued_at: int = NOW, **over: Any) -> dict[str, Any]:
    subject, revision, scope = release.release_parts(dist, COMMIT)
    payload = approvals.build_payload(
        action=R,
        subject=subject,
        revision=revision,
        scope=scope,
        issued_at=issued_at,
        lifetime=3600,
        key_id=op.public.key_id,
        rationale="release 1.2.3",
    )
    payload.update(over)
    return approvals.Approval(payload, op.sign(canonical.encode(payload))).to_json()


def trusted(op: FakeOperator, **kw: Any) -> OperatorKey:
    return OperatorKey(op.public.key_id, "owner", op.public, kw.pop("status", "active"), NOW + YEAR, **kw)


@pytest.fixture
def op() -> FakeOperator:
    return FakeOperator.make(P256)


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    return make_dist(tmp_path)


# ── D-45 / D-37 / schema ───────────────────────────────────────────────────


def test_release_publish_is_an_operator_only_one_time_action_with_a_one_hour_window():
    assert "release.publish" in OPERATOR_ACTIONS and "release.publish" not in RECOVERY_ACTIONS
    assert list(OPERATOR_ACTIONS) == sorted(OPERATOR_ACTIONS)
    assert R in ONE_TIME_ACTIONS and R not in STANDING_ACTIONS  # never a revoke_record target
    assert approvals.MAX_EXPIRY[R] == 3600
    with pytest.raises(BlockedError) as e:
        approvals.build_payload(
            action=R,
            subject={},
            revision="x",
            scope={},
            issued_at=NOW,
            lifetime=3601,
            key_id="k",
            rationale="r",
        )
    assert e.value.code == "expiry_too_long"


def test_signed_release_approval_validates_and_the_schema_branch_is_strict(op, dist):
    good = sign_release(op, dist)
    validate(good, "approval")
    for change in (
        {"subject": {**good["payload"]["subject"], "name": "other"}},
        {"subject": {**good["payload"]["subject"], "commit": "abc"}},
        {"subject": {**good["payload"]["subject"], "extra": "x"}},
        {"revision": "sums:XYZ"},
        {"scope": {"artifacts": []}},
        {"scope": {"artifacts": [{"name": "../evil", "sha256": "0" * 64}]}},
        {"scope": {"artifacts": [{"name": "a", "sha256": "0" * 64}], "more": 1}},
    ):
        bad = {**good, "payload": {**good["payload"], **change}}
        with pytest.raises(Exception):  # noqa: B017 - any schema refusal
            validate(bad, "approval")


# ── SHA256SUMS ─────────────────────────────────────────────────────────────


def test_parse_sums_accepts_exactly_what_sha256sums_writes(dist):
    body = (dist / release.SUMS_NAME).read_bytes()
    arts = release.parse_sums(body)
    assert release.render_sums(arts) == body and [a["name"] for a in arts] == sorted(a["name"] for a in arts)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"%s  a" % (b"0" * 64),  # no trailing newline
        b"%s  b\n%s  a\n" % (b"0" * 64, b"0" * 64),  # unsorted
        b"%s  a\n%s  a\n" % (b"0" * 64, b"0" * 64),  # duplicate
        b"%s  a\n" % (b"A" * 64),  # uppercase hex
        b"%s a\n" % (b"0" * 64),  # one space
        b"%s  dir/a\n" % (b"0" * 64),
        b"%s  ../a\n" % (b"0" * 64),
        b"%s  .hidden\n" % (b"0" * 64),
        b"%s  SHA256SUMS\n" % (b"0" * 64),
        b"%s  SHA256SUMS.approval.json\n" % (b"0" * 64),
        b"".join(b"%s  a%02d\n" % (b"0" * 64, i) for i in range(17)),  # too many
        "{}  ä\n".format("0" * 64).encode(),
    ],
)
def test_parse_sums_refuses_anything_else(body):
    with pytest.raises(ValidationError):
        release.parse_sums(body)


def test_sha256sums_skips_the_manifest_and_its_approval(dist):
    before = release.sha256sums(dist)
    (dist / release.APPROVAL_NAME).write_text("{}")
    assert release.sha256sums(dist) == before


def test_release_parts_recompute_everything_from_the_files(tmp_path, dist):
    subject, revision, scope = release.release_parts(dist, COMMIT)
    sums = (dist / release.SUMS_NAME).read_bytes()
    assert subject == {"type": "release", "name": "sentinel-audit", "version": "1.2.3", "commit": COMMIT}
    assert revision == "sums:" + hashlib.sha256(sums).hexdigest()
    assert scope == {"artifacts": release.parse_sums(sums)}
    with pytest.raises(ValidationError):
        release.release_parts(dist, "ABC")
    (dist / "sentinel-sbom.cdx.json").write_text("changed")
    with pytest.raises(BlockedError) as e:
        release.release_parts(dist, COMMIT)
    assert e.value.code == "sums_mismatch"


@pytest.mark.parametrize(
    ("names", "code"),
    [
        (["sbom.json"], "release_wheel"),
        (["sentinel_audit-1-py3-none-any.whl", "sentinel_audit-2-py3-none-any.whl"], "release_wheel"),
        (["sentinel_audit-1-py3-none-any.whl", "sentinel_audit-2.tar.gz"], "version_mismatch"),
    ],
)
def test_the_release_needs_one_wheel_and_a_matching_sdist(tmp_path, names, code):
    d = tmp_path / "d"
    d.mkdir()
    for n in names:
        (d / n).write_bytes(n.encode())
    (d / release.SUMS_NAME).write_bytes(release.sha256sums(d))
    with pytest.raises(BlockedError) as e:
        release.release_parts(d, COMMIT)
    assert e.value.code == code


# ── prepare and request ────────────────────────────────────────────────────


def _store(tmp_path: Path, op: FakeOperator, auth: FakeRecoveryAuthenticator | None = None) -> TrustStore:
    ts = TrustStore(tmp_path / "trust.json")
    ts.enrol(trusted(op))
    if auth is not None:
        ts.apply_rotation(admin.parse_key_file(auth.key_file()).as_trusted("owner-recovery", NOW + YEAR))
    ts.save()
    return TrustStore(tmp_path / "trust.json")


def test_prepare_release_publish_builds_the_payload_the_verifier_recomputes(tmp_path, op, dist):
    ts = _store(tmp_path, op)
    out = prepare.prepare(
        "release-publish",
        trust=ts,
        now=NOW,
        key_id=op.public.key_id,
        lifetime=3600,
        rationale="release 1.2.3",
        dist=dist,
        commit=COMMIT,
    )
    p = out["payload"]
    assert p["action"] == "release.publish" and p["context"] == "sentinel/v1/approval/release.publish"
    assert (p["subject"], p["revision"], p["scope"]) == release.release_parts(dist, COMMIT)
    with pytest.raises(ValidationError):  # needs exactly dist and commit
        prepare.prepare("release-publish", trust=ts, now=NOW, key_id=op.public.key_id, lifetime=60, dist=dist)
    with pytest.raises(BlockedError):
        prepare.prepare(
            "release-publish",
            trust=ts,
            now=NOW,
            key_id=op.public.key_id,
            lifetime=7200,
            rationale="release 1.2.3",
            dist=dist,
            commit=COMMIT,
        )


def test_a_recovery_key_can_never_request_a_release_signature(tmp_path, op, dist):
    auth = FakeRecoveryAuthenticator()
    ts = _store(tmp_path, op, auth)
    rec_id = admin.parse_key_file(auth.key_file()).public.key_id
    payload = sign_release(op, dist)["payload"]
    payload["key_id"] = rec_id
    vol = tmp_path / "vol"
    vol.mkdir()
    with pytest.raises(BlockedError) as e:
        signing_protocol.emit_request(payload, vol, ts, NOW)
    assert e.value.code == "action_not_permitted"


def test_an_operator_key_without_the_permission_cannot_request_it(tmp_path, op, dist):
    ts = TrustStore(tmp_path / "t.json")
    old = tuple(a for a in OPERATOR_ACTIONS if a != "release.publish")
    ts.enrol(trusted(op, permitted_actions=old))
    with pytest.raises(BlockedError) as e:
        signing_protocol.emit_request(sign_release(op, dist)["payload"], tmp_path, ts, NOW)
    assert e.value.code == "action_not_permitted"


# ── verify ─────────────────────────────────────────────────────────────────


def test_a_correct_release_verifies_with_and_without_the_trust_store(op, dist):
    ap = sign_release(op, dist)
    out = release.verify_release(dist, ap, op.public, trusted=trusted(op))
    assert out["status"] == "verified" and out["version"] == "1.2.3" and out["commit"] == COMMIT
    assert out["role_checked"] is True
    assert release.verify_release(dist, ap, op.public)["role_checked"] is False


def test_an_expired_signing_window_does_not_invalidate_a_signature_made_inside_it(op, dist):
    ap = sign_release(op, dist, issued_at=NOW - 30 * 86400)
    assert release.verify_release(dist, ap, op.public, trusted=trusted(op))["status"] == "verified"


def _mutate(dist: Path, how: str) -> None:
    whl = next(dist.glob("*.whl"))
    if how == "artifact_mismatch":
        whl.write_bytes(b"tampered")
    elif how == "artifact_missing":
        whl.unlink()
    elif how == "artifact_unexpected":
        (dist / "extra.bin").write_bytes(b"x")
    elif how == "sums_mismatch":
        (dist / release.SUMS_NAME).write_bytes(release.sha256sums(dist) + b"0" * 64 + b"  zz\n")
    elif how == "sums_missing":
        (dist / release.SUMS_NAME).unlink()


@pytest.mark.parametrize(
    "how", ["artifact_mismatch", "artifact_missing", "artifact_unexpected", "sums_mismatch", "sums_missing"]
)
def test_any_change_to_the_released_files_is_refused(op, dist, how):
    ap = sign_release(op, dist)
    _mutate(dist, how)
    with pytest.raises(IntegrityError) as e:
        release.verify_release(dist, ap, op.public, trusted=trusted(op))
    assert str(e.value).startswith(how)


def test_a_consistently_replaced_sums_file_is_still_refused(op, dist):
    """Re-hashing tampered files into a fresh SHA256SUMS doesn't help: the signed digest differs."""
    ap = sign_release(op, dist)
    next(dist.glob("*.whl")).write_bytes(b"tampered")
    (dist / release.SUMS_NAME).write_bytes(release.sha256sums(dist))
    with pytest.raises(IntegrityError) as e:
        release.verify_release(dist, ap, op.public)
    assert str(e.value).startswith("sums_mismatch")


def test_a_signed_artifact_list_that_differs_from_sums_is_refused(op, dist):
    ap = sign_release(op, dist)
    arts = ap["payload"]["scope"]["artifacts"]
    forged = sign_release(op, dist, scope={"artifacts": arts[:-1]})
    with pytest.raises(IntegrityError) as e:
        release.verify_release(dist, forged, op.public)
    assert str(e.value).startswith("artifacts_mismatch")


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("other_key", "key_mismatch"),
        ("bad_signature", "bad_signature"),
        ("revoked", "revoked_key"),
        ("recovery_role", "wrong_key_role"),
        ("no_permission", "action_not_permitted"),
        ("expired_key", "expired_key"),
        ("wrong_action", "wrong_action"),
    ],
)
def test_key_and_signature_problems_are_refused(op, dist, case, code):
    ap, pub, tk = sign_release(op, dist), op.public, trusted(op)
    if case == "other_key":
        pub = FakeOperator.make(P256).public
        tk = None
    elif case == "bad_signature":
        ap = {
            **ap,
            "signature": approvals.Approval(ap["payload"], b"\x30\x06\x02\x01\x01\x02\x01\x01").to_json()[
                "signature"
            ],
        }
    elif case == "revoked":
        tk = trusted(op, status="revoked")
    elif case == "recovery_role":
        tk = OperatorKey(
            op.public.key_id,
            "r",
            op.public,
            "active",
            NOW + YEAR,
            role="recovery",
            permitted_actions=RECOVERY_ACTIONS,
        )
    elif case == "no_permission":
        tk = trusted(op, permitted_actions=tuple(a for a in OPERATOR_ACTIONS if a != "release.publish"))
    elif case == "expired_key":
        tk = OperatorKey(op.public.key_id, "owner", op.public, "active", NOW)
    elif case == "wrong_action":
        p = op.approve(
            ApprovalAction.POLICY_CHANGE, {"type": "policy_file", "sha256": "0" * 64}, "policy-prev:none"
        )
        ap = p.to_json()
    with pytest.raises(BlockedError) as e:
        release.verify_release(dist, ap, pub, trusted=tk)
    assert e.value.code == code


# ── CLI ────────────────────────────────────────────────────────────────────


def test_cli_attach_then_verify(home, capsys, tmp_path, op, dist):  # noqa: F811
    ts = TrustStore()
    ts.enrol(trusted(op))
    ts.save()
    ap_file = tmp_path / "received.approval.json"
    ap_file.write_bytes(canonical.encode(sign_release(op, dist)))
    code, out = run(home, capsys, "release", "attach", "--approval", str(ap_file), "--dist", str(dist))
    assert code == 0 and out["status"] == "verified" and out["key_source"] == "trust_store"
    assert (dist / release.APPROVAL_NAME).is_file()
    code, again = run(home, capsys, "release", "attach", "--approval", str(ap_file), "--dist", str(dist))
    assert code != 0  # never overwrites
    code, out = run(home, capsys, "release", "verify", str(dist))
    assert code == 0 and out["role_checked"] is True
    key = tmp_path / "pub.json"
    key.write_text(
        json.dumps({"key_id": op.public.key_id, "algorithm": P256, "public_hex": op.public.public_raw.hex()})
    )
    code, out = run(home, capsys, "release", "verify", str(dist), "--key", str(key))
    assert code == 0 and out["key_source"] == "key_file" and out["role_checked"] is False
    next(dist.glob("*.whl")).write_bytes(b"tampered")
    code, out = run(home, capsys, "release", "verify", str(dist), "--key", str(key))
    assert code != 0


def test_cli_verify_without_a_known_key_is_refused(home, capsys, op, dist):  # noqa: F811
    (dist / release.APPROVAL_NAME).write_bytes(canonical.encode(sign_release(op, dist)))
    code, out = run(home, capsys, "release", "verify", str(dist))
    assert code != 0 and "unknown_key" in json.dumps(out)


def test_cli_prepare_release_publish(home, capsys, tmp_path, op, dist):  # noqa: F811
    ts = TrustStore()
    ts.enrol(trusted(op))
    ts.save()
    code, out = run(
        home,
        capsys,
        "approval",
        "prepare",
        "release-publish",
        "--key-id",
        op.public.key_id,
        "--lifetime",
        "3600",
        "--rationale",
        "release 1.2.3",
        "--dist",
        str(dist),
        "--commit",
        COMMIT,
    )
    assert code == 0 and out["payload"]["action"] == "release.publish"


def test_a_signed_version_that_is_not_the_wheels_is_refused(op, dist):
    forged = sign_release(op, dist, subject={**release.release_parts(dist, COMMIT)[0], "version": "9.9.9"})
    with pytest.raises(IntegrityError) as e:
        release.verify_release(dist, forged, op.public)
    assert str(e.value).startswith("version_mismatch")


def test_cli_verify_refuses_a_recovery_key_file(home, capsys, tmp_path, op, dist):  # noqa: F811
    (dist / release.APPROVAL_NAME).write_bytes(canonical.encode(sign_release(op, dist)))
    key = tmp_path / "rec.json"
    key.write_text(json.dumps(FakeRecoveryAuthenticator().key_file()))
    code, out = run(home, capsys, "release", "verify", str(dist), "--key", str(key))
    assert code != 0 and "wrong_key_role" in json.dumps(out)
