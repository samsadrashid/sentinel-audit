"""Authorisation records (§11, D-16, D-21, D-37) and engine policy (D-07, D-21, D-25, D-27, D-35)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import approvals, authorization, canonical, policy
from sentinel.domain.enums import ActivityClass as C
from sentinel.domain.enums import ApprovalAction as A
from sentinel.domain.enums import AuditLevel, AuditMode, Environment
from sentinel.errors import BlockedError, ValidationError

from .conftest import NOW


def record(**over):
    rec = {
        "id": "rec-1",
        "version": 1,
        "owner": "owner",
        "approver": "owner",
        "assets": [{"id": "app", "locator": "staging.app.test", "environment": "staging"}],
        "permitted_activities": ["A1", "S1"],
        "operations": ["http.get"],
        "limits": {},
        "exclusions": ["staging.app.test/admin*"],
        "valid_from": NOW - 10,
        "expires_at": NOW + 7 * 86400,
        "evidence_of_authority": {},
    }
    rec.update(over)
    return rec


def approve_record(op, rec, lifetime=7 * 86400):
    return op.approve(
        A.AUTHORIZE_RECORD,
        {"type": "authorization_record", "sha256": canonical.digest(rec)},
        f"record:{rec['id']}:{rec['version']}",
        scope=authorization.record_scope(rec),
        lifetime=lifetime,
    )


OWNED = policy.Policy(owned_assets=("app", "prod-api"))


def test_valid_record_and_operation(operator, trust, ledger):
    rec = record()
    vr = authorization.verify_record(rec, approve_record(operator, rec), OWNED, trust, ledger, NOW)
    authorization.authorize_operation(
        vr,
        asset_locator="staging.app.test",
        environment=Environment.STAGING,
        activity=C.A1,
        operation="http.get",
        trust=trust,
        ledger=ledger,
        now=NOW + 1,
    )


def test_signature_is_not_authority(operator, trust, ledger):
    rec = record(evidence_of_authority={"app": "letter.pdf"})
    with pytest.raises(BlockedError) as e:  # not in owned_assets; evidence text alone never suffices in M1
        authorization.verify_record(rec, approve_record(operator, rec), policy.Policy(), trust, ledger, NOW)
    assert e.value.code == "no_authority"


@pytest.mark.parametrize(
    "over,code",
    [
        (
            {
                "assets": [{"id": "prod-api", "locator": "api-*.prod.test", "environment": "production"}],
                "permitted_activities": ["S1"],
            },
            "prod_wildcard",
        ),
        (
            {"assets": [{"id": "prod-api", "locator": "api.prod.test", "environment": "production"}]},
            "prod_a1",
        ),
        ({"permitted_activities": ["B3"]}, "b3_prohibited"),
    ],
)
def test_record_content_rules(operator, trust, ledger, over, code):
    with pytest.raises(BlockedError) as e:
        authorization.verify_record(record(**over), None, OWNED, trust, ledger, NOW)  # type: ignore[arg-type]
    assert e.value.code == code


@pytest.mark.parametrize(
    "over",
    [
        {"extra": 1},
        {"assets": []},
        {"valid_from": "x"},
        {"operations": "x"},
        {"exclusions": [1]},
        {"assets": [{"id": "a", "locator": "b"}]},
    ],
)
def test_malformed_records_rejected(trust, ledger, over):
    rec = record(**over) if "extra" not in over else {**record(), **over}
    with pytest.raises((ValidationError, BlockedError)):
        authorization.verify_record(rec, None, OWNED, trust, ledger, NOW)  # type: ignore[arg-type]


def test_record_validity_window(operator, trust, ledger):
    rec = record(valid_from=NOW + 100)
    with pytest.raises(BlockedError) as e:
        authorization.verify_record(rec, approve_record(operator, rec), OWNED, trust, ledger, NOW)
    assert e.value.code == "record_expired"


def test_approval_scope_must_repeat_record_scope(operator, trust, ledger):
    rec = record()
    ap = operator.approve(
        A.AUTHORIZE_RECORD,
        {"type": "authorization_record", "sha256": canonical.digest(rec)},
        "record:rec-1:1",
        scope={"assets": rec["assets"], "activity_classes": ["S1"], "operations": ["http.get"]},
    )
    with pytest.raises(BlockedError) as e:
        authorization.verify_record(rec, ap, OWNED, trust, ledger, NOW)
    assert e.value.code == "scope_mismatch"


def test_edited_record_breaks_subject_binding(operator, trust, ledger):
    rec = record()
    ap = approve_record(operator, rec)
    widened = record(operations=["http.get", "http.post"])
    with pytest.raises(BlockedError):
        authorization.verify_record(widened, ap, OWNED, trust, ledger, NOW)


@pytest.mark.parametrize(
    "kw,code",
    [
        ({"asset_locator": "other.test"}, "out_of_scope"),
        ({"environment": Environment.LOCAL}, "out_of_scope"),
        ({"activity": C.S2}, "activity_not_permitted"),
        ({"operation": "http.post"}, "operation_not_permitted"),
        ({"asset_locator": "staging.app.test/admin/x"}, "excluded"),
    ],
)
def test_operation_checks(operator, trust, ledger, kw, code):
    rec = record(assets=[{"id": "app", "locator": "staging.app.test*", "environment": "staging"}])
    vr = authorization.verify_record(rec, approve_record(operator, rec), OWNED, trust, ledger, NOW)
    args = {
        "asset_locator": "staging.app.test",
        "environment": Environment.STAGING,
        "activity": C.A1,
        "operation": "http.get",
        **kw,
    }
    with pytest.raises(BlockedError) as e:
        authorization.authorize_operation(vr, trust=trust, ledger=ledger, now=NOW + 1, **args)
    assert e.value.code == code


def test_recheck_before_operation_sees_revocation_and_expiry(operator, trust, ledger):
    rec = record()
    ap = approve_record(operator, rec, lifetime=1000)
    vr = authorization.verify_record(rec, ap, OWNED, trust, ledger, NOW)
    op = {
        "asset_locator": "staging.app.test",
        "environment": Environment.STAGING,
        "activity": C.A1,
        "operation": "http.get",
        "trust": trust,
        "ledger": ledger,
    }
    with pytest.raises(BlockedError):  # record truncated to approval expiry
        authorization.authorize_operation(vr, now=NOW + 1000, **op)
    rev = operator.approve(
        A.REVOKE_RECORD, {"type": "approval", "sha256": ap.payload_hash}, ap.payload["revision"]
    )
    approvals.apply_revocation(rev, ap, trust, ledger, NOW + 5)
    with pytest.raises(BlockedError) as e:
        authorization.authorize_operation(vr, now=NOW + 6, **op)
    assert e.value.code == "revoked"


# ── policy ─────────────────────────────────────────────────────────────────
def test_default_limits_match_decisions():
    lim = policy.default_policy().limits
    assert (lim.scanner_timeout_s, lim.max_audit_duration_s, lim.max_concurrent_scanners) == (900, 14400, 2)
    assert (lim.max_artifact_bytes, lim.max_extracted_total_bytes) == (500 * 2**20, 2**30)
    assert (lim.max_extracted_entries, lim.max_nested_archive_depth, lim.max_path_depth) == (10_000, 3, 32)
    assert (lim.max_entry_ratio, lim.max_total_ratio, lim.max_extracted_file_bytes) == (100, 50, 256 * 2**20)
    assert lim.evidence_retention_days == 90


def test_mode_level_and_activity_rules():
    policy.check_mode_level(AuditMode.READ, AuditLevel.L2)
    with pytest.raises(BlockedError):
        policy.check_mode_level(AuditMode.READ, AuditLevel.L3)
    with pytest.raises(BlockedError):
        policy.check_mode_level(AuditMode.VALIDATE, AuditLevel.L1)
    for cls in (C.S1, C.S2, C.B1, C.B2):
        policy.check_activity(AuditMode.READ, cls, has_record=False)  # D-25: B2 allowed with no record
    with pytest.raises(BlockedError):
        policy.check_activity(AuditMode.READ, C.A1, has_record=True)
    with pytest.raises(BlockedError):
        policy.check_activity(AuditMode.VALIDATE, C.A1, has_record=False)
    policy.check_activity(AuditMode.VALIDATE, C.A1, has_record=True)
    for mode in AuditMode:
        with pytest.raises(BlockedError):
            policy.check_activity(mode, C.B3, has_record=True)


def _policy_files(tmp_path: Path, op, body: dict, prev: str = "none", lifetime=3600):
    pf = tmp_path / "policy.json"
    pf.write_bytes(json.dumps(body).encode())
    ap = op.approve(
        A.POLICY_CHANGE,
        {"type": "policy_file", "sha256": canonical.sha256_hex(pf.read_bytes())},
        f"policy-prev:{prev}",
        lifetime=lifetime,
    )
    af = tmp_path / "policy.approval.json"
    approvals.save_approval_file(af, ap)
    return pf, af


def test_signed_policy_applies(tmp_path, operator, trust, ledger):
    pf, af = _policy_files(
        tmp_path, operator, {"limits": {"max_concurrent_scanners": 1}, "owned_assets": ["x"]}
    )
    p = policy.load_policy(pf, af, trust, ledger, NOW + 1)
    assert p.limits.max_concurrent_scanners == 1 and p.owned_assets == ("x",)
    assert "fixture" in p.adapter_allowlist  # built-in allowlist kept
    assert (
        policy.load_policy(pf, af, trust, ledger, NOW + 2).limits.max_concurrent_scanners == 1
    )  # re-load ok


def test_unsigned_or_changed_policy_blocks(tmp_path, operator, trust, ledger):
    pf, af = _policy_files(tmp_path, operator, {"limits": {}})
    with pytest.raises(BlockedError):
        policy.load_policy(pf, None, trust, ledger, NOW + 1)
    pf.write_bytes(b'{"limits":{"max_concurrent_scanners":50}}')
    with pytest.raises(BlockedError) as e:
        policy.load_policy(pf, af, trust, ledger, NOW + 1)
    assert e.value.code == "wrong_subject"


def test_policy_change_binds_previous_file(tmp_path, operator, trust, ledger):
    pf, af = _policy_files(tmp_path, operator, {"limits": {}})
    first = canonical.sha256_hex(pf.read_bytes())
    policy.load_policy(pf, af, trust, ledger, NOW + 1)
    (tmp_path / "v2").mkdir()
    pf2, af2 = _policy_files(
        tmp_path / "v2", operator, {"limits": {"max_concurrent_scanners": 1}}, prev="none"
    )
    with pytest.raises(BlockedError) as e:  # must name the file it replaces
        policy.load_policy(pf2, af2, trust, ledger, NOW + 2)
    assert e.value.code == "wrong_revision"
    (tmp_path / "v3").mkdir()
    pf3, af3 = _policy_files(
        tmp_path / "v3", operator, {"limits": {"max_concurrent_scanners": 1}}, prev=first
    )
    policy.load_policy(pf3, af3, trust, ledger, NOW + 3)


@pytest.mark.parametrize(
    "body",
    [
        {"limits": {"nope": 1}},
        {"limits": {"max_concurrent_scanners": 0}},
        {"limits": {"max_concurrent_scanners": True}},
        {"other": 1},
        {"adapter_allowlist": {"x": "short"}},
        {"owned_assets": "x"},
    ],
)
def test_invalid_policy_content_rejected(tmp_path, operator, trust, ledger, body):
    pf, af = _policy_files(tmp_path, operator, body)
    with pytest.raises(ValidationError):
        policy.load_policy(pf, af, trust, ledger, NOW + 1)


# ── D-42: adapter allowlist changes need a `policy.change` approval ───────
def test_adapter_allowlist_change_requires_policy_change(tmp_path, operator, trust, ledger):
    body = {"adapter_allowlist": {"extra": "c" * 64}}
    pf, af = _policy_files(tmp_path, operator, body)
    p = policy.load_policy(pf, af, trust, ledger, NOW + 1)
    assert p.adapter_allowlist["extra"] == "c" * 64
    # The same file approved with any other action is refused (wrong context).
    raw = pf.read_bytes()
    subject = {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}
    for other in (A.SUPPRESS, A.REVIEW_ACCEPT_RISK, A.AUTHORIZE_RECORD):
        pf2 = tmp_path / f"p-{other.value}.json"
        pf2.write_bytes(raw.replace(b'"c', b'"d'))
        sub2 = {"type": "policy_file", "sha256": canonical.sha256_hex(pf2.read_bytes())}
        ap = operator.approve(other, sub2, f"policy-prev:{subject['sha256']}")
        af2 = tmp_path / f"a-{other.value}.json"
        approvals.save_approval_file(af2, ap)
        with pytest.raises(BlockedError) as e:
            policy.load_policy(pf2, af2, trust, ledger, NOW + 2)
        assert e.value.code == "wrong_context"
