"""Foundation unit tests: enums, errors, canonical encoding, domain models, lifecycle, path safety.

Synthetic data only. No network, no external targets, no cryptographic approval paths (later sessions).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinel import canonical
from sentinel.domain.enums import (
    COMPLETE_STATUSES,
    ONE_TIME_ACTIONS,
    STANDING_ACTIONS,
    ApprovalAction,
    AuditMode,
    AuditState,
    CheckStatus,
    FindingState,
)
from sentinel.domain.models import Asset, AuditConfig, AuditSummary, CheckResult, ScannerExecution, Scope
from sentinel.errors import BlockedError, LifecycleError, SentinelError, ValidationError
from sentinel.lifecycle import AuditStateMachine, final_state, overall_result
from sentinel.paths import atomic_write, resolve_within, write_once


# ── enums ──────────────────────────────────────────────────────────────────
def test_check_statuses_exact():
    assert {s.value for s in CheckStatus} == {"PASS", "FAIL", "NOT_RUN", "BLOCKED", "ERROR", "NOT_APPLICABLE"}
    assert COMPLETE_STATUSES == {CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.NOT_APPLICABLE}


def test_red_team_mode_absent_in_v1():
    assert {m.value for m in AuditMode} == {"READ", "VALIDATE"}  # D-21


def test_human_verified_status_distinct_from_verified():
    assert FindingState.HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE != FindingState.VERIFIED
    hv = FindingState.HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE
    assert hv.value == "HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE"


def test_approval_actions_partitioned_per_d36():
    # D-74 adds the one-time `release.publish`; the eight D-36 actions are otherwise unchanged.
    assert {a.value for a in ONE_TIME_ACTIONS} == {
        "revoke_record",
        "key.rotate",
        "key.revoke",
        "release.publish",
    }
    assert ONE_TIME_ACTIONS | STANDING_ACTIONS == set(ApprovalAction)
    assert not (ONE_TIME_ACTIONS & STANDING_ACTIONS)
    assert len(ApprovalAction) == 9  # allowlist.change removed (D-42); release.publish added (D-74)
    assert "allowlist.change" not in {a.value for a in ApprovalAction}


# ── errors ─────────────────────────────────────────────────────────────────
def test_error_hierarchy_and_blocked_reason():
    e = BlockedError("no record", "no_record")
    assert isinstance(e, SentinelError) and e.reason == "no record" and e.code == "no_record"
    assert issubclass(ValidationError, SentinelError) and issubclass(LifecycleError, SentinelError)


# ── canonical encoding ─────────────────────────────────────────────────────
def test_canonical_is_deterministic_and_key_order_independent():
    a = {"b": 1, "a": [1, {"y": "x", "x": True}], "c": None}
    b = {"c": None, "a": [1, {"x": True, "y": "x"}], "b": 1}
    assert canonical.encode(a) == canonical.encode(b) == b'{"a":[1,{"x":true,"y":"x"}],"b":1,"c":null}'


def test_canonical_normalises_unicode():
    assert canonical.encode({"k": "é"}) == canonical.encode({"k": "é"})


@pytest.mark.parametrize("bad", [1.5, float("nan"), {1: "x"}, b"bytes", {"a": object()}])
def test_canonical_rejects_unsupported(bad):
    with pytest.raises(ValidationError):
        canonical.encode(bad)


def test_canonical_rejects_deep_nesting():
    v: object = 1
    for _ in range(70):
        v = [v]
    with pytest.raises(ValidationError):
        canonical.encode(v)


def test_decode_strict_rejects_duplicates_constants_and_size():
    with pytest.raises(ValidationError):
        canonical.decode_strict(b'{"a":1,"a":2}')
    with pytest.raises(ValidationError):
        canonical.decode_strict(b'{"a":NaN}')
    with pytest.raises(ValidationError):
        canonical.decode_strict(b"{not json")
    with pytest.raises(ValidationError):
        canonical.decode_strict(b"[" + b"1," * 100 + b"1]", max_bytes=10)
    assert canonical.decode_strict(b'{"a":[1,2]}') == {"a": [1, 2]}


# ── domain models ──────────────────────────────────────────────────────────
ASSET = {"id": "repo", "kind": "local_path", "locator": "./fixture", "environment": "local"}


def test_audit_config_defaults_read_l2():
    cfg = AuditConfig.from_dict({"scope": {"assets": [ASSET]}})
    assert cfg.mode == AuditMode.READ and cfg.level.value == "L2"  # D-07, D-08
    assert [c.value for c in cfg.activity_classes] == ["S1"]


@pytest.mark.parametrize(
    "cfg",
    [
        {"scope": {"assets": [ASSET]}, "mode": "RED_TEAM"},
        {"scope": {"assets": [ASSET]}, "activity_classes": ["B3"]},
        {"scope": {"assets": [ASSET]}, "extra": 1},
        {"scope": {"assets": []}},
        {"scope": {"assets": [ASSET, ASSET]}},
        {"scope": {"assets": [{**ASSET, "kind": "shell"}]}},
        {"scope": {"assets": [{**ASSET, "locator": "../escape"}]}},
        {"scope": {"assets": [{**ASSET, "environment": "production", "locator": "app-*"}]}},
        {"scope": {"assets": [{**ASSET, "locator": "a\x00b"}]}},
        {"scope": {"assets": [ASSET]}, "activity_classes": []},
        "not an object",
    ],
)
def test_audit_config_rejects_invalid(cfg):
    with pytest.raises(ValidationError):
        AuditConfig.from_dict(cfg)


def test_scope_lookup_and_exact_production_asset():
    s = Scope.from_dict(
        {"assets": [{"id": "p", "kind": "host", "locator": "api.example.test", "environment": "production"}]}
    )
    assert s.asset("p") is not None and s.asset("missing") is None
    assert Asset.from_dict(ASSET).environment.value == "local"


def test_check_result_requires_reason_for_unfinished_states():
    for st in (CheckStatus.NOT_RUN, CheckStatus.BLOCKED, CheckStatus.ERROR):
        with pytest.raises(ValidationError):
            CheckResult("c", "fixture", st)
        assert not CheckResult("c", "fixture", st, reason="x").finished
    assert CheckResult("c", "fixture", CheckStatus.PASS).finished


def test_scanner_execution_validates_hashes():
    ScannerExecution("a", "1", "s", "1", "a" * 64, "b" * 64, 0, 10)
    with pytest.raises(ValidationError):
        ScannerExecution("a", "1", "s", "1", "XYZ", "b" * 64, 0, 10)


def test_audit_summary_counts_every_status():
    checks = [CheckResult("a", "f", CheckStatus.PASS), CheckResult("b", "f", CheckStatus.NOT_RUN, "missing")]
    s = AuditSummary.build("id", "Incomplete", "INCOMPLETE", checks)
    assert s.counts["PASS"] == 1 and s.counts["NOT_RUN"] == 1 and len(s.counts) == 6
    assert [c.check_id for c in s.not_finished] == ["b"]


# ── lifecycle and result states ───────────────────────────────────────────
def test_state_machine_happy_path_and_illegal_transitions():
    m = AuditStateMachine()
    for st in (
        AuditState.PLANNED,
        AuditState.AUTHORIZED,
        AuditState.RUNNING,
        AuditState.COMPLETED,
        AuditState.REPORTED,
    ):
        m.to(st)
    with pytest.raises(LifecycleError):
        m.to(AuditState.RUNNING)
    with pytest.raises(LifecycleError):
        AuditStateMachine().to(AuditState.COMPLETED)


def test_paused_can_be_cancelled():
    m = AuditStateMachine()
    for st in (
        AuditState.PLANNED,
        AuditState.AUTHORIZED,
        AuditState.RUNNING,
        AuditState.PAUSED,
        AuditState.CANCELLED,
    ):
        m.to(st)


@pytest.mark.parametrize(
    "statuses,expected",
    [
        ([CheckStatus.PASS, CheckStatus.NOT_APPLICABLE], AuditState.COMPLETED),
        ([CheckStatus.PASS, CheckStatus.FAIL], AuditState.COMPLETED),
        ([CheckStatus.PASS, CheckStatus.NOT_RUN], AuditState.INCOMPLETE),
        ([CheckStatus.PASS, CheckStatus.ERROR], AuditState.INCOMPLETE),
        ([CheckStatus.PASS, CheckStatus.BLOCKED], AuditState.INCOMPLETE),
        ([], AuditState.INCOMPLETE),
    ],
)
def test_final_state(statuses, expected):
    assert final_state(statuses) == expected


def test_incomplete_or_cancelled_audits_never_pass():
    for st in (AuditState.INCOMPLETE, AuditState.CANCELLED, AuditState.BLOCKED, AuditState.REPORTED):
        assert overall_result(st, [CheckStatus.PASS]) != "PASS"
    assert overall_result(AuditState.COMPLETED, []) != "PASS"
    assert overall_result(AuditState.COMPLETED, [CheckStatus.PASS, CheckStatus.ERROR]) != "PASS"
    assert overall_result(AuditState.COMPLETED, [CheckStatus.PASS]) == "PASS"
    assert overall_result(AuditState.COMPLETED, [CheckStatus.PASS, CheckStatus.FAIL]) == "FAIL"
    assert final_state([CheckStatus.PASS], cancelled=True) == AuditState.CANCELLED


# ── path safety ────────────────────────────────────────────────────────────
def test_resolve_within_blocks_traversal_and_symlink_escape(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.txt").write_text("x")
    assert resolve_within(root, "ok.txt") == (root / "ok.txt").resolve()
    with pytest.raises(ValidationError):
        resolve_within(root, "../outside")
    (root / "link").symlink_to(tmp_path)
    with pytest.raises(ValidationError):
        resolve_within(root, "link/x")


def test_atomic_write_is_owner_only_and_write_once_refuses_overwrite(tmp_path: Path):
    p = tmp_path / "d" / "f.json"
    atomic_write(p, b"{}")
    assert p.read_bytes() == b"{}" and (p.stat().st_mode & 0o777) == 0o600
    assert (p.parent.stat().st_mode & 0o777) == 0o700
    w = tmp_path / "e" / "ev"
    write_once(w, b"data")
    with pytest.raises(FileExistsError):
        write_once(w, b"other")
    assert (w.stat().st_mode & 0o777) == 0o400
    os.chmod(w, 0o600)
