"""End-to-end pipeline tests (orchestrator + every engine module), synthetic fixtures only.

Operator approvals are produced by test-only keys (see conftest). No real keystore, network or
external target is used.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel import approvals, authorization, canonical, policy
from sentinel.adapters.fixture import FIXTURE_SCRIPT, FixtureAdapter, script_sha256
from sentinel.crypto.signing import Ed25519Signer
from sentinel.domain.enums import ApprovalAction, AuditState, CheckStatus, FindingState
from sentinel.domain.models import AuditConfig
from sentinel.errors import IntegrityError, ValidationError
from sentinel.isolation import HostCapabilities
from sentinel.orchestrator import AuditRequest, run_audit, verify_run

from .conftest import NOW
from .isolation_testing import TestOnlyRunner, make_test_host

ALLOW = script_sha256(FIXTURE_SCRIPT)
HOST_NO_ISOLATION = HostCapabilities("test", None, None, None, False)
TEST_HOST = make_test_host()


def make_target(tmp_path: Path, name: str, content: str) -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "app.txt").write_text(content)
    return root


def cfg(*targets: Path, mode="READ", level="L2", classes=("S1",), env="local") -> AuditConfig:
    return AuditConfig.from_dict(
        {
            "mode": mode,
            "level": level,
            "activity_classes": list(classes),
            "scope": {
                "assets": [
                    {"id": t.name, "kind": "local_path", "locator": str(t), "environment": env}
                    for t in targets
                ]
            },
        }
    )


def request(tmp_path, trust, ledger, config, *, adapters=None, pol=None, authz=None, clock=None, **kw):
    signer = kw.pop("signer", Ed25519Signer.generate())
    return AuditRequest(
        config=config,
        policy=pol or policy.default_policy(),
        trust=trust,
        ledger=ledger,
        run_signer=signer,
        adapters=adapters or [FixtureAdapter(allowlisted_sha256=ALLOW)],
        runs_dir=tmp_path / "runs",
        authorization=authz,
        clock=clock or (lambda: NOW),
        host=kw.pop("host", TEST_HOST),
        env={},
        **kw,
    )


def record_for(targets, op, *, lifetime=7 * 86400, ops=("fixture.marker",), env="local"):
    rec = {
        "id": "rec-1",
        "version": 1,
        "owner": "owner",
        "approver": "owner",
        "assets": [{"id": t.name, "locator": str(t), "environment": env} for t in targets],
        "permitted_activities": ["S1"],
        "operations": list(ops),
        "limits": {},
        "exclusions": [],
        "valid_from": NOW - 10,
        "expires_at": NOW + 30 * 86400,
        "evidence_of_authority": {},
    }
    ap = op.approve(
        ApprovalAction.AUTHORIZE_RECORD,
        {"type": "authorization_record", "sha256": canonical.digest(rec)},
        "record:rec-1:1",
        scope=authorization.record_scope(rec),
        lifetime=lifetime,
    )
    return rec, ap


def owned(*targets: Path) -> policy.Policy:
    return replace(policy.default_policy(), owned_assets=tuple(t.name for t in targets))


# ── successful audits ──────────────────────────────────────────────────────
def test_clean_local_read_audit_passes_and_verifies(tmp_path, trust, ledger):
    t = make_target(tmp_path, "clean", "nothing to see")
    req = request(tmp_path, trust, ledger, cfg(t))
    out = run_audit(req)
    assert out.state == AuditState.COMPLETED and out.overall == "PASS"
    assert [c.status for c in out.checks] == [CheckStatus.PASS]
    m = verify_run(out.run_dir, req.run_signer.public)
    assert m["state"] == "Completed" and m["revision"].startswith("tree-sha256:")
    assert m["adapters"][0]["engine_owned"] is True


def test_findings_flow_through_with_evidence_and_fingerprints(tmp_path, trust, ledger):
    t = make_target(tmp_path, "vuln", "ok\nSENTINEL-FIXTURE-FINDING\n")
    req = request(tmp_path, trust, ledger, cfg(t))
    out = run_audit(req)
    assert out.overall == "FAIL" and out.state == AuditState.COMPLETED
    (f,) = out.findings
    assert f.state == FindingState.SUSPECTED and f.location == {"file": "app.txt", "line": 2}
    assert len(f.evidence) == 1 and (out.run_dir / "evidence" / f.evidence[0]).is_file()
    manifest = verify_run(out.run_dir, req.run_signer.public)
    assert manifest["finding_fingerprints"] == [f.fingerprint]
    assert f.evidence[0] in manifest["evidence_index"]


def test_authorized_validate_audit(tmp_path, operator, trust, ledger):
    t = make_target(tmp_path, "staged", "clean")
    authz = record_for([t], operator)
    req = request(tmp_path, trust, ledger, cfg(t, mode="VALIDATE", level="L3"), pol=owned(t), authz=authz)
    out = run_audit(req)
    assert out.overall == "PASS" and out.result["authorization_ref"] == "rec-1:1"


def test_fingerprints_reproducible_across_runs(tmp_path, trust, ledger):
    t = make_target(tmp_path, "repro", "SENTINEL-FIXTURE-FINDING")
    a = run_audit(request(tmp_path, trust, ledger, cfg(t)))
    b = run_audit(request(tmp_path, trust, ledger, cfg(t)))
    assert a.audit_id != b.audit_id
    assert [f.fingerprint for f in a.findings] == [f.fingerprint for f in b.findings]  # R-12


# ── authorisation failures ─────────────────────────────────────────────────
def test_missing_authorization_for_a1_blocks(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t, mode="VALIDATE", level="L3", classes=("A1",))))
    assert out.state == AuditState.BLOCKED and out.overall == "BLOCKED"
    assert all(c.status == CheckStatus.BLOCKED and "no_record" in c.reason for c in out.checks)


def test_expired_authorization_blocks(tmp_path, operator, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    authz = record_for([t], operator, lifetime=60)
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, mode="VALIDATE", level="L3"),
            pol=owned(t),
            authz=authz,
            clock=lambda: NOW + 61,
        )
    )
    assert out.state == AuditState.BLOCKED and "expired" in out.checks[0].reason


def test_scope_mismatch_blocks_the_check(tmp_path, operator, trust, ledger):
    in_scope = make_target(tmp_path, "inscope", "x")
    other = make_target(tmp_path, "other", "x")
    authz = record_for([in_scope], operator)
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(in_scope, other, mode="VALIDATE", level="L3"),
            pol=owned(in_scope),
            authz=authz,
        )
    )
    statuses = {c.check_id.split("/")[0]: c for c in out.checks}
    assert statuses["inscope"].status == CheckStatus.PASS
    assert statuses["other"].status == CheckStatus.BLOCKED and "out_of_scope" in statuses["other"].reason
    assert out.state == AuditState.INCOMPLETE and out.overall != "PASS"


def test_operation_not_in_record_blocks(tmp_path, operator, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    authz = record_for([t], operator, ops=("something.else",))
    out = run_audit(
        request(tmp_path, trust, ledger, cfg(t, mode="VALIDATE", level="L3"), pol=owned(t), authz=authz)
    )
    assert out.checks[0].status == CheckStatus.BLOCKED and out.overall != "PASS"


def test_revocation_during_execution_blocks_remaining_checks(tmp_path, operator, trust, ledger):
    a, b = make_target(tmp_path, "a", "x"), make_target(tmp_path, "b", "x")
    rec, ap = record_for([a, b], operator)
    pol = replace(owned(a, b), limits=replace(policy.Limits(), max_concurrent_scanners=1))

    def revoke_after_first(_check):
        if ap.payload_hash not in ledger.revoked:
            rev = operator.approve(
                ApprovalAction.REVOKE_RECORD,
                {"type": "approval", "sha256": ap.payload_hash},
                ap.payload["revision"],
            )
            approvals.apply_revocation(rev, ap, trust, ledger, NOW + 1)

    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(a, b, mode="VALIDATE", level="L3"),
            pol=pol,
            authz=(rec, ap),
            after_check=revoke_after_first,
        )
    )
    assert [c.status for c in out.checks] == [CheckStatus.PASS, CheckStatus.BLOCKED]
    assert "revoked" in out.checks[1].reason and out.state == AuditState.INCOMPLETE


def test_signature_without_authority_blocks(tmp_path, operator, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    authz = record_for([t], operator)
    out = run_audit(request(tmp_path, trust, ledger, cfg(t, mode="VALIDATE", level="L3"), authz=authz))
    assert out.state == AuditState.BLOCKED and "no_authority" in out.checks[0].reason


# ── policy bypass attempts ─────────────────────────────────────────────────
def test_a1_in_read_mode_blocked(tmp_path, operator, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    out = run_audit(
        request(
            tmp_path, trust, ledger, cfg(t, classes=("A1",)), pol=owned(t), authz=record_for([t], operator)
        )
    )
    assert out.state == AuditState.BLOCKED and out.overall != "PASS"


def test_level_mode_mismatch_blocked(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t, level="L3")))
    assert out.state == AuditState.BLOCKED and "mode_level" in out.checks[0].reason


def test_b3_and_red_team_rejected_before_any_run(tmp_path):
    t = make_target(tmp_path, "t", "x")
    with pytest.raises(ValidationError):
        cfg(t, classes=("B3",))
    with pytest.raises(ValidationError):
        cfg(t, mode="RED_TEAM")


def test_validate_against_production_blocked(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t, mode="VALIDATE", level="L3", env="production")))
    assert out.state == AuditState.BLOCKED


@pytest.mark.parametrize("engine_owned", [True, False])
def test_no_isolation_means_not_run_for_every_adapter(tmp_path, trust, ledger, engine_owned):
    """X-5 paths P1 and P2: without a verified isolation layer no adapter runs, engine-owned included."""
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    calls: list[str] = []

    class Spy(FixtureAdapter):
        manifest = replace(FixtureAdapter.manifest, name="spy", engine_owned=engine_owned)

        def execute(self, *a, **kw):  # type: ignore[override]
            calls.append("execute")
            return super().execute(*a, **kw)

    out = run_audit(
        request(
            tmp_path, trust, ledger, cfg(t), adapters=[Spy(allowlisted_sha256=ALLOW)], host=HOST_NO_ISOLATION
        )
    )
    c = out.checks[0]
    assert c.status == CheckStatus.NOT_RUN and c.reason == "host_isolation_unavailable"
    assert calls == [] and out.findings == [] and out.overall != "PASS" and out.state == "Incomplete"
    # Decided at planning: the check never reaches execution-time dispatch.
    assert "check.isolation_unavailable" not in (out.run_dir / "audit-log.jsonl").read_text()
    assert (
        not any((out.run_dir / "evidence").glob("*.meta.json"))
        if (out.run_dir / "evidence").exists()
        else True
    )


def test_layer_name_without_a_production_runner_is_not_run(tmp_path, trust, ledger):
    """X-5 P5: a host that names an isolation layer production has no runner for gets NOT_RUN."""
    t = make_target(tmp_path, "t", "x")
    host = HostCapabilities("test", "some-unverified-layer", None, None, False)
    out = run_audit(request(tmp_path, trust, ledger, cfg(t), host=host))
    assert out.checks[0].status == CheckStatus.NOT_RUN
    assert out.checks[0].reason == "host_isolation_unavailable"


def test_root_host_never_runs_adapters(tmp_path, trust, ledger):
    """X-5 P6: running as root withholds every isolation layer, so nothing runs."""
    t = make_target(tmp_path, "t", "x")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t), host=make_test_host(running_as_root=True)))
    assert out.checks[0].status == CheckStatus.NOT_RUN


def test_adapter_that_ignores_a_runner_is_error(tmp_path, trust, ledger):
    """X-5 P4 (test-only runner): results produced outside the given runner are discarded."""
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")

    class Liar(FixtureAdapter):
        def execute(self, check, root, timeout_s, max_output, runner=None):  # type: ignore[override]
            r = super().execute(check, root, timeout_s, max_output, runner=runner)
            r.isolation = "none"
            return r

    out = run_audit(request(tmp_path, trust, ledger, cfg(t), adapters=[Liar(allowlisted_sha256=ALLOW)]))
    assert out.checks[0].status == CheckStatus.ERROR and out.checks[0].reason == "isolation_not_used"
    assert out.findings == []


def test_not_run_results_keep_nothing(tmp_path, trust, ledger):
    """An adapter reporting NOT_RUN contributes no evidence or findings, whatever else it returns."""
    from sentinel.adapters.base import ExecutionResult

    t = make_target(tmp_path, "t", "x")

    class Sneaky(FixtureAdapter):
        def execute(self, *a, **kw):  # type: ignore[override]
            return ExecutionResult(
                CheckStatus.NOT_RUN,
                "scanner_missing",
                raw_output=b"leaked",
                findings=[{"rule": "r", "file": "f", "line": 1, "message": "m", "severity": "high"}],
            )

    out = run_audit(request(tmp_path, trust, ledger, cfg(t), adapters=[Sneaky(allowlisted_sha256=ALLOW)]))
    assert out.checks[0].status == CheckStatus.NOT_RUN and out.findings == []
    assert not (out.run_dir / "evidence").exists() or not any((out.run_dir / "evidence").iterdir())


def test_execution_time_isolation_gate_blocks_dispatch(tmp_path, trust, ledger):
    """Defence in depth: if planning let a check through but the host has no runner at execution time,
    the adapter is still never invoked."""
    t = make_target(tmp_path, "t", "x")
    calls: list[str] = []

    class Spy(FixtureAdapter):
        def execute(self, *a, **kw):  # type: ignore[override]
            calls.append("execute")
            return super().execute(*a, **kw)

    class PlansButNoRunner(type(TEST_HOST)):  # type: ignore[misc]
        """Isolation is available when the check is planned and gone when it is dispatched."""

        seen = [0]

        def runner_for(self, cls, limits, pins=None, kind=None):
            self.seen[0] += 1
            return TestOnlyRunner() if self.seen[0] == 1 else None

    host = PlansButNoRunner("test", "test-only-runner (NOT isolation)", None, None, False)
    out = run_audit(
        request(tmp_path, trust, ledger, cfg(t), adapters=[Spy(allowlisted_sha256=ALLOW)], host=host)
    )
    assert out.checks[0].status == CheckStatus.NOT_RUN and calls == []
    assert "check.isolation_unavailable" in (out.run_dir / "audit-log.jsonl").read_text()


def test_fixture_adapter_refuses_to_run_without_a_runner(tmp_path):
    """Defence in depth inside the adapter: no runner, no process."""
    import subprocess as sp

    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    a = FixtureAdapter(allowlisted_sha256=ALLOW)
    orig = sp.Popen
    sp.Popen = lambda *x, **k: pytest.fail("a process was started without isolation")  # type: ignore[assignment]
    try:
        r = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=None)
    finally:
        sp.Popen = orig  # type: ignore[assignment]
    assert r.status == CheckStatus.NOT_RUN and r.reason == "host_isolation_unavailable"


def test_test_only_runner_is_never_importable_from_production():
    src = Path(__file__).resolve().parents[1] / "src"
    for p in src.rglob("*.py"):
        text = p.read_text()
        assert "isolation_testing" not in text and "TestOnlyRunner" not in text, p
        assert "test-only-runner" not in text, p


def test_unimplemented_classes_are_visible_not_silent(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t, classes=("S1", "B2"))))
    reasons = {c.reason for c in out.checks}
    assert "no_adapter_for_class" in reasons and out.state == AuditState.INCOMPLETE


# ── scanner failures never PASS ────────────────────────────────────────────
@pytest.mark.parametrize(
    "content,reason", [("SENTINEL-FIXTURE-CRASH", "exit_1"), ("SENTINEL-FIXTURE-GARBAGE", "bad_output")]
)
def test_crash_and_malformed_output_make_audit_incomplete(tmp_path, trust, ledger, content, reason):
    t = make_target(tmp_path, "t", content)
    out = run_audit(request(tmp_path, trust, ledger, cfg(t)))
    assert out.checks[0].status == CheckStatus.ERROR and out.checks[0].reason.startswith(reason)
    assert out.state == AuditState.INCOMPLETE and out.overall == "INCOMPLETE"


def test_scanner_timeout(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-HANG")
    pol = replace(policy.default_policy(), limits=replace(policy.Limits(), scanner_timeout_s=1))
    out = run_audit(request(tmp_path, trust, ledger, cfg(t), pol=pol))
    assert out.checks[0].reason == "timeout" and out.overall == "INCOMPLETE"


def test_missing_scanner_and_hash_mismatch(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    out = run_audit(
        request(tmp_path, trust, ledger, cfg(t), adapters=[FixtureAdapter(allowlisted_sha256="0" * 64)])
    )
    assert out.checks[0].reason == "binary_hash_mismatch" and out.overall == "INCOMPLETE"
    out2 = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t),
            adapters=[FixtureAdapter(script=tmp_path / "gone.py", allowlisted_sha256=ALLOW)],
        )
    )
    assert out2.checks[0].reason == "scanner_missing" and out2.overall == "INCOMPLETE"


def test_missing_target_not_run(tmp_path, trust, ledger):
    ghost = tmp_path / "ghost"
    c = AuditConfig.from_dict(
        {
            "scope": {
                "assets": [
                    {"id": "ghost", "kind": "local_path", "locator": str(ghost), "environment": "local"}
                ]
            }
        }
    )
    out = run_audit(request(tmp_path, trust, ledger, c))
    assert out.checks[0].reason == "target_not_found" and out.overall == "INCOMPLETE"


def test_max_audit_duration_makes_remaining_checks_not_run(tmp_path, trust, ledger):
    a, b = make_target(tmp_path, "a", "x"), make_target(tmp_path, "b", "x")
    times = iter([NOW, NOW, NOW + 5, NOW + 14_400, NOW + 14_400, NOW + 14_400, NOW + 14_400])
    pol = replace(policy.default_policy(), limits=replace(policy.Limits(), max_concurrent_scanners=1))
    out = run_audit(
        request(tmp_path, trust, ledger, cfg(a, b), pol=pol, clock=lambda: next(times, NOW + 99_999))
    )
    assert out.checks[-1].status == CheckStatus.NOT_RUN and out.checks[-1].reason == "audit_timeout"
    assert out.state == AuditState.INCOMPLETE


def test_cancellation(tmp_path, trust, ledger):
    a, b = make_target(tmp_path, "a", "x"), make_target(tmp_path, "b", "x")
    stop = threading.Event()
    pol = replace(policy.default_policy(), limits=replace(policy.Limits(), max_concurrent_scanners=1))
    out = run_audit(
        request(tmp_path, trust, ledger, cfg(a, b), pol=pol, cancel=stop, after_check=lambda _c: stop.set())
    )
    assert out.checks[1].reason == "cancelled" and out.state == AuditState.CANCELLED and out.overall != "PASS"


# ── evidence and manifest integrity ───────────────────────────────────────
def test_evidence_tampering_detected(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING")
    req = request(tmp_path, trust, ledger, cfg(t))
    out = run_audit(req)
    ev = out.run_dir / "evidence" / out.findings[0].evidence[0]
    os.chmod(ev, 0o600)
    ev.write_bytes(b"forged output")
    with pytest.raises(IntegrityError):
        verify_run(out.run_dir, req.run_signer.public)


def test_manifest_verification_failure(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    req = request(tmp_path, trust, ledger, cfg(t))
    out = run_audit(req)
    m = json.loads((out.run_dir / "manifest.json").read_text())
    m["overall"] = "PASS-forged"
    (out.run_dir / "manifest.json").write_bytes(canonical.encode(m))
    with pytest.raises(IntegrityError):
        verify_run(out.run_dir, req.run_signer.public)
    with pytest.raises(IntegrityError):
        verify_run(out.run_dir, Ed25519Signer.generate().public)


def test_audit_log_tampering_detected(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    req = request(tmp_path, trust, ledger, cfg(t))
    out = run_audit(req)
    log = out.run_dir / "audit-log.jsonl"
    log.write_text(log.read_text().replace("check.finished", "check.finishex", 1))
    with pytest.raises(IntegrityError):
        verify_run(out.run_dir, req.run_signer.public)


# ── reports ────────────────────────────────────────────────────────────────
def test_reports_written_and_consistent(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-CRASH")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t), caller="Claude Code"))
    assert set(out.report_paths) == {"json", "sarif", "md", "html"}
    data = canonical.decode_strict(out.report_paths["json"].read_bytes())
    assert data["overall"] == "INCOMPLETE" and data["checks_not_finished"]
    assert data["disclosure"]["zone"] == "agent_assisted"
    sarif = json.loads(out.report_paths["sarif"].read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    for fmt in ("md", "html"):
        text = out.report_paths[fmt].read_text()
        assert "INCOMPLETE" in text and "not a statement that the target is secure" in text
    assert data["operator_trust_fingerprint"] == trust.fingerprint()


def test_operator_signing_still_fails_closed():
    from sentinel.errors import CapabilityUnavailable
    from sentinel.keys.operator import available_provider

    with pytest.raises(CapabilityUnavailable):
        available_provider()


def test_engine_blocks_scope_expansion_even_if_adapter_does_not(tmp_path, trust, ledger):
    """A hostile adapter that plans an outside target and skips its own scope check is still blocked."""
    t = make_target(tmp_path, "t", "x")
    outside = make_target(tmp_path, "secret", "SENTINEL-FIXTURE-FINDING")

    class Hostile(FixtureAdapter):
        def plan(self, root):
            from sentinel.adapters.base import PlannedCheck

            return [PlannedCheck("fixture.marker", (str(outside),))]

        def validate_scope(self, plan, root):
            return None  # lies

    out = run_audit(request(tmp_path, trust, ledger, cfg(t), adapters=[Hostile(allowlisted_sha256=ALLOW)]))
    assert out.checks[0].status == CheckStatus.BLOCKED and "scope_expansion" in out.checks[0].reason
    assert out.findings == [] and out.overall != "PASS"
