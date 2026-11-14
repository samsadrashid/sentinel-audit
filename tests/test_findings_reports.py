"""Findings (§6.3, §7, D-26, R-12), reports (D-17), disclosure (§13.3, D-31) and host detection (D-32)."""

from __future__ import annotations

import json

import pytest

from sentinel import findings as F
from sentinel import reports
from sentinel.disclosure import detect
from sentinel.domain.enums import (
    ActivityClass,
    ApprovalAction,
    Confidence,
    FindingOrigin,
    FindingState,
    Severity,
)
from sentinel.errors import BlockedError
from sentinel.isolation import detect as detect_host

from .conftest import NOW

REV = "commit:abc"


def scanner_finding(rule="r1", line=3, producer="fixture", sev="medium"):
    return F.new_finding(
        domain="web",
        rule=rule,
        title="t",
        file="a.py",
        line=line,
        component="app",
        severity=sev,
        origin=FindingOrigin.SCANNER,
        evidence_id="e" * 64,
        producer=producer,
    )


def test_fingerprint_is_deterministic_and_identity_based():
    a, b = scanner_finding(), scanner_finding()
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != scanner_finding(line=4).fingerprint
    assert F.fingerprint("web", "r", "a:1", "c") == F.fingerprint("web", "r", "a:1", "c")


def test_starting_states():
    assert scanner_finding().state == FindingState.SUSPECTED
    agent = F.new_finding(
        domain="web",
        rule="r",
        title="t",
        file="a",
        line=1,
        component="c",
        severity="high",
        origin=FindingOrigin.AGENT,
        evidence_id="e" * 64,
        producer="agent",
    )
    assert agent.state == FindingState.UNVERIFIED and agent.confidence == Confidence.LOW
    bogus = scanner_finding(sev="catastrophic")
    assert bogus.severity == Severity.MEDIUM  # unknown severities don't escalate or crash


def test_dedup_merges_evidence_and_raises_confidence():
    a = scanner_finding(producer="semgrep", sev="low")
    b = scanner_finding(producer="fixture", sev="high")
    b.evidence = ["f" * 64]
    (m,) = F.deduplicate([a, b])
    assert m.severity == Severity.HIGH and m.confidence == Confidence.HIGH
    assert m.producers == ["fixture", "semgrep"] and len(m.evidence) == 2


def test_promotion_requires_deterministic_evidence():
    agent = F.new_finding(
        domain="web",
        rule="r",
        title="t",
        file="a",
        line=1,
        component="c",
        severity="high",
        origin=FindingOrigin.AGENT,
        evidence_id="e" * 64,
        producer="agent",
    )
    with pytest.raises(BlockedError):
        F.promote_deterministic(agent, "x" * 64, confirmed_by_scanner=False)
    F.promote_deterministic(agent, "x" * 64, confirmed_by_scanner=True)
    assert agent.state == FindingState.SUSPECTED
    F.promote_deterministic(agent, "y" * 64, confirmed_by_scanner=True)
    assert agent.state == FindingState.VERIFIED


def test_human_review_gives_distinct_state(operator, trust, ledger):
    f = scanner_finding()
    ap = operator.approve(
        ApprovalAction.REVIEW_VERIFY_NO_EVIDENCE, {"type": "finding", "fingerprint": f.fingerprint}, REV
    )
    F.apply_human_review(f, ap, REV, trust, ledger, NOW + 1)
    assert f.state == FindingState.HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE
    s = F.summary([f, scanner_finding(rule="other")])
    assert s["verified"] == 0 and s["human_verified_no_deterministic_evidence"] == 1


def test_human_review_bound_to_finding_and_revision(operator, trust, ledger):
    f = scanner_finding()
    ap = operator.approve(
        ApprovalAction.REVIEW_VERIFY_NO_EVIDENCE, {"type": "finding", "fingerprint": f.fingerprint}, REV
    )
    with pytest.raises(BlockedError):
        F.apply_human_review(f, ap, "commit:other", trust, ledger, NOW + 1)
    other = scanner_finding(rule="other")
    with pytest.raises(BlockedError):
        F.apply_human_review(other, ap, REV, trust, ledger, NOW + 1)
    assert other.state == FindingState.SUSPECTED


def test_suppression_and_accepted_risk_require_approval(operator, trust, ledger):
    from sentinel import canonical

    f = scanner_finding()
    entry = {
        "kind": "suppress",
        "finding": f.fingerprint,
        "revision": REV,
        "reason": "known test fixture",
        "author": "owner",
        "created_at": NOW,
        "expires_at": NOW + 3600,
    }
    subj = {"type": "suppression_entry", "sha256": canonical.digest(entry)}
    sup = operator.approve(ApprovalAction.SUPPRESS, subj, REV, rationale=entry["reason"])
    risk_entry = {
        **entry,
        "kind": "accept_risk",
        "approver": "owner",
        "compensating_controls": "WAF rule 12 blocks it",
    }
    with pytest.raises(BlockedError):  # a suppression approval can't be used as an accepted risk
        F.apply_suppression(f, risk_entry, sup, trust, ledger, NOW + 1)
    F.apply_suppression(f, entry, sup, trust, ledger, NOW + 1)
    assert f.suppression and f.state == FindingState.SUSPECTED and f.severity.value == "medium"
    risk = operator.approve(
        ApprovalAction.REVIEW_ACCEPT_RISK,
        {"type": "suppression_entry", "sha256": canonical.digest(risk_entry)},
        REV,
        rationale=entry["reason"],
    )
    F.apply_suppression(f, risk_entry, risk, trust, ledger, NOW + 1)
    assert f.state == FindingState.ACCEPTED_RISK


# ── reports ────────────────────────────────────────────────────────────────
def result(overall="INCOMPLETE", state="Incomplete", title="<script>alert(1)</script>"):
    f = scanner_finding()
    f.title = title
    fs = [f.to_json()]
    return {
        "audit_id": "id-1",
        "sentinel_version": "0.1.0.dev1",
        "overall": overall,
        "state": state,
        "mode": "READ",
        "level": "L2",
        "target": {"revision": "abc"},
        "disclosure": detect("operator", env={}),
        "checks": [
            {
                "check_id": "c1",
                "adapter": "fixture",
                "status": "NOT_RUN",
                "reason": "scanner_missing",
                "evidence": [],
                "duration_ms": 0,
            }
        ],
        "findings": fs,
        "summary": F.summary([f]),
        "integrity_note": "run-key signature only (D-34)",
    }


def test_json_report_is_canonical():
    r = result()
    assert reports.to_json(r) == reports.to_json(json.loads(reports.to_json(r)))


def test_sarif_structure():
    s = json.loads(reports.to_sarif(result()))
    assert s["version"] == "2.1.0" and len(s["runs"]) == 1
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Sentinel"
    res = run["results"][0]
    assert {"ruleId", "level", "message", "locations", "partialFingerprints"} <= set(res)
    assert run["invocations"][0]["executionSuccessful"] is False  # incomplete audit


def test_html_escapes_untrusted_content():
    out = reports.to_html(result()).decode()
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "Content-Security-Policy" in out


def test_markdown_escapes_and_never_claims_secure():
    out = reports.to_markdown(result(title="x | y")).decode()
    assert "not a statement that the target is secure" in out
    assert "INCOMPLETE" in out and "NOT_RUN" in out
    assert "secure." not in out.replace("not a statement that the target is secure.", "")


@pytest.mark.parametrize("fmt", sorted(reports.RENDERERS))
def test_all_renderers_show_incomplete_state(fmt):
    assert b"INCOMPLETE" in reports.RENDERERS[fmt](result()) or b"Incomplete" in reports.RENDERERS[fmt](
        result()
    )


# ── disclosure ─────────────────────────────────────────────────────────────
def test_disclosure_local_and_agent():
    local = detect("operator", env={})
    assert local["zone"] == "local_only" and "local only" in local["statement"]
    agent = detect(None, env={"CLAUDECODE": "1"})
    assert agent["zone"] == "agent_assisted" and "Claude Code" in agent["agents"]
    assert agent["skill_confirmation"] == "not independently verified"
    hidden = detect("operator", env={"CODEX_SANDBOX": "seatbelt"})  # caller can't hide the env marker
    assert hidden["zone"] == "agent_assisted"


# ── host capability detection ──────────────────────────────────────────────
def test_host_detection_never_claims_unimplemented_isolation():
    caps = detect_host()
    for cls in (ActivityClass.S2, ActivityClass.B1, ActivityClass.B2, ActivityClass.A1, ActivityClass.B3):
        assert caps.isolation_for(cls) is None
    assert caps.user_presence is None
