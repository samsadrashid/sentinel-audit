"""M9: comparison of two verified runs, risk aggregation and remediation tracking."""

# ruff: noqa: F811
from __future__ import annotations

import copy

import pytest

from sentinel import cli, compare, schema
from sentinel.errors import ValidationError

from .test_cli import config, deps, ready, run, target  # noqa: F401

FINDING = "SENTINEL-FIXTURE-FINDING\n"


def audit_same(ready, capsys, tmp_path, root, content):  # type: ignore[no-untyped-def]
    (root / "app.txt").write_text(content)
    code, out = run(ready, capsys, "audit", "--config", config(tmp_path, root))
    return out["audit_id"]


def test_fixed_finding_is_evidence_backed_and_remediation_resolved(ready, capsys, tmp_path):
    root = target(tmp_path, "t", FINDING)
    a = audit_same(ready, capsys, tmp_path, root, FINDING)
    b = audit_same(ready, capsys, tmp_path, root, "clean")
    code, out = run(ready, capsys, "compare", a, b)
    assert code == 0
    c = out["comparison"]
    assert c["before"]["run_id"] == a and c["after"]["run_id"] == b
    assert len(c["fixed"]) == 1 and not c["introduced"] and not c["unverified"]
    assert [r["status"] for r in c["remediation"]] == ["resolved"]
    assert c["risk"]["after"]["weighted_score"] == 0 < c["risk"]["before"]["weighted_score"]
    schema.check_output(out, "cli-output", "compare")


def test_introduced_and_persisting(ready, capsys, tmp_path):
    root = target(tmp_path, "t", "clean")
    a = audit_same(ready, capsys, tmp_path, root, "clean")
    b = audit_same(ready, capsys, tmp_path, root, FINDING)
    c = audit_same(ready, capsys, tmp_path, root, FINDING)
    assert len(run(ready, capsys, "compare", a, b)[1]["comparison"]["introduced"]) == 1
    out = run(ready, capsys, "compare", b, c)[1]["comparison"]
    assert len(out["persisting"]) == 1 and [r["status"] for r in out["remediation"]] == ["open"]


def test_missing_finding_from_a_check_that_did_not_run_is_unverified_not_fixed(ready, capsys, tmp_path):
    root = target(tmp_path, "t", FINDING)
    a = audit_same(ready, capsys, tmp_path, root, FINDING)
    b = audit_same(ready, capsys, tmp_path, root, "clean")
    ma, ra = cli.verified_run(a)[1:]
    mb, rb = cli.verified_run(b)[1:]
    rb = copy.deepcopy(rb)
    for ch in rb["checks"]:
        ch["status"] = "ERROR"
    out = compare.compare(ma, ra, mb, rb)
    assert out["fixed"] == [] and len(out["unverified"]) == 1
    assert [r["status"] for r in out["remediation"]] == ["unverified"]
    assert out["checks_not_completed_after"]


def test_accepted_findings_stay_visible_and_leave_open_risk():
    f = {
        "fingerprint": "a" * 64,
        "domain": "D01",
        "rule": "r",
        "severity": "high",
        "location": {},
        "producers": ["x"],
        "state": "suspected",
        "suppression": {"type": "review.accept_risk"},
    }
    r = compare.risk([f, {**f, "fingerprint": "b" * 64, "suppression": None}])
    assert r["accepted"] == 1 and r["open_by_severity"]["high"] == 1 and r["weighted_score"] == 5


def test_different_targets_and_same_run_are_refused(ready, capsys, tmp_path):
    a = audit_same(ready, capsys, tmp_path, target(tmp_path, "t1", "clean"), "clean")
    b = audit_same(ready, capsys, tmp_path, target(tmp_path, "t2", "clean"), "clean")
    assert run(ready, capsys, "compare", a, b)[0] == cli.EXIT_INVALID
    assert run(ready, capsys, "compare", a, a)[0] == cli.EXIT_INVALID
    ma, ra = cli.verified_run(a)[1:]
    with pytest.raises(ValidationError):
        compare.compare(ma, ra, ma, ra)


def test_tampered_run_is_refused(ready, capsys, tmp_path):
    root = target(tmp_path, "t", FINDING)
    a = audit_same(ready, capsys, tmp_path, root, FINDING)
    b = audit_same(ready, capsys, tmp_path, root, "clean")
    ev = next(p for p in (cli.run_path(b) / "evidence").iterdir() if not p.name.endswith(".meta.json"))
    ev.chmod(0o600)
    ev.write_bytes(ev.read_bytes() + b"x")
    assert run(ready, capsys, "compare", a, b)[0] == cli.EXIT_INTEGRITY


# ── D-64 issue identity (V-2) ───────────────────────────────────────────────
EV = "e" * 64


def fnd(line, rule="semgrep.r1", file="app.py", title="unsafe call", component="t", producers=("semgrep",)):
    from sentinel.findings import fingerprint

    return {
        "fingerprint": fingerprint("D01", rule, f"{file}:{line}", component),
        "domain": "D01",
        "rule": rule,
        "title": title,
        "location": {"file": file, "line": line},
        "component": component,
        "severity": "high",
        "confidence": "medium",
        "origin": "scanner",
        "state": "suspected",
        "evidence": [EV],
        "producers": list(producers),
        "review": None,
        "suppression": None,
    }


def result(rid, findings, status="FAIL", component="t"):
    return {
        "audit_id": rid,
        "overall": "FAIL" if findings else "PASS",
        "target": {
            "assets": [{"id": component, "kind": "local_path", "environment": "local"}],
            "revision": rid,
        },
        "findings": findings,
        "checks": [{"check_id": "semgrep.scan", "adapter": "semgrep", "status": status, "reason": ""}],
    }


def man(rid):
    return {"audit_id": rid, "evidence_index": {EV: {}}, "result_sha256": "0" * 64, "run_key_id": "k"}


def cmp(before, after, status="FAIL"):
    return compare.compare(man("a"), result("a", before), man("b"), result("b", after, status))


def statuses(c):
    return [r["status"] for r in c["remediation"]]


def test_line_movement_is_persisting_never_fixed():
    c = cmp([fnd(10)], [fnd(42)])
    assert c["fixed"] == [] and c["introduced"] == [] and len(c["persisting"]) == 1
    assert c["persisting"][0]["moved"] is True and statuses(c) == ["open"]


def test_genuine_remediation_is_resolved():
    c = cmp([fnd(10)], [], status="PASS")
    assert len(c["fixed"]) == 1 and statuses(c) == ["resolved"]


def test_incomplete_later_check_is_unverified():
    for st in ("NOT_RUN", "ERROR", "TIMEOUT", "BLOCKED"):
        c = cmp([fnd(10)], [], status=st)
        assert c["fixed"] == [] and c["unverified"][0]["reason"] == "producer_not_completed"
        assert statuses(c) == ["unverified"]


def test_changed_rule_identity_at_same_location_is_unverified():
    c = cmp([fnd(10, rule="semgrep.old")], [fnd(10, rule="semgrep.new")])
    assert c["fixed"] == [] and c["unverified"][0]["reason"] == "possible_rule_change"
    assert len(c["introduced"]) == 1 and statuses(c) == ["unverified"]


def test_changed_asset_is_refused():
    with pytest.raises(ValidationError):
        compare.compare(
            man("a"), result("a", [fnd(1)]), man("b"), result("b", [fnd(1, component="u")], component="u")
        )


def test_duplicates_equal_counts_persist_and_unequal_counts_are_unverified():
    c = cmp([fnd(10), fnd(20)], [fnd(15), fnd(25)])
    assert len(c["persisting"]) == 2 and c["fixed"] == [] and statuses(c) == ["open", "open"]
    c = cmp([fnd(10), fnd(20)], [fnd(30)])
    assert c["fixed"] == [] and {u["reason"] for u in c["unverified"]} == {"ambiguous_identity"}
    assert set(statuses(c)) == {"unverified"}
    c = cmp([fnd(10), fnd(20)], [fnd(10)])  # exact survivor; the other really gone, check completed
    assert len(c["fixed"]) == 1 and sorted(statuses(c)) == ["open", "resolved"]


def test_different_title_or_file_is_a_different_issue():
    c = cmp([fnd(10, file="a.py")], [fnd(10, file="b.py")])
    assert len(c["fixed"]) == 1 and len(c["introduced"]) == 1


def test_informational_severity_is_counted_under_its_engine_label():
    f = {**fnd(1), "severity": "informational"}
    r = compare.risk([f])
    assert r["open_by_severity"]["informational"] == 1 and "info" not in r["open_by_severity"]


def test_identity_includes_title_and_asset():
    """Mutation survivors eng-t-d64-title / eng-t-d64-asset: distinct issues must stay distinct."""
    a, b = fnd(10, title="eval of user input"), fnd(10, title="eval of constant")
    assert compare.identity(a) != compare.identity(b)
    x, y = fnd(10, component="api"), fnd(10, component="web")
    assert compare.identity(x) != compare.identity(y)
    # Two assets in one scope, same file name: fixing one asset's issue must not hide the other's.
    two = {
        "assets": [
            {"id": "api", "kind": "local_path", "environment": "local"},
            {"id": "web", "kind": "local_path", "environment": "local"},
        ],
        "revision": "r",
    }
    before = {**result("a", [fnd(10, component="api"), fnd(30, component="web")]), "target": two}
    after = {**result("b", [fnd(31, component="web")], status="PASS"), "target": two}
    c = compare.compare(man("a"), before, man("b"), after)
    assert [f["location"]["line"] for f in c["fixed"]] == [10] and len(c["persisting"]) == 1


def test_informational_findings_add_nothing_to_the_weighted_score():
    """Mutation survivor eng-t-risk-informational."""
    f = {**fnd(1), "severity": "informational"}
    assert compare.risk([f])["weighted_score"] == 0
    assert compare.risk([{**fnd(1), "severity": "low"}, f])["weighted_score"] == 1
