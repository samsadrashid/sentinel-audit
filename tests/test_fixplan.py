"""D-50: `fix-plan` is deterministic, read-only and only for verified runs."""

# ruff: noqa: F811
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from sentinel import canonical, cli, fixplan, schema
from sentinel.errors import IntegrityError

from .test_cli import audit as cli_audit
from .test_cli import deps, ready  # noqa: F401

FINDING = "SENTINEL-FIXTURE-FINDING\n"


def tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def plan_for(ready, capsys, rid):  # type: ignore[no-untyped-def]
    assert cli.main(["--json", "fix-plan", rid], ready) == 0
    return json.loads(capsys.readouterr().out)


def test_plan_references_findings_and_signed_evidence(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    rid = out["audit_id"]
    _, manifest, result = cli.verified_run(rid)
    printed = plan_for(ready, capsys, rid)
    plan = printed["plan"]
    schema.validate(plan, "fix-plan")
    assert plan["run_id"] == rid and plan["result_sha256"] == manifest["result_sha256"]
    assert plan["items"], "the fixture finding must be planned"
    fps = {f["fingerprint"] for f in result["findings"]}
    for it in plan["items"]:
        assert it["finding"] in fps
        assert it["evidence"] and set(it["evidence"]) <= set(manifest["evidence_index"])
        assert it["remediation_verified"] is False and it["requires_operator_review"] is True
    assert printed["plan_sha256"] == canonical.sha256_hex(canonical.encode(plan))


def test_plan_is_deterministic_and_never_writes_into_the_run(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    rid = out["audit_id"]
    root = cli.run_path(rid)
    before = tree(root)
    first = plan_for(ready, capsys, rid)
    second = plan_for(ready, capsys, rid)
    assert first == second
    assert tree(root) == before
    _, _, result = cli.verified_run(rid)
    assert all(f["state"] == "suspected" for f in result["findings"])  # nothing promoted


def test_tampered_run_is_refused(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    rid = out["audit_id"]
    ev = next(p for p in (cli.run_path(rid) / "evidence").iterdir() if not p.name.endswith(".meta.json"))
    ev.chmod(0o600)
    ev.write_bytes(ev.read_bytes() + b"x")
    assert cli.main(["--json", "fix-plan", rid], ready) == cli.EXIT_INTEGRITY
    assert '"plan"' not in capsys.readouterr().out


def test_evidence_outside_the_manifest_is_refused(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    _, manifest, result = cli.verified_run(out["audit_id"])
    bad = copy.deepcopy(result)
    bad["findings"][0]["evidence"].append("0" * 64)
    with pytest.raises(IntegrityError):
        fixplan.build(manifest, bad)


def test_closed_findings_are_listed_not_planned(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    _, manifest, result = cli.verified_run(out["audit_id"])
    r = copy.deepcopy(result)
    r["findings"][0]["state"] = "accepted_risk"
    plan = fixplan.build(manifest, r)
    assert plan["items"] == [] and plan["excluded"][0]["reason"] == "accepted_risk"
    fixplan.render(plan)


def test_output_file_rules(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    rid = out["audit_id"]
    inside = cli.run_path(rid) / "plan.json"
    assert cli.main(["--json", "fix-plan", rid, "--output", str(inside)], ready) == cli.EXIT_INVALID
    assert not inside.exists()
    dest = tmp_path / "plan.json"
    assert cli.main(["--json", "fix-plan", rid, "--output", str(dest)], ready) == 0
    capsys.readouterr()
    schema.validate(canonical.decode_strict(dest.read_bytes()), "fix-plan")
    assert cli.main(["--json", "fix-plan", rid, "--output", str(dest)], ready) != 0  # never overwrites


def test_plan_contract_refuses_a_verified_claim():
    plan = {
        "kind": "sentinel/v1/fix-plan",
        "plan_version": "1.0",
        "run_id": "00000000-0000-4000-8000-000000000000",
        "manifest_sha256": "a" * 64,
        "result_sha256": "b" * 64,
        "run_key_id": "ed25519:" + "0" * 32,
        "overall_result": "FAIL",
        "items": [],
        "excluded": [],
        "counts": {s: 0 for s in fixplan.SEVERITY_RANK},
        "note": fixplan.NOTE,
    }
    schema.validate(plan, "fix-plan")
    item = {
        "finding": "c" * 64,
        "rule": "r",
        "title": "t",
        "severity": "low",
        "confidence": "low",
        "finding_state": "suspected",
        "location": {"file": "f", "line": 1},
        "component": "c",
        "evidence": [],
        "step": "s",
        "check_after_fix": "c",
        "requires_operator_review": True,
        "remediation_verified": True,
    }
    with pytest.raises(schema.SchemaError):
        schema.validate({**plan, "items": [item]}, "fix-plan")


def test_render_refuses_an_off_contract_plan():
    with pytest.raises(schema.SchemaViolation):
        fixplan.render({"kind": "sentinel/v1/fix-plan", "items": [{"remediation_verified": True}]})


def test_plan_uses_d64_resolution_wording_and_stays_keyed_by_fingerprint(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path, content=FINDING)
    _, _, result = cli.verified_run(out["audit_id"])
    plan = plan_for(ready, capsys, out["audit_id"])["plan"]
    for it in plan["items"]:
        assert "D-64" in it["check_after_fix"] and "fingerprint" not in it["check_after_fix"]
        assert it["finding"] in {f["fingerprint"] for f in result["findings"]}  # compatibility key
        assert it["remediation_verified"] is False
