"""Owner acceptance-review gaps for M6, M7 and M9 (2026-11-10): end-to-end and integration evidence.

* M6: a real audit with a **signed policy** containing a plugin pin, inside the **real macOS Seatbelt**
  sandbox; failure isolation between plugins and other checks; plugin provenance hashes equal the bytes
  that were executed.
* M7: the **real MCP stdio server** in a subprocess runs an audit end to end; the run verifies, the
  caller is `mcp`, the target is unchanged, and trust/signing/approval operations stay unavailable.
* M9: AC-05 (two complete audits agree), AC-06 (SARIF carries coverage, checks not finished and
  limitations), AC-13 (human-verified findings are never counted as verified), evidence IDs in compare.

Sandbox tests skip where the native sandbox self-test fails; a skip is never a pass.
"""

# ruff: noqa: F811, E501
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel import canonical, cli, compare, plugins, reports, schema
from sentinel.adapters.fixture import FixtureAdapter
from sentinel.approvals import save_approval_file
from sentinel.domain.enums import ApprovalAction
from sentinel.isolation import detect as detect_host
from sentinel.isolation import sandbox
from sentinel.paths import state_dir

from .test_cli import _enrol, config, deps, ready, run, target  # noqa: F401
from .test_plugins import GOOD, make_plugin

needs_sandbox = pytest.mark.skipif(
    not sandbox.probe().available, reason="native sandbox unavailable (not a pass)"
)
CRASH_EXIT = "import sys\nsys.exit(3)\n"
CRASH_BAD_LINE = 'import json\nprint(json.dumps({"tool": "bad-line", "findings": [{"rule": "r", "file": "f", "line": [], "message": "m", "severity": "low"}]}))\n'


def tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def signed_policy(tmp_path: Path, operator, body: dict) -> tuple[Path, Path]:  # type: ignore[no-untyped-def]
    raw = canonical.encode(body)
    pp = tmp_path / "policy.json"
    pp.write_bytes(raw)
    ap = operator.approve(
        ApprovalAction.POLICY_CHANGE,
        {"type": "policy_file", "sha256": canonical.sha256_hex(raw)},
        "policy-prev:none",
    )
    pa = tmp_path / "policy-approval.json"
    save_approval_file(pa, ap)
    return pp, pa


def real_sandbox_deps(ready):  # type: ignore[no-untyped-def]
    """The CLI test deps (in-memory run key) but the REAL host isolation and plugin adapters from policy."""
    return dataclasses.replace(
        ready,
        host=detect_host,
        adapters=lambda pol: [
            FixtureAdapter(allowlisted_sha256=pol.adapter_allowlist.get("fixture")),
            *plugins.plugin_adapters(pol.plugins),
        ],
    )


def audit_with_policy(d, capsys, tmp_path, t, pp, pa):  # type: ignore[no-untyped-def]
    return run(
        d, capsys, "audit", "--config", config(tmp_path, t), "--policy", str(pp), "--policy-approval", str(pa)
    )


# ── M6 ────────────────────────────────────────────────────────────────────
@needs_sandbox
def test_m6_signed_policy_plugin_audit_end_to_end(ready, capsys, tmp_path, operator, monkeypatch):
    _enrol(operator)
    pdir, digest = make_plugin(tmp_path / "plugins", "todo-scan")
    pp, pa = signed_policy(
        tmp_path, operator, {"plugins": {"todo-scan": {"path": str(pdir), "manifest_sha256": digest}}}
    )
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    (t / "a.py").write_text("x = 1  # SECURITY-TODO validate\n")
    before = tree(t)
    executed: list[list[str]] = []
    real_run = sandbox.MacSeatbeltRunner.run

    def spy(self, exe, args, **kw):  # type: ignore[no-untyped-def]
        executed.append(list(args))
        return real_run(self, exe, args, **kw)

    monkeypatch.setattr(sandbox.MacSeatbeltRunner, "run", spy)
    code, out = audit_with_policy(real_sandbox_deps(ready), capsys, tmp_path, t, pp, pa)
    assert code == cli.EXIT_FINDINGS, out
    assert tree(t) == before  # target read-only
    _, manifest, result = cli.verified_run(out["audit_id"])  # signature, evidence and stored result
    by = {c["adapter"]: c for c in result["checks"]}
    assert by["plugin-todo-scan"]["status"] == "FAIL" and by["fixture"]["status"] == "FAIL"
    pf = [f for f in result["findings"] if f["rule"].startswith("plugin.")]
    assert [f["rule"] for f in pf] == ["plugin.todo-scan.todo"]
    prov = pf[0]["sources"][0]["plugin"]
    # 3 + 4: provenance equals the exact manifest bytes (pinned, verified) and the exact executed source
    assert prov == {
        "name": "todo-scan",
        "version": "1.2.3",
        "manifest_sha256": hashlib.sha256((pdir / "sentinel-plugin.json").read_bytes()).hexdigest(),
        "entry_sha256": hashlib.sha256(GOOD.encode()).hexdigest(),
    }
    assert prov["manifest_sha256"] == digest
    plugin_args = [a for a in executed if a[:2] == ["-I", "-c"]]
    assert (
        len(plugin_args) == 1
        and hashlib.sha256(plugin_args[0][2].encode()).hexdigest() == prov["entry_sha256"]
    )
    assert pf[0]["sources"][0]["evidence"] in manifest["evidence_index"]


@needs_sandbox
def test_m6_unsigned_or_edited_plugin_policy_is_refused(ready, capsys, tmp_path, operator):
    _enrol(operator)
    pdir, digest = make_plugin(tmp_path / "plugins", "todo-scan")
    pp, pa = signed_policy(
        tmp_path, operator, {"plugins": {"todo-scan": {"path": str(pdir), "manifest_sha256": digest}}}
    )
    t = target(tmp_path, "t", "clean")
    d = real_sandbox_deps(ready)
    assert (
        run(d, capsys, "audit", "--config", config(tmp_path, t), "--policy", str(pp))[0] == cli.EXIT_BLOCKED
    )
    pp.write_bytes(
        canonical.encode({"plugins": {"todo-scan": {"path": str(pdir), "manifest_sha256": "0" * 64}}})
    )
    assert audit_with_policy(d, capsys, tmp_path, t, pp, pa)[0] == cli.EXIT_BLOCKED


@needs_sandbox
@pytest.mark.parametrize("bad_source", [CRASH_EXIT, CRASH_BAD_LINE], ids=["exit3", "malformed-line"])
def test_m6_failing_plugin_does_not_affect_other_checks(ready, capsys, tmp_path, operator, bad_source):
    _enrol(operator)
    good, gd = make_plugin(tmp_path / "plugins", "todo-scan")
    bad, bd = make_plugin(tmp_path / "plugins", "bad-line", source=bad_source)
    pp, pa = signed_policy(
        tmp_path,
        operator,
        {
            "plugins": {
                "bad-line": {"path": str(bad), "manifest_sha256": bd},
                "todo-scan": {"path": str(good), "manifest_sha256": gd},
            }
        },
    )
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    (t / "a.py").write_text("x = 1  # SECURITY-TODO\n")
    code, out = audit_with_policy(real_sandbox_deps(ready), capsys, tmp_path, t, pp, pa)
    assert code != cli.EXIT_INTERNAL, out
    _, _, result = cli.verified_run(out["audit_id"])
    by = {c["adapter"]: c for c in result["checks"]}
    assert by["plugin-bad-line"]["status"] == "ERROR"  # never PASS, never an engine crash
    assert by["plugin-todo-scan"]["status"] == "FAIL" and by["fixture"]["status"] == "FAIL"
    rules = {f["rule"] for f in result["findings"]}
    assert "plugin.todo-scan.todo" in rules and not any(r.startswith("plugin.bad-line") for r in rules)
    assert out["overall"] != "PASS" and code != cli.EXIT_INTERNAL


# ── M7 ────────────────────────────────────────────────────────────────────
LAUNCHER = r'''
"""TEST-ONLY launcher: the real `sentinel.mcp.serve()` and `Server` over real stdio pipes, executing the
real `cli.main`. Only the run-key store is a file in the test directory, so the user's keychain is never
touched. Host isolation is the real one."""
import contextlib, io, sys
from pathlib import Path
from sentinel import cli, mcp
from sentinel.adapters.fixture import FixtureAdapter
from sentinel.keys.runkey import RunKeyManager

KEYS = Path(sys.argv[1])


class FileBackend:  # TEST ONLY
    name = "test-file"

    def store(self, account, secret_hex):
        (KEYS / account).write_text(secret_hex)

    def load(self, account):
        p = KEYS / account
        return p.read_text() if p.exists() else None


DEPS = cli.Deps(
    run_keys=lambda: RunKeyManager(FileBackend()),
    env={},
    agent_version=lambda a: None,
    adapters=lambda pol: [FixtureAdapter(allowlisted_sha256=pol.adapter_allowlist.get("fixture"))],
)
if sys.argv[2] == "init":
    sys.exit(cli.main(["--json", "init"], DEPS))


def run_cli(argv):
    raw = io.BytesIO()
    buf = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(argv, DEPS)
    buf.flush()
    return code, raw.getvalue().decode()


sys.exit(mcp.serve(server=mcp.Server(run_cli=run_cli)))
'''


def trust_files() -> dict[str, bytes]:
    root = state_dir()
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and "runs" not in p.relative_to(root).parts
    }


@needs_sandbox
def test_m7_real_stdio_server_runs_an_audit_end_to_end(tmp_path, isolated_home):
    keys = tmp_path / "keys"
    keys.mkdir()
    launcher = tmp_path / "launch_mcp.py"
    launcher.write_text(LAUNCHER)
    env = {**os.environ, "SENTINEL_HOME": str(isolated_home)}
    for k in ("CLAUDECODE", "CODEX_SANDBOX", "CLAUDE_CODE_ENTRYPOINT"):
        env.pop(k, None)
    init = subprocess.run(
        [sys.executable, "-I", str(launcher), str(keys), "init"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert init.returncode == 0, init.stderr
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    before = tree(t)
    cfg = config(tmp_path, t)
    trust_before = trust_files()
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "e2e"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "audit", "arguments": {"config": cfg}},
        },
        *(
            {"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": {"name": n, "arguments": {}}}
            for i, n in enumerate(
                ["key", "approval", "review", "suppress", "decisions", "policy_change", "init", "history"]
            )
        ),
    ]
    p = subprocess.run(
        [sys.executable, "-I", str(launcher), str(keys), "serve"],
        input="".join(json.dumps(m) + "\n" for m in msgs),
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    assert p.returncode == 0, p.stderr
    replies = {r["id"]: r for r in map(json.loads, p.stdout.splitlines())}
    audit = replies[2]["result"]["structuredContent"]
    assert audit["untrusted_content"] is True and audit["exit_code"] == cli.EXIT_FINDINGS, audit
    rid = audit["result"]["audit_id"]
    # 1: the resulting Sentinel run verifies (manifest signature, evidence, stored result)
    _, manifest, result = cli.verified_run(rid)
    # 2: caller identity is `mcp`
    assert result["disclosure"]["declared_caller"] == "mcp" and "mcp" in result["disclosure"]["agents"]
    # 3: target unchanged (target-read-only); only Sentinel's own state gained a run
    assert tree(t) == before
    # 4: trust-store, signing and approval operations stay unavailable and changed nothing
    for i in range(10, 18):
        assert replies[i]["error"]["message"] == "tool_not_exposed"
    assert trust_files() == trust_before


# ── M9 ────────────────────────────────────────────────────────────────────
def test_ac05_two_complete_audits_give_identical_fingerprints_and_statuses(ready, capsys, tmp_path):
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    _, a = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    _, b = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    _, ma, ra = cli.verified_run(a["audit_id"])
    _, mb, rb = cli.verified_run(b["audit_id"])
    assert a["audit_id"] != b["audit_id"] and ra["findings"]
    assert sorted(f["fingerprint"] for f in ra["findings"]) == sorted(
        f["fingerprint"] for f in rb["findings"]
    )
    assert sorted((c["check_id"], c["status"], c["reason"]) for c in ra["checks"]) == sorted(
        (c["check_id"], c["status"], c["reason"]) for c in rb["checks"]
    )
    c = compare.compare(ma, ra, mb, rb)
    assert c["introduced"] == c["fixed"] == c["unverified"] == [] and len(c["persisting"]) == len(
        ra["findings"]
    )
    assert all(r["status"] == "open" for r in c["remediation"])


def test_ac06_sarif_carries_coverage_checks_not_finished_and_limitations(ready, capsys, tmp_path):
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    _, a = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    _, _, result = cli.verified_run(a["audit_id"])
    sarif = json.loads(reports.to_sarif(result))  # validated against the SARIF profile inside to_sarif
    props = sarif["runs"][0]["properties"]
    assert props["domain_coverage"] == result["domain_coverage"]
    assert props["checks_not_finished"] == result["checks_not_finished"]
    assert props["limitations"] == result["integrity_note"] and props["limitations"]
    assert sarif["version"] == "2.1.0" and set(sarif) == {"$schema", "version", "runs"}
    # incomplete runs: what didn't finish is visible to SARIF consumers
    inc = {
        **result,
        "checks_not_finished": [{**result["checks"][0], "status": "NOT_RUN", "reason": "scanner_missing"}],
    }
    assert (
        json.loads(reports.to_sarif(inc))["runs"][0]["properties"]["checks_not_finished"][0]["reason"]
        == "scanner_missing"
    )


def test_ac06_historical_sarif_without_new_properties_still_validates():
    old = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Sentinel", "version": "0.1.0", "rules": []}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"audit_state": "Completed", "overall": "PASS"},
                    }
                ],
                "properties": {"checks": [], "disclaimer": "x"},
            }
        ],
    }
    schema.validate(old, "sarif-profile")


def test_ac13_human_verified_findings_are_never_counted_as_verified():
    from sentinel.domain.enums import FindingState
    from sentinel.findings import summary

    from .test_findings_reports import result as base_result
    from .test_findings_reports import scanner_finding

    hv, ver, sus = scanner_finding(line=1), scanner_finding(line=2), scanner_finding(line=3)
    hv.state, hv.review = FindingState.HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE, {"rationale": "looked at it"}
    ver.state = FindingState.VERIFIED
    s = summary([hv, ver, sus])
    assert s["verified"] == 1 and s["human_verified_no_deterministic_evidence"] == 1 and s["total"] == 3
    r = base_result(overall="FAIL", state="Completed")
    r["findings"] = [f.to_json() for f in (hv, ver, sus)]
    r["summary"] = s
    md = reports.to_markdown(r).decode()
    assert "verified 1; human-verified without deterministic evidence 1" in md
    section = md.split("## Human-verified without deterministic evidence", 1)[1].split("##", 1)[0]
    assert hv.fingerprint[:16] in section and ver.fingerprint[:16] not in section
    html = reports.to_html(r).decode()
    assert "Human-verified without deterministic evidence" in html
    sarif = json.loads(reports.to_sarif(r))
    states = [x["properties"]["state"] for x in sarif["runs"][0]["results"]]
    assert states.count("verified") == 1 and states.count("HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE") == 1


def test_compare_items_carry_evidence_ids_traceable_to_the_manifest(ready, capsys, tmp_path):
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    _, a = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    (t / "app.txt").write_text("clean")
    _, b = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    _, ma, ra = cli.verified_run(a["audit_id"])
    code, out = run(ready, capsys, "compare", a["audit_id"], b["audit_id"])
    c = out["comparison"]
    assert c["fixed"]
    for f in c["fixed"]:
        assert f["evidence"], "every comparison item must name its evidence"  # mutation eng-f-cmp-evidence
        assert set(f["evidence"]) <= set(ma["evidence_index"])
    for r in c["remediation"]:
        assert r["evidence_before"] and set(r["evidence_before"]) <= set(ma["evidence_index"])
        assert r["status"] == "resolved" and r["evidence_after"] == []
    schema.check_output(out, "cli-output", "compare")
