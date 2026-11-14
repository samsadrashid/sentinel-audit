"""CLI tests: parsing, exit codes, end-to-end audits with the fixture adapter, authorisation and scope
enforcement, missing capabilities, evidence verification, malformed input and non-interactive use.

The run key uses an in-memory test backend (never the real keychain) and the host is a fixed test
host, so no sandbox probe or prompt runs. Operator approvals come from test-only keys (conftest).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from sentinel import authorization, canonical, cli
from sentinel.approvals import save_approval_file
from sentinel.domain.enums import ApprovalAction
from sentinel.errors import CapabilityUnavailable
from sentinel.keys.operator import OperatorKey, TrustStore
from sentinel.keys.runkey import RunKeyManager
from sentinel.paths import state_dir

from .conftest import FIXTURE_ONLY, NOW
from .isolation_testing import make_test_host

HOST = make_test_host()  # test-only runner; production never runs an adapter unsandboxed (X-5)


class MemBackend:
    """TEST ONLY in-memory secret store."""

    name = "test-memory"

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def store(self, account: str, secret_hex: str) -> None:
        self.data[account] = secret_hex

    def load(self, account: str) -> str | None:
        return self.data.get(account)


@pytest.fixture
def deps() -> cli.Deps:
    backend = MemBackend()
    return cli.Deps(
        run_keys=lambda: RunKeyManager(backend),
        host=lambda: HOST,
        clock=lambda: NOW,
        env={},
        agent_version=lambda a: None,
        adapters=FIXTURE_ONLY,
    )


def run(deps: cli.Deps, capsys, *argv: str) -> tuple[int, Any]:
    code = cli.main(["--json", *argv], deps)
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip().startswith("{") else out


@pytest.fixture
def ready(deps, capsys) -> cli.Deps:
    assert run(deps, capsys, "init")[0] == 0
    return deps


def target(tmp_path: Path, name: str, content: str) -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "app.txt").write_text(content)
    return root


def config(tmp_path: Path, *targets: Path, mode="READ", level="L2", classes=("S1",), **extra) -> str:
    p = tmp_path / f"cfg-{len(list(tmp_path.glob('cfg-*')))}.json"
    body = {
        "mode": mode,
        "level": level,
        "activity_classes": list(classes),
        "scope": {
            "assets": [
                {"id": t.name, "kind": "local_path", "locator": str(t), "environment": "local"}
                for t in targets
            ]
        },
        **extra,
    }
    p.write_text(json.dumps(body))
    return str(p)


def audit(deps, capsys, tmp_path, content="clean", **kw) -> tuple[int, Any]:
    t = target(tmp_path, f"t{len(list(tmp_path.glob('t*')))}", content)
    return run(deps, capsys, "audit", "--config", config(tmp_path, t, **kw))


# ── parsing and usage ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["bogus"],
        ["runs"],
        ["runs", "delete", "x"],
        ["evidence"],
        ["audit"],
        ["report"],
        ["report", "x", "--format", "pdf"],
        ["policy"],
        ["audit", "--config"],
    ],
)
def test_bad_usage_exits_invalid(deps, capsys, argv):
    code, out = run(deps, capsys, *argv)
    assert code == cli.EXIT_INVALID and out["error"] == "invalid"


def test_help_exits_zero(deps, capsys):
    assert cli.main(["--help"], deps) == 0


def test_version(deps, capsys):
    code, out = run(deps, capsys, "version")
    assert code == 0 and out["sentinel_version"] and out["schema_version"] and out["platform"]


def test_human_output_and_stderr_errors(deps, capsys):
    assert cli.main(["version"], deps) == 0
    assert "sentinel_version:" in capsys.readouterr().out
    assert cli.main(["runs", "show", "nope"], deps) == cli.EXIT_INVALID
    err = capsys.readouterr()
    assert err.out == "" and "sentinel: invalid:" in err.err


# ── init and status ────────────────────────────────────────────────────────
def test_init_creates_private_state_and_is_idempotent(deps, capsys):
    code, out = run(deps, capsys, "init")
    assert code == 0 and out["run_key"]["created"] is True and out["run_key"]["algorithm"] == "ed25519"
    assert (state_dir().stat().st_mode & 0o777) == 0o700
    code, again = run(deps, capsys, "init")
    assert again["run_key"]["created"] is False and again["run_key"]["key_id"] == out["run_key"]["key_id"]


def test_init_never_prints_secrets(deps, capsys):
    backend = MemBackend()
    deps.run_keys = lambda: RunKeyManager(backend)
    cli.main(["--json", "init"], deps)
    out = capsys.readouterr().out
    assert all(secret not in out for secret in backend.data.values())


def test_init_without_keystore_is_capability_error(deps, capsys):
    def unavailable() -> RunKeyManager:
        raise CapabilityUnavailable("run-key-keystore", "no keystore")

    deps.run_keys = unavailable
    code, out = run(deps, capsys, "init")
    assert code == cli.EXIT_CAPABILITY and out["error"] == "capability_unavailable"


def test_status_reports_capabilities_and_operator_signing_unavailable(ready, capsys):
    code, out = run(ready, capsys, "status")
    assert code == 0 and out["host"]["platform"] == "test"
    # The only S1 layer on the test host is the test-only runner, which production never accepts.
    assert {k: v for k, v in out["isolation"].items() if v is not None} == {
        "S1": "test-only-runner (NOT isolation)"
    }
    assert out["operator_signing"].startswith("unavailable")
    assert out["run_key"]["keystore"] == "test-memory"


# ── audits ─────────────────────────────────────────────────────────────────
def test_clean_audit_passes_with_reports(ready, capsys, tmp_path):
    code, out = audit(ready, capsys, tmp_path)
    assert code == cli.EXIT_OK and out["overall"] == "PASS" and out["state"] == "Completed"
    assert set(out["reports"]) == {"json", "sarif", "md", "html"}


def test_findings_exit_one(ready, capsys, tmp_path):
    code, out = audit(ready, capsys, tmp_path, content="x\nSENTINEL-FIXTURE-FINDING\n")
    assert code == cli.EXIT_FINDINGS and out["overall"] == "FAIL" and out["findings"] == 1


def test_unsupported_isolation_is_incomplete(ready, capsys, tmp_path):
    code, out = audit(ready, capsys, tmp_path, classes=("S2",))
    assert code == cli.EXIT_INCOMPLETE and out["overall"] != "PASS"
    assert set(out["checks"].values()) <= {"NOT_RUN", "ERROR"}


def test_scanner_failure_is_incomplete(ready, capsys, tmp_path, monkeypatch):
    from sentinel.adapters import fixture

    monkeypatch.setattr(
        cli,
        "FixtureAdapter",
        lambda allowlisted_sha256: fixture.FixtureAdapter(
            script=tmp_path / "missing.py", allowlisted_sha256=allowlisted_sha256
        ),
    )
    code, out = audit(ready, capsys, tmp_path)
    assert code == cli.EXIT_INCOMPLETE and "PASS" not in out["checks"].values()


def test_validate_without_record_is_blocked(ready, capsys, tmp_path):
    for classes in (("S1",), ("A1",)):
        code, out = audit(ready, capsys, tmp_path, mode="VALIDATE", level="L3", classes=classes)
        assert code == cli.EXIT_BLOCKED and out["overall"] == "BLOCKED"


def test_read_mode_cannot_reach_a1_or_l3(ready, capsys, tmp_path):
    assert audit(ready, capsys, tmp_path, classes=("A1",))[0] == cli.EXIT_BLOCKED
    assert audit(ready, capsys, tmp_path, level="L3")[0] == cli.EXIT_BLOCKED


def test_audit_without_init_fails_closed(deps, capsys, tmp_path):
    code, out = audit(deps, capsys, tmp_path)
    assert code == cli.EXIT_CAPABILITY and "init" in out["message"]


def test_audit_is_non_interactive_and_never_prompts(ready, capsys, tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("CLI prompted"))
    monkeypatch.setattr("sys.stdin", open("/dev/null"))
    assert audit(ready, capsys, tmp_path)[0] == cli.EXIT_OK


# ── authorisation via signed files only ────────────────────────────────────
def _enrol(operator) -> TrustStore:
    ts = TrustStore()
    ts.enrol(OperatorKey(operator.public.key_id, "owner", operator.public, "active", NOW + 365 * 86400))
    ts.save()
    return ts


def _record(tmp_path, t, operator, *, env="local"):
    rec = {
        "id": "rec-1",
        "version": 1,
        "owner": "owner",
        "approver": "owner",
        "assets": [{"id": t.name, "locator": str(t), "environment": env}],
        "permitted_activities": ["S1"],
        "operations": ["fixture.marker"],
        "limits": {},
        "exclusions": [],
        "valid_from": NOW - 10,
        "expires_at": NOW + 30 * 86400,
        "evidence_of_authority": {},
    }
    ap = operator.approve(
        ApprovalAction.AUTHORIZE_RECORD,
        {"type": "authorization_record", "sha256": canonical.digest(rec)},
        "record:rec-1:1",
        scope=authorization.record_scope(rec),
        lifetime=7 * 86400,
    )
    rp, apath = tmp_path / "record.json", tmp_path / "approval.json"
    rp.write_text(json.dumps(rec))
    save_approval_file(apath, ap)
    return rec, rp, apath


def _owned_policy(tmp_path, operator, *names):
    raw = canonical.encode({"owned_assets": list(names)})
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


def test_authorized_validate_audit_runs(ready, capsys, tmp_path, operator):
    _enrol(operator)
    t = target(tmp_path, "staged", "clean")
    _, rp, ap = _record(tmp_path, t, operator)
    pp, pa = _owned_policy(tmp_path, operator, t.name)
    code, out = run(
        ready,
        capsys,
        "audit",
        "--config",
        config(tmp_path, t, mode="VALIDATE", level="L3"),
        "--authorization",
        str(rp),
        "--approval",
        str(ap),
        "--policy",
        str(pp),
        "--policy-approval",
        str(pa),
    )
    assert code == cli.EXIT_OK and out["overall"] == "PASS"
    code, shown = run(ready, capsys, "runs", "show", out["audit_id"])
    assert shown["authorization_ref"] == "rec-1:1"


def test_tampered_record_is_blocked(ready, capsys, tmp_path, operator):
    _enrol(operator)
    t = target(tmp_path, "staged", "clean")
    rec, rp, ap = _record(tmp_path, t, operator)
    rp.write_text(json.dumps({**rec, "operations": ["fixture.marker", "anything"]}))
    pp, pa = _owned_policy(tmp_path, operator, t.name)
    code, out = run(
        ready,
        capsys,
        "audit",
        "--config",
        config(tmp_path, t, mode="VALIDATE", level="L3"),
        "--authorization",
        str(rp),
        "--approval",
        str(ap),
        "--policy",
        str(pp),
        "--policy-approval",
        str(pa),
    )
    assert code == cli.EXIT_BLOCKED


def test_scope_outside_record_is_blocked(ready, capsys, tmp_path, operator):
    _enrol(operator)
    t, other = target(tmp_path, "staged", "clean"), target(tmp_path, "other", "clean")
    _, rp, ap = _record(tmp_path, t, operator)
    pp, pa = _owned_policy(tmp_path, operator, t.name, other.name)
    code, out = run(
        ready,
        capsys,
        "audit",
        "--config",
        config(tmp_path, other, mode="VALIDATE", level="L3"),
        "--authorization",
        str(rp),
        "--approval",
        str(ap),
        "--policy",
        str(pp),
        "--policy-approval",
        str(pa),
    )
    assert code == cli.EXIT_BLOCKED and out["overall"] != "PASS" and "BLOCKED" in out["checks"].values()


def test_record_without_approval_and_unsigned_policy_rejected(ready, capsys, tmp_path, operator):
    t = target(tmp_path, "staged", "clean")
    _, rp, _ = _record(tmp_path, t, operator)
    c = config(tmp_path, t)
    assert run(ready, capsys, "audit", "--config", c, "--authorization", str(rp))[0] == cli.EXIT_INVALID
    pp = tmp_path / "p.json"
    pp.write_text("{}")
    assert run(ready, capsys, "audit", "--config", c, "--policy", str(pp))[0] == cli.EXIT_BLOCKED


def test_agent_caller_is_disclosed_not_trusted(ready, capsys, tmp_path):
    t = target(tmp_path, "a", "clean")
    code, out = run(ready, capsys, "audit", "--config", config(tmp_path, t), "--caller", "claude-code")
    assert code == 0
    _, _, result = cli.verified_run(out["audit_id"])
    assert result["disclosure"]["zone"] == "agent_assisted"
    assert run(ready, capsys, "audit", "--config", config(tmp_path, t), "--caller", "Bad Caller!")[0] == 4


# ── malformed input ────────────────────────────────────────────────────────
A = b'{"id":"a","kind":"local_path","locator":"/x","environment":"local"}'


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[]",
        b'{"scope": {"assets": []}}',
        b'{"scope": {"assets": []}, "extra": 1}',
        b'{"scope":{"assets":[]},"scope":{"assets":[]}}',
        b'{"mode": "RED_TEAM", "scope": {"assets": [' + A + b"]}}",
        b'{"scope": {"assets": [{"id":"a","kind":"local_path","locator":"/x/../y","environment":"local"}]}}',
        b'{"activity_classes":["B3"],"scope":{"assets":[' + A + b"]}}",
    ],
)
def test_malformed_config_is_invalid(ready, capsys, tmp_path, body):
    p = tmp_path / "bad.json"
    p.write_bytes(body)
    code, out = run(ready, capsys, "audit", "--config", str(p))
    assert code == cli.EXIT_INVALID and out["error"] == "invalid"


def test_oversized_missing_and_non_regular_inputs(ready, capsys, tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (cli.MAX_INPUT_BYTES + 1))
    for p in (str(big), str(tmp_path / "missing.json"), str(tmp_path), "/dev/zero"):
        assert run(ready, capsys, "audit", "--config", p)[0] == cli.EXIT_INVALID


@pytest.mark.parametrize("rid", ["../../etc", "x", "0" * 36, "ABCDEF00-0000-0000-0000-000000000000"])
def test_bad_run_ids(ready, capsys, rid):
    for cmd in (["runs", "show", rid], ["evidence", "verify", rid], ["report", rid]):
        assert run(ready, capsys, *cmd)[0] == cli.EXIT_INVALID


# ── runs, evidence and reports ─────────────────────────────────────────────
def test_runs_list_and_show(ready, capsys, tmp_path):
    _, a = audit(ready, capsys, tmp_path)
    _, b = audit(ready, capsys, tmp_path, content="SENTINEL-FIXTURE-FINDING\n")
    code, listed = run(ready, capsys, "runs", "list")
    assert code == 0 and {r["run_id"] for r in listed["runs"]} == {a["audit_id"], b["audit_id"]}
    assert all(r["verified"] is False for r in listed["runs"])
    code, shown = run(ready, capsys, "runs", "show", b["audit_id"])
    assert code == 0 and shown["verified"] is True and shown["overall"] == "FAIL" and shown["findings"] == 1


def test_runs_list_empty(ready, capsys):
    assert run(ready, capsys, "runs", "list")[1]["runs"] == []


def test_evidence_verify_valid(ready, capsys, tmp_path):
    _, a = audit(ready, capsys, tmp_path, content="SENTINEL-FIXTURE-FINDING\n")
    code, out = run(ready, capsys, "evidence", "verify", a["audit_id"])
    assert code == 0 and out["manifest_signature"] == "valid" and out["evidence_files"] >= 1


@pytest.mark.parametrize("what", ["evidence", "manifest", "log", "result", "signature", "extra_evidence"])
def test_evidence_verify_detects_tampering(ready, capsys, tmp_path, what):
    _, a = audit(ready, capsys, tmp_path, content="SENTINEL-FIXTURE-FINDING\n")
    root = state_dir() / "runs" / a["audit_id"]
    if what == "evidence":
        f = next(p for p in (root / "evidence").iterdir() if "." not in p.name)
        f.chmod(0o600)
        f.write_bytes(b"tampered")
    elif what == "manifest":
        m = json.loads((root / "manifest.json").read_text())
        m["overall"] = "PASS"
        (root / "manifest.json").write_bytes(canonical.encode(m))
    elif what == "log":
        lines = (root / "audit-log.jsonl").read_text().splitlines()
        (root / "audit-log.jsonl").write_text("\n".join(lines[:-1]) + "\n")
    elif what == "result":
        r = json.loads((root / "reports" / "report.json").read_text())
        r["findings"] = []
        (root / "reports" / "report.json").write_bytes(canonical.encode(r))
    elif what == "signature":
        s = json.loads((root / "manifest.sig.json").read_text())
        s["signature"] = "A" * 86 + "=="
        (root / "manifest.sig.json").write_text(json.dumps(s))
    else:
        (root / "evidence" / ("f" * 64)).write_bytes(b"planted")
    for cmd in (["evidence", "verify"], ["runs", "show"], ["report"]):
        code, out = run(ready, capsys, *cmd, a["audit_id"])
        assert code == cli.EXIT_INTEGRITY, (what, cmd, out)


def test_verify_with_other_run_key_fails(ready, capsys, tmp_path):
    _, a = audit(ready, capsys, tmp_path)
    shutil.rmtree(state_dir() / "keys")
    run(ready, capsys, "init")  # new run key
    assert run(ready, capsys, "evidence", "verify", a["audit_id"])[0] == cli.EXIT_INTEGRITY


@pytest.mark.parametrize("fmt", ["json", "sarif", "md", "html"])
def test_report_formats_to_stdout(ready, capsys, tmp_path, fmt):
    _, a = audit(ready, capsys, tmp_path, content="SENTINEL-FIXTURE-FINDING\n")
    assert cli.main(["report", a["audit_id"], "--format", fmt], ready) == 0
    body = capsys.readouterr().out
    stored = (state_dir() / "runs" / a["audit_id"] / "reports" / f"report.{cli.REPORT_EXT[fmt]}").read_text()
    assert body == stored


def test_report_output_file_is_new_and_private(ready, capsys, tmp_path):
    _, a = audit(ready, capsys, tmp_path)
    out = tmp_path / "r.sarif"
    code, res = run(ready, capsys, "report", a["audit_id"], "--format", "sarif", "--output", str(out))
    assert code == 0 and (out.stat().st_mode & 0o777) == 0o600
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert run(ready, capsys, "report", a["audit_id"], "--output", str(out))[0] == cli.EXIT_INVALID
    assert run(ready, capsys, "report", a["audit_id"], "--output", str(tmp_path / "no/dir/x"))[0] == 4


# ── policy validate ────────────────────────────────────────────────────────
def test_policy_validate_defaults(ready, capsys):
    code, out = run(ready, capsys, "policy", "validate")
    assert code == 0 and out["policy"]["source"] == "built-in defaults"


def test_policy_validate_signed_file_does_not_consume(ready, capsys, tmp_path, operator):
    _enrol(operator)
    pp, pa = _owned_policy(tmp_path, operator, "x")
    for _ in range(2):
        code, out = run(
            ready, capsys, "policy", "validate", "--policy", str(pp), "--policy-approval", str(pa)
        )
        assert code == 0 and out["policy"]["owned_assets"] == ["x"]
    assert not (state_dir() / "policy" / "applied.json").exists()


def test_policy_validate_failures(ready, capsys, tmp_path, operator):
    _enrol(operator)
    pp, pa = _owned_policy(tmp_path, operator, "x")
    assert run(ready, capsys, "policy", "validate", "--policy", str(pp))[0] == cli.EXIT_BLOCKED
    pp.write_bytes(canonical.encode({"owned_assets": ["x", "y"]}))  # changed after approval
    assert run(ready, capsys, "policy", "validate", "--policy", str(pp), "--policy-approval", str(pa))[0] == 3
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"{nope")
    assert (
        run(ready, capsys, "policy", "validate", "--policy", str(bad), "--policy-approval", str(pa))[0] != 0
    )
    assert run(ready, capsys, "policy", "validate", "--policy-approval", str(pa))[0] == cli.EXIT_INVALID


# ── internal errors never leak tracebacks ─────────────────────────────────
def test_unexpected_error_maps_to_internal(deps, capsys, monkeypatch):
    monkeypatch.setattr(cli, "cmd_version", lambda a, d: (_ for _ in ()).throw(RuntimeError("secret detail")))
    code = cli.main(["--json", "version"], deps)
    out = capsys.readouterr().out
    assert code == cli.EXIT_INTERNAL and "Traceback" not in out and "secret detail" not in out


def test_engine_blocks_validate_without_record_independent_of_cli(tmp_path, trust, ledger):
    from sentinel import policy
    from sentinel.adapters.fixture import FIXTURE_SCRIPT, FixtureAdapter, script_sha256
    from sentinel.crypto.signing import Ed25519Signer
    from sentinel.domain.models import AuditConfig
    from sentinel.orchestrator import AuditRequest, run_audit

    t = target(tmp_path, "v", "clean")
    cfg = AuditConfig.from_dict(
        json.loads(Path(config(tmp_path, t, mode="VALIDATE", level="L3")).read_text())
    )
    out = run_audit(
        AuditRequest(
            cfg,
            policy.default_policy(),
            trust,
            ledger,
            Ed25519Signer.generate(),
            [FixtureAdapter(allowlisted_sha256=script_sha256(FIXTURE_SCRIPT))],
            tmp_path / "runs",
            clock=lambda: NOW,
            host=HOST,
            env={},
        )
    )
    assert out.overall == "BLOCKED" and all(c.status.value == "BLOCKED" for c in out.checks)


def test_cli_subprocess_non_interactive(tmp_path):
    import os
    import subprocess
    import sys

    env = {"SENTINEL_HOME": str(tmp_path / "h"), "PATH": "/usr/bin:/bin"}
    r = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "--json", "version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={**env, "PYTHONPATH": os.pathsep.join(sys.path)},
        timeout=60,
    )
    assert r.returncode == 0 and json.loads(r.stdout)["exit_code"] == 0
    r = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "--json", "runs", "show", "x"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={**env, "PYTHONPATH": os.pathsep.join(sys.path)},
        timeout=60,
    )
    assert r.returncode == cli.EXIT_INVALID and b"Traceback" not in r.stderr
