"""S1 native-sandbox boundary tests, run against the real sandbox on this host (macOS only).

Each "hostile" script is a benign local probe that *attempts* an action and reports whether the
sandbox allowed it. Nothing touches the network beyond a loopback listener created by the test.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel import policy
from sentinel.adapters.base import sandbox_interpreter
from sentinel.adapters.fixture import FIXTURE_SCRIPT, FixtureAdapter, script_sha256
from sentinel.crypto.signing import Ed25519Signer
from sentinel.domain.enums import CheckStatus
from sentinel.domain.models import AuditConfig
from sentinel.isolation import detect
from sentinel.isolation.sandbox import MacSeatbeltRunner, ResourceLimits, build_profile, probe
from sentinel.orchestrator import AuditRequest, run_audit, verify_run

from .conftest import NOW

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="S1 sandbox implemented for macOS only")
PY = sandbox_interpreter()  # what production runs (a framework build's bundle binary, not its launcher)
BASE = Path(sys.base_prefix).resolve()


def run_script(tmp_path: Path, code: str, *args: str, timeout=20, limits=None, extra=None):
    scripts = tmp_path / "scripts"
    scripts.mkdir(exist_ok=True)
    s = scripts / "probe.py"
    s.write_text(code)
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    runner = MacSeatbeltRunner(limits=limits, workspaces=tmp_path / "ws")
    return runner.run(
        PY,
        ["-I", str(s), *args],
        target_root=target,
        extra_read=[BASE, scripts, *(extra or [])],
        timeout_s=timeout,
        max_output=100_000,
    )


def out(res) -> str:
    return res.run.stdout.decode().strip()


ATTEMPT = """
import sys
def attempt(fn):
    try:
        fn(); print("allowed")
    except OSError:
        print("denied")
"""


def test_probe_passes_on_this_host():
    p = probe(force=True)
    assert p.available, p.reason
    assert p.observations["read_outside"] == "denied" and p.observations["network"] == "denied"
    caps = detect()
    assert caps.native_sandbox == "s1-macos-seatbelt" and caps.report()["native_sandbox_probe"]["passed"]


def test_cannot_read_unrelated_host_files(tmp_path):
    secret = tmp_path / "unrelated" / "secret.txt"
    secret.parent.mkdir()
    secret.write_text("TOP SECRET")
    for path in (str(secret), "/etc/hosts", str(Path.home() / ".zshrc"), str(Path.home())):
        r = run_script(
            tmp_path,
            ATTEMPT + "import os\nattempt(lambda: (open(sys.argv[1]).read()"
            " if os.path.isfile(sys.argv[1]) else os.listdir(sys.argv[1])))",
            path,
        )
        assert out(r) == "denied", path
        assert b"TOP SECRET" not in r.run.stdout


def test_can_read_target_but_not_write_it(tmp_path):
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "f.txt").write_text("data")
    t = str(tmp_path / "target")
    r = run_script(
        tmp_path,
        ATTEMPT + "attempt(lambda: open(sys.argv[1] + '/f.txt').read())\n"
        "attempt(lambda: open(sys.argv[1] + '/new.txt', 'w').write('x'))",
        t,
    )
    assert out(r).split() == ["allowed", "denied"]
    assert not (tmp_path / "target" / "new.txt").exists()


def test_writes_only_in_workspace_and_workspace_is_removed(tmp_path):
    outside = tmp_path / "outside.txt"
    r = run_script(
        tmp_path,
        ATTEMPT + "import os\nattempt(lambda: open('in-ws.txt','w').write('x'))\n"
        "attempt(lambda: open(sys.argv[1],'w').write('x'))\nprint(os.getcwd())",
        str(outside),
    )
    lines = out(r).split()
    assert lines[:2] == ["allowed", "denied"] and not outside.exists()
    assert r.workspace_removed and not Path(lines[2]).exists()
    assert list((tmp_path / "ws").iterdir()) == []


def test_network_denied_even_to_loopback(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(3)
    port = srv.getsockname()[1]
    got: list[bool] = []

    def accept():
        try:
            srv.accept()
            got.append(True)
        except OSError:
            pass

    th = threading.Thread(target=accept)
    th.start()
    r = run_script(
        tmp_path,
        ATTEMPT + "import socket\n"
        "attempt(lambda: socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=2))\n"
        "attempt(lambda: socket.getaddrinfo('example.com', 443))",
        str(port),
    )
    th.join()
    srv.close()
    assert out(r).split()[0] == "denied" and not got


def test_no_credentials_or_sensitive_env_inherited(tmp_path, monkeypatch):
    for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "ANTHROPIC_API_KEY"):
        monkeypatch.setenv(k, "leak-me")
    r = run_script(tmp_path, "import os; print(sorted(os.environ))")
    env = out(r)
    assert "leak-me" not in env and "TOKEN" not in env and "SSH_AUTH_SOCK" not in env
    assert set(eval(env)) <= {"PATH", "LANG", "HOME", "__CF_USER_TEXT_ENCODING"}  # noqa: S307 - test output


def test_cannot_execute_other_binaries(tmp_path):
    r = run_script(
        tmp_path,
        ATTEMPT + "import subprocess\n"
        "attempt(lambda: subprocess.run(['/bin/sh', '-c', 'echo hi'], check=True))\n"
        "attempt(lambda: subprocess.run(['/usr/bin/curl', '--version'], check=True))",
    )
    assert out(r).split() == ["denied", "denied"]


def test_timeout_kills_process_tree(tmp_path):
    marker = tmp_path / "ws-pid"
    code = (
        "import os, time\nr, w = os.pipe()\npid = os.fork()\n"
        "if pid == 0:\n    time.sleep(60)\n    os._exit(0)\n"
        "print(pid, flush=True)\ntime.sleep(60)"
    )
    start = time.monotonic()
    r = run_script(tmp_path, code, timeout=1)
    assert r.run.timed_out and time.monotonic() - start < 10
    child = int(out(r).split()[0])
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)  # the forked child was killed with the group
    assert not marker.exists()


def test_file_size_limit_enforced(tmp_path):
    r = run_script(
        tmp_path,
        ATTEMPT + "attempt(lambda: open('big','wb').write(b'x' * 200_000))",
        limits=ResourceLimits(max_file_bytes=50_000),
    )
    assert out(r) == "denied" or r.run.returncode != 0


def test_cpu_limit_enforced(tmp_path):
    r = run_script(tmp_path, "while True: pass", timeout=30, limits=ResourceLimits(cpu_seconds=1))
    assert r.run.returncode != 0 and not r.run.timed_out  # killed by CPU limit, before the wall clock


def test_profile_rejects_unsafe_paths(tmp_path):
    for bad in ('a"b', "a(b", "a\nb", "a\\b"):
        with pytest.raises(ValueError):
            build_profile(Path("/usr/bin/true"), [Path(f"/tmp/{bad}")], tmp_path)


# ── through the adapter and the pipeline ──────────────────────────────────
ALLOW = script_sha256(FIXTURE_SCRIPT)


def test_fixture_adapter_runs_sandboxed(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "a.txt").write_text("SENTINEL-FIXTURE-FINDING")
    a = FixtureAdapter(allowlisted_sha256=ALLOW)
    res = a.execute(a.plan(root)[0], root, 20, 100_000, runner=MacSeatbeltRunner(workspaces=tmp_path / "ws"))
    assert res.status == CheckStatus.FAIL and res.isolation == "s1-macos-seatbelt" and res.workspace_removed


def audit_req(tmp_path, trust, ledger, adapters):
    root = tmp_path / "target"
    root.mkdir(exist_ok=True)
    (root / "a.txt").write_text("SENTINEL-FIXTURE-FINDING")
    cfg = AuditConfig.from_dict(
        {
            "scope": {
                "assets": [{"id": "t", "kind": "local_path", "locator": str(root), "environment": "local"}]
            }
        }
    )
    return AuditRequest(
        cfg,
        policy.default_policy(),
        trust,
        ledger,
        Ed25519Signer.generate(),
        adapters,
        tmp_path / "runs",
        clock=lambda: NOW,
        env={},
    )


def test_pipeline_records_real_isolation(tmp_path, trust, ledger):
    req = audit_req(tmp_path, trust, ledger, [FixtureAdapter(allowlisted_sha256=ALLOW)])
    out_ = run_audit(req)
    assert out_.overall == "FAIL"
    m = verify_run(out_.run_dir, req.run_signer.public)
    assert m["host_isolation"]["native_sandbox"] == "s1-macos-seatbelt"
    meta = next(p for p in (out_.run_dir / "evidence").iterdir() if p.name.endswith(".meta.json"))
    assert '"isolation_ref":"s1-macos-seatbelt"' in meta.read_text()


def test_third_party_adapter_runs_only_inside_sandbox(tmp_path, trust, ledger):
    class ThirdParty(FixtureAdapter):
        manifest = replace(FixtureAdapter.manifest, name="thirdparty", engine_owned=False)

    out_ = run_audit(audit_req(tmp_path, trust, ledger, [ThirdParty(allowlisted_sha256=ALLOW)]))
    assert out_.checks[0].status == CheckStatus.FAIL  # ran, sandboxed


def test_adapter_that_ignores_the_sandbox_is_rejected(tmp_path, trust, ledger):
    class Escaper(FixtureAdapter):
        manifest = replace(FixtureAdapter.manifest, name="escaper", engine_owned=False)

        def execute(self, check, root, timeout_s, max_output, runner=None):
            # Runs its scan itself, outside the sandbox it was given, and reports a result.
            from sentinel.adapters.base import ExecutionResult

            return ExecutionResult(
                CheckStatus.FAIL,
                raw_output=b"SENTINEL-FIXTURE-FINDING",
                findings=[{"rule": "r", "file": "f", "line": 1, "message": "m", "severity": "high"}],
                isolation="none",
            )

    out_ = run_audit(audit_req(tmp_path, trust, ledger, [Escaper(allowlisted_sha256=ALLOW)]))
    assert out_.checks[0].status == CheckStatus.ERROR and out_.checks[0].reason == "isolation_not_used"
    assert out_.findings == [] and out_.overall != "PASS"


# --- framework-build interpreters (first remote CI run, 2026-11-13) ---------------------------------
# python.org and Homebrew Pythons are framework builds: bin/pythonX.Y re-executes
# Resources/Python.app/Contents/MacOS/Python, which a one-executable Seatbelt profile denies. Every
# sandboxed check failed on the GitHub macOS runner for that reason.


def _fake_framework(tmp_path: Path, executable: bool = True) -> Path:
    app = tmp_path / "Versions" / "3.13" / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    app.parent.mkdir(parents=True)
    app.write_text("#!/bin/sh\n")
    app.chmod(0o755 if executable else 0o644)
    return app


def test_sandbox_interpreter_uses_the_framework_bundle_binary(tmp_path, monkeypatch):
    import sysconfig

    from sentinel.adapters import base

    app = _fake_framework(tmp_path)
    monkeypatch.setattr(sysconfig, "get_config_var", lambda k: "Python" if k == "PYTHONFRAMEWORK" else None)
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "Versions" / "3.13"))
    assert base.sandbox_interpreter() == app.resolve()
    app.chmod(0o644)  # not executable: fall back to the resolved launcher, never a guess
    assert base.sandbox_interpreter() == Path(os.path.realpath(sys.executable))


def test_sandbox_interpreter_is_the_resolved_executable_without_a_framework(tmp_path, monkeypatch):
    import sysconfig

    from sentinel.adapters import base

    _fake_framework(tmp_path)
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "Versions" / "3.13"))
    monkeypatch.setattr(sysconfig, "get_config_var", lambda k: None)
    assert base.sandbox_interpreter() == Path(os.path.realpath(sys.executable))


def _framework_pythons() -> list[Path]:
    import glob

    found = []
    for pattern in (
        "/Library/Frameworks/Python.framework/Versions/3.*/bin/python3.*",
        "/opt/homebrew/opt/python@3.*/bin/python3.*",
        "/usr/local/opt/python@3.*/bin/python3.*",
    ):
        for p in sorted(glob.glob(pattern)):
            if p.rsplit("python", 1)[1].replace(".", "").isdigit() and os.access(p, os.X_OK):
                found.append(Path(p))
    return found


def test_seatbelt_probe_passes_under_a_real_framework_python():
    """The probe, with every denial, must pass when Sentinel runs on a framework-build interpreter."""
    import subprocess

    pythons = _framework_pythons()
    if not pythons:
        pytest.skip("no framework-build Python on this host (not a pass)")
    src = str(Path(__file__).resolve().parents[1] / "src")
    code = (
        f"import sys; sys.path.insert(0, {src!r})\n"
        "from sentinel.isolation.sandbox import probe\n"
        "r = probe(force=True); print(r.available, r.reason)\n"
    )
    for py in pythons:
        r = subprocess.run([str(py), "-I", "-c", code], capture_output=True, text=True, timeout=120)
        if "ModuleNotFoundError" in r.stderr or "SyntaxError" in r.stderr:
            continue  # too old for Sentinel's own syntax or imports; try the next one
        assert r.stdout.strip() == "True self-test passed", (py, r.stdout, r.stderr[-500:])
        return
    pytest.skip("no usable framework-build Python on this host (not a pass)")
