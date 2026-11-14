"""AC-17: kill switch, pause and resume (§8.2, R-04, D-52).

`cancel` must stop every running scanner process tree within 10 s, measured over at least 20 runs with
a long-running scanner. Every stopped check is BLOCKED, the audit is Cancelled, and overall is never
PASS. `pause` starts no new checks; `resume` re-authorises every remaining check, and restarts if the
source revision changed. Every transition is logged.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sentinel import controls, policy
from sentinel.adapters.base import BoundedRun, run_bounded
from sentinel.adapters.scanners import GitleaksAdapter
from sentinel.domain.enums import ActivityClass, AuditState, CheckStatus
from sentinel.orchestrator import Orchestrator

from .isolation_testing import TestHost
from .m2_fakes import FakeRunner, pins_with, slow_until_cancelled
from .test_pipeline import cfg, make_target, request

LIMIT_S = 10.0
RUNS = 20


class _Host(TestHost):
    __test__ = False

    def runner_for(self, cls: ActivityClass, limits: Any, pins: Any = None, kind: Any = None) -> Any:
        return self.runner if cls == ActivityClass.S1 else None


def _audit(tmp_path: Path, trust, ledger, respond, *, n_assets: int = 1, workers: int = 2):  # type: ignore[no-untyped-def]
    targets = [make_target(tmp_path, f"t{i}", "x") for i in range(n_assets)]
    pins = pins_with(tmp_path, gitleaks="binary")
    runner = FakeRunner("s1-macos-seatbelt", respond)
    host = _Host("darwin", "s1-macos-seatbelt", None, None, False, runner=runner)
    pol = replace(policy.default_policy(), limits=replace(policy.Limits(), max_concurrent_scanners=workers))
    orch = Orchestrator(
        request(tmp_path, trust, ledger, cfg(*targets), adapters=[GitleaksAdapter(pins)], host=host, pol=pol)
    )
    return orch, runner, targets


def _start(orch: Orchestrator) -> tuple[threading.Thread, dict[str, Any]]:
    box: dict[str, Any] = {}
    th = threading.Thread(target=lambda: box.setdefault("out", orch.execute()), daemon=True)
    th.start()
    assert controls.wait_until(lambda: controls.is_active(orch.audit_id), 10)
    return th, box


def _log(orch: Orchestrator) -> str:
    return (orch.run.root / "audit-log.jsonl").read_text()


def test_cancel_stops_a_long_running_scanner_within_10s_over_20_runs(tmp_path, trust, ledger):
    durations = []
    for i in range(RUNS):
        sub = tmp_path / f"run{i}"
        sub.mkdir()
        orch, runner, _ = _audit(sub, trust, ledger, slow_until_cancelled(300))
        th, box = _start(orch)
        assert controls.wait_until(lambda: bool(runner.calls), 10)  # the scanner is running
        t0 = time.monotonic()
        controls.send(orch.audit_id, "cancel", 0)
        th.join(timeout=LIMIT_S + 5)
        durations.append(time.monotonic() - t0)
        out = box["out"]
        assert out.state == AuditState.CANCELLED and out.overall != "PASS"
        assert [c.status for c in out.checks] == [CheckStatus.BLOCKED] and out.checks[0].reason == "cancelled"
        assert "audit.cancel_requested" in _log(orch) and not controls.is_active(orch.audit_id)
    assert len(durations) == RUNS and max(durations) < LIMIT_S, durations


def test_kill_switch_kills_the_whole_real_process_tree_within_10s(tmp_path):
    """A real shell that forks a long-lived child: cancel must kill parent and child (process group)."""
    pidfile = tmp_path / "child.pid"
    script = f"sleep 300 & echo $! > {pidfile}; wait"
    for _ in range(RUNS):
        pidfile.unlink(missing_ok=True)
        ev = threading.Event()
        threading.Timer(0.3, ev.set).start()
        t0 = time.monotonic()
        r = run_bounded(
            ["/bin/sh", "-c", script],
            cwd=tmp_path,
            env={"PATH": "/bin:/usr/bin"},
            timeout_s=300,
            max_output=1000,
            cancel=ev,
        )
        elapsed = time.monotonic() - t0
        assert r.cancelled and r.returncode is None and elapsed < LIMIT_S
        child = int(pidfile.read_text())
        assert controls.wait_until(lambda: not _alive(child), 5), "child process survived the kill switch"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
    return bool(out.strip()) and not out.strip().startswith("Z")


def test_pause_starts_no_new_check_and_resume_reauthorises_the_rest(tmp_path, trust, ledger):
    release = threading.Event()

    def respond(target: Any, args: list[str], runner: FakeRunner) -> BoundedRun:
        release.wait(30)
        return BoundedRun(0, b"[]", False, False, 1)

    orch, runner, _ = _audit(tmp_path, trust, ledger, respond, n_assets=3, workers=1)
    th, box = _start(orch)
    assert controls.wait_until(lambda: len(runner.calls) == 1, 10)
    controls.send(orch.audit_id, "pause", 0)
    assert controls.wait_until(lambda: orch.sm.state == AuditState.PAUSED, 5)
    release.set()  # the running check finishes; no further check may start while paused
    time.sleep(1.0)
    assert len(runner.calls) == 1
    controls.send(orch.audit_id, "resume", 0)
    th.join(timeout=20)
    out = box["out"]
    assert len(runner.calls) == 3 and out.state == AuditState.COMPLETED and out.overall == "PASS"
    log = _log(orch)
    assert "audit.paused" in log and "audit.resumed" in log
    resumed = next(t for t in out.result["control"]["transitions"] if t["event"] == "audit.resumed")
    assert resumed["reauthorised"] == 2 and resumed["refused"] == 0


def test_resume_refuses_checks_that_no_longer_pass_authorisation(tmp_path, trust, ledger, monkeypatch):
    release = threading.Event()
    orch, runner, _ = _audit(
        tmp_path,
        trust,
        ledger,
        lambda *a: (release.wait(30), BoundedRun(0, b"[]", False, False, 1))[1],
        n_assets=2,
        workers=1,
    )
    th, box = _start(orch)
    assert controls.wait_until(lambda: len(runner.calls) == 1, 10)
    controls.send(orch.audit_id, "pause", 0)
    assert controls.wait_until(lambda: orch.sm.state == AuditState.PAUSED, 5)

    from sentinel.errors import BlockedError

    def refuse(self, p, root):  # type: ignore[no-untyped-def]
        raise BlockedError("authorisation withdrawn", "record_revoked")

    monkeypatch.setattr(Orchestrator, "_gate", refuse)
    release.set()
    controls.send(orch.audit_id, "resume", 0)
    th.join(timeout=20)
    out = box["out"]
    assert len(runner.calls) == 1
    assert [c.status for c in out.checks] == [CheckStatus.PASS, CheckStatus.BLOCKED]
    assert out.overall != "PASS"
    resumed = next(t for t in out.result["control"]["transitions"] if t["event"] == "audit.resumed")
    assert resumed["refused"] == 1  # refused at resume time, before anything restarted


def test_resume_after_a_source_change_restarts_instead(tmp_path, trust, ledger):
    release = threading.Event()
    orch, runner, targets = _audit(
        tmp_path,
        trust,
        ledger,
        lambda *a: (release.wait(30), BoundedRun(0, b"[]", False, False, 1))[1],
        n_assets=2,
        workers=1,
    )
    th, box = _start(orch)
    assert controls.wait_until(lambda: len(runner.calls) == 1, 10)
    controls.send(orch.audit_id, "pause", 0)
    assert controls.wait_until(lambda: orch.sm.state == AuditState.PAUSED, 5)
    (targets[0] / "app.txt").write_text("changed while paused")
    release.set()
    controls.send(orch.audit_id, "resume", 0)
    th.join(timeout=20)
    out = box["out"]
    assert out.state == AuditState.CANCELLED and out.overall != "PASS"
    assert out.result["control"]["restart_required"] is True
    assert out.checks[-1].status == CheckStatus.BLOCKED and out.checks[-1].reason == "revision_changed"
    assert "audit.restart_required" in _log(orch)


def test_controls_refuse_unknown_commands_and_inactive_audits():
    from sentinel.errors import ValidationError

    with pytest.raises(ValidationError):
        controls.send("01a1c049-fd7e-7acb-ae9e-3406332d7387", "cancel", 0)
    with pytest.raises(ValidationError):
        controls.send("not-a-uuid", "cancel", 0)
    with pytest.raises(ValidationError):
        controls.send("01a1c049-fd7e-7acb-ae9e-3406332d7387", "skip-auth", 0)


def test_cli_audit_restarts_once_when_the_revision_changed(tmp_path, monkeypatch, capsys):
    """The interrupted run stays Cancelled; a fresh run covers the new revision."""
    import json

    from sentinel import cli
    from sentinel.orchestrator import AuditOutcome

    from .test_cli import MemBackend, config, target
    from .test_cli import deps as _deps_fixture  # noqa: F401

    calls: list[int] = []
    real = cli.run_audit

    def fake_run(req):  # type: ignore[no-untyped-def]
        out: AuditOutcome = real(req)
        calls.append(1)
        if len(calls) == 1:
            out.result["control"] = {"transitions": [], "restart_required": True}
        return out

    monkeypatch.setattr(cli, "run_audit", fake_run)
    from sentinel.keys.runkey import RunKeyManager

    from .conftest import FIXTURE_ONLY, NOW
    from .test_cli import HOST

    backend = MemBackend()
    d = cli.Deps(
        run_keys=lambda: RunKeyManager(backend),
        host=lambda: HOST,
        clock=lambda: NOW,
        env={},
        agent_version=lambda a: None,
        adapters=FIXTURE_ONLY,
    )
    assert cli.main(["--json", "init"], d) == 0
    capsys.readouterr()
    t = target(tmp_path, "t", "clean")
    cli.main(["--json", "audit", "--config", config(tmp_path, t)], d)
    out = json.loads(capsys.readouterr().out)
    assert len(calls) == 2 and out["restarted_from"] != out["audit_id"]


def test_unknown_command_is_refused_even_for_a_running_audit():
    from sentinel.errors import ValidationError

    aid = "01a1c049-fd7e-7acb-ae9e-3406332d7387"
    controls.register(aid)
    try:
        with pytest.raises(ValidationError, match="unknown control command"):
            controls.send(aid, "skip-auth", 0)
        assert controls.read(aid) is None
    finally:
        controls.unregister(aid)


def test_a_check_interrupted_by_the_kill_switch_is_blocked_whatever_the_adapter_reports(
    tmp_path, trust, ledger
):
    """An adapter that reports ERROR (not 'cancelled') after the kill switch fires is still BLOCKED,
    and nothing it returned is kept."""

    def respond(target: Any, args: list[str], runner: FakeRunner) -> BoundedRun:
        assert runner.cancel_event is not None
        runner.cancel_event.set()  # the kill switch fires while the scanner runs
        return BoundedRun(3, b"partial output", False, False, 1)

    orch, runner, _ = _audit(tmp_path, trust, ledger, respond)
    out = orch.execute()
    assert [c.status for c in out.checks] == [CheckStatus.BLOCKED] and out.checks[0].reason == "cancelled"
    assert out.checks[0].evidence == () and out.state == AuditState.CANCELLED and out.overall != "PASS"
    assert not any((orch.run.root / "evidence").iterdir())
