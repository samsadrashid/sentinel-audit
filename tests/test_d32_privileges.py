"""D-32 / §10.2: the engine refuses effective root and elevated Linux capabilities (fail closed)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from sentinel import cli, isolation
from sentinel.paths import state_dir

from .test_cli import deps  # noqa: F401  (fixture)


def _run(d, capsys, *argv):
    code = cli.main(["--json", *argv], d)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip().startswith("{") else out)


@pytest.mark.parametrize(
    "argv",
    [["init"], ["status"], ["runs", "list"], ["policy", "validate", "--policy", "x"], ["key", "list"]],
)
def test_effective_root_is_refused_before_anything_is_written(deps, capsys, monkeypatch, argv):  # noqa: F811
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    code, out = _run(deps, capsys, *argv)
    assert code == cli.EXIT_BLOCKED and out["code"] == "privileged_execution"
    assert not state_dir().exists()


def test_version_still_answers_as_root(deps, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert _run(deps, capsys, "version")[0] == 0


def test_unprivileged_user_is_allowed(deps, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert _run(deps, capsys, "init")[0] == 0


def test_macos_admin_group_membership_is_not_refused(monkeypatch):
    # An administrator is unprivileged until it elevates: only the effective UID matters on macOS.
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(os, "getgroups", lambda: [20, 80], raising=False)  # 80 = admin
    assert isolation.privilege_problem() is None


def _status(tmp_path: Path, body: str | bytes | None) -> Path:
    p = tmp_path / "status"
    if isinstance(body, bytes):
        p.write_bytes(body)
    elif body is not None:
        p.write_text(body)
    return p


@pytest.mark.parametrize(
    ("body", "refused"),
    [
        ("Name:\tpython\nCapEff:\t0000000000000000\n", False),
        ("Name:\tpython\nCapEff:\t0000000000200000\n", True),  # CAP_SYS_ADMIN
        ("Name:\tpython\nCapEff:\t000001ffffffffff\n", True),  # full set
        ("Name:\tpython\n", True),  # missing line
        ("CapEff:\t0\nCapEff:\t0\n", True),  # ambiguous
        ("CapEff:\tzz\n", True),  # malformed
        (None, True),  # unreadable
        (b"CapEff:\t\xff\n", True),  # not ASCII
    ],
)
def test_linux_effective_capabilities(tmp_path, monkeypatch, body, refused):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sys, "platform", "linux")
    problem = isolation.privilege_problem(_status(tmp_path, body))
    assert (problem is not None) is refused


def test_linux_capabilities_refused_through_cli(deps, capsys, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(isolation, "PROC_STATUS", _status(tmp_path, "CapEff:\t0000000000000001\n"))
    code, out = _run(deps, capsys, "status")
    assert code == cli.EXIT_BLOCKED and out["code"] == "privileged_execution"
    assert not state_dir().exists()


def test_root_host_gets_no_isolation_layer():
    host = isolation.HostCapabilities("darwin", "s1-macos-seatbelt", None, None, True)
    from sentinel.domain.enums import ActivityClass

    assert host.isolation_for(ActivityClass.S1) is None
    assert host.runner_for(ActivityClass.S1, None) is None
