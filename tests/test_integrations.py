"""Claude Code and Codex integrations (D-11, D-23, D-41)."""

# ruff: noqa: F811
from __future__ import annotations

import os
import re
import shlex
import stat
from pathlib import Path

import pytest

from sentinel import cli, integrations
from sentinel.errors import BlockedError

from .test_cli import config, deps, ready, run, target  # noqa: F401


def cli_audit(d, capsys, tmp_path, *extra):  # type: ignore[no-untyped-def]
    t = target(tmp_path, f"t{len(list(tmp_path.glob('t*')))}", "clean")
    return run(d, capsys, "audit", "--config", config(tmp_path, t), *extra)


ROOT = Path(__file__).resolve().parents[1]
SKILLS = {
    "claude-code": ROOT / "src/sentinel/agent_skills/claude-code/skills/sentinel/SKILL.md",
    "codex": ROOT / "src/sentinel/agent_skills/codex/skills/sentinel/SKILL.md",
}
FORBIDDEN = ("key", "review", "suppress", "decisions", "approval", "init", "policy")


# ── D-41 version gate ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "agent, text, status",
    [
        ("claude-code", "2.1.317 (Claude Code)", "compatible"),
        ("claude-code", "2.2.0 (Claude Code)\n", "compatible"),
        ("claude-code", None, "unverified"),
        ("codex", "codex-cli 0.162.1", "compatible"),
        ("codex", "codex-cli 1.0.0", "compatible"),
        ("codex", None, "unverified"),
    ],
)
def test_compatible_and_unverified(agent, text, status):
    assert integrations.check(agent, text)["status"] == status


@pytest.mark.parametrize(
    "agent, text",
    [
        ("claude-code", "2.1.316 (Claude Code)"),
        ("claude-code", "1.9.999 (Claude Code)"),
        ("claude-code", "2.1.317"),  # unrecognised format
        ("claude-code", "codex-cli 9.9.9"),
        ("claude-code", "garbage"),
        ("codex", "codex-cli 0.162.0"),
        ("codex", "codex-cli 0.99.9"),
        ("codex", "codex 0.162.1"),
        ("codex", ""),
    ],
)
def test_older_or_unknown_versions_are_refused(agent, text):
    with pytest.raises(BlockedError) as e:
        integrations.check(agent, text)
    assert e.value.code == "agent_version_unsupported"


def test_integration_is_identified_from_caller_or_environment():
    assert integrations.integration_for("claude-code", []) == "claude-code"
    assert integrations.integration_for(None, ["OpenAI Codex"]) == "codex"
    assert integrations.integration_for("operator", []) is None
    assert integrations.integration_for(None, ["Claude Code", "OpenAI Codex"]) is None  # ambiguous


def test_version_detection_runs_the_binary_without_a_shell(tmp_path, monkeypatch):
    b = tmp_path / "claude"
    b.write_text("#!/bin/sh\necho '2.1.400 (Claude Code)'\n")
    b.chmod(b.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert integrations.detect_version_text("claude-code") == "2.1.400 (Claude Code)"
    b.write_text("#!/bin/sh\nexit 3\n")
    assert integrations.detect_version_text("claude-code") is None
    monkeypatch.setenv("PATH", str(tmp_path / "missing"))
    assert integrations.detect_version_text("codex") is None


def _deps_with(base: cli.Deps, version: str | None, env: dict[str, str] | None = None) -> cli.Deps:
    return cli.Deps(
        run_keys=base.run_keys,
        host=base.host,
        clock=base.clock,
        env=env if env is not None else {},
        agent_version=lambda a: version,
        adapters=base.adapters,
    )


def test_audit_from_an_old_agent_is_refused_before_it_runs(ready, capsys, tmp_path):
    d = _deps_with(ready, "2.0.0 (Claude Code)")
    code, out = cli_audit(d, capsys, tmp_path, "--caller", "claude-code")
    assert code == cli.EXIT_BLOCKED and out["code"] == "agent_version_unsupported"
    assert not cli.runs_dir().exists() or not any(cli.runs_dir().iterdir())


def test_compatible_agent_is_recorded_in_the_disclosure(ready, capsys, tmp_path):
    d = _deps_with(ready, "codex-cli 0.162.1")
    code, out = cli_audit(d, capsys, tmp_path, "--caller", "codex")
    _, _, result = cli.verified_run(out["audit_id"])
    ai = result["disclosure"]["agent_integration"]
    assert ai == {"agent": "codex", "version": "0.162.1", "minimum": "0.162.1", "status": "compatible"}


def test_agent_without_a_version_is_declared_unverified(ready, capsys, tmp_path):
    d = _deps_with(ready, None, env={"CLAUDECODE": "1"})
    code, out = cli_audit(d, capsys, tmp_path)
    _, _, result = cli.verified_run(out["audit_id"])
    disc = result["disclosure"]
    assert disc["agent_integration"]["status"] == "unverified" and "unverified (D-41)" in disc["statement"]


def test_operator_runs_carry_no_integration_block(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path)
    _, _, result = cli.verified_run(out["audit_id"])
    assert "agent_integration" not in result["disclosure"]


def test_agent_check_command(ready, capsys):
    code, out = run(
        ready, capsys, "agent", "check", "--agent", "codex", "--agent-version", "codex-cli 0.200.0"
    )
    assert code == 0 and out["status"] == "compatible"
    code, out = run(ready, capsys, "agent", "check", "--agent", "codex", "--agent-version", "codex-cli 0.1.0")
    assert code == cli.EXIT_BLOCKED and out["code"] == "agent_version_unsupported"


# ── skills ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("agent", sorted(SKILLS))
def test_skill_frontmatter_and_caller(agent):
    text = SKILLS[agent].read_text()
    m = re.match(r"^---\nname: sentinel\ndescription: (.+)\n---\n", text)
    assert m and 20 < len(m.group(1)) < 1024
    assert f"--caller {agent}" in text and f"agent check --agent {agent}" in text


@pytest.mark.parametrize("agent", sorted(SKILLS))
def test_every_command_in_the_skill_parses_and_none_is_privileged(agent):
    text = SKILLS[agent].read_text()
    commands = re.findall(r"`(sentinel [^`]+)`", text) + re.findall(r"^(sentinel .+)$", text, re.M)
    assert len(commands) >= 8
    parser = cli.build_parser()
    for c in commands:
        argv = [
            a if not a.startswith("<") else ("x.json" if "json" in a else "r") for a in shlex.split(c)[1:]
        ]
        argv = [a for a in argv if a not in ("(or", "json,", "sarif,", "html)")]
        if argv and argv[0] == "--json":
            argv = argv[1:]
        assert argv[0] not in FORBIDDEN, c
        parser.parse_args(argv)


def test_skills_differ_only_in_agent_names():
    a = SKILLS["claude-code"].read_text().replace("claude-code", "AGENT").replace("Claude Code", "NAME")
    b = SKILLS["codex"].read_text().replace("codex", "AGENT").replace("Codex", "NAME")
    assert a == b


def test_skills_are_not_executable_or_linked():
    for p in SKILLS.values():
        st = os.lstat(p)
        assert stat.S_ISREG(st.st_mode) and not st.st_mode & 0o111


def test_agent_check_reports_the_installed_skill_path(ready, capsys):
    code, out = run(
        ready, capsys, "agent", "check", "--agent", "codex", "--agent-version", "codex-cli 0.162.1"
    )
    p = Path(out["skill_path"])
    assert p.name == "SKILL.md" and p.read_text() == SKILLS["codex"].read_text()
