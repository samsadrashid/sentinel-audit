"""Claude Code and Codex integrations: the D-41 compatibility check.

Each integration is a Skill that calls the Sentinel CLI (D-11, D-23). Before an agent-invoked audit runs,
the engine checks the agent version against the minimum recorded for that integration:

* a detected version **older** than the minimum, or a version string that can't be recognised, is
  refused (`BLOCKED`, `agent_version_unsupported`);
* if the agent exposes no version at all, the run proceeds and the disclosure says the integration is
  **unverified**;
* a compatible version is recorded in the disclosure.

The version comes from the agent's own `--version` output (or the Skill's `--agent-version`), so it is
a compatibility signal, not a security boundary: an agent can misreport it. The security controls stay
in the engine (authorisation, approvals, isolation, redaction), whatever the agent claims.

Minimum versions are the versions this integration was built and tested with (D-41); the evidence is
recorded as D-51 (evidence: docs/user/agents.md).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from .errors import BlockedError

#: D-51 (completes D-41): the versions each integration was built and tested with (2026-11-09).
MIN_VERSIONS: dict[str, tuple[int, int, int]] = {"claude-code": (2, 1, 317), "codex": (0, 162, 1)}
BINARIES = {"claude-code": "claude", "codex": "codex"}
ENV_AGENT = {"Claude Code": "claude-code", "OpenAI Codex": "codex"}
VERSION_PATTERNS = {
    "claude-code": re.compile(r"^\s*(\d{1,4})\.(\d{1,4})\.(\d{1,6})\s+\(Claude Code\)\s*$"),
    "codex": re.compile(r"^\s*codex-cli\s+(\d{1,4})\.(\d{1,4})\.(\d{1,6})\s*$"),
}
MAX_VERSION_TEXT = 200


def integration_for(declared_caller: str | None, env_agents: list[str]) -> str | None:
    """The integration this run belongs to: the declared caller, else the agent seen in the environment."""
    if declared_caller in MIN_VERSIONS:
        return declared_caller
    found = sorted({ENV_AGENT[a] for a in env_agents if a in ENV_AGENT})
    return found[0] if len(found) == 1 else None


def parse(agent: str, text: str) -> tuple[int, int, int] | None:
    first = text.strip().splitlines()[0] if text.strip() else ""
    m = VERSION_PATTERNS[agent].match(first[:MAX_VERSION_TEXT])
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def detect_version_text(agent: str, timeout: float = 10.0) -> str | None:
    """Run `<agent binary> --version` (no shell, minimal environment). None if the agent exposes nothing."""
    binary = shutil.which(BINARIES[agent])
    if binary is None:
        return None
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/")}
    try:
        r = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=timeout, env=env, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (r.stdout or "").strip()
    return out[:MAX_VERSION_TEXT] if r.returncode == 0 and out else None


def skill_path(agent: str) -> str:
    """The packaged Skill file for this agent (copy it into the agent's skills directory)."""
    from importlib import resources

    return str(resources.files("sentinel") / "agent_skills" / agent / "skills" / "sentinel" / "SKILL.md")


def check(agent: str, version_text: str | None) -> dict[str, Any]:
    """Apply D-41. Raises BlockedError for an older or unrecognised version."""
    minimum = ".".join(map(str, MIN_VERSIONS[agent]))
    if version_text is None:
        return {"agent": agent, "version": None, "minimum": minimum, "status": "unverified"}
    v = parse(agent, version_text)
    if v is None:
        raise BlockedError(
            f"unrecognised {agent} version {version_text[:60]!r}; refusing (D-41)",
            "agent_version_unsupported",
        )
    if v < MIN_VERSIONS[agent]:
        raise BlockedError(
            f"{agent} {'.'.join(map(str, v))} is older than the minimum {minimum} (D-41)",
            "agent_version_unsupported",
        )
    return {"agent": agent, "version": ".".join(map(str, v)), "minimum": minimum, "status": "compatible"}
