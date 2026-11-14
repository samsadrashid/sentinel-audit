"""Engine-produced data-boundary disclosure (§13.3, F-07, D-05, D-31).

The engine, not the agent, determines and prints the disclosure. It detects agent environments from
the process environment and from the caller's declaration; either one marks the run agent-assisted.
An agent can lie about itself, so the report says the Skill's confirmation is not independently
verified. In V1 the engine itself never sends data off the machine.
"""

from __future__ import annotations

import os
from typing import Any

AGENT_ENV_MARKERS = {
    "CLAUDECODE": "Claude Code",
    "CLAUDE_CODE_ENTRYPOINT": "Claude Code",
    "CODEX_SANDBOX": "OpenAI Codex",
    "CODEX_THREAD_ID": "OpenAI Codex",
    "CODEX_CI": "OpenAI Codex",
}

ENGINE_STATEMENT = (
    "Sentinel engine processing is local only: in V1 the engine has no feature that sends "
    "source code, evidence or findings to any external service."
)
AGENT_STATEMENT = (
    "This run was invoked through an AI coding agent ({agents}). Anything that agent reads, "
    "including this report, is processed by that agent's model provider under the provider's "
    "own terms. Sentinel cannot control that. Disclosure confirmed by the Skill is not "
    "independently verified."
)


def detect(declared_caller: str | None, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ) if env is None else env
    found = sorted({name for var, name in AGENT_ENV_MARKERS.items() if env.get(var)})
    if declared_caller and declared_caller not in ("operator", "ci"):
        found = sorted(set(found) | {declared_caller})
    zone = "agent_assisted" if found else "local_only"
    statement = ENGINE_STATEMENT
    if found:
        statement += " " + AGENT_STATEMENT.format(agents=", ".join(found))
    return {
        "zone": zone,
        "agents": found,
        "declared_caller": declared_caller,
        "skill_confirmation": "not independently verified" if found else None,
        "statement": statement,
    }
