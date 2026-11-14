# Claude Code and Codex

Sentinel ships a Skill for each agent (D-11, D-23). The Skill calls the CLI; the engine enforces every
security decision, whatever the agent does.

## Install the Skill

```bash
sentinel --json agent check --agent claude-code
```

The output's `skill_path` is the packaged `SKILL.md`. Copy it into the agent's skills directory as
`sentinel/SKILL.md`: `~/.claude/skills/` for Claude Code, `~/.codex/skills/` for Codex.

## Compatibility (D-41, D-51)

| Agent | Minimum version | Tested with |
|---|---|---|
| Claude Code | 2.1.317 | 2.1.317 |
| Codex CLI | 0.162.1 | 0.162.1 |

Before an agent-invoked audit runs, the engine reads the agent's version (`--version`, or the
Skill's `--agent-version`). An older or unrecognised version is refused (`agent_version_unsupported`).
If the agent exposes no version, the audit runs and its disclosure says the integration is
unverified. The version is self-reported by the agent, so this is a compatibility check, not a
security control.

## What the Skill may and may not do

The Skill may run `status`, `audit --caller <agent>`, `runs`, `evidence verify`, `report` and
`fix-plan`. It must never prepare, request, receive or apply approvals, or run `key`, `review`,
`suppress`, `decisions revoke` or `init`; the engine refuses trust changes from agent environments
anyway. Every agent-assisted report carries a disclosure that the agent's model provider processes
what the agent reads.
