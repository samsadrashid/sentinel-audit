"""AI agent and MCP configuration analyzer (M7, roadmap D11). Static and offline.

Checks MCP server configurations, coding-agent permission settings, and agent instruction files for
prompt-injection payloads (T2). It never starts an MCP server, never contacts a model, and never
prints a secret value: inline-secret findings name the variable only.
"""

from __future__ import annotations

import json
import os  # noqa: E402
import re
import sys  # noqa: E402
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import finding, line_of, main, read_text, walk

MCP_FILES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json"}
SETTINGS = {"settings.json", "settings.local.json"}
INSTRUCTION_FILES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", "SKILL.md"}
LAUNCHERS = {"npx", "uvx", "bunx", "pnpx", "pipx"}
SECRET_KEY = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
INJECTION = [
    re.compile(
        r"\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules)",
        re.I,
    ),
    re.compile(r"\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|god)\s*mode", re.I),
    re.compile(r"\b(do\s+not|don't|never)\s+(tell|inform|show|mention\s+(this\s+)?to)\s+the\s+user", re.I),
    re.compile(r"\bcurl\b[^\n|]{0,200}\|\s*(ba|z)?sh\b", re.I),
    re.compile(r"\b(exfiltrate|send)\b[^\n]{0,80}\b(\.ssh|id_rsa|\.aws|credentials|\.env)\b", re.I),
]
HIDDEN = re.compile("[\U000e0000-\U000e007f​-‏‪-‮⁦-⁩]")


def _pinned(pkg: str) -> bool:
    name = pkg[1:] if pkg.startswith("@") else pkg
    return bool(re.search(r"@\d", name) or re.search(r"==\d", name))


def mcp_servers(rel: str, text: str, servers: dict[str, Any], out: list[dict[str, Any]]) -> None:
    for name, s in sorted(servers.items()):
        if not isinstance(s, dict):
            continue
        cmd = s.get("command")
        args = [a for a in s.get("args") or [] if isinstance(a, str)]
        line = line_of(text, f'"{name}"')
        if isinstance(cmd, str) and os.path.basename(cmd) in LAUNCHERS:
            pkgs = [a for a in args if not a.startswith("-")]
            if pkgs and not _pinned(pkgs[0]):
                out.append(
                    finding(
                        "mcp.unpinned_server", rel, line, f"server {name} runs an unpinned package", "high"
                    )
                )
        if isinstance(cmd, str) and os.path.basename(cmd) in {"sh", "bash", "zsh", "cmd", "powershell"}:
            out.append(
                finding(
                    "mcp.shell_wrapper", rel, line, f"server {name} is launched through a shell", "medium"
                )
            )
        env = s.get("env")
        if isinstance(env, dict):
            for k, v in sorted(env.items()):
                if SECRET_KEY.search(k) and isinstance(v, str) and v and not v.startswith(("${", "$")):
                    out.append(
                        finding(
                            "mcp.inline_secret",
                            rel,
                            line_of(text, f'"{k}"'),
                            f"literal value for {k}",
                            "high",
                        )
                    )
        if any(a in ("/", "~", "$HOME", "${HOME}", "C:\\", "C:/") for a in args):
            out.append(
                finding(
                    "mcp.broad_filesystem",
                    rel,
                    line,
                    f"server {name} is given the whole filesystem or home",
                    "high",
                )
            )
        approve = s.get("autoApprove") or s.get("alwaysAllow")
        if isinstance(approve, list) and approve:
            out.append(
                finding(
                    "mcp.auto_approve", rel, line, f"server {name} tools run without confirmation", "medium"
                )
            )
        url = s.get("url") or s.get("serverUrl")
        if isinstance(url, str) and url.startswith("http://"):
            host = url[7:].split("/", 1)[0].split(":", 1)[0]
            if host not in ("localhost", "127.0.0.1", "[::1]"):
                out.append(
                    finding("mcp.plaintext_remote", rel, line, f"server {name} uses plain HTTP", "high")
                )


def agent_settings(rel: str, text: str, d: dict[str, Any], out: list[dict[str, Any]]) -> None:
    perms = d.get("permissions")
    if isinstance(perms, dict):
        allow = [a for a in perms.get("allow") or [] if isinstance(a, str)]
        for a in allow:
            if a in ("*", "Bash", "Bash(*)", "Bash(*:*)"):
                out.append(
                    finding(
                        "agent.permissive_allow", rel, line_of(text, a), f"allows {a} without asking", "high"
                    )
                )
            elif re.match(r"Bash\((?:sudo|rm|curl|wget|chmod|ssh|scp|nc|eval|sh|bash)\b[^)]*\)$", a):
                out.append(
                    finding(
                        "agent.dangerous_allow",
                        rel,
                        line_of(text, a),
                        f"pre-approves a dangerous command: {a}",
                        "medium",
                    )
                )
        if perms.get("defaultMode") == "bypassPermissions":
            out.append(
                finding(
                    "agent.bypass_permissions", rel, line_of(text, "bypassPermissions"), "bypass mode", "high"
                )
            )


def project_trust(rel: str, text: str, d: dict[str, Any], out: list[dict[str, Any]]) -> None:
    """Untrusted-input boundary: a repository must not be able to enable its own MCP servers."""
    if d.get("enableAllProjectMcpServers") is True:
        out.append(
            finding(
                "agent.auto_trust_project_mcp",
                rel,
                line_of(text, "enableAllProjectMcpServers"),
                "every MCP server defined by the project is trusted automatically",
                "high",
            )
        )


def codex_config(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    if re.search(r'^\s*sandbox_mode\s*=\s*"danger-full-access"', text, re.M):
        out.append(
            finding("agent.no_sandbox", rel, line_of(text, "danger-full-access"), "agent sandbox off", "high")
        )
    if re.search(r'^\s*approval_policy\s*=\s*"never"', text, re.M):
        out.append(
            finding(
                "agent.no_approval", rel, line_of(text, "approval_policy"), "never asks approval", "medium"
            )
        )


def injection(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for rx in INJECTION:
        m = rx.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            out.append(
                finding(
                    "agent.prompt_injection", rel, line, "instruction-override payload in agent input", "high"
                )
            )
            break
    m = HIDDEN.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        out.append(finding("agent.hidden_unicode", rel, line, "invisible or bidi control characters", "high"))


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in walk(root):
        rel = str(p.relative_to(root))
        name = p.name
        posix = rel.replace("\\", "/")
        if name in MCP_FILES or name in SETTINGS:
            text = read_text(p)
            try:
                d = json.loads(text)
            except ValueError:
                continue
            if not isinstance(d, dict):
                continue
            servers = d.get("mcpServers") or d.get("servers")
            if isinstance(servers, dict):
                mcp_servers(rel, text, servers, out)
                injection(rel, text, out)  # tool descriptions and args are agent input too
            if name in SETTINGS and ("/.claude/" in "/" + posix or posix.startswith(".claude/")):
                agent_settings(rel, text, d, out)
                project_trust(rel, text, d, out)
        elif name == "config.toml" and ".codex" in posix.split("/"):
            codex_config(rel, read_text(p), out)
        elif (
            name in INSTRUCTION_FILES
            or name.endswith((".prompt.md", ".instructions.md"))
            or name == "copilot-instructions.md"
        ):
            injection(rel, read_text(p), out)
    return out


if __name__ == "__main__":
    raise SystemExit(main("agents", analyze))
