# Sentinel user guide (release candidate)

Sentinel is a local security-audit engine for software you own or are authorised to assess. It reads by
default, fails closed, and never treats an AI agent as a security boundary.

| Guide | Contents |
|---|---|
| [installation.md](installation.md) | Requirements, install, first-time setup |
| [cli.md](cli.md) | Every command, exit codes, JSON output |
| [configuration.md](configuration.md) | Audit config, policy file, authorisation records |
| [environments.md](environments.md) | `local`, `staging`, `production`; modes, levels and activity classes |
| [operator-approvals.md](operator-approvals.md) | Keys, approvals, the signing device protocol, recovery |
| [agents.md](agents.md) | Claude Code and Codex Skills |
| [security-model.md](security-model.md) | Trust boundaries, fail-closed rules, privacy and network behaviour, threat model |
| [mcp.md](mcp.md) | Local MCP server: tools, boundary, limits |
| [limitations.md](limitations.md) | What is limited, blocked or not implemented; production-signing status |

**Status in one paragraph.** The release candidate ships:

- the engine, schemas, CLI, policy and authorisation, approvals and their verification, evidence and the hash-chained audit log, redaction, and the macOS S1 sandbox;
- the approved real scanners (Gitleaks, Semgrep, OSV-Scanner, Syft) under Seatbelt and rootless Podman, with M3 domain rules and honest per-domain coverage;
- native static analysers for Android, iOS, OS-configuration snapshots (macOS, Linux, Windows), supply chain (including SBOM validation), PE, MSI and MSIX header metadata, browser and VS Code extensions, and AI-agent and MCP configuration;
- pinned, sandboxed plugins;
- a local MCP server;
- reports (JSON, SARIF, Markdown, HTML), the read-only `fix-plan`, `compare` and the installed-package `self-check`.

**Production operator signing is disabled.** Trivy, Grype and Checkov await approval, and Linux and Windows are untested. See [limitations.md](limitations.md).
