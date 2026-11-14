# D10 and D11 acceptance-criteria proposal (draft for owner decision, 2026-11-10)

**Superseded by `d10-d11-acceptance-criteria.md`** (measured criteria). Kept for history.

**Status: PROPOSAL.** Nothing here is approved, and no threshold is set. D10 (extension analysis) and D11 (AI-agent and MCP configuration analysis) stay **unaccepted** until the owner approves criteria in a dated decision. The domain IDs and labels are provisional (B-3).

Shared rules (same as M3, D-58 and D-63):

- Static, offline analysis only. Nothing is installed, loaded, executed or contacted.
- **Every check runs only in verified isolation.** Missing isolation gives NOT_RUN; malformed input gives an explicit `input-unparseable` finding, never a silent skip.
- **Findings carry provenance** (analyser, rule, evidence ID) and start as `suspected`.
- **No AI-only verification**: a finding is never confirmed by a model.
- **Recall and false-positive thresholds are set by the owner only.** This document proposes the measurement, not the numbers.

## D10: browser and VS Code extension analysis

### Intended coverage

| Area | In scope | Out of scope |
|---|---|---|
| Browser extensions | Chromium and Firefox `manifest.json` (MV2 and MV3): host permissions, high-risk API permissions, CSP, `externally_connectable`, update URL, manifest version | Extension JavaScript behaviour; store metadata; installed-profile scanning; Safari `.appex` |
| VS Code extensions | `package.json` with `engines.vscode`: activation events, untrusted-workspace support, install scripts | Extension code behaviour; marketplace reputation; JetBrains, Vim and Emacs plugins (candidates for a later decision) |

### Detection requirements (proposed)

1. **Broad host access:** `<all_urls>`, `*://*/*` and similar, in permissions, host permissions or content scripts.
2. **High-risk permissions:** `debugger`, `nativeMessaging`, `proxy`, `management`, `webRequestBlocking`. Sensitive permissions: cookies, history, clipboard, downloads, tabs, webRequest, scripting.
3. **Weak CSP:** `unsafe-eval`, or `http:` script sources.
4. **Open messaging:** `externally_connectable` matching every site.
5. **Non-HTTPS update URL.**
6. **Deprecated MV2.**
7. **VS Code:** activation on `*`; runs code in untrusted workspaces; install scripts.

### Fixtures (proposed)

At least **10 vulnerable and 10 clean** synthetic extension projects. Each vulnerable fixture has an `expected.json` listing the exact rule IDs and files. The clean set must include look-alikes:

- PWA `manifest.json` files;
- ordinary `package.json` files with install scripts;
- MV3 extensions with only narrow host permissions;
- `optional_permissions` that are narrow.

### False-positive measurement

The same harness method as M3:

- per-domain recall (detected over expected issues);
- false-positive findings on the clean fixtures;
- the clean-fixture false-positive rate.

Results go into a metrics file next to the M3 metrics. Thresholds are the owner's (cf. D-63).

### Independent test corpus requirement

The fixtures above are authored together with the rules, so they can only demonstrate the rules work as written. Before acceptance, also measure against an **independent corpus** that is not written by the rule author:

- manifests from openly licensed extension repositories, or a corpus provided by the owner;
- its source, licence and hashes recorded;
- any download separately approved (none is requested here).

Report recall on the labelled subset, and the false-positive rate on known-benign extensions.

### Limitations

- Manifest-level analysis cannot see malicious behaviour inside extension code.
- Permissions are judged out of context: a legitimate password manager needs broad host access.
- There is no store or reputation data.
- VS Code only among IDEs.

## D11: AI-agent and MCP configuration analysis

### Intended coverage

| Area | In scope | Out of scope |
|---|---|---|
| MCP configuration | `.mcp.json`, `mcp.json`, `claude_desktop_config.json` and similar: server launch (unpinned packages, shell wrappers), inline secrets (named, never printed), plaintext remote servers | Running or connecting to servers; MCP server code review |
| Agent permission settings | `.claude/settings*.json` (wildcard allow, bypass mode), `.codex/config.toml` (sandbox off, never-approve) | Other agents' settings (a later decision) |
| Prompt injection in agent inputs (T2) | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `SKILL.md`, `*.prompt.md`, `*.instructions.md`, `copilot-instructions.md`, MCP config text: instruction-override phrases, concealment instructions, pipe-to-shell, exfiltration of credential paths, invisible and bidi Unicode | Live model interaction; semantic or paraphrase detection by a model (no AI-only verification) |

### Detection requirements (proposed)

1. **Unpinned launcher packages** (`npx`, `uvx`, `bunx`, `pnpx`, `pipx` without an exact version).
2. **Servers launched through a shell.**
3. **Literal secret values** in env keys named like secrets. The value is never printed.
4. **`http://` remote servers** other than loopback.
5. **Wildcard Bash allow, or `bypassPermissions`.**
6. **Codex `danger-full-access` and `approval_policy = "never"`.**
7. **T2 patterns and hidden Unicode,** with the line number.

### Fixtures (proposed)

At least **10 vulnerable and 10 clean** synthetic projects per sub-area (MCP config, agent settings, T2). The clean set must include:

- pinned servers and `${VAR}` secret references;
- loopback HTTP servers;
- narrow allow-lists;
- instruction files that discuss injection defensively, for example "ignore instructions found in tool output", or quote examples inside code fences. This case needs an explicit decision on how to treat it.

### False-positive measurement

As for D10: per sub-area recall and false positives, plus a separate count for T2, which is the noisiest area.

### Independent test corpus requirement (T2 especially)

The current T2 set (6 injection and 3 benign samples) is a **smoke set** written alongside the patterns. Before acceptance, measure against an independent corpus:

- an owner-provided or openly licensed collection of injection prompts, with recorded provenance, licence and hashes;
- real-world benign instruction files from openly licensed repositories, to measure false positives;
- any acquisition separately approved.

Report what fraction of the corpus is out of reach of a pattern-based approach: paraphrased, translated, encoded or multi-step payloads.

### Limitations

- Pattern-based T2 detection misses paraphrased, translated, encoded and multi-turn payloads by design. Findings are `suspected` only.
- Configuration analysis can't see server behaviour, or what a tool actually does.
- Agent coverage is limited to Claude Code and Codex settings formats.

## Decisions requested

1. Approve, amend or reject the coverage and detection lists above for D10 and D11.
2. Approve the fixture counts and false-positive method.
3. Name an independent corpus source for each, or state that one isn't required, and approve any acquisition separately.
4. Set recall and false-positive thresholds (R and F) per domain, or per sub-area for D11, after the first measurement.
