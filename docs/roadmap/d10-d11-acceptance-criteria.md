# D10 and D11 acceptance criteria (approved 2026-11-10, D-69)

This document supersedes the draft `d10-d11-criteria-proposal.md` and keeps its scope. **The owner approved these criteria on 2026-11-10 (D-69).** The thresholds in §4 are binding and enforced by `tests/test_d10_d11_corpus.py`. T2 detection remains heuristic: it is not a protection against prompt injection. The measurements are reproducible:

```bash
python scripts/d10d11/make_corpus.py
python scripts/d10d11/measure.py
```

Results are written to `docs/roadmap/d10-d11-metrics.json`, and `tests/test_d10_d11_corpus.py` fails if they go stale.

## 1. Detection classes

| Class | Meaning | Rules |
|---|---|---|
| **Deterministic** | A structural fact read from a parsed JSON or TOML field. If the field has the value, the finding is certain. It is still `suspected` until reviewed, because context decides the risk | All D10 rules; D11 `mcp.*` and `agent.*` except the two below |
| **Heuristic** | Text patterns over free-form instructions. Paraphrase, encoding or translation defeats them. **They are not a protection against prompt injection**: they flag known shapes for human review | `agent.prompt_injection`, `agent.hidden_unicode` (the T2 rules) |

## 2. Supported checks and measurable requirements

| Domain | Check | Requirement (measurable) |
|---|---|---|
| D10 | `ext.broad_host_access` | Detects `<all_urls>` and scheme wildcards in permissions, host permissions or content-script matches |
| D10 | `ext.sensitive_permission` | Detects the listed high- and medium-risk API permissions, including optional ones |
| D10 | `ext.weak_csp` | Detects `unsafe-eval` or `http:` in a CSP string or object |
| D10 | `ext.open_messaging` | Detects `externally_connectable` matching every site |
| D10 | `ext.web_accessible_all` | Detects web-accessible resources matching every site |
| D10 | `ext.insecure_update` | Detects a non-HTTPS `update_url` |
| D10 | `ext.manifest_v2` | Reports manifest version 2 |
| D10 | `ide.activate_always`, `ide.untrusted_workspace`, `ide.install_script`, `ide.dependency_unpinned` | VS Code `package.json` only (requires `engines.vscode`) |
| D11 | `mcp.unpinned_server` | npx, uvx, bunx, pnpx and pipx without an exact version |
| D11 | `mcp.shell_wrapper` | Server launched directly through a shell |
| D11 | `mcp.inline_secret` | Literal values for secret-named env keys. **The value is never output** |
| D11 | `mcp.plaintext_remote` | Non-loopback `http://` server URL |
| D11 | `mcp.broad_filesystem` | Server argument `/`, `~`, `$HOME` or a drive root |
| D11 | `mcp.auto_approve` | Non-empty `autoApprove` or `alwaysAllow` |
| D11 | `agent.permissive_allow`, `agent.dangerous_allow`, `agent.bypass_permissions`, `agent.auto_trust_project_mcp` | Claude Code settings in `.claude/` only |
| D11 | `agent.no_sandbox`, `agent.no_approval` | Codex `config.toml` in `.codex/` only |
| D11 | `agent.prompt_injection`, `agent.hidden_unicode` (heuristic) | Instruction-override, concealment, pipe-to-shell and credential-exfiltration phrasings; invisible and bidi Unicode |

Every rule also requires:

- **Malformed input** gives no crash. The analyser ignores non-JSON, or reports `input-unparseable` where the format is required.
- **Sandboxed execution** with the target unchanged (tested in `tests/test_native_analyzers.py`).

## 3. Corpus and measurement (78 cases, repository-authored)

The cases were written from threat descriptions, with varied wording, not copied from the rule patterns. Adversarial cases are included on purpose.

| Area | Vulnerable (adversarial) | Clean | Recall | Recall without adversarial | Adversarial detected | Clean cases with findings |
|---|---|---|---|---|---|---|
| D10 extensions | 14 (1) | 10 | 1.0 | 1.0 | 1/1 | 0/10 |
| D11 MCP configuration | 10 (1) | 8 | 0.90 | 1.0 | 0/1 | 0/8 |
| D11 agent settings | 8 (1) | 6 | 0.875 | 1.0 | 0/1 | 0/6 |
| D11 T2 prompt injection | 14 (5) | 8 | 0.643 | 1.0 | **0/5** | 0/8 |

**Known misses**, recorded and locked by test:

- **MCP:** a shell hidden behind `/usr/bin/env`.
- **Agent settings:** an interpreter one-liner allow rule.
- **T2:** paraphrase, punctuation obfuscation, base64, German, and multi-step exfiltration.

## 4. Acceptance criteria (approved, D-69)

| Area | Proposed R (non-adversarial) | Proposed F (clean cases with findings) | Adversarial | Status today |
|---|---|---|---|---|
| D10 | ≥ 0.95 | ≤ 0.10 | Reported, not gated | Meets |
| D11 MCP and agent (deterministic) | ≥ 0.95 | ≤ 0.10 | Reported, not gated | Meets |
| D11 T2 (heuristic) | ≥ 0.90 on the listed phrasing classes | ≤ 0.15 | **Reported; never gated as protection** | Meets on the non-adversarial cases; 0/5 adversarial |

## 5. Independence and its limit

The corpus is still written in this repository, so it shows the rules work on described threats, not on real-world data. Before relying on D10 or D11 for assurance, the owner should name an external corpus and approve its acquisition separately (none is requested here). For example:

- openly licensed extension manifests;
- published prompt-injection datasets;
- real instruction files from public repositories, for false-positive measurement.

## 6. Limitations

- Manifest analysis can't see extension or MCP server behaviour or code.
- Permission findings need context: a password manager legitimately needs broad host access.
- Agent coverage is limited to Claude Code and Codex settings formats.
- T2 detection is pattern-based and will miss novel, paraphrased, encoded or translated payloads. A clean T2 result means "no known pattern", **not** "safe".
