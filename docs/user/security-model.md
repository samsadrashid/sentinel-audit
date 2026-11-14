# Security model, privacy and threat model (release candidate)

The full architecture, decisions and threat analysis are in `docs/architecture/discovery.md` and `docs/architecture-discovery-plan.md`. This page summarises what an operator relies on.

## Trust boundaries

| Boundary | Enforced by | Notes |
|---|---|---|
| **Engine versus everything else** | Policy, authorisation, approvals and isolation in `sentinel` | AI agents, plugins and MCP clients are **requesters**. They can't approve, sign, change policy or mark a finding verified |
| **Engine versus scanners, analysers and plugins** | Verified isolation only: macOS Seatbelt (S1) or rootless Podman (S2). Network denied, target read-only, disposable workspace | No unsandboxed fallback: without verified isolation, a check is `NOT_RUN` or `BLOCKED` |
| **Operator authority** | ECDSA P-256 operator keys and signed approvals (D-45, D-47) | Production signing (the signing device) is disabled; approvals come from outside Sentinel |
| **Evidence integrity** | Run key (Ed25519), hash-chained audit log, signed manifests | Integrity relative to the run key (D-34) |
| **Installed code** | `sentinel self-check` against the wheel RECORD | Detects corruption and tampering by others, not a determined same-user attacker |

## Fail-closed rules

- A missing, unapproved, unpinned, hash-mismatched, failed, timed-out or unsupported check is never `PASS`. It is `NOT_RUN`, `ERROR` or `BLOCKED`, and the audit is `INCOMPLETE`.
- Domain coverage is `FULL` only when every required check completed. `NOT_APPLICABLE` needs explicit discovery evidence.
- Malformed input gives an explicit `input-unparseable` finding or a check `ERROR`, never a silent skip.
- Plugins run only from bytes verified against the pinned manifest, and only inside S1.
- Binaries (PE, MSI, MSIX) are read header-only, and nothing analysed is ever executed (D-65). Archives (APK, AAB, IPA) are unpacked only by B2, inside a no-mount container in the share-free Podman machine (D-70).
- Before an image runs, its stored layers are re-hashed against the image's config. A damaged image is never started, and the check is `NOT_RUN image_integrity_failed`.
- Container checks run only in a Podman machine with no host share (D-71). The target and databases are copied into VM-local volumes, never bind-mounted, so a container can't write to the host (M2-SA-12).

## Privacy and network behaviour

**Sentinel's own process.** It makes no network connection and no DNS lookup while running these commands:

- `init`, `audit`, `report` (all formats), `fix-plan`, `compare`;
- `runs`, `evidence verify`, `policy validate`, `status`, `self-check`;
- `mcp serve`.

This is tested by `tests/test_no_network.py`, which makes every socket connect and name lookup fail loudly. There is no telemetry, analytics, update check or upload in the code.

**Local subprocesses Sentinel starts:**

| Subprocess | Network |
|---|---|
| `/usr/bin/security`, for the run-key seed in the macOS keychain | none |
| The pinned Podman client, which talks to its local VM socket | containers run with `--network=none` |
| An agent's own `--version` (the D-41 compatibility check) | none |
| Sandboxed analysers, scanners and plugins | network denied by the sandbox |

**The sandbox self-test** deliberately attempts one connection to `127.0.0.1:9` *inside* the sandbox, to prove that network access is denied.

**Out of Sentinel's control:**

- AI agents such as Claude Code or Codex, and their model providers, make their own network requests, and may send the contents of files or of Sentinel's output to their services. Sentinel can't see or prevent this; it marks its output as untrusted data and redacts it.
- Container runtimes may contact registries when *you* pull images. Sentinel never pulls (`--pull=never`).

**Evidence and redaction.** Secrets and PII are redacted before evidence is stored or printed (D-31, AC-15, AC-16). Inline secret values in MCP configurations are never reported, only the variable name.

## Threat model summary

| Threat | Mitigation | Residual |
|---|---|---|
| A malicious target tries to escape, or to execute during an audit | Read-only mounts; nothing in the target is executed; Seatbelt and Podman isolation | Isolation strength is S1/S2 as measured in M2 |
| A malicious plugin | Pinned manifest hash; exact verified bytes executed; S1 isolation; permissions refused, not downgraded; failures isolated to the plugin's check | macOS only |
| Prompt injection through target content or tool output | Output is labelled `untrusted_content`; the verdict comes only from the exit code; agents can't approve or verify | Pattern-based T2 detection misses novel payloads |
| Scanner supply-chain compromise | Hash- and digest-pinned scanners and databases; no runtime pulls; acquisitions approved individually | Depends on the owner verifying acquisitions |
| A forged approval or tampered evidence | Signature verification; nonce ledger; hash chain; `verified_run` before reports, fix-plans and comparisons | Same-user write access to the state directory (AUD-05) |
| An exposed MCP server | stdio only; no network transport; trust and state tools never exposed | No client authentication; an external bridge removes the local-only property |
| An archive bomb or path traversal | B2 unpacking disabled; MSIX central-directory checks for traversal, symlinks, ratio and entry count | APK and IPA contents are not analysed |
