# Architecture freeze remediation proposal (for AFR-01)

**Date:** 2026-11-09. **Source of findings:** `docs/architecture/freeze-review.md` (AFR-01).

**Status:** this is a proposal only.
- No production code, decision, test or dependency was changed.
- No network access was used, and nothing is staged or committed.
- **The architecture is not frozen.**

Each item has the same seven parts:
1. finding and evidence;
2. security impact;
3. proposed correction;
4. required tests;
5. files affected;
6. risks and trade-offs;
7. exact operator approval required.

Part A covers production-code changes (Priority 1). Part B covers architecture decisions (Priority 2). Part C covers documentation-only corrections and validation (Priority 3).

---

# Part A: security contradictions (production-code changes, not yet made)

## A1. X-4: what the operator approves at the Secure Enclave prompt

### 1. Finding and evidence: the payload path today

| Step | Where | What happens |
|---|---|---|
| 1 | `src/sentinel/prepare.py:55` `prepare()`, via `sentinel approval prepare` (`cli.py:497`) | Builds the **unsigned** canonical payload from validated inputs. It returns `payload`, `payload_sha256` (`canonical.digest`), `display` (`approvals.display_text`) and the "UNSIGNED" note. Nothing is signed; the CLI never signs |
| 2 | `src/sentinel/keys/secure_enclave.py:214` `sign_payload()` | `message = canonical.encode(payload)`, then `show(display_text(payload))` writes the pretty JSON plus a `sha256:` line **to the caller's terminal** |
| 3 | `secure_enclave.py:179` `sign_with_presence()` | Requires `interactive()` (a tty check), the trust-store key and metadata match, and computes `digest`. It builds a `reason` string, which the backend does **not** forward (`secure_enclave.py:361`) |
| 4 | `secure_enclave.py:360` `NativeHelperBackend.sign()` → `_run()` | Runs the hash-pinned helper with the **message bytes on stdin** and a minimal environment |
| 5 | `native/macos/se-helper/main.swift:137` `cmdSign` | Reads stdin, computes `SHA256(stdin)` **itself**, and calls `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)` with the text "approve a Sentinel operator action. Check this matches the payload SHA-256 shown in your terminal: <64 hex>" (`main.swift:157`). It signs exactly those stdin bytes, then verifies its own signature |
| 6 | `sign_with_presence()` (back in Python) | Checks that the helper's `message_sha256` equals Sentinel's digest, that the key ID matches, and that the signature verifies against the registered key |

**What the operator actually sees:**
- **Terminal:** a readable JSON payload plus a "sha256" line. Both are printed by whichever process is driving the terminal.
- **System prompt** (drawn by macOS, not by the caller): a fixed sentence plus the 64-hex SHA-256 **of the bytes the helper will sign**.

**Who controls what:**
- **An agent running as the operator's user** controls everything in the terminal. It can:
  - print a harmless-looking JSON payload with **any** "sha256" line it likes, including the hash of a different, harmful payload;
  - call the pinned helper directly with harmful bytes (the helper is a normal user-runnable binary);
  - time the prompt so that it appears while the operator expects one.
- **It can't change the system prompt's text or the hash the helper computes.** The prompt therefore binds the signature to *some* byte string. It doesn't tell the operator *what* that byte string says.

**Conclusion:** the D-33 rule "the prompt displays exactly these bytes, in readable form" is not met. A matching 64-hex hash in the prompt and the terminal shows only that the terminal *claims* that hash. **Displaying a hash doesn't show that the operator reviewed the payload**, because no human can recompute SHA-256 over the JSON they read.

### 2. Security impact

**High.** This is the residual risk D-27 and T16 exist to close: an agent getting a trust-anchor signature for content the operator didn't intend. Examples:
- widening an `authorize_record` scope;
- a `policy.change` that adds an allowlist entry;
- a `key.rotate` to an agent-controlled key.

The current defence relies on the operator noticing a hash mismatch, which a capable agent can avoid by printing a consistent fake.

Signing is still **off in production** (`production_provider` fails closed), so nothing is exploitable today. It must be fixed before activation.

### 3. Proposed correction (consistent with D-33 and D-38)

**Principle:** the human-readable decision must be rendered **by the helper, from the exact bytes it signs, in a surface the calling process can't draw into**. That surface is the system authentication dialog. Nothing shown by the caller counts as review.

1. **The helper parses and renders the payload itself.** Before prompting, the helper:
   - parses stdin with a strict, size-capped JSON parser;
   - **re-encodes it canonically** (sorted keys, no insignificant whitespace, the same rules as `canonical.encode`) and **refuses** (`invalid_request`) unless the result equals stdin byte for byte;
   - checks that the field set is exactly the §11.3 payload (`context`, `action`, `subject`, `revision`, `scope`, `issued_at`, `expires_at`, `nonce`, `key_id`, `rationale`) and that `context` matches `sentinel/v1/approval/<action>`;
   - checks that `key_id` equals the helper key's own ID.
2. **The prompt shows a deterministic, human-readable summary built by the helper.** Each action gets a fixed template with no caller-supplied text except the signed fields themselves:
   - the action in words;
   - the subject type and a short subject identifier (for example the finding fingerprint prefix, the operator name and new key fingerprint for `key.rotate`, or the policy file hash prefix and previous-file prefix);
   - the revision;
   - for `authorize_record`: every asset, environment and activity class, and the exact production asset names;
   - the expiry as an absolute UTC date and time plus its lifetime;
   - the rationale, truncated with an explicit "(truncated)" marker;
   - the full payload SHA-256 as a reference, not as the means of review.
3. **Fail closed on anything that can't be shown in full.** If the scope or another security-relevant field doesn't fit the prompt's display limit, the helper refuses (`payload_too_large_to_display`) instead of truncating it. This needs an H-test to measure the real limit of `localizedReason` on the supported macOS versions; it is **not** assumed here. Smaller approvals (split records) are the workaround.
4. **The terminal stays a secondary display only.** `display_text` remains useful, but docs and prompts must say that the system prompt is the authoritative view.
5. **No change to D-38's mechanism:** the same P-256 Secure Enclave key, the same user-presence policy and no software fallback.
6. **Documentation:** a new decision **D-39 (proposed)** amends D-33's display rule, replacing "the prompt displays exactly these bytes" with "the prompt displays a helper-rendered, complete rendering of every security-relevant field of the exact signed bytes, or the helper refuses". It doesn't change any other part of D-33.

**Alternative considered:** a helper-owned native window (NSAlert or NSPanel) showing the full payload before the authentication prompt.
- More room, but another same-user process with Accessibility permission can script or cover windows; the authentication dialog is harder to spoof.
- Could be added **in addition** to the prompt summary, never as a replacement.

### 4. Required tests

Each hardware test runs at the Mac, by the operator.
- **Unit (Swift, no prompt):**
  - non-canonical input (reordered keys, extra whitespace, duplicate keys, a trailing newline) is refused before any prompt;
  - unknown, missing or extra fields are refused;
  - a `context`/`action` mismatch is refused;
  - a `key_id` that isn't the helper's key is refused;
  - an oversized scope gives `payload_too_large_to_display`;
  - rendering each of the nine actions is deterministic (golden strings).
- **Python contract:**
  - the helper's canonical check agrees with `canonical.encode` on a corpus of payloads, including Unicode and large integers;
  - any disagreement is a refusal, never a signature.
- **New hardware tests** (for `docs/m1/se-hardware-tests.md`):

  | Test | Check |
  |---|---|
  | H12 | The prompt shows the action, subject, revision, scope and expiry matching the payload |
  | H13 | An agent-style run: the terminal shows payload A while the helper is fed payload B, and the prompt shows **B's** fields |
  | H14 | An oversized scope is refused before any prompt |
  | H15 | The measured maximum displayable prompt length is recorded |

- **Regression:** the existing H1–H11 still pass. Mutation catalogue entries are added for the canonical re-encode check, the field-set check and the display-limit refusal.

### 5. Files affected

`native/macos/se-helper/main.swift`, `docs/m1/se-helper-contract.md` (§4: the "never parses the payload" rule is reversed, deliberately and under the new decision), `docs/m1/se-hardware-tests.md`, `src/sentinel/keys/secure_enclave.py` (new error codes), `tests/test_se_helper.py`, `tests/test_secure_enclave.py`, `scripts/mutation/mutations.py`, `docs/architecture-discovery-plan.md` (D-39), and `discovery.md` §11.2 and §11.3. The helper pin `se_helper_sha256` changes, so the operator must re-pin after rebuilding.

### 6. Risks and trade-offs

- **More code in the helper** (a JSON parser): mitigated by strict size caps, an exact-field schema and refusal on any doubt.
- **Prompt length is limited:** large `authorize_record` scopes may need splitting. That is acceptable, since smaller approvals are easier to review.
- **Residual risk:** an operator can still approve without reading. No mechanism removes that, and it must stay documented (§9 of `discovery.md`).
- **Retesting:** H1–H11 must be re-run on the new build, so the current H1–H3 results don't carry over.

### 7. Exact operator approval required

> "Approve D-39: amend D-33's display rule so that the Secure Enclave system prompt shows a helper-rendered rendering of every security-relevant field of the exact signed bytes, and the helper refuses any payload it cannot fully render or that is not canonical. Approve changing the helper contract to parse the payload. Production signing remains disabled until H1–H15 pass on the new build and a separate activation decision is recorded."

---

## A2. X-5: fixture adapter running without isolation

### 1. Finding and evidence: every adapter execution path

| Path | Code | Behaviour today |
|---|---|---|
| P1: no isolation layer for the class, third-party adapter | `orchestrator.py:203` | `NOT_RUN` (`host_isolation_unavailable`) ✅ |
| P2: no isolation layer for the class, **engine-owned** adapter (`FixtureAdapter.manifest.engine_owned=True`, `adapters/fixture.py:38`) | skips the `:203` gate. `orchestrator.py:277` sets `runner = None`, then `adapter.execute(..., runner=None)` reaches `adapters/base.py:101` `subprocess.Popen` **on the host, unsandboxed**. `orchestrator.py:295` labels it `isolation_ref: none (...)` | ❌ runs with no isolation |
| P3: isolation available, adapter uses the runner | `MacSeatbeltRunner`; `res.isolation == runner.name` | ✅ sandboxed |
| P4: isolation available, adapter ignores the runner | `orchestrator.py:287-289` | `ERROR` (`isolation_not_used`) ✅ |
| P5: no runner, but the adapter *claims* an isolation name | no check when `runner is None` | ⚠ the claim is unverified (it only affects the label) |
| P6: running as root | `isolation_for` returns `None`, so it falls through to P1 or P2 | engine-owned adapter runs **as root, unsandboxed** ❌ |
| P7: test host | `tests/test_cli.py:28` `HOST = HostCapabilities("test", None, …)` | every CLI and pipeline test currently exercises P2 |

### 2. Security impact

- **High in principle, low today.** The fixture adapter runs an engine-owned, hash-pinned, synthetic Python script (`FIXTURE_SCRIPT`) that is read-only by construction. It reads target files the operator chose.
- **The invariant still matters:** D-32 says "nothing falls back to weaker isolation", and an exception in the engine sets a precedent that a future built-in adapter could inherit.
- **Root (P6) makes it worse:** the target is read as root.

### 3. Proposed correction (no unsandboxed fallback on any path)

1. **Remove the exemption.** The `:203` gate applies to every adapter: `engine_owned` no longer bypasses isolation. P2 becomes `NOT_RUN` (`host_isolation_unavailable`).
2. **Status choice:**
   - **Recommended: `NOT_RUN`**, matching D-32 and the §10.2 table ("Those classes are `NOT_RUN`").
   - **`BLOCKED`**, as the operator suggested, is also fail-closed, but §5 and R-10 reserve `BLOCKED` for policy and authorisation denials.
   - Either way the audit is `Incomplete` and never PASS. **The operator chooses**; this proposal doesn't decide it.
3. **Make execution impossible without a runner.** `ScannerAdapter.execute` (or `base.run_process`) refuses `runner=None` for any adapter, raising an internal error that the orchestrator maps to `ERROR` (`isolation_missing`). This is defence in depth, so a future caller can't reintroduce P2.
4. **P5:** when `runner is None`, the orchestrator never calls `execute`, so a claimed isolation can't be recorded.
5. **Tests use a real or test isolation layer instead of none:**
   - macOS CI and dev: the real `MacSeatbeltRunner` where the probe passes;
   - elsewhere: a **test-only runner** in `tests/` (never importable from `src/`) that records it was used, so pipeline tests keep running without making production code accept "none".
6. **Remove the `"none (engine-owned adapter run unsandboxed …)"` label** (`orchestrator.py:295`).

### 4. Required tests (one per path)

| Path | Test |
|---|---|
| P1 | Third-party adapter with no layer → `NOT_RUN`, `execute` never called (spy) |
| P2 | Engine-owned adapter with no layer → `NOT_RUN` (or `BLOCKED`, as decided), `execute` never called, audit `Incomplete`, no evidence stored |
| P3 | Sandboxed run → `isolation_ref` equals the runner name |
| P4 | Adapter ignores the runner → `ERROR` (`isolation_not_used`) (existing test kept) |
| P5 | Adapter claiming isolation with no runner → never executed |
| P6 | Root → see A3 |
| Defence in depth | `execute(runner=None)` raises for every adapter class, including `FixtureAdapter` |
| Mutation | New mutants: re-add the `engine_owned` bypass; drop the `runner is None` refusal in `execute`. Both must be caught |

### 5. Files affected

`src/sentinel/orchestrator.py`, `src/sentinel/adapters/base.py`, `src/sentinel/adapters/fixture.py` (the `engine_owned` field stays as metadata), `tests/test_pipeline.py`, `tests/test_cli.py`, `tests/test_isolation.py`, `tests/test_redaction.py`, `tests/test_aud19.py` (switched to the test runner), `tests/conftest.py` (shared test runner), `scripts/mutation/mutations.py` (mutants that anchor on the removed code are re-anchored), `docs/m1/progress.md`, and `discovery.md` (no change needed: it already says no fallback).

### 6. Risks and trade-offs

- **Linux and other hosts with no verified sandbox:** every fixture check becomes `NOT_RUN`, so audits there are always `Incomplete`. That is correct under D-32, but `audit` gives no positive result on Linux until the M2 container work.
- **Test churn:** many tests move to a test runner. The runner must stay test-only, or it becomes a backdoor; a test can check that `src/` has no import of it.
- **No security downside identified.**

### 7. Exact operator approval required

> "Approve removing the engine-owned isolation exemption: when no verified isolation layer exists for an activity class, every adapter's check is `NOT_RUN` (reason `host_isolation_unavailable`) [or: `BLOCKED`, choose one], and adapter execution without an isolation runner is impossible. No decision change is needed (this enforces D-32)."

---

## A3. D-32: running as root

### 1. Finding and evidence

- **Detection exists but isn't enforced.** `src/sentinel/isolation/__init__.py:54` sets `root = hasattr(os, "geteuid") and os.geteuid() == 0`. That is the **effective** UID, so it catches `sudo sentinel …` on macOS and Linux. The only use is `isolation_for` (`:35`), which withholds S1 isolation; with A2's current exemption, the fixture adapter then runs **as root, unsandboxed**.
- **Not detected:**
  - Linux processes with elevated capabilities but a non-zero UID (for example `CapEff` with `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`);
  - running inside a user namespace as UID 0, which looks like root and is reported as such: a safe refusal;
  - a setuid wrapper, where the effective UID is root (caught);
  - Windows (out of scope until M10).
- **macOS "administrator" accounts** (members of `admin`) are not root. §10.2 says "root or an administrator". Refusing admin-group users would block the default macOS account type, which is an **ambiguity for the operator**.
- **§10.2 says "the engine refuses to start"**, but no CLI command checks root.

### 2. Security impact

**Medium.** Running as root:
- lets any adapter, scanner or parser bug act with full privileges;
- writes root-owned state into the operator's state folder;
- reads files the operator can't.

### 3. Proposed correction (fail closed)

1. **At the start of `cli.main`,** before parsing any command except `version` and `--help`, call a new `host.privilege_check()`. It refuses when:
   - the effective UID is 0 (`os.geteuid() == 0`) on any POSIX host;
   - on Linux, `/proc/self/status` `CapEff` is non-zero. If `/proc/self/status` can't be read on Linux, that is also a refusal, so the check fails closed.
2. **Result:** exit `EXIT_BLOCKED` (3) with error kind `privileged_execution` and a message saying to run as an unprivileged user. Nothing is written: no state folder is created and no log entry is made, because writing as root is what this prevents.
3. **Defence in depth:** `isolation_for` keeps returning `None` for root.
4. **macOS admin group:** no refusal is proposed (an administrator isn't privileged until it elevates). §10.2's wording is corrected to "root (effective UID 0) or elevated capabilities". **This is a doc correction that needs operator approval**, because it narrows the written rule.

### 4. Required tests

- Mock `os.geteuid` returning 0: every command except `version` and `--help` exits 3 (`privileged_execution`), and no state folder is created.
- Linux: a mock `/proc/self/status` with a non-zero `CapEff` is refused, a zero `CapEff` is allowed, and an unreadable file is refused.
- The normal user path is unchanged (the existing suite).
- A mutation removing the startup check must be caught.

### 5. Files affected

`src/sentinel/cli.py`, `src/sentinel/isolation/__init__.py`, `tests/test_cli.py`, `tests/test_isolation.py`, `scripts/mutation/mutations.py`, and `discovery.md` §10.2 (wording).

### 6. Risks and trade-offs

- The Linux capability check may refuse some container setups that grant extra capabilities. That is intended (fail closed).
- Tests must not run as root; CI runners don't.

### 7. Exact operator approval required

> "Approve fail-closed refusal at CLI start when the effective UID is 0 or (Linux) any effective capability is set, with exit 3 `privileged_execution` and no state written; and approve correcting §10.2 from 'root or an administrator' to 'root (effective UID 0) or elevated capabilities', leaving macOS admin-group accounts allowed."

---

# Part B: proposed decision updates (wording for the operator; not yet recorded)

D-01–D-38 are **not edited**. Each item is a new proposed entry that the operator can accept, change or reject.

## B1. D-01: policy format and schemas (proposed D-40)

1. **Finding:** D-01 says "policies in YAML". The policy file is canonical JSON (`policy.py:_parse_policy`, `canonical.decode_strict`), signed over its exact bytes (§11.3). There is no `schemas/` directory (X-6), though §4 and the M1 exit criterion "Schemas validate" need one.
2. **Impact:** YAML has several encodings for the same data, which conflicts with signing exact bytes. JSON is the safer choice, but the decision log says otherwise.
3. **Proposed D-40:**
   - V1 policy, authorisation-record, decision and approval files are canonical JSON (`canonical.encode`) only; YAML is not accepted.
   - **Versioned JSON Schemas are required** for every external contract: CLI JSON output, run manifest, finding, report, canonical approval payload, policy file, authorisation record, decision file and evidence record. They live in `schemas/` with a `$id` and version, and CI validates them. This fulfils §4 and the M1 exit criterion.
   - The engine's strict parsers remain the enforcement; schemas document and test the contract, but are not a second parser in the trust path.
4. **Tests:** every schema validates its golden examples; the engine's outputs validate against their schemas in CI; a schema-version bump needs a changelog entry.
5. **Files:** `docs/architecture-discovery-plan.md`, `discovery.md` §4, new `schemas/` (implementation work later), tests.
6. **Trade-off:** keeping schemas and code in step is ongoing work. The alternative of deferring schemas would need the M1 exit criterion changed, which is a separate decision.
7. **Approval:**
   > "Approve D-40: JSON (canonical) is the only V1 policy and trust-anchor format; versioned JSON Schemas for all external contracts are required in M1."

## B2. D-23: minimum agent versions (proposed D-41)

1. **Finding:** D-23 and §14.2 say the minimum Claude Code and Codex versions are "fixed at M1 start". M1 started; none is recorded (X-7).
2. **Impact:** low now, because no integration exists.
3. **Proposed D-41:** minimum versions are set **when each integration is built** (its milestone), not at M1 start. Before either integration can be activated or released:
   - its minimum supported agent version is recorded in the decision log, with the evidence it was tested against;
   - the integration refuses to run (an error, not a degraded mode) when it detects an older or unknown agent version, **if** the agent exposes a version. Otherwise the integration declares itself unverified in its disclosure.

   This proposal sets **no version numbers**.
4. **Tests:** at integration time, a compatibility check test for older or unknown versions.
5. **Files:** the plan (D-41), `discovery.md` §14.2 and §17.1.
6. **Trade-off:** none for the engine.
7. **Approval:**
   > "Approve D-41: defer minimum Claude Code/Codex versions to each integration's build; compatibility checks are mandatory before activation."

## B3. `allowlist.change` (proposed D-42)

1. **Finding:** `allowlist.change` is a defined action with a 90-day maximum (`approvals.py:41`, §11.3, D-36, D-37), but **nothing consumes it**. `prepare.py:9` refuses it, and adapter allowlists change through `policy.change`, because the allowlist lives in the policy file (X-12).
2. **Impact:** low. Two names for one trust-anchor change cause confusion, and an unused action is an untested path.
3. **Options:**
   - **(a) Retain with a consumer:** move `adapter_allowlist` into its own signed file approved by `allowlist.change`, so policy limits and binary pins change separately (D-20 lists them separately).
   - **(b) Remove:** declare in a decision that adapter and binary allowlists are part of the policy file and change only by `policy.change`; remove `allowlist.change` from §11.3, D-36 and D-37 by amendment.
   - **Recommendation: (a)** for M2, when real scanners arrive with digest and hash pins. It keeps the D-20 separation and smaller approvals. Until then, `prepare` keeps refusing it.
4. **Tests (a):** an allowlist file needs an `allowlist.change` approval; a `policy.change` approval doesn't authorise an allowlist change and vice versa; there are mutants for both.
5. **Files:** `policy.py`, a new allowlist loader, `prepare.py`, `approvals.py`, tests, the plan, and §11.3.
6. **Trade-off:** (a) adds a trust-anchor file; (b) simplifies, but mixes limits and binary pins in one approval.
7. **Approval:**
   > "Approve D-42 option (a): `allowlist.change` is retained and consumed by a separate signed adapter-allowlist file from M2; until then it is refused" (or option (b), with the amendment wording).

## B4. Third-party asset authority (proposed D-43)

1. **Finding:** §11's `evidence_of_authority` field implies third-party assets can be authorised. The code establishes authority **only** from the approved policy's `owned_assets` and refuses third-party authority (AUD-06, G-5).
2. **Impact:** none for security. This is a documentation gap, and the code is the safer of the two.
3. **Proposed D-43:** in V1, authority over an asset is established only by the operator-approved policy's `owned_assets`. `evidence_of_authority` is recorded but never establishes authority, and any asset not in `owned_assets` is `BLOCKED`. Third-party authorisation needs a separate future decision.
4. **Tests:** the existing tests stay (`authority check` mutation); add one that a record whose only basis is `evidence_of_authority` is `BLOCKED`.
5. **Files:** the plan, and `discovery.md` §11 (the field description and the "valid signature is not proof of authority" rule).
6. **Trade-off:** no assessment of third-party assets in V1.
7. **Approval:**
   > "Approve D-43: third-party asset authority is refused (fail closed) in V1."

## B5. Interactive-terminal spoofing (proposed D-44, an accepted residual risk)

1. **Finding:** `admin.require_human_channel` and `SecureEnclaveProvider.interactive()` check `sys.stdin.isatty() and sys.stdout.isatty()` and the caller environment. A same-user process can allocate a pseudo-terminal (pty) and pass these checks (G-8b, M-7).
2. **Impact:** the tty check is **not a security boundary**. It stops accidental non-interactive use (CI, scripts) and gives a clear refusal. The control that matters is the operator-presence signature (D-27, D-38), together with A1 above.
3. **Proposed D-44:**
   - The interactive-terminal check is a usability and accident guard, **not** proof of human presence. It can be bypassed by any same-user process that allocates a pty.
   - No security property may depend on it.
   - Every trust-anchor action still needs a Secure Enclave or FIDO2 user-presence signature over a payload the operator can review in a surface the caller can't control (A1).
   - The residual risk is accepted for V1.
4. **Tests:** existing; add a documentation test that no trust-anchor path relies only on `interactive()` (a code review item, plus a mutation removing the signature check, which is already caught).
5. **Files:** the plan, `discovery.md` §9 (residual risks) and §11.2, `implementation-audit.md` G-8.
6. **Trade-off:** none. This is honesty about an existing limit.
7. **Approval:**
   > "Approve D-44: the interactive-terminal check is not a presence control; pty spoofing is an accepted V1 residual risk; operator presence rests solely on the user-presence signature."

---

# Part C: documentation corrections and validation (no code)

Each correction is listed with its exact location. **None is applied yet;** applying them is a docs-only change that needs the operator's go-ahead.

| ID | File and section | Current text (excerpt) | Proposed correction |
|---|---|---|---|
| C-a (X-1) | `docs/architecture/discovery.md` line 3 | "No implementation has started, and nothing in this document has been implemented or tested." | "M1 implementation is in progress (see `docs/m1/progress.md` and `docs/m1/implementation-audit.md`). `[P]` items are implemented only where those documents say so." |
| C-b (X-2) | `discovery.md` §11 field table, `signature`, `key_id` row | "Ed25519 signature by an **operator key** …" | "Signature by an **operator key**, using the algorithm recorded for that key in the trust store (Ed25519, or ECDSA P-256 in the Secure Enclave) [D-16, D-38] …" |
| C-c (X-13) | AFR-01 brief, and any reference to `docs/architecture/discovery-plan.md` | the non-existent path | The decision register is `docs/architecture-discovery-plan.md`. A search of `docs`, `src`, `scripts`, `tests`, `native` and `README.md` found the wrong path only in AFR-01 and this proposal, both of which mention it as non-existent. No file edit is needed beyond noting this in AFR-01, which is already done |
| C-d | `discovery.md` §10.2 | "Running as root or an administrator" | per A3 (after approval) |
| C-e | `discovery.md` §17.1 | freeze table | add rows for AFR-01 conditions C-1–C-6 and their state |

## C-f. Target milestones for scheduled gaps (proposal)

| Gap | Architecture source | Proposed milestone | Reason |
|---|---|---|---|
| PII detection and minimisation | §6.4, §13.4 | **M2** (with the first real scanners, Gitleaks or Semgrep, whose output can contain PII) | First point where third-party output contains personal data; must precede AC-04 measurement |
| Live/test secret classification | §6.4 | **M2** | Same producers |
| Kill switch (`sentinel cancel <run>` → running checks `BLOCKED`) and pause/resume | §8.1, §11, R-04 | **M2** (with concurrent real scanners and longer runs) | M1 runs are short and synthetic |
| Retention: listing and deletion of runs past 90 days | D-19, §13.5 | **M2** (CLI `runs prune --list` / `--delete`, with a log entry) | Needs real evidence volumes; never deletes silently |
| JSON Schemas (`schemas/`) | §4, D-40 | **M1** (exit criterion) | Part of the M1 exit criteria |

**Approval:**
> "Approve the target milestones in C-f."

## C-g. Reproducible Mermaid rendering and inspection method

**Current state:** no renderer is installed. `mmdc` is absent, and `npx` would download `@mermaid-js/mermaid-cli`. The local npx cache has `puppeteer` but **no Mermaid package**. Local Chrome and Edge exist. Nothing was downloaded.

**Proposed method** (needs one approved download):
1. Create `tools/diagram-render/package.json` and `package-lock.json` (committed, with `integrity` hashes) pinning one exact `@mermaid-js/mermaid-cli` version, chosen and approved by the operator. This proposal names no version.
2. `npm ci --ignore-scripts` into that folder (one network fetch, verified against the lockfile hashes). Use the locally installed Chrome through `PUPPETEER_EXECUTABLE_PATH`, so no browser is downloaded.
3. Extract the 8 blocks from `discovery.md` deterministically (the same extractor as AFR-01 §8) into `build/diagrams/NN.mmd`.
4. Render each block with `mmdc -i NN.mmd -o NN.svg` and `-o NN.png`, recording the renderer version, the input SHA-256 and the output SHA-256 in `build/diagrams/manifest.json`.
5. Inspection:
   - (a) the tool's exit code and error output (parse errors fail);
   - (b) the PNGs opened and checked visually against a checklist per diagram: every node and edge from the source is present, labels are readable, and no overlaps hide arrows;
   - (c) the result recorded in §17.1 with the manifest hashes.
6. Render `build/diagrams/` offline afterwards, since it is gitignored under `build/`.

**Alternative with no new tool:** paste each block into a trusted renderer the operator already uses and record screenshots. This is less reproducible.

**Approval:**
> "Approve downloading `@mermaid-js/mermaid-cli` <exact version> with a committed lockfile, using local Chrome, to render and inspect the 8 diagrams."

---

# Summary: approvals required

| # | Approval | Type |
|---|---|---|
| 1 | D-39: helper-rendered prompt display (X-4); helper parses the payload; H12–H15 | New decision + production code |
| 2 | Remove the engine-owned isolation exemption (X-5), choosing `NOT_RUN` or `BLOCKED` | Production code (enforces D-32) |
| 3 | Root and capabilities refusal and the §10.2 wording (A3) | Production code + doc |
| 4 | D-40: JSON only, with schemas required in M1 | New decision |
| 5 | D-41: agent versions deferred, with mandatory compatibility checks | New decision |
| 6 | D-42: `allowlist.change`, option (a) or (b) | New decision |
| 7 | D-43: third-party authority refused in V1 | New decision |
| 8 | D-44: tty-spoofing residual accepted | New decision |
| 9 | Documentation corrections C-a, C-b, C-e (and C-d after #3) | Docs only |
| 10 | Milestones C-f | Plan |
| 11 | Mermaid tool download (C-g) | Download |

**Freeze can't be approved until** #1 to #8 are decided, #9 is applied and #11 (or its alternative) is done. **Production signing stays disabled** regardless: it needs #1 implemented, H1–H15 passed on the new build, and a separate activation decision.

---

**Resolved 2026-11-09:**
- D-39 is withdrawn (superseded by D-47).
- D-40, D-41, D-42, D-43 and D-44 are recorded in `docs/architecture-discovery-plan.md` §4 as new dated entries, with forward pointers on D-01, D-16, D-23, D-27, D-33, D-36 and D-37.
- Correction C-a (the `discovery.md` status line) is applied.
