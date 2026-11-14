# Sentinel M1 progress

Last updated: 2026-11-09 (session 38). **M1 ACCEPTED on 2026-11-09. M2 ACCEPTED on 2026-11-09** (baseline record: `docs/m2/m2-completion-report.md`; residual risk M2-SA-12 and the §7 limitations stay open). **M3 scope approved (D-58 to D-63); implementation in progress; Trivy, Checkov and Grype downloads await owner approval.** **The architecture is frozen as a design baseline (D-48).** Statements elsewhere in this file that say "not frozen" are dated history. **M1 is not complete.** This file records what exists, what is tested, and what remains. Status words:

| Status | Meaning |
|---|---|
| **Tested** | Implemented, with unit tests that actually ran and passed |
| **Drafted** | Code exists but has no tests yet; treat it as unverified |
| **Stub** | Placeholder only |
| **Not started** | No code yet |
| **Blocked** | Can't proceed safely without an owner decision |

Architecture note: the architecture has **not** been formally frozen. The 8 diagrams are unrendered and the owner hasn't given the freeze approval. Implementation follows D-01–D-37 as currently written.

## Session 1: foundation (2026-11-08)

Scope:
- package foundation and packaging;
- domain models and validation;
- errors and result states;
- initial unit tests;
- developer instructions.

| Area | Module | Status | Tests |
|---|---|---|---|
| Packaging (Python ≥ 3.12, hatchling, uv lock) | `pyproject.toml`, `uv.lock` | Tested: installs with `uv sync` on Python 3.13.13 (macOS arm64) | install verified manually |
| Errors | `sentinel/errors.py` | Tested | `test_error_hierarchy_and_blocked_reason` |
| Result and lifecycle enums | `sentinel/domain/enums.py` | Tested | 4 enum tests |
| Canonical encoding and strict JSON | `sentinel/canonical.py` | Tested | 8 tests |
| Domain models (Asset, Scope, AuditConfig, CheckResult, ScannerExecution, AuditSummary) | `sentinel/domain/models.py` | Tested | 17 tests |
| Audit state machine and outcome rules | `sentinel/lifecycle.py` | Tested | 11 tests |
| Path safety (scope root, atomic and write-once writes) | `sentinel/paths.py` | Tested | 2 tests |
| Developer docs | `README.md` | Done | — |

**Verification run (2026-11-08):**

| Check | Result |
|---|---|
| `pytest tests/test_foundation.py` | **41 passed, 0 failed, 0 skipped** |
| `ruff check` on the scoped files | passed |
| `mypy --strict` on the scoped modules | passed (7 files) |
| `compileall src` | passed |
| Mutation check | Two deliberate weakenings in a scratch copy were each caught by a failing test: allowing B3, and PASS for an incomplete audit |
| `uv build` | Builds a wheel and sdist (output written to a scratch folder, not `dist/`) |
| Repo-wide `uv run ruff check src tests` | **Fails: 24 issues, all in drafted modules** (adapters, approvals, archive, authorisation, evidence, findings, keys, policy, reports) |
| Repo-wide `uv run mypy` | **Fails: 7 errors, all in drafted modules** (archive, evidence, keys) |

The scoped foundation modules pass ruff and strict mypy cleanly. The drafted modules get their lint and type fixes in the session that tests them.

## Session 2: drafted-module audit and repair (2026-11-08)

- **D-38 recorded** (algorithm-agile operator signing; Secure Enclave P-256 allowed; no software fallback). D-16 is annotated, and discovery.md §13.7 is updated.
- **Every drafted module audited:** see [`implementation-audit.md`](implementation-audit.md). 12 defects found and fixed (AUD-01 to AUD-12), including two security issues:
  - AUD-06: free-text authority evidence was accepted as proof of authority;
  - AUD-11: unbounded scanner output was buffered in memory.
- **Verification run:**

| Check | Result |
|---|---|
| `pytest` (full suite) | **202 passed, 0 failed, 0 skipped** |
| Repo-wide `ruff check src tests` | passed |
| `ruff format --check` | passed |
| Repo-wide `mypy --strict` | passed (27 files) |
| `uv build` | wheel and sdist built (to a scratch folder) |
| Mutation test of 22 security checks | 22 of 22 caught |

| Area | Status |
|---|---|
| Crypto, keys, approvals, authorisation, policy, evidence, archive, adapters, findings, reports, disclosure, isolation detection | **Unit-tested** with synthetic fixtures. Not integrated: no orchestrator or CLI yet |
| Real OS keystore backends | Not tested (tests use a fake backend) |
| Secure Enclave operator signing | Not implemented; fails closed (G-1) |
| Isolation managers | Not implemented (G-3) |

## Session 3: integrated audit pipeline (2026-11-08)

`sentinel/orchestrator.py` now connects every engine module:
- config, then mode and level, then authorisation record (signature *and* authority), then class enforcement;
- planning, then per-check re-authorisation (immediately before each check) and engine-side scope check;
- bounded adapter execution, then evidence, then findings and dedup, then final state;
- run-key-signed manifest (verified right after it is written), then JSON, SARIF, Markdown and HTML reports.

**Fail-closed behaviour now executable end to end:**
- Missing scanner, hash mismatch, crash, malformed output, timeout, missing target, a class with no adapter, maximum audit duration, cancellation, and a third-party adapter with no isolation each give an explicit `NOT_RUN`, `ERROR` or `BLOCKED`, and the audit is never PASS.
- Policy bypasses (A1 in READ, wrong level for the mode, VALIDATE against production, signature without authority) give `BLOCKED`.

**Defect found during this session:** the orchestrator first relied on the adapter's own `validate_scope`, so a mutation that removed it went undetected. An engine-side scope check was added, plus a hostile-adapter test (`test_engine_blocks_scope_expansion_even_if_adapter_does_not`).

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **231 passed, 0 failed, 0 skipped** (29 new pipeline tests; the earlier 202 still pass) |
| Repo-wide `ruff check` and `ruff format --check` | passed |
| `mypy --strict` (27 files) | passed |
| `uv build` | passed |
| Installed-wheel smoke test (full audit, from a separate environment) | passed: Completed / FAIL, 1 finding, manifest verifies, 4 reports |
| Mutation test, 29 security checks (22 earlier + 7 orchestrator) | **29 of 29 caught** |

**What the pipeline does not do yet (not claimed):**
- **No OS isolation.** The engine-owned fixture adapter runs unsandboxed. That is recorded as `isolation_ref: none (...)` in evidence, and every third-party adapter is `NOT_RUN`.
- **Only `local_path` assets.** Other asset kinds are `NOT_RUN`.
- **No real scanners** (M2).
- **No redaction engine.** Evidence records say so; the fixture output contains no secrets.
- **Operator approvals still fail closed.** No Secure Enclave helper yet.
- **No CLI or agent integrations.**

## Session 4: OS isolation layer (2026-11-08)

New: `sentinel/isolation/sandbox.py` (S1 native sandbox for macOS) and capability detection in `sentinel/isolation/__init__.py`, wired into the adapters and the orchestrator.

**Host verified:** macOS 26.6.2 (build 25G83), arm64, not running as root.

| Capability | Status on this host | How it was determined |
|---|---|---|
| Native sandbox (Seatbelt via `sandbox-exec`) | **Available** | Functional self-test (`probe()`) under the real profile: target read allowed; reads outside allowed roots denied; writes outside the workspace denied; network denied; environment minimal |
| Filesystem isolation (S1) | Deny-by-default reads and writes | Boundary tests: unrelated files, `/etc/hosts`, home directory, writes to target and outside the workspace all denied |
| Network isolation (S1) | All network denied, including loopback and DNS | Boundary test with a local listener: no connection received |
| Exec restriction | Only the approved interpreter | `/bin/sh` and `/usr/bin/curl` denied |
| Credential and environment isolation | Fixed minimal environment | Planted `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK` and `ANTHROPIC_API_KEY` were not visible |
| Resource limits | CPU seconds, max file size, open files, no core dumps | CPU-limit and file-size tests |
| Process termination | Whole process group killed on timeout or output cap | A forked grandchild is gone after a timeout |
| Disposable workspace | Fresh 0700 folder per check, removed afterwards | Cleanup test |
| **Memory limit** | **Not enforced** (macOS doesn't honour `RLIMIT_AS`) | Documented gap |
| **File metadata (`stat`)** | **Readable host-wide** inside the sandbox (needed by the runtime) | Documented gap |
| Container runtime | Docker present, **not used**: no digest-pinned scanner images (D-22) | S2, B1 and B2 stay `NOT_RUN` |
| Rootless containers, VM isolation | **Not implemented or verified** | — |
| Linux hosts | **No native sandbox implemented** (no Linux host to verify on) | Reported unavailable; third-party checks `NOT_RUN` |

**Profiles:**
- `s1-macos-seatbelt`: used for both the engine-owned fixture adapter and third-party S1 adapters when the probe passes. The fixture adapter is now **recorded as sandboxed** when it runs this way.
- When no verified sandbox exists, the fixture adapter still runs unsandboxed, recorded as `isolation_ref: none (...)`, and third-party adapters are `NOT_RUN`.
- An adapter that ignores the sandbox it is given gets `ERROR` (`isolation_not_used`), and its results are discarded.

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **246 passed, 0 failed, 0 skipped** (15 new real-sandbox tests; the earlier 231 still pass) |
| Repo-wide `ruff check` and `ruff format --check` | passed |
| `mypy --strict` (28 files) | passed |
| `uv build` | passed |
| Mutation test, 35 checks (29 earlier + 6 isolation) | **35 of 35 caught** |

## Session 5: Secure Enclave Python foundation (2026-11-08)

New: `sentinel/keys/secure_enclave.py`, `tests/test_secure_enclave.py`, and the helper contract `docs/m1/se-helper-contract.md`. Changed: `keys/operator.py`, where `available_provider()` now delegates to the Secure Enclave production factory.

| Part | Status |
|---|---|
| Python implementation (provider interface, metadata store and validation, registration, rotation and revocation through `key.rotate`/`key.revoke` approvals, response verification, payload binding) | **Complete** |
| Fake-backend tests | **Complete**: 40 tests. The fake holds a **software** key and declares `genuine_hardware=False`. These tests prove the Python trust logic only |
| Real Secure Enclave integration (native helper) | **Not implemented.** `production_provider()` always raises `CapabilityUnavailable`, so operator approvals are refused on every host |
| Physical user-presence tests (H1–H11 in the contract) | **Not performed** |

**Trust rules the Python side enforces, whatever a backend returns:**
- Metadata must have exact fields; the algorithm must be P-256 and the backend name must match; the key ID is recomputed from the public key.
- The key must be active, unexpired, and in the trust store with the identical public key (checked before the backend is called).
- The response must have exact keys; its `key_id` must match; `message_sha256` must equal Sentinel's hash of the displayed canonical payload; the DER signature must verify against the registered key.
- Backend errors map only to the six documented codes (`BLOCKED presence_*`); anything else is `backend_malformed`.
- Non-hardware backends are refused unless a test passes `allow_test_backend=True`; no production code path sets it.
- Every approval calls the backend again; nothing is cached.
- Rotation approvals bind the new key's ID, the SHA-256 of its public key, and the current trust-store fingerprint, and are one-time.

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **286 passed, 0 failed, 0 skipped** (40 new; the earlier 246 still pass) |
| `ruff check` and `ruff format --check` | passed |
| `mypy --strict` (29 files) | passed |
| `uv build` | passed (wheel and sdist) |
| Mutation test, 48 checks (35 earlier + 13 Secure Enclave) | **48 of 48 caught** (one survivor on the first pass, the trust/metadata key-match pre-check; the test was tightened) |

## Session 6: native Secure Enclave helper (2026-11-08)

New: `native/macos/se-helper/{main.swift,build.sh,manual_hardware_tests.py}`, `tests/test_se_helper.py`, `docs/m1/se-hardware-tests.md`. Changed: `keys/secure_enclave.py` (adds `NativeHelperBackend` and `parse_helper_output`, invocation only) and the contract (adds `invalid_request`, size limits, full hash in the prompt).

| Part | Status |
|---|---|
| Swift helper (`status`, `create`, `sign`) | **Implemented and builds** on this Mac (Swift 6.4.2, macOS 26.6.2) |
| Python invocation backend (pinned hash, private copy, minimal env, output cap, exit-status check) | **Implemented and tested** with fake executables |
| Prompt-free helper paths (status, create, every invalid request, garbage handle) | **Tested against the real binary** |
| Hardware-backed signing with user presence | **Not demonstrated.** No signature has been made; H1–H11 not run |
| `production_provider()` | **Still off** (always raises) |

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **332 passed, 0 failed** (46 new; earlier 286 still pass). No test reaches a user-presence prompt |
| `ruff check`, `ruff format --check`, `mypy --strict`, `uv build` | passed |
| Mutation test, 53 checks (48 earlier + 5 helper backend) | **53 of 53 caught** |

## Session 7: CLI (2026-11-08)

New: `src/sentinel/cli.py` (the `sentinel` entry point) and `tests/test_cli.py`. Engine changes:
- `policy.check_mode_authorization`, called by the orchestrator: VALIDATE now needs a verified authorisation record whatever classes are requested. Before this, VALIDATE L3 with only S1 classes ran without a record, contrary to D-21.
- `policy.validate_policy_file`: the same checks as `load_policy`, but read-only (the approval is verified, not consumed; the applied-policy record is not written). `load_policy` was split into helpers with unchanged behaviour.
- `keys/runkey.run_public_key()`: reads the run key's public half from metadata, so verifying a run needs no keystore access.

| Command | What it does |
|---|---|
| `init` | Creates the private state folders and the run key (keystore-backed). Creates no operator key |
| `status` | Host report, isolation per class, run-key keystore, operator signing (reports `unavailable`), trust-store fingerprint |
| `audit --config` | Calls `run_audit` with the fixture adapter. Authorisation (`--authorization` plus `--approval`) and policy (`--policy` plus `--policy-approval`) are accepted only as pre-signed files and verified by the engine. Optional `--caller` is disclosed, never trusted |
| `runs list` | Lists runs from their manifests, marked **unverified** |
| `runs show`, `evidence verify` | Verify the manifest signature, every evidence hash, the log chain, and that the stored result matches the signed manifest's `result_sha256` |
| `report --format json/sarif/md/html [--output]` | Re-renders from the verified result. `--output` must be a new file (0600, no overwrite, no symlink) |
| `policy validate` | Built-in defaults, or a signed policy file checked without consuming its approval |
| `version` | Version, schema and platform |

**Exit codes:** 0 success or PASS; 1 findings; 2 incomplete or cancelled; 3 blocked (including any check BLOCKED by re-authorisation); 4 invalid input or usage; 5 integrity failure; 6 capability unavailable; 7 internal error (no traceback or exception text shown).

**Input limits:** input files must be regular files of at most 1 MiB, parsed strictly (duplicate keys rejected). Run IDs must be lowercase UUIDs. The CLI never prompts, never signs, and prints no secret.

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **397 passed, 0 failed** (65 new CLI tests; earlier 332 still pass) |
| `ruff check`, `ruff format --check`, `mypy --strict` (30 files), `uv build` | passed |
| Mutation test, 64 checks (53 earlier + 11 CLI, D-21 gate and policy validation) | **64 of 64 caught** |

**Hardware tests (owner, 2026-11-08, in progress):** H1, H2 and H3 **passed**. H3 produced the first real Secure Enclave signature with user presence, and `approvals.verify` accepted it. H4–H11 had not been reported when this was written.

## Session 8: trust administration and review decisions (2026-11-08)

New: `src/sentinel/admin.py`, `src/sentinel/decisions.py`, `tests/test_trust_admin.py`. Changed: `findings.py` (entry-bound suppressions; summary counts suppressed and accepted risk separately), `orchestrator.py` (applies decisions after deduplication, re-verified at that moment), `reports/__init__.py` (human-verified and exclusions sections; SARIF `suppressions`), `cli.py` (new commands), `tests/test_findings_reports.py` (updated to the entry-based suppression).

| Command | Effect |
|---|---|
| `key list` | Keys, public-key SHA-256, status, trust fingerprint (read-only) |
| `key enrol` | Only into an empty trust store, with a `key.rotate` approval **signed by the new key itself** over its identity (proof of possession). Prints the public-key SHA-256 for out-of-band comparison |
| `key rotate` | Adds a key with a one-time `key.rotate` approval from another active key; needs `--trust-fingerprint` to match the current store |
| `key revoke` | One-time `key.revoke` approval, `--trust-fingerprint` required; the last active key can't be revoked |
| `review verify` | Records a `review.verify_no_evidence` decision (finding plus revision) |
| `review accept-risk`, `suppress add` | Record an entry whose SHA-256 is the approval subject (§7.4, §11.3). Entries need scope (finding plus revision), a reason of at least 10 characters equal to the approval rationale, author, creation time and an expiry no later than the approval's. Accepted risk also needs approver and compensating controls |
| `decisions list` | Lists recorded decisions and malformed files (not a verification) |
| `history verify` | Verifies the append-only admin log (hash chain plus run-key checkpoints) |

**Rules enforced:**
- **Approvals:** every change uses `approvals.verify`. That enforces exact canonical payload and signature, context and action, subject, revision, the D-37 maximum lifetime, expiry, revocation, and the D-36 nonce rules: one-time for key changes; standing, bound to one payload hash, for decisions.
- **Refused callers:** mutating commands refuse non-interactive sessions and agent environments (`non_interactive`, `agent_caller`), and log the refusal.
- **No signing:** no CLI path creates an operator signature.
- **Decisions at audit time:** each decision is verified again immediately before it is applied. Decisions that are invalid, expired, revoked, from a revoked key, tampered with or renamed are reported under `decisions.rejected` and not applied. Decisions for another revision are counted under `other_revision`.
- **Suppressions never hide or soften:** findings stay in the result, severity and check status are unchanged (an accepted-risk FAIL still exits 1), and reports list them in an exclusions section.
- **Human-verified is separate:** `HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE` is reported in its own section and never counted as `verified`.

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **441 passed, 0 failed** (44 new; earlier 397 still pass) |
| `ruff check`, `ruff format --check`, `mypy --strict` (32 files), `uv build` | passed |
| Mutation test, 82 checks (64 earlier + 18 trust-admin and decision gates) | **82 of 82 caught** |

**Production signing:** still off. H1–H3 passed; H4–H11 have not been reported, and no enabling decision record exists. Until then nobody can produce the approvals these commands need on a real host; tests use test-only keys.

## Session 9: governance completion (2026-11-08)

New: `src/sentinel/prepare.py`, `tests/test_governance.py`. Changed: `decisions.py` (revocation), `policy.py` (`se_helper_sha256`), `keys/secure_enclave.py` (fixed helper path, `helper_backend`, `helper_status`, pin-aware `production_provider`), `cli.py` (new commands; `report --output` now shares one no-overwrite writer), `tests/test_secure_enclave.py` (message match), `docs/m1/se-hardware-tests.md` (pin approval process).

**1. Approval preparation.** `sentinel approval prepare <kind>` supports key-enrol, key-rotate, key-revoke, review, accept-risk, suppress, decision-revoke, policy-change and authorize-record.
- **Exact payload:** subject and revision are derived from the same objects the verifier recomputes them from. The output shows every field, the canonical bytes and the full `payload_sha256`.
- **Strict inputs:** each kind needs exactly its inputs; missing, extra or ambiguous inputs are refused. The signer must be an active key, and D-37 limits are applied.
- **Refused:** `allowlist.change`, because no engine operation consumes it (allowlist changes go through `policy.change`).
- **No side effects:** preparing writes nothing (tested by snapshotting the whole state directory). Nothing is signed, and no nonce is registered or consumed. The output has no signature, so no loader accepts it as an approval.
- **Inspection:** `sentinel approval inspect` re-canonicalises any payload or approval file and shows its hash.

**2. Decision revocation.** `sentinel decisions revoke --decision-id --approval`.
- **Approval:** a one-time `revoke_record` approval whose subject is `{type: decision, decision_id, entry_sha256}` and whose revision is the decision's own revision.
- **Records:** the original decision file is kept byte for byte, and the revocation is a write-once record in `decisions-revocations/`. Revocations are logged in the admin history, and refused attempts are logged too.
- **At audit time:** revocation state is re-checked. A revoked decision is listed as `decision_revoked` and not applied. A revocation file that doesn't verify blocks the decision (`revocation_unverifiable`) rather than letting it apply.
- **Later key revocation:** a revocation stays in force even after its signing key is revoked.
- **History:** `decisions list` shows each decision's revocation state and whether its original signature is still valid.

**3. Helper pin.** The trusted helper hash is now `se_helper_sha256` in the operator-approved policy file, so changing it needs a `policy.change` approval.
- **Fixed path:** the helper lives at `<state>/bin/sentinel-se-helper`.
- **Refusals:** a missing pin, a missing binary or a symlink is refused, and the helper hash is checked before every run (no fallback).
- **Status:** `sentinel status --policy … --policy-approval …` reports the pin without running the helper.
- **Activation:** `production_provider()` validates the pin and then still refuses, because activation needs H1–H11 plus a decision record.

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **476 passed, 0 failed** (35 new; earlier 441 still pass) |
| `ruff check`, `ruff format --check`, `mypy --strict` (33 files), `uv build` | passed |
| Mutation test, 98 checks (82 earlier + 16 new) | **98 of 98 caught** |

**Hardware tests:** H1–H3 passed (owner, 2026-11-08). **H4–H11 not yet reported.** Production signing stays off.

## Session 10: AUD-16 closure and redaction engine (2026-11-08)

New: `src/sentinel/redaction.py`, `tests/test_redaction.py`, `docs/m1/redaction.md`. Changed:
- `approvals.py` (AUD-16);
- `evidence.py` (evidence and log redaction, fail closed);
- `orchestrator.py` (redactor from policy, `redaction_failed` handling, result redaction);
- `policy.py` (`redaction_patterns`);
- `cli.py` (all output redacted; `init` creates the redaction key; `redaction_failed` error kind);
- `prepare.py` and `decisions.py` (refuse secret-like signed content);
- tests updated: `test_approvals.py`, `test_authorization_policy.py`, `test_pipeline.py`, `test_evidence.py`.

**Part A: AUD-16 closed.**
- **The fix:** `approvals.apply_revocation` now requires the revocation's revision to equal the **target approval's own revision**, so placeholder revisions (`"n/a"`) and stale ones are refused. It also requires the target to be a well-formed approval signed by a registered operator key (`malformed_target`).
- **Unchanged:** the subject binding (target payload hash), one-time nonce, D-37 expiry, and revoked-key and expired-revocation checks still apply through `approvals.verify`.
- **Callers:** all callers are tests and were updated; a regression test asserts none still passes a placeholder. Decision revocation keeps its own stricter binding (decision ID, entry hash and revision, session 9).
- **Fail-closed state:** an unverifiable revocation state still blocks a decision rather than letting it apply.

**Part B: redaction engine.** Local, deterministic and pattern-based; see `docs/m1/redaction.md` for rules, sinks, blind spots and false positives.
- **Markers:** `[REDACTED:<rule>:<HMAC fingerprint>]`, keyed per installation.
- **Where it applies:** before evidence is written (otherwise refused), to every finding, check reason, the result, the manifest and all reports, to the run and admin logs, and to all CLI output including errors and exported reports.
- **Failures:** if evidence redaction fails, the check is `ERROR` with `redaction_failed` and nothing is kept. If result redaction fails, the audit stops before any manifest or report.
- **Custom patterns:** come only from the approved policy.

| Check | Result (2026-11-08) |
|---|---|
| `pytest` (full) | **518 passed, 0 failed** (42 new; earlier 476 still pass) |
| `ruff check`, `ruff format --check`, `mypy --strict` (34 files), `uv build` | passed |
| Mutation test, 118 checks (98 earlier + 20 new) | **118 of 118 caught** |

Bugs found and fixed during this session, by its own tests:
- markers were re-matched by the assignment rule;
- a second pass redacted the word `Bearer`;
- env names that *are* the keyword (`API_KEY=`) were missed;
- the policy parser accepted `redaction_patterns` without storing or validating it.

## Session 11: third-party license inventory (2026-11-09)

New: `scripts/license_audit.py`, `licenses/review.json`, `licenses/inventory.json` (generated), `THIRD_PARTY_NOTICES` (generated), `tests/test_license_audit.py`, `docs/m1/licensing.md`. Changed: `pyproject.toml` (`license-files`, explicit sdist allowlist).

- **Inventory:** all 15 locked packages. 3 are runtime (cryptography, cffi, pycparser; direct and transitive) and 12 are dev and test, listed separately. Packages behind environment markers are kept.
  - License comes from each package's own metadata.
  - License text is copied only when its hash matches the package's `RECORD`.
  - A license is never inferred from a package name or a classifier.
- **Review register and CI gate:** `check` fails on any unreviewed package, any change in version, scope, license or license-file hash, a stale review, a stale generated file, or a disallowed runtime license. `--strict` also fails on open `needs_review` questions, and is the release gate.
- **Native helper:** the Apple frameworks, the Swift runtime and the Xcode tools are recorded. None is redistributed.
- **Packaging:** the wheel ships `THIRD_PARTY_NOTICES` in `.dist-info/licenses/`. The sdist is now an explicit allowlist (AUD-18).
- **Open questions** (details in `docs/m1/licensing.md`):
  - cryptography's embedded OpenSSL and Rust crates are unverified;
  - cffi's per-file license exceptions are unreviewed;
  - colorama isn't installed here, so it is unverified;
  - the Swift runtime license text is unverified;
  - the repository has no top-level `LICENSE` file for Sentinel's MIT license.

| Check | Result (2026-11-09) |
|---|---|
| `pytest` (full) | **567 passed, 0 failed** (49 new; earlier 518 still pass) |
| `ruff check`, `ruff format --check`, `mypy --strict` (34 files plus `scripts/license_audit.py`), `uv build` | passed |
| `license_audit.py check` | 0 issues (2 acknowledged, 4 open reviews); `--strict` fails as intended |
| Mutation test: 118 engine checks plus 20 license-audit checks | 20 of 20 license-audit checks caught; 100 of 118 engine checks caught and 18 survive (AUD-19, closed in session 12) |

## Session 12: AUD-19 mutation coverage recovery (2026-11-09)

New: `scripts/mutation/harness.py`, `scripts/mutation/mutations.py` (138 mutants with stable ids), `tests/test_mutation_harness.py` (17 tests), `tests/test_aud19.py` (29 tests). No production code changed.

- **Harness:**
  - **Inputs:** every declared input is checked first; if any is missing, nothing runs.
  - **Baseline:** the unmodified baseline must pass before any mutant runs.
  - **Statuses:** `caught`, `survived`, `invalid` and `infra_failed`; only `caught` counts.
  - **Report:** a JSON report with each mutant's id, exit code and failing test ids, plus the input hashes. Details are under AUD-19 in the implementation audit.
- **All 18 survivors investigated.**
  - 14 were genuine test gaps. One of them is high severity: a signed suppression entry edited after signing.
  - 2 are redundant layers whose only visible effect is the reason code (self-signed enrolment) or the burned nonce (enrol-when-empty ordering).
  - 2 fail closed either way, but the revocation state was reported wrongly.
  - Each now has a focused test that fails under its mutant. Full table under AUD-19.

| Check | Result (2026-11-09) |
|---|---|
| `pytest` (full) | **613 passed, 0 failed** (46 new) |
| Mutation baseline (unmodified copy) | engine suite exit 0 (79.4 s); license suite exit 0 (3.1 s) |
| Mutation campaign, catalogue sha256 `8ef65b45436cb96e…` | **138 caught, 0 survived, 0 invalid, 0 infra-failed** (118 engine, 20 license); all 18 former survivors are caught by their `test_aud19.py` tests |
| `ruff check`, `ruff format --check` (58 files), `mypy --strict` (34 files plus both scripts), `uv build` | passed |
| `license_audit.py check` | 0 issues |
| sdist inspection | only allowlisted paths. No `.ecc-src`, `tools`, `.claude`, `integrations` or `docs/private`, and none of the private project names. The wheel holds only `sentinel/` and dist-info, including `THIRD_PARTY_NOTICES` |

## Session 13: licensing closure and distribution readiness (2026-11-09)

New: `LICENSE` (MIT, Copyright (c) 2026 Samsad Rashid Ony, holder confirmed by the owner), `licenses/build-lock.txt`, `licenses/texts/openssl-3.5.6-LICENSE.txt`.

Changed:
- `pyproject.toml`: hatchling pinned to 1.33.0, the version already in use; `[tool.uv].build-constraint-dependencies`; `LICENSE` added to the license files and the sdist allowlist.
- `uv.lock`: only a `[manifest] build-constraints` block; no package versions changed.
- `scripts/license_audit.py`: build-dependency inventory and new gates.
- `licenses/review.json`, the regenerated notices and inventory, the tests, the mutation catalogue (+9 license mutants), and `docs/m1/licensing.md`.

**Outcome:**
- All four open reviews are resolved and approved with evidence (see `docs/m1/licensing.md`).
- One finding: cffi contains an MIT-licensed file (`_cffi_gen_src.py`, Rose Davidson), so its effective terms are MIT-0 AND MIT; that notice is now reproduced.
- The gate now also fails on:
  - unreviewed or unpinned build dependencies;
  - a missing build environment;
  - missing attribution;
  - unverified embedded notices or upstream texts.

| Check | Result (2026-11-09) |
|---|---|
| `pytest` (full) | **633 passed, 0 failed** (20 new) |
| `license_audit.py check --strict` | **0 issues** (3 runtime, 6 build, 12 dev); 4 acknowledged classifier/not-installed notes |
| Mutation baseline | engine exit 0 (51.5 s), license exit 0 |
| Mutation campaign, catalogue `274f2b3f748a2ef4…` | **147 caught, 0 survived, 0 invalid, 0 infra-failed** (118 engine, 29 license) |
| `ruff check`, `ruff format --check` (58 files), `mypy --strict` (34 files plus both scripts), `uv build` | passed |
| Artifacts | wheel: `sentinel/` plus dist-info with `licenses/LICENSE` and `licenses/THIRD_PARTY_NOTICES`. sdist: allowlist only; 0 forbidden paths (`.ecc-src`, `tools`, `.claude`, `integrations`, `docs/private`, `build`, `.venv`); 0 private project names |

## Session 14: licensing workstream closed (2026-11-09)

**The owner accepted:**
- `Copyright (c) 2026 Samsad Rashid Ony`;
- the verified network downloads;
- the exact hatchling and build pins;
- the `uv.lock` build-constraints block;
- the documented license readings.

**Residual risks:** recorded as **accepted, not verified** in three places: `docs/m1/licensing.md` (LR-1 to LR-4), `licenses/review.json` (`residual_risks`), and a "RESIDUAL LICENSING RISKS" section in `THIRD_PARTY_NOTICES`. A test enforces all three.
- LR-1: the OpenSSL build process;
- LR-2: cffi Windows wheels and libffi;
- LR-3: Rust crate license texts;
- LR-4: the reviewer readings.

**CI:** there was no CI workflow in the repository. Added `.github/workflows/license-gate.yml` (macOS):
- `uv lock --check`, then `uv sync --frozen`, so the lockfile hashes are enforced;
- builds the hash-pinned build env (`--require-hashes`);
- runs `license_audit.py check --strict`, which covers notices, inventory, build pins and attribution;
- runs `tests/test_license_audit.py` with `SENTINEL_CI=1`, so the real wheel and sdist content test can never skip.

**The workflow has not been run on GitHub yet** (nothing is pushed). It is verified locally only.

| Check | Final result (2026-11-09) |
|---|---|
| `pytest` (full) | **634 passed, 0 failed**: the session-13 633, plus 1 residual-risk disclosure test |
| `license_audit.py check --strict` | **0 issues**: 3 runtime, 6 build, 12 dev |
| Mutation baseline | engine exit 0 (52.3 s), license exit 0 (1.2 s) |
| Mutation campaign, catalogue `274f2b3f748a2ef4…` | **147 caught, 0 survived, 0 invalid, 0 infra-failed** (118 engine, 29 license) |
| `ruff check`, `ruff format --check` (58 files), `mypy --strict` (34 files plus 2 scripts), `uv build` | passed |
| Artifacts | the wheel's `THIRD_PARTY_NOTICES` is byte-identical to the repository's. The wheel holds `sentinel/`, the dist-info `LICENSE` and the notices. The sdist has 0 forbidden paths (`.ecc-src`, `tools`, `.claude`, `integrations`, `docs/private`, `build`, `.venv`, `.github`) and 0 private names |

**Licensing workstream: CLOSED.**

## Session 15: architecture freeze review AFR-01 (2026-11-09)

New: `docs/architecture/freeze-review.md`. No code or decisions were changed.

- **Verdict: READY WITH CONDITIONS.**
  - The 38 decisions are complete and coherent.
  - There are 13 contradictions (X-1 to X-13), two of them touching security invariants:
    - **X-4:** the Secure Enclave prompt shows the payload hash, not the payload (D-33);
    - **X-5:** the engine-owned fixture adapter runs unsandboxed, against D-32's no-fallback rule.
  - Eight decisions are missing or implicit (M-1 to M-8).
  - Six freeze conditions are proposed (C-1 to C-6), including rendering the diagrams.
- **Validation:** the structural documentation and diagram check passed. The decision register is D-01 to D-38 with none missing, all references resolve, and the 8 Mermaid blocks are balanced. **No diagram was rendered:** `mmdc` isn't installed and no download was made.
- **The architecture is NOT frozen.** Work on the Fix-plan waits for the operator's explicit freeze approval (statement in `freeze-review.md` §9).

## Session 16: freeze remediation proposal (2026-11-09)

New: `docs/architecture/freeze-remediation-proposal.md`. It is a proposal only: no code, decisions or tests were changed, and no network access was used.

- **X-4:** the full payload path is traced. The proposal is **D-39**: the Secure Enclave helper parses the exact signed bytes, refuses non-canonical input, and shows every security-relevant field in the system prompt, or refuses. New hardware tests H12–H15.
- **X-5:** paths P1–P7 are traced. The proposal removes the engine-owned exemption (the check becomes `NOT_RUN` or `BLOCKED`, the operator's choice) and makes execution without a runner impossible.
- **A3:** `os.geteuid()` detects effective root but nothing enforces it. The proposal is a fail-closed refusal at CLI start; Linux `CapEff` is also checked.
- **Proposed decisions:** D-40 (JSON plus required schemas), D-41 (defer agent versions), D-42 (`allowlist.change`), D-43 (third-party authority refused), D-44 (accept the tty-spoofing residual risk).
- **Documentation corrections:** C-a to C-e. **Milestones** for the scheduled gaps: C-f. **Mermaid rendering:** method C-g, which needs one approved download.
- **The architecture is NOT frozen.** Eleven approvals are listed in the proposal summary.

## Session 17: approved X-5 and D-32 corrections; round-2 proposals (2026-11-09)

**Code**, implementing only the approved items:
- **X-5:** no adapter runs unsandboxed. The engine-owned exemption is removed (`NOT_RUN`, `host_isolation_unavailable`).
  - `HostCapabilities.runner_for` returns a runner only for the verified Seatbelt profile.
  - There is an execution-time gate, and `FixtureAdapter` refuses to run without a runner.
  - A `NOT_RUN` returned by an adapter keeps nothing.
- **D-32:** `isolation.privilege_problem()` checks for effective UID 0 and, on Linux, for elevated `CapEff` (fail closed). The CLI refuses at start with exit 3 `privileged_execution` and writes no state. macOS `admin` membership is allowed. `discovery.md` §10.2 wording is updated as approved.
- **Tests:** the test-only runner lives in `tests/isolation_testing.py` (never importable from `src/`, enforced by a test). New tests are in `tests/test_pipeline.py` and `tests/test_d32_privileges.py`. Nine mutants were added and two re-anchored.

**Docs:** `docs/architecture/freeze-remediation-round2.md` covers:
- the D-39 dialog design and analysis. **It finds that a same-user process can use the Secure Enclave key handle directly, with any dialog text, bypassing the helper**; option (a), an app-bound key, is recommended for review;
- the D-42 removal wording;
- M2 criteria AC-15 to AC-18;
- the Mermaid installation plan.

Not recorded: D-39 to D-44. Not implemented: D-39. Not installed: anything.

| Check | Result (2026-11-09) |
|---|---|
| `pytest` (full) | **660 passed, 0 failed, 0 warnings** |
| Mutation baseline | engine exit 0 (54.2 s), license exit 0 (1.4 s) |
| Mutation campaign, catalogue `b356969a04f703a0…` | **156 caught, 0 survived, 0 invalid, 0 infra-failed** (127 engine, 29 license). The first run flagged one re-anchored mutant as `invalid` (lost indentation); it was fixed and the full campaign re-run |
| `ruff check`, `ruff format --check` (60 files), `mypy --strict` (34 files plus 2 scripts), `uv build`, `license_audit.py check --strict` | passed |
| Doc and diagram structural check | PASS (no rendering) |

**The architecture is NOT frozen.** Production signing stays disabled.

## Session 18: Secure Enclave key-boundary review SE-01 (2026-11-09)

New: `docs/architecture/secure-enclave-boundary-review.md`. It is analysis only: no code, decisions or keys were changed or used, and no network access was used.

**Verified from local SDK headers and the source:**
- the operator key is a CryptoKit `dataRepresentation` handle stored in the user-readable state folder, not a keychain item;
- `SecAccessControl` has no code-identity flag;
- `.userPresence` accepts the device passcode;
- keychain access groups (entitlement-based, data-protection keychain) are the only documented code-binding mechanism.

**Recommendation for decision:** design A, a Developer ID-entitled helper with an access-group-bound Secure Enclave key and no handle on disk, conditional on hardware tests SE-H1 to SE-H8. B (a signing service) adds little because the client is Python. C1 (FIDO2) signs blind and fails D-33's display rule.

**Waiting on the operator:**
- the choice of A, B or C;
- `.userPresence` or `.biometryCurrentSet`;
- whether to run SE-H1 first;
- the Developer Program step (the host has only an Apple Development identity).

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 19: SE-H1 and Design A feasibility (2026-11-09)

New:
- the test-only kit `native/macos/se-boundary-tests/`;
- the evidence file `docs/m1/evidence/se-h1-raw.txt`;
- the report `docs/architecture/secure-enclave-design-a-feasibility.md`.

Only disposable keys and directories were used, and both were removed (verified). No production key exists.

- **SE-H1: FAIL** (current design). An independently built ad-hoc program loaded a copied key handle, showed attacker-written dialog text, and got a P-256 signature over its own payload. The signature verifies against the throwaway public key, and a tampered control fails.
- **Design A probes:**
  - an unentitled program can't create or look up an access-group Secure Enclave key (`-34018`);
  - a self-claimed `keychain-access-groups` entitlement gets the process killed (exit 137).
- **Design A same-user isolation: INCONCLUSIVE.** It couldn't be tested without a provisioned, entitled build. Open questions U-1 to U-7 include the dialog observations, which the operator didn't record.
- The revised Design A covers keychain access groups, `.biometryCurrentSet`, a code-signing-requirement pin and D-39 display. It is **not implemented**. Production signing stays disabled. **The architecture is NOT frozen.**

## Session 20: Design A feasibility, round 2 (2026-11-09)

This round tested local signing with the existing Apple Development identity (team `<TEAM-ID>`). There are no provisioning profiles on the host, and everything ran in a disposable directory, which was removed. No network access was used and nothing was purchased.

- **Probes:**
  - team-signed without entitlements gets `-34018`;
  - team-signed while claiming `keychain-access-groups`, with or without the application and team identifiers but without a profile, gets the process **killed (exit 137)**;
  - **a provisioning profile is the gate.**
- **New finding U-8:** codesign used the team identity **without a prompt** from the agent session. A same-user attacker can sign its own binaries as the operator's team, which is expected to defeat Design A's code-identity boundary unless signing is moved off-host (test T-07).
- The test matrix T-01 to T-19 records 5 tests done locally, plus the ones that need a profile, D-39 or paid Developer ID.
- **Verdict: INCONCLUSIVE.** Recommendation: Design A amended with off-host signing. **Next, if approved:** a one-time Xcode network sign-in to check whether a free development profile with an access group is possible.

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 21: signing trust architecture review SE-02 (2026-11-09)

New: `docs/architecture/signing-trust-architecture.md`. The feasibility report is updated with round 3 (U-8 and the revised Design A assessment: not approved for implementation). Analysis only.

**Host facts:**
- the daily account is an **administrator**;
- a separate admin account exists;
- sudo needs a password, and Touch ID for sudo is off;
- FileVault and SIP are on.

**Comparison:**
- **A (off-host code signing):** needs no signing credential on the Mac, release authorisation against CI and repository abuse, and no root compromise.
- **B (separate account):** its boundary falls if the admin password is phished.
- **C (separate signing device):** strongest, and needs no Apple programme if the device is a Mac.

**Recommendation for decision:** C, a dedicated second Mac signer with D-39 full display and `.biometryCurrentSet`. B only as an interim, with a non-admin daily account. Five operator decisions are listed in the review.

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 22: separate signing device design SE-03 (2026-11-09)

New: `docs/architecture/separate-signing-device-design.md`. `signing-trust-architecture.md` §11 records the selected direction: Architecture C, conditionally approved. Design only: no code, keys, account changes, purchases or network access.

**Contents:**
- component architecture;
- a threat model with the DM fully compromised, and the honest limit that the DM's own verdicts can't be trusted;
- the request and response envelope protocol: canonical, no display fields, SD-side replay ledger and trust mirror;
- the QR and removable-media flows;
- the key lifecycle, with recovery through an offline FIDO2 key used through the SD's display;
- full-window display with scroll-to-approve and Touch ID;
- SD provisioning, and source-reviewed builds on the SD;
- **hardware tests SD-T01 to SD-T18**;
- the daily-account demotion assessment;
- the Apple Development identity audit: Sentinel doesn't use it.

**Open items:**
- per-key permitted actions;
- the FIDO2 dependency review;
- reading the response QR on the DM;
- the QR size limit (SD-T05).

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 23: signing device design, round 2, and protocol v1 (2026-11-09)

New: `docs/architecture/signing-protocol-v1.md`. `separate-signing-device-design.md` gains a round-2 revision. Design only: no code, keys, dependencies, account changes or network access.

**Protocol:**
- canonical request, response and public-key artifacts with exact key sets;
- USB-first layout, file names and size limits;
- read-only intake through `O_NOFOLLOW` and `fstat`, copied to a private spool (no TOCTOU);
- symlink, hard-link and special-file refusal;
- atomic output with `O_EXCL` and `rename`;
- replay and duplicate handling;
- hash-chained audit records on the SD.

**Design:**
- an authoritative SD registry; the SD computes the expected DM trust fingerprint itself; trust-store audit;
- per-key roles and permitted actions (proposed **D-45**), with the recovery key limited to enrolling a replacement key and revoking other keys;
- FIDO2 options F-1 to F-4 (investigation only; WebAuthn assertion format; ES256 vs D-38);
- the field-by-field display contract;
- a trusted update process with independent provenance, review on the SD, local build and Touch ID-approved replacement with rollback;
- the exact 12-step first-enrolment ceremony;
- **tests SD-T19 to SD-T42**.

**Decisions requested:** O-P1, D-45, the recovery format and library, exFAT, `signer.release`, and the registry commit.

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 24: signing protocol decisions applied, round 3 (2026-11-09)

Updated `signing-protocol-v1.md` (§R3), `separate-signing-device-design.md` (round 3) and `signing-trust-architecture.md` (§12, the proposed wording for D-45 and the D-38 amendment, **not recorded**). Design only.

**Applied:**
- refusals give no response (O-P1); APFS only, with an intake threat model; fail-closed rules for timeouts and interrupted transfers;
- **recovery as ES256 WebAuthn assertions:** a domain-separated challenge over the canonical payload, a 9-step verification, and a separate engine path;
- recovery enrolment and revocation rules (the replacement key is generated and verified on the SD; no self-revocation);
- `signer.release` records signed by the SD key, with rollback by signed record;
- the registry state machine (IDLE, PENDING, COMMITTED, ABANDONING; no automatic transitions);
- **AuthenticationServices:** the API exists (macOS 12+, challenge, raw authenticator data, client data and signature) [V-SDK]; whether it needs Associated Domains or provisioning is unknown, so the offline test SD-T35 decides; a libfido2 review outline is ready;
- tests updated, plus SD-T43 to SD-T50;
- open decisions OD-1 to OD-6.

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 25: signing protocol final review, round 4 (2026-11-09)

New: `docs/architecture/signing-protocol-final-review.md`. Analysis and final proposed wording only: no code, keys, dependencies or network access, and **nothing recorded**.

- **WebAuthn:** the AuthenticationServices API exists [V-SDK]. Whether `sentinel-recovery.invalid` works offline is **unknown**; no live probe was run, because it could reach Apple's domain-association service. The offline test SD-T35a decides; libfido2 (SD-T35b) is the fallback. The strict client-data, origin and rpId table is never relaxed. Offline verification is pure computation.
- **Counter policy:** the mode is fixed at the ceremony; rollback, equal or reset counts are rejected and the key marked `suspect`; zero-counter authenticators are accepted, with the residual documented.
- **Signed registry checkpoint** (proposed **D-46**): stored on a dedicated drive with the recovery key; restore is anchored by the paper fingerprint plus the paper sequence and hash (no rollback).
- **Release provenance:** a genesis full review on the SD plus diff-review chain; external commit IDs are advisory.
- Final wording for D-45, the D-38 amendment, OD-2 to OD-6 and D-46.
- Remaining hardware tests: SD-T35a/b, SD-T36, SD-T51 to SD-T55, plus SD-T01 to SD-T50.

Production signing stays disabled. **The architecture is NOT frozen.**

## Session 26: signing decisions recorded (2026-11-09)

**D-46 strengthened** per the owner's correction, in the final review §5 and the protocol pointer:
- explicit confirmation for every checkpoint;
- the sequence and full hash displayed;
- the paper anchor (with re-typed hash) is part of the ceremony;
- any anchor mismatch refuses restoration;
- no automatic restore;
- replay and pending state preserved;
- no rollback, revocation reversal, suspect clearing or counter decrease.

**Decision register** (`docs/architecture-discovery-plan.md`; unstaged edits only, the staged index is unchanged):
- **added:** a D-39–D-44 *reserved* row (proposals not in force), **D-45**, **D-46**, **D-47** (amends D-38), and §4.1 **OD-2 to OD-6**;
- D-38's notes gained "Amended by D-47"; its text is unchanged, because the register changes only by new entries;
- the status line is updated.

**Cross-references:** `discovery.md` §11 (signature row), §13.7 (D-47 pointer) and §17.1 (two rows); "Recorded" notes appended to the four signing documents.

**Validation:**
- the structural doc and diagram check passes: 41 register rows (D-01 to D-38 and D-45 to D-47), reserved D-39 to D-44, all references resolve, 8 Mermaid blocks balanced;
- the checker was fixed for an `SD-T` false positive, and proposed AC-15 to AC-18 are allowed only in proposal documents;
- `pytest`: 660 passed.

**Not done:**
- the signing device isn't implemented;
- no diagram shows the signing device (there's no contradiction, but none is rendered either);
- hardware tests SD-T01 to SD-T55 are outstanding.

**The architecture is NOT frozen.**

## Session 27: diagrams rendered; freeze checklist (2026-11-09)

**Rendering:**
- No `mmdc` is installed. The locally installed **Mermaid 11.11.0** bundled with Goodnotes (Mac App Store, notarised) was run in **headless Microsoft Edge**, offline: name resolution blocked, a dummy proxy, local files only. Nothing was downloaded or installed.
- All 8 original diagrams rendered `RENDER_OK` and were inspected. Diagram 1's engine title is partly covered by a node, and diagram 4 has two overlapping label pairs; both are readable and pre-existing.

**Diagram updates:**
- Diagram 1 now shows the separate signing Mac with a USB-only data path.
- New `discovery.md` §11.4 adds three diagrams: the signing trust-boundary flowchart (DM, USB boundary, signing Mac, offline custody, operator and recovery keys, checkpoint and paper anchor), the registry state machine, and the checkpoint-ceremony sequence.
- Rendering caught a defect the structural checker missed (a `;` in a state-diagram note split it into stray states). It's fixed, and the checker now detects it (negative test confirmed).

**New tooling:**
- `scripts/docs/render_mermaid.py` (reproducible offline render);
- `scripts/docs/check_architecture_docs.py` (the structural and reference checker, moved into the repository);
- the render manifest `docs/architecture/evidence/diagram-render-manifest.json`.

**Validation:**
- checker PASS: 41 register rows, reserved D-39 to D-44, 11 diagrams balanced, all references resolve;
- 11 of 11 `RENDER_OK`;
- `pytest`: 660 passed;
- Ruff and format (62 files), `mypy --strict` and `license_audit --strict`: clean.

**Freeze checklist:** `freeze-review.md` §10 marks each item PASS, OPEN or ACCEPTED. Open: the D-40 to D-44 recordings, the D-39 withdrawal, the C-a status line, AC-15 to AC-18 approval, and the freeze approval.

**The architecture is NOT frozen.**

## Session 28: AFR-01 remediation completed (2026-11-09)

**Decision register (append-only):**
- **D-39 withdrawn** (obsolete; superseded by D-47);
- **D-40** canonical JSON only, with schemas mandatory in M1;
- **D-41** agent versions set per integration, with compatibility checks;
- **D-42** `allowlist.change` removed;
- **D-43** third-party authority refused in V1;
- **D-44** the tty check isn't presence (accepted residual);
- forward pointers added to D-01, D-16, D-23, D-27, D-33, D-36 and D-37, and to the reserved row. No existing decision text changed.

**`discovery.md`:**
- the status line is factual (C-a);
- cross-references to D-40 to D-44, with `allowlist.change` struck through in §11.3, §11.3.1 and §11.3.2;
- **AC-15 to AC-18 are mandatory M2 exit criteria** (zero raw PII; zero live secrets labelled `test`; cancel within 10 s; no file of a deleted run remains), added to the §16 M2 row.

**`freeze-review.md` §11:** the final readiness report. **No reviewer-side OPEN conditions remain;** only the operator's freeze approval does, with a revised §11.5 statement. Signing is **decided, not implemented and not hardware-validated.**

| Check | Result |
|---|---|
| Structural and reference checker | PASS: 47 register rows; AC-01 to AC-18; 11 diagrams |
| Diagram renders | 11 of 11 `RENDER_OK` (Mermaid 11.11.0, local, offline) |
| `pytest` | 660 passed |
| Ruff, format (62 files), `mypy --strict` (34 files plus 2 scripts) | clean |
| Mutation campaign (catalogue `b356969a04f703a0`) | baseline engine 59.2 s and license 1.5 s, both exit 0; **156 caught, 0 survived, 0 invalid, 0 infra-failed** |
| `license_audit check --strict` | 0 issues |
| Git index | unchanged (staged-diff and index hashes identical before and after) |

**The architecture is NOT frozen.**

## Session 29: architecture freeze recorded (2026-11-09)

The owner approved the freeze (freeze-review §11.5). It is recorded as **D-48** in the decision register, appended; no existing decision was rewritten.

**Updated:**
- the register status line;
- `discovery.md`: the status line, the §17.1 row and its closing line;
- `freeze-review.md` §12;
- dated freeze notes in the four signing documents.

**Not covered by the freeze:** M1 completion, production signing, any waiver of AC-15 to AC-18, any waiver of hardware tests SD-T01 to SD-T55, and any weakening of controls.

**Checks:** checker PASS (48 register rows); `pytest` 660 passed; Git index unchanged.

## Session 30: M1 scope clarifications recorded (2026-11-09)

New dated entries **D-49** and **D-50** in the decision register; no existing text was rewritten. Forward pointers were added to D-11, D-12, D-45, D-47 and D-48, and the `discovery.md` M1 row points to them.

- **D-49:** M1 delivers the engine side only: D-45 roles and permissions, trust-store fingerprint and permission verification, the separate D-47 WebAuthn verifier, request emit and response receive, and test-key fixtures. The signing Mac, the hardware, the ceremonies, SD-T01 to SD-T55 and activation form a separate milestone. AC-11 is test-key evidence only, never hardware validation.
- **D-50:** M1 `fix-plan` is read-only and deterministic, uses only a verified run, produces a schema-validated plan with finding and evidence references, and never applies or promotes anything. M9 completes the full report.

## Session 31: M1 task 1, `ALLOWLIST_CHANGE` removed (D-42) (2026-11-09)

**Changed:**
- `domain/enums.py`: the enum member is removed; the docstring now says eight actions.
- `approvals.py`:
  - the D-37 maximum for `allowlist.change` is removed;
  - **new load-time checks in `Approval.from_json`:** the action must be one of the defined actions, and the context must equal that action's context (`ValidationError` otherwise).
- `prepare.py`: docstring only. There was no preparation branch; the `allowlist-change` kind was never in `KINDS`.
- **Tests:**
  - `test_foundation.py`: 8 actions;
  - `test_approvals.py`: the D-37 table without allowlist; the scope test now uses `policy.change`; 19 new D-42 tests (load rejection, file-load rejection, never verifying as any of the 8 actions, a foreign context, every defined action still loading);
  - `test_authorization_policy.py`: adapter-allowlist changes apply only under `policy.change`, and suppress, accept-risk and authorise approvals are refused (`wrong_context`).
- **Mutation catalogue:** 2 new mutants.

**Results:**

| Check | Result |
|---|---|
| `pytest` | **679 passed** (19 new) |
| Ruff, format (62 files), `mypy --strict` (34 files plus 2 scripts), `license_audit --strict`, docs checker | clean |
| Mutation campaign (catalogue `9c54b5decb2cbf29`) | baseline engine 70.7 s and license 8.0 s, both exit 0; **158 caught, 0 survived, 0 invalid, 0 infra-failed** (129 engine, 29 license). Both new D-42 mutants are caught by their intended tests |
| Git index | unchanged |

**Acceptance: met.**

## Session 32: M1 task 2, versioned JSON Schemas (D-40) (2026-11-09)

**Changed (summary; details in `docs/m1/schemas.md`):**
- **Contracts and validator:** 19 contracts and the in-house validator `src/sentinel/schema.py`.
- **Validation order:** every input runs **strict decoding → schema → domain**.
  - Policy files are schema-checked before approval verification, nonce consumption or any state write.
  - Run manifests are schema-checked before signature verification.
  - Stored results are schema-checked before the manifest comparison.
  - Approval error classifications are preserved by an explicit mapping.
- **Raw CLI output:** `_raw` stdout and `report --output` are contract-checked. JSON bodies use `audit-result`, SARIF bodies use `sarif-profile`, and Markdown/HTML bodies must not be JSON.
- **Run-key creation order:** the run-key metadata is now contract-checked *before* the secret seed is stored. Previously the seed was stored first. The mutation campaign found this.
- **Legacy key format removed (operator-approved):** `handle_b64` Secure Enclave key files are refused with `legacy_key_format`, and the handle is never decoded or stored. The conversion procedure is in `docs/m1/schemas.md`.
- **Mutation harness integrity:**
  - Mutant runs deselect the catalogue anchor meta-test.
  - `classify` counts a mutant as caught only on a behavioural test failure; an anchor-only failure is `infra_failed`.
  - The baseline still runs the meta-test.
  - A read-only macOS session preflight (`ioreg`, `CGSSessionScreenIsLocked`) runs before the baseline and again after the campaign, and returns `environment_unsuitable` (exit 5) if the session is locked or can't be confirmed unlocked.
  - Regression tests cover all of this.
- **Catalogue:** 222 mutants. `eng-d40-regex-ascii` was removed as an equivalent mutant (see the catalogue docstring). `eng-d40-legacy-key-format-refused` was added.

**Mutation history audit.** Every campaign recorded before this session counted the catalogue meta-test as a catch. The figures below are anchor-only catches, out of the total reported:

| Campaign | Anchor-only catches |
|---|---|
| Catalogue `8ef65b45` | 43 of 138 |
| Catalogue `274f2b3f` | 43 of 147 |
| Catalogue `5bc7568e` | 48 of 156 |
| Catalogue `b356969a` | 48 of 156 |
| **Task 1, catalogue `9c54b5de`** | **48 of 158** |

Those historical results are **not valid** as reported. The 48 mutants affected in Task 1 are:

- `eng-admin-*` (4)
- `eng-aud-16-*` (3)
- `eng-dec-*` (3)
- `eng-helper-*` (4)
- `eng-orch-*` (4)
- `eng-red-*` (13)
- `eng-se-*` (12)
- `eng-x5-*` (5)

All 48, and every other mutant, were re-run in this session's campaign with the corrected harness, and **all are caught behaviourally**. That campaign independently supersedes every earlier result, so no further re-run is needed.

**Final verification (session confirmed unlocked before and after the campaign):**

| Check | Result |
|---|---|
| `pytest`, Secure Enclave hardware test included | **1092 passed** |
| Ruff, format, `mypy --strict` (src plus the mutation scripts) | clean |
| `license_audit --strict`, docs checker | clean |
| Wheel and sdist (`test_schema_distribution.py`) | all 19 schemas present and byte-identical; installed-wheel load under `-I` |
| Historical `SHA256SUMS` and signature verification (`test_schemas.py`) | all OK |
| Mutation campaign, catalogue `edbaf3ab` | baseline engine 58.3 s and license 1.4 s, both exit 0. **Behavioural: 222 caught (193 engine, 29 license), 0 survived. Invalid: 0. Infrastructure-failed: 0. Anchor-only: 0.** Four `eng-helper-*` mutants are caught only by the real-helper hardware tests, which is expected for helper-backend checks |
| Git index | unchanged (`c1a18d46…` / `e0cdc1fa…`) |

**Acceptance: all approved criteria verified; awaiting operator review.** The official JSON Schema Test Suite is still pending separate approval.

## Session 33: M1 tasks 3 to 12 (2026-11-09)

Everything is summarised in `docs/m1/m1-completion-report.md`.

**Final verification:** run while the session was confirmed unlocked before and after the mutation campaign.

- **`pytest`:** all 1226 tests pass, including the Secure Enclave hardware tests.
- **Mutation campaign** (catalogue `ef7fb375`, 278 mutants):
  - 278 caught by behavioural test failures (249 engine, 29 license);
  - 0 survived, 0 invalid, 0 infrastructure-failed, 0 anchor-only.
- **Static and licence gates:** Ruff, format, `mypy --strict`, `license_audit --strict` and the docs checker are clean.
- **Wheel, sdist and historical evidence:** all 24 contracts and both Skills are present, the historical hashes match and the signatures verify.
- **Git index:** unchanged.

## Session 34: M1 closure (2026-11-09)

**Changes:**
- D-47: operator keys are P-256 only; Ed25519 is refused on every operator path, with negative tests.
- D-51 (minimum agent versions) appended to the register.
- SA-08 fixed.
- 5 mutants added.

**Final results (session confirmed unlocked):**
- **`pytest`:** 1234 passed, 0 failed, 0 skipped. This includes the 46 Secure Enclave helper tests.
- **Mutation campaign** (catalogue `55b4907f`): 282 of 282 caught by behavioural test failures, with 0 survived, 0 invalid, 0 infrastructure-failed and 0 anchor-only.
- **All static, licence, documentation, packaging and historical-integrity gates** are clean.
- **Git index:** unchanged.
- **Remote CI:** unverified.

See `docs/m1/m1-completion-report.md`.

## Session 35: M1 accepted (2026-11-09)

**The owner accepted M1 as software-complete** on the basis of `docs/m1/m1-completion-report.md`. That report is the **baseline record**: its results and limitations are preserved and must not be regenerated or rewritten without a specific reason.

Still outstanding, and not part of M1 acceptance:
- **Remote CI:** not yet executed, because there is no commit or remote.
- **Hardware validation:** SD-T01 to SD-T55, physical FIDO2 recovery and the first-enrolment ceremony.
- **Production signing:** stays disabled.
- **Official JSON Schema Test Suite:** pending separate approval.

The project working rules are in `CLAUDE.md` at the repository root.

**Next:** M2 scope and acceptance criteria are presented for owner approval. M2 implementation does not start before that approval.

## Session 36: M2 implementation (2026-11-09)

M2 scope and conditions are recorded as D-52 to D-57, with details in `docs/m2/scope.md`. Every deliverable is implemented and has its own tests, using test-only fake runners for the adapters.

The consolidated M2 audit, the final verification and the mutation campaign wait for the approved downloads (`docs/m2/acquisition-request.md`), so that real-scanner AC-02 and AC-03 runs are part of the single final cycle.

## Session 37: M2 closure (2026-11-09)

The approved dependencies are installed and verified, and all four real scanners are integrated under rootless Podman and Seatbelt.

**Final results:**
- **`pytest`:** 1375 passed, 0 skipped.
- **Mutation campaign:** 340 of 340 mutants caught.
- **All gates:** clean.
- **Git index:** unchanged.

**Verified residual risk:** Podman Machine host shares are writable from inside the VM (M2-SA-12).

See `docs/m2/m2-completion-report.md`.

## Session 38: M2 accepted (2026-11-09)

The owner accepted M2 as complete. `docs/m2/m2-completion-report.md` is the M2 baseline record; it is preserved unchanged.

**Still visible and still open:**
- **M2-SA-12:** the Podman Machine host shares are writable from inside the VM, so the VM is not a read-only host boundary. B2 and A1 stay `NOT_RUN`.
- **CLI use of real scanners:** needs a signed `policy.change`, and production signing is disabled.
- **Not yet run:** the Linux scanner paths and remote CI.
- **OSV data:** there is no publisher signature.
- **Podman Machine image:** pinned only by its recorded digest.
- **Hardware tests:** SD-T01 to SD-T55 are outstanding.

**Next:** the M3 scope and acceptance criteria are presented for owner approval. M3 implementation doesn't start before that approval.

## Session 39: M3 implementation (2026-11-09)

The M3 scope is recorded as D-58 to D-63 (`docs/m3/scope.md`). These are implemented:
- the domain modules and rules;
- the Trivy, Checkov and Grype adapters;
- D-29 snapshot pinning;
- deduplication with provenance;
- 80 fixtures;
- the measurement harness.

**Preliminary real measurement** (Semgrep, OSV-Scanner and Syft only; Checkov, Trivy and Grype not installed):

| Domain | Recall | False positives |
|---|---|---|
| D01 | 1.0 | 0 |
| D02 | 1.0 | 0 |
| D08 | 0.85 | — |
| D14 | 0.82 | — |

- The D08 and D14 misses were all Checkov-designated issues; Checkov isn't installed yet.
- One clean fixture turned out to contain a genuinely vulnerable dependency (requests 2.32.4, CVE-2026-25645) and was corrected.
- These figures are preliminary, not acceptance evidence.

The downloads in `docs/m3/acquisition-request.md` await approval.


## Session 40: overnight M4 to M10 implementation (2026-11-09)

- Native static analyzers (stdlib only, hash-allowlisted, Seatbelt-only) for:
  - Android and iOS (M4);
  - OS configuration (M5);
  - extensions (M6, D10);
  - AI agents and MCP, with the T2 fixture set (M7, D11);
  - supply chain (M8).
- Pinned, sandboxed plugin system (M6) and MCP stdio server (M7).
- Run comparison and remediation tracking (M9).
- Installed-package self-check and SHA256SUMS (M10).
- Report: `docs/roadmap/m3-m10-implementation-report.md`. Resume point and blocked items B-1 to B-8: `docs/roadmap/overnight-progress.md`.
- Nothing is accepted; nothing was downloaded, staged or committed.

## Remaining M1 work

Updated 2026-11-09 (session 33). Order and scope per the M1 checklist, D-49 and D-50. Earlier versions of this table are superseded.

| # | Area | Status |
|---|---|---|
| 1 | Remove `ALLOWLIST_CHANGE` (D-42) | **Done (session 31)** |
| 2 | Versioned JSON Schemas and validation (D-40) | **Done; accepted (session 32)** |
| 3 | Engine-side operator-signing infrastructure (D-49: D-45 roles and permissions, D-47 WebAuthn verifier, request emit and response receive, test-key fixtures) | **Done (session 33)** |
| 4 | `fix-plan`, read-only (D-50) | **Done (session 33)** |
| 5 | Claude Code integration (D-41 compatibility check) | **Done (session 33); minimum 2.1.317** |
| 6 | Codex integration (D-41) | **Done (session 33); minimum 0.162.1** |
| 7 | Engine CI workflow (macOS and Linux) | **Done (session 33)**: `engine-ci.yml`; actions pinned by commit |
| 8 | First remote CI run | **Blocked:** no commit and no remote; needs operator approval |
| 9 | Security self-audit and findings review | **Done (session 33)**: `docs/m1/security-audit.md` |
| 10 | User documentation (installation, CLI, configuration, environments, limitations) | **Done (session 33)**: `docs/user/` |
| 11 | Release preparation (artifact inspection, licensing of real artifacts, metadata, changelog, hashes, checklist) | **Done (session 33)**: `CHANGELOG.md`, `docs/m1/release-checklist.md` |
| 12 | M1 completion report | **Done (session 33)**: `docs/m1/m1-completion-report.md`; awaiting owner acceptance |
| — | Signing device, Secure Enclave and FIDO2 hardware, SD-T01 to SD-T55, activation | **Outside M1** (D-49), a separate milestone; production signing disabled |
| — | The old Secure Enclave helper (handle on disk) | **Rejected** (SE-H1 FAIL); superseded by D-47 |
| — | Linux native sandbox, containers and VMs; PII detection | M2 and later (AC-15 to AC-18 are mandatory M2 criteria) |

## Blockers

1. ~~Operator user presence (D-16 vs host).~~ **Resolved by D-38 (2026-11-08).** The Python side exists (session 5); the native helper is still to be built and hardware-tested, and operator approvals fail closed until it is.
2. **Architecture freeze approval** is still outstanding: the diagrams haven't been rendered and the owner hasn't given the explicit freeze approval.
