# M1 completion report

**Date:** 2026-11-09 (closure run).

**Status:**
- **M1 implementation and local verification are complete**, within D-48, D-49, D-50 and D-51, and the report awaits owner acceptance.
- **Production operator signing is disabled.** Remote CI is **unverified**.
- Nothing has been staged, committed, pushed or published.

## 1. Scope delivered

| # | M1 item | Result |
|---|---|---|
| 1 | Remove `ALLOWLIST_CHANGE` (D-42) | Done (accepted) |
| 2 | Versioned JSON Schemas and validation (D-40) | Done (accepted); 24 contracts |
| 3 | Engine-side operator signing (D-49): D-45 roles and permissions, fingerprint, D-47 recovery verifier, protocol-v1 request and receive, test-key fixtures | Done |
| 4 | Read-only `fix-plan` (D-50) | Done |
| 5, 6 | Claude Code and Codex Skills with the D-41 check | Done; minimum versions recorded as **D-51** |
| 7 | Engine CI workflow (macOS and Linux) | Done; **never run remotely** (§5) |
| 8 | First remote CI run | **Not done: needs your authorisation for a commit and a remote** |
| 9 | Security self-audit | Done; final closure audit included (§3) |
| 10 | User documentation | Done: `docs/user/` |
| 11 | Release preparation | Done: `CHANGELOG.md`, `docs/m1/release-checklist.md`, hashes (§2.4) |
| 12 | Completion report | This document |

**Closure changes in this run:**
- **D-47, P-256 only:** Ed25519 operator keys are refused everywhere. Test fixtures are P-256 software keys under `tests/`, and there is no production switch.
- **D-51 appended** to the decision register: existing rows unchanged (diff: 0 lines removed), and the docs checker extended.
- **SA-08 fixed:** symlinked-directory cleanup.
- **5 new mutants**, for 282 in total.

## 2. Actual results

The session was confirmed unlocked by the read-only `ioreg` preflight before and after the mutation campaign.

### 2.1 Tests

| Run | Result |
|---|---|
| Full `pytest` (`-p no:randomly -rs`), Secure Enclave hardware tests **included** | **1234 passed, 0 failed, 0 skipped**, 69.9 s |
| Of these: Secure Enclave helper tests on this Mac (unlocked session, a real Secure Enclave) | 46 passed |

### 2.2 Mutation campaign (corrected harness)

| Item | Value |
|---|---|
| Catalogue | `55b4907f8188f757…`, 282 mutants, including every M1 mutant |
| Baseline | engine exit 0 (61.8 s); license exit 0 (2.2 s) |
| **Behavioural catches** | **282** (253 engine, 29 license) |
| Survived | **0** |
| Invalid | **0** |
| Infrastructure-failed | **0** |
| Anchor-only (catalogue meta-test) catches | **0** (excluded by design) |

Four `eng-helper-*` mutants are caught only by the real Secure Enclave helper tests. That's expected for checks in the helper backend.

**History:** campaigns recorded before session 32, including Task 1's 158/158, contained 43 to 48 anchor-only catches each. They are **not valid** as reported. This campaign supersedes them.

### 2.3 Static, licence, documentation and integrity gates

| Check | Result |
|---|---|
| Ruff / format | clean / 113 files formatted |
| `mypy --strict` (src and the mutation scripts) | clean, 41 files |
| `license_audit.py check --strict` | 3 runtime, 6 build, 12 dev packages; 0 issues |
| Architecture docs checker | PASS (register D-01 to D-51 in order) |
| Wheel and sdist build (`uv build --offline`) | built |
| Installed-package check | the wheel installed with `--no-deps` into a temporary target loads all 24 contracts under `python -I`; both Skills are byte-identical in the wheel |
| Historical integrity | `SHA256SUMS`: all OK; every historical signature verifies |
| Git index | unchanged: `c1a18d46…` (`git diff --cached`) and `e0cdc1fa…` (`git ls-files -s`) |

### 2.4 Artifacts of this build (not published)

| File | SHA-256 |
|---|---|
| `sentinel_audit-0.1.0.dev1-py3-none-any.whl` | `38fb4ca3fc05405222ee9bab32b0fb091f5e660fd89563baad597611acfdb719` |
| `sentinel_audit-0.1.0.dev1.tar.gz` | `5a70dbb283503f40438d1acf9e7a1442b64df6b6bd7996ea9a0a378351e4e510` |

## 3. Security audit findings and fixes

Full record: `docs/m1/security-audit.md`.

| ID | Finding | Status |
|---|---|---|
| SA-01 | Listing and inspection showed raw signatures by recovery-role keys as valid | Fixed |
| SA-02 | CI actions pinned to moving tags; checkout kept its credentials | Fixed (commit SHAs; `persist-credentials: false`) |
| SA-03 | Run-key seed stored before its metadata contract check | Fixed |
| SA-04 | Mutation harness counted anchor-only failures as catches | Fixed; history invalidated |
| SA-05 | Harness unit tests depended on the host's lock state | Fixed |
| SA-06 | Nine new defences not pinned by tests | Fixed (targeted tests) |
| SA-07 | Ed25519 operator keys accepted, contrary to D-47 | **Fixed:** P-256 only, with negative tests (`tests/test_d47_p256_only.py`) |
| SA-08 | `approval receive` cleanup could follow a symlinked `to-signer` directory | Fixed |

The final closure audit covered the whole engine, the Skills, CI, the harness and D-51. It found no further issues; scope and method are in the audit record.

## 4. Hardware tests not performed

**None of the following is validated. The software fixtures in `tests/signing_fixtures.py` prove engine-side enforcement only.**

- The dedicated signing device (signing Mac) and `sentinel-signer`: not implemented in M1 (D-49).
- Secure Enclave operator signing with `.biometryCurrentSet` and no passcode fallback, on the signing device.
- Biometric user presence for operator approvals.
- Physical FIDO2 recovery authenticators, platform WebAuthn API behaviour, and the recovery ceremonies.
- Registry checkpoints (D-46) and the paper-anchor ceremony.
- APFS read-only intake on the signing device (SD-T22 to SD-T26).
- Hardware tests **SD-T01 to SD-T55** (including SD-T35a/b) and the first-enrolment ceremony.
- Production activation, which needs a separate decision.

The only hardware exercised was this Mac's Secure Enclave, through the native helper tests: 46 passed with the session unlocked. Those tests cover the helper's behaviour, not the signing-device design.

## 5. Remote CI status

**Unverified.** `engine-ci.yml` (macOS 14 and Ubuntu 24.04) and `license-gate.yml` exist, are pinned by commit and are structurally tested (`tests/test_ci_workflow.py`). Neither has run on a remote runner. There is no commit and no remote, and both wait on your authorisation.

## 6. Remaining limitations and residual risks

**Limitations** (`docs/user/limitations.md`):
- No real scanners; only the fixture adapter.
- Production signing is disabled.
- There is no Linux native sandbox: checks that need isolation are `BLOCKED`.
- `fix-plan` is read-only; the remediation workflow is M9.
- Red-team mode and `B3` are excluded.

**Residual risks** (`docs/m1/security-audit.md`):

| ID | Risk |
|---|---|
| R-1 | The state directory, trust store, ledger and pending requests are writable by the same macOS user (AUD-05). The development Mac's recovery counters are untrusted |
| R-2 | Resolved by SA-07. An installation with an Ed25519 operator key must enrol a P-256 key; there is no automatic migration |
| R-3 | The D-41/D-51 agent version is self-reported: a compatibility gate, not a security control |
| R-4 | Replaying an old valid recovery assertion marks the key `suspect` (OD-3), a denial-of-service avenue for anyone who can write to the transfer volume |
| R-5 | Run-manifest signatures prove integrity relative to the run key only (D-34) |
| R-6 | No hardware validation of operator presence, Secure Enclave access control or FIDO2 (§4) |
| R-7 | Pre-D-45 trust stores change fingerprint when rewritten in explicit form; key-operation approvals bound to the old fingerprint fail closed |
| R-8 | The mutation campaign and the Secure Enclave tests need an unlocked macOS session; they can't run unattended on a locked host |

## 7. M1 acceptance criteria status

The frozen M1 row: "Schemas validate; AC-09, AC-10, AC-11, AC-14".

| Criterion | Status | Evidence |
|---|---|---|
| Schemas validate (D-40) | **Met** | 24 contracts; `test_schemas.py`, `test_schema_boundaries.py`, `test_schema_distribution.py`; historical corpus validates |
| AC-09: evidence hash and manifest signature verified on every read; tampering detected (excluding same-user re-signing, D-34) | **Met** | `test_evidence.py`, `test_pipeline.py`, `test_cli.py`, `test_fixplan.py::test_tampered_run_is_refused` |
| AC-10: every authorisation and scope fixture ends in `BLOCKED` | **Met** | `test_authorization_policy.py`, `test_pipeline.py`, `test_cli.py` |
| AC-11: zero trust-anchor actions accepted without a valid operator-presence signature (T16) | **Met at engine level only, with software test keys (D-49)** | `test_trust_admin.py`, `test_governance.py`, `test_d49_signing.py`, `test_d47_p256_only.py`. **This is not hardware validation of operator presence** |
| AC-14: every approval-misuse fixture rejected | **Met** | `test_approvals.py`, `test_d49_signing.py` (recovery path), `test_governance.py` |
| M1 deliverables: `fix-plan` (D-50); agent Skills with the D-41 check (D-51) | **Met** | `test_fixplan.py`, `test_integrations.py` |
| AC-15 to AC-18 | **Not M1:** mandatory M2 criteria | — |
| AC-01 to AC-08, AC-12, AC-13 | Not M1 exit gates. The existing T/R regression, read-only, no-false-PASS, redaction, report, T17 and D-26 tests all pass in the 1234-test run. AC-07 and AC-08 are provisional, set from M3 | — |

## 8. Owner decisions and actions

1. **Accept M1**, or return findings.
2. **Authorise a commit and a remote** for the first remote CI run (item 8). Until then, remote CI stays unverified.
3. **The JSON Schema Test Suite download** still awaits separate approval; nothing was downloaded.
4. **Before production activation:** the signing-device milestone (SD-T01 to SD-T55) and a recorded activation decision.
