# Sentinel M1: implementation audit of drafted modules

Audit date: 2026-11-08 (session 2). This covers about 2,000 lines drafted in an interrupted session without tests. Every module was read against the architecture (`docs/architecture/discovery.md`, D-01–D-38), its defects were fixed, and it now has tests.

**What this does not claim:**
- These are unit-level tests on synthetic fixtures. No module is integrated into an audit pipeline yet: the orchestrator, CLI and integrations are not built.
- Nothing here has been tested against a real OS keystore, the Secure Enclave or a real scanner.

## 1. Cryptographic implementation mapping (D-16, D-34, D-38)

| Role | Algorithm | Where the private key lives | Who can use it | Module |
|---|---|---|---|---|
| Run key | Ed25519 only | macOS login keychain via `/usr/bin/security`, or Linux Secret Service via `secret-tool`. The secret is passed on stdin, never argv | Any same-user process (by design, D-34) | `keys/runkey.py`, `crypto/signing.py` |
| Operator key | Ed25519, or ECDSA P-256 with SHA-256 (D-38) | Hardware-backed only: Secure Enclave P-256 with a user-presence ACL, or a FIDO2 authenticator. **Never in engine memory or on disk** | Only through a `PresenceProvider` after genuine user presence | `keys/operator.py` |
| Signature verification | The algorithm recorded per key in the trust store. No guessing from signature bytes | — | — | `crypto/signing.PublicKey.verify` |

**Status of D-38 in code:**
- Verification supports both operator algorithms, and both are tested.
- The trust store records each key's algorithm.
- The run-key verifier rejects any non-Ed25519 key.
- **The Secure Enclave signing helper is not implemented**, so `available_provider()` fails closed on every host. There is no software fallback.
- **Session 5:** the Python side of the Secure Enclave boundary (`keys/secure_enclave.py`) is implemented and tested against fake backends only. Fake backends are software keys and are never treated as hardware. No real Secure Enclave signature or user-presence prompt has been exercised.

**Context strings used for signatures:**
- `sentinel/v1/approval/<action>` (inside the payload)
- `sentinel/v1/run/manifest`
- `sentinel/v1/run/checkpoint`

A signature made for one purpose can't be presented as another, because the context is part of the signed bytes.

## 2. Module-by-module audit

Status words:
- **Fixed**: a defect was found and repaired.
- **OK**: no defect found.
- **Gap**: a known limitation that still applies.

| Module | Maps to | Findings | Status | Tests |
|---|---|---|---|---|
| `crypto/signing.py` | D-16, D-38 | AUD-01: Ed25519 only, so P-256 operator keys couldn't be verified. Rewritten to be algorithm-agile: key IDs bound to algorithm and key, point validation for P-256, a single verify path per declared algorithm | Fixed | `test_crypto_and_keys.py` (17 tests in the file, shared with keys) |
| `keys/runkey.py` | §11.2, D-34 | Dead helper removed. Backends pass secrets on stdin. A keystore mismatch or missing secret fails closed. **Gap:** the real macOS and Linux keystore backends are not exercised by tests (tests use a fake backend so they never write to the user's keychain) | Fixed / Gap | in `test_crypto_and_keys.py` |
| `keys/operator.py` | §11.2, D-27, D-38 | AUD-02: loose typing and incomplete validation of trust-store entries. Now: exact fields, allowed algorithms, status values, key-ID match, duplicate rejection. AUD-05 (**Gap, residual risk**): the trust store is same-user writable, so a same-user process could replace operator public keys. Mitigation: show the trust-store fingerprint in reports and prompts for out-of-band comparison (not yet wired up); hardware attestation is future work | Fixed / Gap | in `test_crypto_and_keys.py` |
| `approvals.py` | §11.3, D-33, D-36, D-37 | AUD-03: `from_json` didn't type-check fields, so malformed files crashed instead of being rejected. Now strict on types, nonce format and canonical encoding. AUD-04: revocation was unimplemented; added `apply_revocation` (one-time `revoke_record`, standing approvals only, persisted). Path typing fixed | Fixed | `test_approvals.py` (38) |
| `authorization.py` | §11, D-16, D-21, D-37 | AUD-06 (**security**): any non-empty `evidence_of_authority` string was accepted as authority over a third-party asset, so a signer could claim authority with free text. Now only the operator-approved policy's `owned_assets` establishes authority. Third-party authority is **not supported in M1** and fails closed. A redundant tautological check was removed, and timestamp and exclusion types are validated | Fixed | `test_authorization_policy.py` (31, with policy) |
| `policy.py` | D-07, D-19, D-21, D-25, D-27, D-35 | AUD-07: unknown or invalid limit keys raised `TypeError`, and allowlist and owned-asset types weren't validated. Now strict. The policy-change revision binds the previous file's hash (§11.3) | Fixed | same file |
| `evidence.py` | §6, R-11, R-13, R-14, D-18, D-34 | AUD-08: mypy found entries typed as `Any` from untrusted JSON. Now validated as objects. AUD-09: the verifier didn't require the run key to be Ed25519; it does now. The same-user re-signing limitation is **demonstrated by a test**, not hidden | Fixed / Gap (D-34) | `test_evidence.py` (17) |
| `archive.py` | §10.3, D-25, D-28, D-35 | AUD-10: an over-deep nested archive aborted the whole extraction, which contradicts §10.3. Deeper archives are now left unopened and recorded as `limit_nesting`. `peek` replaced with read and seek to fix typing. Limits are enforced against actual bytes while extracting. **Gap:** D-25 requires extraction inside isolation, and the engine has no B2 isolation manager yet, so this extractor is only exercised by unit tests and must not be called on the host by the engine | Fixed / Gap | `test_archive.py` (23) |
| `adapters/base.py`, `fixture.py` | §5, R-05, R-06, R-16 | AUD-11 (**security**): scanner output was fully buffered before the size check, so a hostile scanner could exhaust memory. Added `run_bounded`: streamed, capped and killed on overrun or timeout, in its own process group, with no shell. The environment is minimal; a test shows secrets aren't inherited. **Gap:** the fixture adapter doesn't run inside an OS sandbox yet (the S1 sandbox is an isolation-manager deliverable) | Fixed / Gap | `test_adapters.py` (18) |
| `adapters/fixture_scanner.py` | test fixture | Reads text only, never executes target files, doesn't follow symlinks | OK | via adapter tests |
| `findings.py` | §6.3, §7, D-26, R-12 | Starting states, deterministic fingerprints and dedup are correct. `promote_deterministic` takes a caller-supplied boolean, so it must stay engine-internal (no agent path); recorded for the orchestrator design | OK / note | `test_findings_reports.py` |
| `reports/__init__.py` | D-17 | AUD-12: finding titles were missing from the HTML and Markdown reports (found by a failing test). Added, and escaped. HTML has a strict CSP. Every format states the audit state and that it isn't a security guarantee | Fixed | same file |
| `disclosure.py` | §13.3, D-31, F-07 | The engine detects agent environment markers itself; a caller declaring "operator" can't hide them | OK | same file |
| `isolation/__init__.py`, `isolation/sandbox.py` | D-04, D-32, R-05, R-06, §10.2 | Session 4: S1 macOS Seatbelt sandbox, deny-by-default. Availability comes only from a functional self-test, never from the executable existing. AUD-14 (design): adapters could ignore a supplied sandbox, so the engine now rejects results whose reported isolation doesn't match (`isolation_not_used`). **Gaps:** memory limits not enforced on macOS; file metadata readable host-wide; no Linux sandbox; no containers or VM | Fixed / Gap | `test_isolation.py` (15) |
| `canonical.py`, `paths.py`, `lifecycle.py`, `domain/*`, `errors.py` | foundation | Already covered in session 1 | OK | `test_foundation.py` (41) |
| `orchestrator.py` | §3, §5, §8, §10.1, §11 | Implemented in session 3. AUD-13 (**security**, found by mutation testing): the first version trusted the adapter's own `validate_scope`; an engine-side scope check was added, so a hostile adapter can't widen scope. The fixture adapter runs without isolation (recorded); third-party adapters are `NOT_RUN` with no isolation | Fixed / Gap | `test_pipeline.py` (29) |

## 3. Critical requirements and their executable tests

| Requirement | Test(s) |
|---|---|
| Altered payload, wrong context or action, subject, revision or scope → BLOCKED | `test_semantic_mismatches_blocked`, `test_altered_payload_fails_signature`, `test_cross_action_reuse_rejected`, `test_scope_coverage` |
| Expired, future-dated or over-maximum approvals rejected (D-37) | `test_expiry_boundary_and_future_issue`, `test_d37_maximum_expiry`, `test_authorization_expiry_by_environment`, `test_over_maximum_lifetime_rejected_at_verify_even_if_signed` |
| One-time nonce consumed; standing re-verification doesn't consume, extend or widen; rebinding rejected (D-36) | `test_one_time_nonce_consumed`, `test_standing_reverification_does_not_consume_extend_or_widen`, `test_changed_payload_with_registered_nonce_rejected` |
| Revocation | `test_revocation_of_standing_approval`, `test_recheck_before_operation_sees_revocation_and_expiry` |
| Unknown, revoked or run keys authorise nothing | `test_unknown_revoked_and_run_keys_authorise_nothing`, `test_unknown_revoked_expired_keys_authorise_nothing` |
| P-256 operator keys (D-38) | `test_p256_operator_key_is_accepted`, `test_trust_store_roundtrip_both_algorithms` |
| Operator signing fails closed | `test_operator_signing_fails_closed_without_provider` |
| A signature is not authority | `test_signature_is_not_authority` |
| Production: exact assets, no A1 | `test_record_content_rules` |
| Check immediately before each operation | `test_recheck_before_operation_sees_revocation_and_expiry`, `test_operation_checks` |
| A1 needs a record; B3 always blocked; B2 allowed in READ | `test_mode_level_and_activity_rules` |
| Unsigned or changed policy → BLOCKED; policy change binds the previous file | `test_unsigned_or_changed_policy_blocks`, `test_policy_change_binds_previous_file` |
| Evidence hash checked on read; manifest and log tampering detected | `test_tampered_evidence_detected_on_read`, `test_manifest_tamper_and_wrong_key_detected`, `test_added_or_removed_evidence_detected`, `test_audit_log_chain_break_detected`, `test_audit_log_deleted_entry_detected` |
| Archive limits, traversal, links, unsafe formats, nesting | `test_archive.py` (23 tests) |
| Missing scanner, hash mismatch, crash, timeout, bad output → never PASS | `test_adapters.py` |
| HUMAN_VERIFIED kept separate from verified | `test_human_review_gives_distinct_state` |
| Incomplete audit never PASS | `test_foundation.py::test_incomplete_or_cancelled_audits_never_pass`, `test_all_renderers_show_incomplete_state` |

**Residual risks demonstrated by tests, not hidden:**
- `test_known_limitation_ledger_rollback_replays_until_expiry`
- `test_known_limitation_same_user_resign_is_not_detected`

**Full suite (session 4):** 246 tests, 246 passed (isolation 15 added). Per file: adapters 18, approvals 38, archive 23, authorisation and policy 31, crypto and keys 17, evidence 17, findings and reports 17, foundation 41, pipeline 29.

**Mutation testing:** 22 security checks were each removed in turn in a scratch copy. All 22 were caught by a failing test.
- The first pass let two survive: path traversal, because a second layer masked it, and the per-entry compression ratio, because the whole-artifact limit tripped first.
- Targeted tests were added for both, and the second pass caught all 22.
- **Session 3:** 7 orchestrator checks were added: re-authorisation before each check, the isolation gate, maximum duration, engine scope check, class enforcement, mode and level, and cancellation. All **29 of 29** are caught.
- **Session 4:** 6 isolation checks were added: deny-by-default profile, environment allowlist, resource limits, workspace cleanup, the `isolation_not_used` rejection, and the class gate. All **35 of 35** are caught.
- **Session 5:** 13 Secure Enclave checks were added: fake-backend refusal, interactive gate, trust/metadata key match, response key ID, response digest, signature verification, exact response keys, strict error codes, metadata key ID, metadata algorithm, payload key ID, rotation binding of the public key, and production fail-closed. First pass: 1 survivor (key-match pre-check); the test was tightened, and all **48 of 48** are caught.
- **Session 6:** 5 helper-backend checks were added: hash pin, minimal environment, exit-status consistency, message size, and Sentinel-side key ID. All **53 of 53** are caught.
- **Session 7:** 11 checks were added: the D-21 VALIDATE gate and its orchestrator call, non-consuming policy validation, and CLI checks (result bound to manifest, run-ID validation, input size, regular files only, no overwrite, blocked and findings exit codes, record needs approval). All **64 of 64** are caught.
- **Session 8:** 18 checks were added: enrol-only-when-empty, enrol self-signed, trust fingerprint check, duplicate key, last active key, agent refusal, non-interactive refusal, already revoked, rationale equals reason, entry within approval expiry, entry expiry at use, revision binding at apply, compensating controls required, decision file-name integrity, suppression names its finding, entry hash as subject, exclusions listed in reports, and the CLI human-channel guard. All **82 of 82** are caught.
- **Session 9:** 16 checks were added: exact preparation inputs, preparing signer must be usable, entry within approval lifetime, rationale equals reason, policy must parse before preparation, revocation checked at audit, revocation signature, subject and revision, unverifiable revocation blocks, double revocation, revocation bound to the decision, pin format, pin required, helper not a symlink, revocation logged. The production fail-closed mutation was updated to the new code. All **98 of 98** are caught.
- **AUD-16 (session 9, closed in session 10):** `approvals.apply_revocation` accepted any revocation revision (every caller passed `"n/a"`). It now requires the target's exact revision and a target signed by a registered key. The regression tests are in `tests/test_redaction.py`.
- **Session 10:** 20 checks were added. Three are AUD-16 bindings: revision, signed target and revision present. The redaction checks are: evidence redacted, evidence needs a redactor, audit log redacted, result redacted, evidence failure becomes check `ERROR`, CLI output, raw output and error messages, marker protection, size limit, key length, key not a symlink, truncated private key, empty-match custom pattern, prepare and decisions refuse secrets, and custom patterns validated. All **118 of 118** are caught.
- **Session 11:** 20 license-audit checks were added (in a separate harness, `tests/test_license_audit.py`):
  - SPDX `OR`, `AND` and `WITH` handling;
  - duplicate locked and duplicate installed packages;
  - transitive closure and orphan detection;
  - `RECORD` verification and version mismatch;
  - unknown and runtime-incompatible licenses;
  - never-acceptable issue codes and stale reviews;
  - unreviewed changes and `needs_review` tracking;
  - stale output, the strict gate and the CI exit code;
  - the free-form `License` field and classifier-only ambiguity.

  The first pass let one survive (the free-form `License` field). A test was added, and all **20 of 20** are caught. The engine campaign now copies `scripts/` and `licenses/` too, so the new tests can't hide mutants by failing to import.
- **Session 14:** no new mutants. The final campaign (catalogue `274f2b3f748a2ef4…`) catches **147 of 147** (118 engine, 29 license; 0 survived, invalid or infra-failed). Full suite: 634 passed.
- **Session 13:** 9 license-audit checks were added: missing attribution, attribution never acceptable, build requires pinned, build constraints match the lock, build-lock hashes required, unpinned build lines rejected, build environment required, embedded notice verified, and upstream text verified. With the corrected harness, all **147 of 147** are caught (0 survived, invalid or infra-failed).
- **AUD-19 (session 11, closed in session 12):** the mutation harness copied only `src/` and `tests/`. From session 6 on, `tests/test_se_helper.py` needs `native/`, so the **unmodified** baseline failed in the copy and mutants were counted as killed with no security test catching them. The "98 of 98" (session 9) and "118 of 118" (session 10) results were overstated.
  - **Harness, session 12:** the scratchpad scripts are replaced by `scripts/mutation/harness.py` and a catalogue with stable ids, `scripts/mutation/mutations.py`.
    - Every declared input must exist (`setup_failed`).
    - The unmodified baseline must pass before any mutant runs (`baseline_failed`).
    - Each mutant is classified as `caught` (pytest exit 1 with named failing tests), `survived`, `invalid` (anchor missing or repeated, no-op, or doesn't compile) or `infra_failed` (timeout, collection or import error, or another exit code). Only `caught` counts as caught.
    - The report records each mutant's id, exit code and failing test ids, plus SHA-256 hashes of the catalogue and of every input.
    - `tests/test_mutation_harness.py` covers the harness itself, including a broken baseline and a test needing an uncopied `native/`.
  - **Disposition of the 18 survivors:**

    | # | Mutant id | Disposition | Invariant | Enforced in | Test (`tests/test_aud19.py`) |
    |---|---|---|---|---|---|
    | 1 | `eng-policy-validate-non-consuming` | Genuine test gap | `policy validate` must be read-only (no nonce recorded) | `policy.validate_policy_file` | `test_policy_validate_does_not_consume_the_approval` |
    | 2 | `eng-cli-run-id-validation` | Genuine (defence in depth) | run IDs must be UUIDs, so `../` can't reach a directory outside `runs/`. Earlier tests used paths that didn't exist, so the later `is_dir` check hid the gap | `cli.run_path` | `test_run_id_must_be_a_uuid_even_if_the_path_exists` |
    | 3 | `eng-cli-input-size` | Genuine (resource limit) | oversized input is refused **before** it is read into memory. The check after reading hid this | `cli.read_input` | `test_oversized_input_is_refused_before_it_is_read` |
    | 4 | `eng-admin-enrol-only-when-empty` | Genuine (ordering) | the state check comes before approval verification. `TrustStore.enrol` refuses too, but only after the one-time nonce was burned | `admin.enrol` | `test_refused_second_enrolment_does_not_burn_its_approval` |
    | 5 | `eng-admin-enrol-self-signed` | Redundant layer; reason code | still refused without the check (the signer is not in the probe store), but with a misleading code. The test pins `not_self_signed` | `admin.enrol` | `test_enrolment_signed_by_another_key_says_why` |
    | 6 | `eng-dec-entry-expiry-at-use` | Genuine test gap | an entry that expires before its approval must stop applying | `decisions.verify_decision` | `test_decision_entry_expires_before_its_approval` |
    | 7 | `eng-dec-compensating-controls-required` | Genuine test gap | an accepted risk needs real compensating controls (empty or too short is refused) | `decisions.validate_entry` | `test_accepted_risk_needs_real_compensating_controls` |
    | 8 | `eng-dec-file-name-integrity` | Genuine test gap | a renamed decision file is reported and never applied | `DecisionStore.load` | `test_renamed_decision_file_is_reported_not_applied` |
    | 9 | `eng-findings-suppression-names-finding` | Genuine (API boundary) | a signed suppression can't be applied to a different finding | `findings.apply_suppression` | `test_suppression_cannot_be_applied_to_another_finding` |
    | 10 | `eng-findings-entry-hash-is-subject` | Genuine, high | an entry edited after signing (expiry, author) is refused. Without the check, any edit to a signed entry would apply | `findings.apply_suppression` | `test_suppression_entry_edited_after_signing_is_refused` |
    | 11 | `eng-reports-exclusions-listed` | Genuine test gap | the Markdown report lists suppressed and accepted-risk findings (D-15 transparency) | `reports.to_markdown` | `test_markdown_report_lists_exclusions` |
    | 12 | `eng-prep-rationale-is-reason` | Genuine (ambiguous input) | prepare refuses a rationale that differs from the entry reason instead of silently ignoring it | `prepare.prepare` | `test_prepare_refuses_a_rationale_that_differs_from_the_entry_reason` |
    | 13 | `eng-dec-revocation-subject` | Fail-closed either way; reporting | a revocation for another entry is `unverifiable`, not `revoked`. The decision is blocked in both cases | `DecisionStore.revocation_state` | `test_revocation_for_something_else_is_unverifiable_not_revoked[subject]` |
    | 14 | `eng-dec-revocation-revision` | Fail-closed either way; reporting | as above, for a different revision | `DecisionStore.revocation_state` | `test_revocation_for_something_else_is_unverifiable_not_revoked[revision]` |
    | 15 | `eng-red-cli-output` | Genuine (last line of defence) | the CLI redacts every structured payload it prints, whatever the command | `cli.main` | `test_cli_redacts_structured_output_last` |
    | 16 | `eng-red-cli-raw-output` | Genuine (last line of defence) | the CLI redacts raw report bytes | `cli.main` | `test_cli_redacts_raw_output_last` |
    | 17 | `eng-red-key-length` | Genuine (`init` path) | a malformed key file is refused on load. `Redactor()` hid this, but `sentinel init` would have accepted a corrupt key | `redaction.load_or_create_key` | `test_malformed_redaction_key_file_is_refused_on_load, test_init_refuses_a_corrupt_redaction_key` |
    | 18 | `eng-red-custom-empty-match` | Genuine (partial second clause) | `^(?!x)` matches empty input but not `x`, so only the first clause catches it | `redaction.compile_custom` | `test_custom_pattern_that_matches_empty_input_is_refused` |

  - **Not changed:**
    - `compile_custom` accepts zero-width patterns that match only after other text, such as `(?<=a)` and `\b`. The redactor ignores zero-length matches, so they redact nothing; this is a residual note, not a leak.
    - No production code was changed to kill a mutant.
- **AUD-18 (session 11, fixed):** the sdist was built from the whole working tree. It included `.ecc-src/` (about 4,700 files of third-party agent tooling under its own MIT license), `tools/ecc-hooks/`, `.claude/settings.json` and `docs/private/`, so third-party code and private notes would have been redistributed under Sentinel's name. The sdist is now an explicit allowlist, and a test asserts those paths are absent.
- **AUD-17 (session 10, fixed):** evidence was stored without redaction. The record said "redaction engine not in M1", so any secret a scanner printed was written to disk and copied into reports and CLI output. Now redacted before writing, with fail-closed handling.
- **AUD-14 (session 8, fixed):** suppressions and accepted risks bound only the finding fingerprint, not the entry (§11.3 requires the entry's SHA-256 as subject), so expiry, author and compensating controls were unsigned. Now entry-bound.
- **AUD-15 (session 8, fixed):** reports did not show suppressions, accepted risks or human reviews at all. Now listed in their own sections, with SARIF `suppressions`.
- **AUD-13 (session 7, fixed):** the engine allowed VALIDATE L3 with only S1 classes and no authorisation record, contrary to D-21. Fixed engine-side (`policy.check_mode_authorization`), with an engine-level test and a mutation check.

## 4. Open gaps

**Session 28, AFR-01:** D-42 is recorded, but `ApprovalAction.ALLOWLIST_CHANGE` and its maximum still exist in code (`prepare` refuses it). **Resolved in session 31:** removed, and refused at load time as an unknown action. The D-40 JSON Schemas are not implemented (an M1 exit criterion). **Session 32:** implemented. See `docs/m1/schemas.md`. Verified with the corrected mutation harness: 222 caught behaviourally and 0 survivors. **Earlier mutation results, including Task 1's 158/158, are not valid as reported.** They counted 43 to 48 anchor-only catches; the session 32 campaign supersedes them. See `progress.md`, session 32.

**Session 19, SE-H1 (security):** confirmed on hardware (macOS 26.6.2, Mac15,6). Any same-user program can use the current Secure Enclave key handle with its own dialog text and payload. The current helper design is not a key boundary. This is G-1 extended: production activation is blocked until Design A or an alternative is verified.

**Session 17:**
- X-5 is fixed: no unsandboxed adapter path remains.
- D-32 root and capability refusal is implemented.
- **New security note (D-39 analysis):** the Secure Enclave key is created with `.userPresence` only, without app binding, and its handle is stored in the same-user state folder. Any same-user process can therefore request signatures with its own dialog text, bypassing the pinned helper. This blocks production activation until it is decided (round2 §2.3).

**AFR-01 (session 15):** the architecture freeze review (`docs/architecture/freeze-review.md`) cross-references these gaps and adds implementation contradictions:
- X-3: YAML policies in D-01 vs JSON in the code;
- X-4: the prompt shows a hash, not the payload;
- X-5: the fixture adapter runs unsandboxed;
- X-6: no `schemas/`;
- X-8: no refusal to run as root;
- X-10: no kill switch or pause;
- X-11: no retention deletion.

Not frozen.


| ID | Gap | Owner / plan |
|---|---|---|
| G-1 | Helper implemented (session 6). Owner's run: H1–H3 passed (real Secure Enclave signature with user presence verified); H4–H11 pending. Helper pin now lives in approved policy (session 9). `production_provider()` still off, so operator approvals are refused through the CLI | Swift helper per `docs/m1/se-helper-contract.md`, then owner runs H1–H11; enabling `production_provider()` needs a new decision record |
| G-2 | Real keystore backends untested | A test that opts into the real keychain, run manually by the owner |
| G-3 | S1 macOS sandbox done (session 4). No Linux sandbox, containers or VM; memory limits not enforced on macOS | Non-S1 classes and Linux third-party checks stay `NOT_RUN` |
| G-4 | Trust store same-user writable (AUD-05) | Fingerprint in reports and prompts; owner keeps an out-of-band record |
| G-5 | Third-party authority evidence unsupported | Fails closed by design in M1 |
| G-6 | CLI core done (session 7); trust admin (session 8), redaction (session 10) and `THIRD_PARTY_NOTICES` (session 11) since done. Still missing: `fix-plan` and the agent integrations | Later M1 sessions |
| G-8 | Trust admin residual risks: (a) the first key is trust-on-first-use, so the owner must compare its fingerprint out-of-band; (b) the interactive/agent check can be faked by an agent with a pty, so the real control is the presence-backed signature; (c) the admin log and decision files are same-user writable (integrity relative to the run key only, D-34); (d) decision revocation records live in the same user-writable state folder. Deleting a revocation file resurrects the decision, and deleting a decision is undetected: same-user tampering is outside V1 protection (D-34). The ledger's revoked set is also same-user writable (D-36 residual risk) | Owner awareness; revocation command later |
| G-9 | Redaction is pattern-based and incomplete. Not detected: encoded secrets, bare high-entropy strings, split values, names without a listed keyword, and PII. Finding fingerprints are computed before redaction. Custom regexes have no backtracking limit. See `docs/m1/redaction.md` | Owner awareness; PII detection and entropy checks later |
| G-10 | **Closed (session 14).** Accepted residual risks, not verified: LR-1 cryptography's OpenSSL build process; LR-2 cffi Windows wheels and libffi; LR-3 Rust crate license texts and which crates are linked; LR-4 reviewer readings (colorama, pathspec, trove-classifiers). All four become blockers for any bundled redistribution. The CI workflow `license-gate.yml` hasn't run remotely yet | Revisit on a dependency change (the gate forces it) or before bundled distribution |
| G-7 | CLI `audit` only knows the fixture adapter; no real scanner adapters exist yet. `runs list` reads manifests unverified (labelled) | Real adapters are a later milestone |
