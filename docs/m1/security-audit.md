# M1 security self-audit (M1 task 9 and final closure audit, 2026-11-09)

**Scope:**
- All code added in M1 tasks 2 to 7: schemas and validator, D-45 roles, the D-47 recovery verifier, the protocol-v1 transport, `fix-plan`, the D-41 integrations, and CI.
- A pattern sweep of the whole engine: process execution, deserialisation, archive extraction, temporary files, weak hashes and shell use.
- The mutation catalogue's integrity.

The method was manual review against the frozen design (D-48), signing-protocol v1 and the final review (§1.3 and OD-3), followed by targeted tests and the full mutation campaign.

## Findings fixed

| ID | Finding | Fix | Evidence |
|---|---|---|---|
| SA-01 | `decisions list` and `approval inspect` reported a raw signature by a **recovery-role** key as valid. This was informational output only, but misleading (D-47) | Only operator-role keys count | `test_listing_never_shows_a_recovery_key_raw_signature_as_valid` |
| SA-02 | CI actions were pinned to moving tags; checkout kept its credentials | Pinned to full commit SHAs; `persist-credentials: false` | `tests/test_ci_workflow.py` |
| SA-03 | Run-key creation stored the secret seed before checking its metadata contract | Contract check first (found by the mutation campaign, task 2) | `test_run_key_metadata_checked_before_secret_or_file_is_stored` |
| SA-04 | The mutation harness counted catalogue-anchor failures as catches, inflating every earlier campaign | Only behavioural failures count; anchor meta-test excluded from mutant runs; session preflight | `tests/test_mutation_harness.py`; progress session 32 |
| SA-05 | The harness's own unit tests depended on the host's lock state | Preflight injected in those tests | `tests/test_mutation_harness.py` |
| SA-07 | The engine accepted **Ed25519 operator keys**, contrary to D-47 | Operator keys are P-256 only. Ed25519 is refused in key files and in trust-store entries (contract and domain), at enrolment and rotation, and in `authorise` as defence in depth. Test fixtures are P-256 software keys under `tests/`; there is no production switch | `tests/test_d47_p256_only.py`; mutants `eng-d47-*-p256-only` |
| SA-08 | `approval receive` cleanup could follow a symlinked `to-signer` directory on a hostile volume and delete a same-named file elsewhere | Cleanup removes only plain files in verified, non-link directories | `test_cleanup_never_follows_a_symlinked_to_signer_directory`; mutant `eng-d49-cleanup-no-link-dirs` |
| SA-06 | Nine new defences were not pinned by any test (second layers behind the schema, receive-time assertion check, plan contract) | Targeted tests | Final campaign: 278 of 278 caught |

## Reviewed, no change needed

- **Transport:**
  - Responses are opened with `O_NOFOLLOW | O_NONBLOCK`, and `fstat` must show a regular file with a single link and a size within the limit; the read is capped at limit + 1 bytes.
  - Volume directories are checked with `lstat`.
  - Canonical bytes are re-encoded and compared.
  - File names must equal the `request_id`.
  - Every response is verified against the engine's own pending payload.
  - Refusals leave the volume untouched.
- **Recovery verifier:**
  - Every rule in final-review §1.3 is implemented exactly.
  - Origin and RP ID are compared byte for byte.
  - Duplicate client-data keys are refused.
  - Counter state is updated only after every other check passes and the nonce is consumed.
- **`fix-plan`:**
  - It runs on verified runs only.
  - It has no write path into the run or the state directory (resolved-path check, `O_EXCL | O_NOFOLLOW`).
- **D-41 check:**
  - The agent binary runs without a shell, with a minimal environment and a 10 s timeout.
  - Version text is bounded and must match exactly.
- **Engine-wide sweep:**
  - No `shell=True`, `eval`, `pickle`, `yaml.load` or `mktemp`.
  - Archive extraction keeps its existing safe-path, ratio and size limits.

## Residual risks (accepted for M1; owner visibility)

| ID | Residual |
|---|---|
| R-1 | The trust store, ledger, pending requests and state directory are writable by the same macOS user (AUD-05). The development Mac's copy of recovery counters is untrusted; the signing device is authoritative (OD-3) |
| R-2 | **Resolved (SA-07).** The historical pre-D-47 signed fixtures keep their Ed25519 operator key as byte-identical evidence: their signatures still verify, but that trust store is refused as production trust. An installation with an Ed25519 operator key must enrol a P-256 key; there is no automatic migration |
| R-3 | The D-41 agent version is self-reported; the check is a compatibility gate, not a security control |
| R-4 | Replaying an old, valid recovery assertion marks the recovery key `suspect` (OD-3, by design). An attacker with write access to the transfer volume can cause this denial of service |
| R-5 | Run-manifest signatures prove integrity relative to the run key only (D-34) |
| R-6 | Real operator presence, the Secure Enclave access control and FIDO2 behaviour are **not** validated in M1; the D-49 tests use software keys only |
| R-7 | Legacy (pre-D-45) trust-store entries are read as operator keys with the full permission set, and the fingerprint changes when they are rewritten in explicit form. Key-operation approvals bound to the old fingerprint then fail closed |

## Final closure audit (whole M1)

- **Scope:** all engine modules under `src/sentinel/`, the Skills, the CI workflows, the mutation harness and the decision register entry D-51.
- **Operator-key paths:**
  - Every path that parses, stores, enrols, rotates in or uses an operator key goes through `OPERATOR_ALGORITHMS` (P-256) and `TrustStore.authorise` (role, action, algorithm).
  - The run key (Ed25519) can't authorise anything: wrong algorithm, and not in the trust store.
- **Production signing:**
  - `production_provider` still has no success path, and `available_provider` always raises.
  - No production module constructs a Secure Enclave signer.
  - Sentinel never signs operator payloads.
- **Untrusted input:**
  - Every input boundary decodes strictly, then checks the schema, then the domain rules.
  - Every output is contract-checked before it is signed, persisted or printed.
  - Transfer-volume files are refused if they are links, special files, have extra hard links or are over size.
- **D-49/D-50 re-review:**
  - One new finding (SA-08), fixed.
  - Recovery and operator verification stay disjoint, and both share one binding, expiry and nonce routine (`approvals.check_binding_and_replay`).
  - `fix-plan` has no write path into run or state.
- **Not claimed:**
  - No physical signing-device, Secure Enclave access-control, biometric or FIDO2 hardware behaviour is validated by the software fixtures.
  - Remote CI is unverified.
