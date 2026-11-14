# Architecture freeze review AFR-01

**Date:** 2026-11-09. **Reviewer:** Claude Code (implementation session). **Status:** review delivered; **the architecture is NOT frozen**. Freezing needs the operator's explicit approval (§9).

**Inputs read:**
- `docs/architecture/discovery.md` §1–§17;
- `docs/architecture/review.md`;
- `docs/architecture-discovery-plan.md`, the decision log D-01–D-38. The task named `docs/architecture/discovery-plan.md`; **that file does not exist**, and the plan lives one level up;
- `docs/m1/progress.md` and `docs/m1/implementation-audit.md`;
- the source under `src/sentinel/`, `native/macos/se-helper/` and `.github/workflows/`.

**Limits of this review:**
- Passing tests (634) and mutation results (147 of 147) are cited as evidence of **implementation behaviour**, not as proof that the architecture is correct.
- **No diagram was rendered** (§8). Diagram checks are structural only.
- Nothing in the architecture was redesigned, and no decision was changed. Every ambiguity below is listed for the operator to resolve; none is resolved here.

---

## 1. Executive verdict

**READY WITH CONDITIONS.**

The decision set D-01–D-38 is complete, uniquely numbered and internally coherent. No architectural question is open by O-ID, and the security model holds together:
- engine-side authorisation;
- the operator-presence trust anchors;
- the canonical payload, nonces and expiry;
- the narrowed run-key claims;
- the isolation matrix, with no fallback.

The M1 implementation follows that model closely where it exists.

**Freeze is not recommended until:**
- the documentation contradictions in §3 are corrected;
- the operator records decisions on the items in §4;
- the diagrams are rendered (C-1 to C-6 in §7).

Two of the contradictions touch security invariants, so they can't be waived silently:
- **X-4:** the presence prompt shows a payload hash, not the payload;
- **X-5:** the engine-owned fixture adapter falls back to running unsandboxed.

---

## 2. Decision-by-decision review (D-01 to D-38)

Legend:
- **Doc:** documented consistently in discovery.md (✅, or ⚠ with a contradiction ID).
- **Impl:** M1 implementation state:
  - ✅ implemented, with evidence;
  - ◐ partial or by design limited;
  - ⏳ scheduled for a later milestone;
  - ❌ contradicts the decision;
  - — not applicable yet.

| ID | Decision (short) | Doc | Impl | Evidence and notes |
|---|---|---|---|---|
| D-01 | Python 3.12+; contracts in JSON Schema; **policies in YAML** | ⚠ | ❌ ◐ | `pyproject.toml` `requires-python = ">=3.12"` ✅. **No `schemas/` directory exists**, although §4 and the M1 deliverables need JSON Schemas (X-6). **The policy file is canonical JSON** (`policy.py` `_parse_policy` → `canonical.decode_strict`), not YAML (X-3) |
| D-02 | Sentinel licence MIT | ✅ | ✅ | `LICENSE` (session 13), `pyproject.toml` `license = "MIT"` |
| D-03 | Scanners keep their upstream licences; `THIRD_PARTY_NOTICES` | ✅ | ✅ | Strict license gate; `AdapterManifest.licence` field (`adapters/base.py`). §16 schedules notices for M10; they were delivered early (no conflict) |
| D-04 | Layered isolation (rootless containers, VMs, native sandbox) | ✅ | ◐ | Only the macOS native sandbox exists. Containers and VMs are absent (G-3), so S2, B1 and B2 are `NOT_RUN` (`isolation/__init__.py:isolation_for`) |
| D-05 | Local-first; disclosure; opt-in | ✅ | ✅ | `disclosure.py` (`local_only` / `agent_assisted`); no outbound code path found (only the sandbox's deny-probe `socket` call in `isolation/sandbox.py`) |
| D-06 | Claude Code and Codex integrations, thin | ✅ | ⏳ | Not built (`integrations/` empty). The engine has no agent dependency ✅ |
| D-07 | Read-only default | ✅ | ✅ | `audit` runs READ unless the config asks for VALIDATE (`cli.py` header); `policy.MODE_CLASSES`. The target-tree-hash guarantee (AC-02) is M2 |
| D-08 | Default depth L2 | ✅ | — | **Not verified.** I found no code default that selects L2 when the level is omitted. Recorded as an open check, not a contradiction |
| D-09 | No coverage claim before fixtures pass | ✅ | — | No domains exist in M1 |
| D-10 | Active testing needs authorisation, scope and safety limits | ✅ | ✅ | `policy.check_activity`: A1 needs a record; B3 is prohibited |
| D-11 | Commands audit, report, fix-plan, verify; CI | ✅ | ◐ | `audit` and `report` exist. **`fix-plan` and the finding-`verify` workflow are not built** (`evidence verify` is integrity only). CI license gate added; it hasn't run remotely |
| D-12 | Finding schema; six check statuses; four report types; never a false PASS | ✅ | ◐ | Statuses and the never-PASS rules are implemented and mutation-tested (`lifecycle.py`, `orchestrator.py`). The four report **types** (executive, technical, remediation, verification) are M9; M1 has formats only |
| D-13 | Scanner catalogue; adapter contract | ✅ | ◐ | `adapters/base.py` defines detect, plan, validate_scope, execute, normalize and health ✅. Only the fixture adapter exists (catalogue is M2+) |
| D-14 | Milestones M1–M10 | ✅ | — | §16 matches |
| D-15 | Isolation matrix; B3 prohibited | ✅ | ✅ ◐ | B3 refused (`check_activity`); S1 sandbox only |
| D-16 | Authorisation records; signatures; authority independent of signature | ⚠ | ✅ ◐ | Asset authority comes only from policy `owned_assets` (AUD-06). **§11's field table still says the record signature is "Ed25519"** (X-2) although D-38 amends the operator algorithm. Third-party `evidence_of_authority` is **unsupported and fails closed** (G-5), narrower than §11 (M-6) |
| D-17 | JSON canonical; SARIF 2.1.0; Markdown and HTML | ✅ | ✅ | `cli.REPORT_EXT`, `reports/` |
| D-18 | Per-run filesystem storage, no database | ✅ | ✅ | `evidence.RunStore` |
| D-19 | Operational defaults | ✅ | ◐ | `policy.Limits` holds every value. **Retention deletion (90 days) and listing of expired runs are not implemented** (only the limit exists) |
| D-20 | Change control: reviewed PRs, signed tags, human approval for trust anchors | ✅ | ◐ | Trust-anchor changes need `policy.change` ✅. The repository has **no commits, no PR history and no signed tags** yet (process not started) |
| D-21 | READ = L1/L2; VALIDATE = L3 with record; no RED TEAM | ✅ | ✅ | `MODE_LEVELS`, `check_mode_authorization` (AUD-13), mutation-tested |
| D-22 | Images pinned by digest; native binaries only if hash-allowlisted | ✅ | ◐ | The hash allowlist is enforced for the fixture script (mutation "binary hash"); no container images exist |
| D-23 | Native Codex and Claude Code skill formats; **minimum agent versions fixed at M1 start** | ✅ | ❌ | M1 has started (sessions 1–14) but **minimum agent versions are not recorded** (X-7) |
| D-24 | Python 3.12+; pipx and `uv tool`; macOS and Linux first; Windows by M10 | ✅ | ◐ | The wheel builds. pipx and `uv tool` installs not verified. **No Linux host has been tested**, and Linux has no sandbox (progress, isolation table). Package index open until M10 (by decision) |
| D-25 | B2 in READ without a record, under strict isolation | ✅ | ◐ | `archive.py` enforces the B2 rules and is mutation-tested. B2 is `NOT_RUN` in the pipeline because no VM or hardened container exists (consistent: no host extraction) |
| D-26 | `HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE` distinct and signed | ✅ | ✅ | `findings.py`; separate report section (`test_human_review_state_is_distinct`) |
| D-27 | Operator presence for every trust-anchor action; refuse non-interactive | ✅ | ✅ ◐ | `admin.require_human_channel`; trust-anchor actions need operator signatures. **The production signer is still disabled** (`production_provider` fails closed until H1–H11 and a decision record), so operator approvals are unavailable through the CLI. Same-session tty spoofing is a known residual (G-8b) |
| D-28 | Code-executing formats never deserialised | ✅ | ✅ | `archive.is_unsafe_serialisation` (mutation "unsafe format") |
| D-29 | Vulnerability databases pinned; otherwise `non_reproducible` | ✅ | — | Manifest field `vulnerability_db_snapshots: {}`. No scanner uses one; the `non_reproducible` marking is not implemented yet (M3) |
| D-30 | Windows split (M5 static, M10 native) | ✅ | — | — |
| D-31 | No outbound data path in V1 | ✅ | ✅ | No outbound client code in `src/sentinel` |
| D-32 | Host requirements; **nothing falls back to weaker isolation**; refuse to run as root | ⚠ | ❌ ◐ | Missing layers give `NOT_RUN` ✅. **The engine-owned fixture adapter runs unsandboxed** when no S1 sandbox exists (`orchestrator.py:203, 295`; progress "No OS isolation") (X-5). **Root:** §10.2 says "the engine refuses to start"; the implementation only withholds S1 isolation when root (`isolation_for`), so it doesn't refuse to start (X-8) |
| D-33 | Canonical signed payload; **the prompt shows the exact canonical payload** | ⚠ | ✅ ❌ | Payload, context, subject, revision, scope, expiry, nonce and key ID are implemented and mutation-tested. **The Secure Enclave prompt shows the helper-computed SHA-256 of the payload, not the payload itself**; the payload is shown in the terminal (`main.swift:157`, `se-helper-contract.md` §4, H4) (X-4) |
| D-34 | Run-key integrity narrowed (option a) | ✅ | ✅ | Docs and report notes are consistent (`integrity_note`); same-user residual accepted (G-4, G-8) |
| D-35 | Provisional B2 limits | ✅ | ✅ | `policy.Limits` values match §10.3; mutation-tested |
| D-36 | One-time vs standing nonces | ✅ | ✅ | `approvals.NonceLedger`; AUD-16 closed |
| D-37 | Maximum approval expiry | ✅ | ✅ | `approvals.max_expiry_for`; over-max refused at build and verify |
| D-38 | Algorithm-agile operator keys; Secure Enclave P-256 with presence; no software fallback | ⚠ (X-2) | ◐ | Helper and Python side implemented; H1–H3 passed, **H4–H11 pending**; no software fallback (mutation "se: production fails closed") |

**Summary:**
- **33 decisions** are documented consistently.
- **5** have documentation contradictions: D-01, D-16, D-32, D-33 and D-38 (the last through X-2).
- **3** contradict the implementation: D-01 (YAML, schemas), D-23 (agent versions overdue) and D-32 (fixture fallback, root).
- **D-33** has an implementation deviation in the prompt display.

---

## 3. Contradictions (exact references)

| ID | Severity | Where | Contradiction | Needs |
|---|---|---|---|---|
| X-1 | Low (stale) | `discovery.md` line 3 (status) | "No implementation has started, and nothing in this document has been implemented or tested" is false after M1 sessions 1–14 | Doc correction |
| X-2 | Medium | `discovery.md` §11 field table (`signature`, `key_id` row) vs D-38, §13.7 | §11 says records carry an "Ed25519 signature by an operator key". D-38 allows P-256 Secure Enclave operator keys; §13.7 was updated but §11 wasn't | Doc correction (no decision change) |
| X-3 | Medium | D-01 ("policies in YAML") vs `src/sentinel/policy.py` | Policies are canonical JSON, decoded strictly and signed over their exact bytes (§11.3 requires a deterministic encoding). YAML isn't used anywhere | **Operator decision:** amend D-01 to JSON, or require YAML |
| X-4 | **High (security invariant)** | D-33, `discovery.md` §11.2 rule 2 and §11.3 ("the prompt displays exactly these bytes"), review B-1 ("the prompt renders this exact payload") vs `native/macos/se-helper/main.swift:157`, `docs/m1/se-helper-contract.md` | The OS user-presence prompt shows only the **full SHA-256** of the bytes being signed. The readable payload is shown in the terminal, which the operator must compare by hash (H4). A same-user agent controls the terminal, so it could show a misleading payload whose hash matches; the binding then rests on the operator comparing 64 hex characters. LocalAuthentication can't display arbitrary payloads | **Operator decision:** record a decision amending D-33's display rule (hash-in-prompt plus payload-in-terminal, with its residual risk), or require a different presence mechanism |
| X-5 | **High (security invariant)** | D-32 ("nothing falls back to weaker isolation"), `discovery.md` §10.2 last line vs `orchestrator.py:203, 295`, `progress.md` "No OS isolation" | With no verified S1 sandbox, the **engine-owned fixture adapter still runs unsandboxed**, recorded as `isolation_ref: none (...)`. Third-party adapters are correctly `NOT_RUN` | **Operator decision:** accept a recorded exception (the engine-owned synthetic fixture only, labelled) or require `NOT_RUN` |
| X-6 | Medium | `discovery.md` §4 ("typed records defined in `schemas/`"), §16 M1 deliverables ("Schemas …"), exit criterion "Schemas validate" vs the repository | There is no `schemas/` directory and no JSON Schema files; records are Python dataclasses and canonical JSON | Implementation gap (M1 exit criterion), or decision to defer |
| X-7 | Medium | D-23, `discovery.md` §14.2 ("Minimum agent versions are fixed at M1 start"), §17.1 deferred items | M1 is well under way; the versions are not recorded | **Operator decision** (values), before the integrations are built |
| X-8 | Medium | `discovery.md` §10.2 ("Running as root or an administrator. The engine refuses to start") vs `isolation/__init__.py:35, 54` | As root, the engine only declines S1 isolation (checks `NOT_RUN`); it doesn't refuse to start | Implementation gap or doc correction (operator chooses) |
| X-9 | Low | `discovery.md` §6.4 ("detectors cover … common personal data patterns"; "whether it looks live or like a test value") vs `redaction.py`, `docs/m1/redaction.md` | No PII detection and no live/test classification (G-9) | Scheduled gap; record a target milestone |
| X-10 | Low | `discovery.md` §8.1 (`Paused`, resume, kill switch) and §11 ("There is a kill switch") vs `lifecycle.py`, `cli.py` | No pause, resume or kill-switch command exists; cancellation exists only as an engine event (mutation "orch: cancellation") | Scheduled gap; record a target milestone |
| X-11 | Low | D-19 and §13.5 (retention deletion and listing) vs code | Only `Limits.evidence_retention_days` exists | Scheduled gap |
| X-12 | Low | §11.3 action list (`allowlist.change`) vs `prepare.py:9` | `allowlist.change` is defined with a 90-day maximum, but **no operation consumes it**: adapter allowlists change through `policy.change` (the allowlist sits inside the policy file). Two actions now describe one change | **Operator decision:** keep `allowlist.change` reserved, or document that `policy.change` governs allowlists |
| X-13 | Low | Task brief vs repository | `docs/architecture/discovery-plan.md` doesn't exist; the plan is at `docs/architecture-discovery-plan.md` | Path note only |

**Checked and consistent** (earlier review items, no contradiction found):
- review F-04 (§8.1 `Completed` label);
- F-06 (Windows split);
- F-08 (`Running → BLOCKED`);
- F-10 (maximum-duration transition);
- F-12 (M3 exclusion);
- contradiction 3, B2 in READ (D-25).

### Missing or implicit decisions (not silently treated as decided)

| ID | Missing decision | Currently |
|---|---|---|
| M-1 | Presence-prompt display rule under D-33 (X-4) | Implemented as hash-in-prompt; no decision record |
| M-2 | Exception for the engine-owned fixture adapter under D-32 (X-5) | Implemented as an unsandboxed run with an `isolation_ref` label |
| M-3 | Policy file format (X-3) | JSON in code, YAML in D-01 |
| M-4 | Minimum Claude Code and Codex versions (X-7) | Unset |
| M-5 | Secure Enclave production activation record (D-38, G-1) | Pending H4–H11 by design; not missing, but required before activation |
| M-6 | Third-party asset authority (`evidence_of_authority`) is unsupported in V1 | Implemented as fail-closed (AUD-06, G-5); §11 still describes the field as functional |
| M-7 | Interactive-channel check is spoofable with a pty (G-8b) | Documented residual; the real control is the presence signature. Not formally accepted as a risk under D-27 |
| M-8 | Target milestones for PII detection, live/test secret classification, kill switch and retention deletion (X-9–X-11) | Unscheduled |

---

## 4. Security invariant verification matrix

Evidence types:
- **Test:** unit or integration test;
- **Mut:** caught mutation in `scripts/mutation/mutations.py` (147 of 147 caught, 2026-11-09);
- **Doc:** documented only;
- **Gap:** not implemented.

| # | Invariant | Source | Implementation | Evidence | Verdict |
|---|---|---|---|---|---|
| I-1 | No promotion or trust anchor without an operator-presence signature | D-26, D-27, T16 | `approvals.verify`, `admin.require_human_channel`, `findings` | Test, Mut (signature, context, subject, revision, agent refusal, human-channel guard) | ✅ logic; presence itself **pending H4–H11** |
| I-2 | Engine-side authorisation, re-checked before every operation | D-10, R-03 | `orchestrator` re-auth, `authorization.authorize_operation` | Mut "orch: re-auth before check" | ✅ |
| I-3 | Asset authority independent of signature | D-16 | `owned_assets` only (AUD-06) | Mut "authority check" | ✅ (third-party unsupported, M-6) |
| I-4 | No execution of analysed content; B3 prohibited; no unsafe deserialisation | D-15, D-28, T17 | `check_activity`, `archive` | Mut "unsafe format", B3 test | ✅ |
| I-5 | Never weaker isolation; missing layer → `NOT_RUN` | D-32 | `isolation_for`, orchestrator gate | Mut "orch: isolation gate", "iso: class gate" | ❌ **exception for the fixture adapter (X-5)** |
| I-6 | Deny-by-default sandbox, environment allowlist, resource limits | R-05, R-06 | `isolation/sandbox.py` | Mut "iso: deny-by-default", "env allowlist", "resource limits" | ✅ macOS S1 only |
| I-7 | No false PASS: missing, failed, timed-out or blocked checks → `Incomplete` | D-12, §8.2 | `lifecycle.py` | Mut "Completed rule", "orch: max duration" | ✅ |
| I-8 | Evidence content-addressed, hash-checked on every read | R-13 | `evidence.RunStore` | Mut "evidence hash on read", "log chain" | ✅ |
| I-9 | Run-key signature claims limited to key-relative integrity | D-34 | report `integrity_note` | Doc and Test | ✅ (residual accepted) |
| I-10 | Canonical payload, context separation, no cross-use | D-33 | `approvals` | Mut (context, subject, revision, nonce binding) | ✅ logic; **display rule deviates (X-4)** |
| I-11 | Nonce semantics and bounded replay | D-36, D-37 | `NonceLedger`, `max_expiry_for` | Mut (one-time nonce, D-37 max), AUD-16 tests | ✅ (rollback residual per D-34) |
| I-12 | Secrets redacted before any write or output; fail closed | §6.4, §13.4, T10 | `redaction.py`, `RunStore`, `AuditLog`, `cli.main` | Mut (8 redaction mutants), AUD-17 | ✅ secrets; ❌ PII (X-9) |
| I-13 | No outbound data path | D-31 | — | Code inspection | ✅ |
| I-14 | Scanner binary hash checked before every run | R-16, D-22 | fixture allowlist | Mut "binary hash" | ✅ (fixture only) |
| I-15 | No software fallback for operator signing | D-38 | `production_provider`, `require_genuine` | Mut "se: refuse fake backend", "production fails closed" | ✅ |
| I-16 | Agent can't impersonate the operator via CLI | D-27, T16 | human-channel guard | Test; residual G-8b (pty) | ◐ (M-7) |
| I-17 | Target config can only narrow, never widen | §4 | engine-side scope check (AUD-13) | Mut "orch: engine scope check" | ✅ |
| I-18 | Kill switch stops checks → `BLOCKED` | §11, R-04 | — | Gap | ❌ (X-10) |
| I-19 | Refuse to run as root | §10.2 | partial | — | ❌ (X-8) |

---

## 5. Implementation alignment matrix (by architecture area)

| Area | Architecture | M1 implementation | Alignment |
|---|---|---|---|
| Trust boundaries (§9) | 6 boundaries, T1–T17 | T2, T5, T9, T12 and T15 are mostly M2+; T3, T6, T8, T10, T11, T14, T16 and T17 covered at M1 depth | Partial by milestone |
| Authorisation (§11) | Records, two policy checks, kill switch | Records, policy, re-check, revocation; no kill switch; third-party authority unsupported | Mostly aligned (X-10, M-6) |
| Isolation (§10) | S1 sandbox, containers, VMs, no fallback | S1 macOS sandbox only; S2, B1 and B2 `NOT_RUN`; fixture exception | Aligned except X-5 |
| Evidence integrity (§6, §13.8) | Content addressing, manifest, hash chain, run-key checkpoints | Implemented; D-34 limits stated | Aligned |
| Signing (§11.2, §13.7, D-38) | Ed25519 run key; Secure Enclave P-256 operator key with presence | Implemented; activation pending H4–H11 | Aligned (X-2 doc, X-4 display) |
| Redaction (§6.4, §13.4) | Secrets and PII, live/test, fail closed | Secrets, fail closed; no PII or live/test | Partial (X-9) |
| Audit lifecycle (§8) | States including Paused, resume, checkpoints, max duration | Completed/Incomplete rules, max duration, cancellation event; no pause or resume | Partial (X-10) |
| Failure handling (§5, §8.2) | Never PASS on failure | Implemented and mutation-tested | Aligned |
| Contracts (§4, D-01) | JSON Schemas in `schemas/` | None | Not aligned (X-6) |
| Integrations (§14) | Skills, CI | Not built; CI license gate only | Scheduled |
| Supply chain (T13, D-03) | Hash-locked dependencies, SBOM, notices | Lock with hashes, license gate, notices; SBOM is M10 | Aligned for M1 |

**Roadmap support (D-14, §16):** the dependency graph M1 → M2 → {M3…M8} → M9 → M10 is consistent with the decisions.
- No decision blocks a later milestone.
- M2 and M4 depend on container and VM availability, which is unverified on any host (review.md §5 assumption, row "Rootless containers and disposable VMs"). That remains the main **feasibility risk** for M2, M4 and Linux support (D-24).
- M1 exit criteria not yet met:
  - "Schemas validate" (X-6);
  - "Claude Code and Codex skills calling the CLI" (D-06);
  - "run key and operator key with user presence", which needs H4–H11;
  - AC-09, AC-10, AC-11 and AC-14 have tests, but formal acceptance hasn't been run as a criteria pass.

---

## 6. Risks: accepted vs requiring resolution

**Accepted (by recorded decision or owner acceptance):**

| Risk | Basis |
|---|---|
| Same-user tampering with run data, re-signing with the run key, and nonce-ledger rollback | D-34, D-36 |
| First operator key is trust-on-first-use | G-8a |
| Admin log, decisions and revocations are same-user writable | G-8c, G-8d, D-34 |
| Trust store is same-user writable | G-4, AUD-05 |
| Redaction blind spots (encoded, high-entropy, split values) | G-9, `docs/m1/redaction.md` |
| Licensing residuals LR-1 to LR-4 | session 14, `docs/m1/licensing.md` |
| AC-07 and AC-08 thresholds provisional until M3 | D-19, §17.1 |
| Package index open until M10; dynamic adapter review | D-24, D-10 |

**Requiring resolution before freeze:** X-3, X-4, X-5, X-7, X-12 and M-6 need an operator decision. X-1, X-2 and X-13 need a documentation correction. The diagrams need rendering.

**Requiring resolution before M1 completion (not freeze-blocking if accepted as scheduled):**
- X-6: schemas;
- X-8: root refusal;
- X-9 to X-11: PII and live/test classification, kill switch, retention;
- M-7: pty spoofing acceptance;
- H4–H11 and the activation record (M-5);
- the integrations;
- the first CI run.

---

## 7. Recommended freeze conditions

| # | Condition | Type |
|---|---|---|
| C-1 | Record operator decisions for X-4 (prompt display), X-5 (fixture adapter isolation exception), X-3 (policy format), X-12 (`allowlist.change`) and M-6 (third-party authority in V1) as new D-entries in `docs/architecture-discovery-plan.md`, **without changing D-01–D-38's meaning except where the operator explicitly amends them** | Operator decision |
| C-2 | Record the minimum Claude Code and Codex versions (D-23, X-7), or record an explicit decision deferring them to the start of integration work | Operator decision |
| C-3 | Correct the stale documentation: X-1 (status line), X-2 (§11 signature algorithm), and an M1 reality note in §17.1 | Doc edit |
| C-4 | Render all 8 Mermaid diagrams with a trusted renderer and inspect them visually; record the renderer, its version and the result in §17.1 | Validation (not done; no renderer installed) |
| C-5 | Assign target milestones to X-6, X-8, X-9, X-10 and X-11 (scheduled gaps), so that nothing is silently treated as decided | Operator decision or plan |
| C-6 | Explicitly accept or reject residual M-7 (pty spoofing of the interactive check) under D-27 | Operator decision |

**Not freeze conditions** (they govern **production activation** and **M1 completion**, separately):
- H4–H11 plus the Secure Enclave activation decision record (D-38, G-1);
- the first remote CI run;
- the M1 exit criteria.

---

## 8. Validation performed (exact commands and results)

**1. Documentation and diagram structural check.** A script in the session scratchpad (not part of the repository) checked:
- that the decision register is exactly D-01..D-38 in order;
- that every D, R, T, AC and O reference in `discovery.md`, `review.md` and the plan resolves;
- that every `§` reference in `discovery.md` has a heading;
- for the Mermaid blocks: diagram type, balanced `subgraph`/`alt` … `end`, balanced quotes, and declared sequence participants.

```
.venv/bin/python -I <scratch>/doccheck.py .
```

Result: exit 0.
- `decision register rows: 38 missing: [] dupes: []`.
- `section headings: 55`; no unresolved references.
- `mermaid blocks: 8`: diagrams 1, 6, 7 and 8 are flowcharts; 3 and 4 are `stateDiagram-v2`; 5 is a `sequenceDiagram`; all blocks are balanced (1: 3/3, 5: 1/1, 6: 2/2).
- `RESULT: PASS`.

**2. Renderer availability.**
- `which mmdc` printed `mmdc not found`.
- `node` and `npx` exist, but using `npx @mermaid-js/mermaid-cli` would download a package. That was **not done** (no download approved).
- **No diagram has been rendered or visually inspected.** Diagram validity is structural only (C-4).

**3. Implementation facts.** These were read-only source inspections, not tests. Each fact cited in §2–§5 gives its `file:line`.

**Not used as architectural proof:** the 634 passing tests and 147 of 147 caught mutations (session 14) show the implementation behaves as tested. They don't show that the architecture is complete or correct.

---

## 9. Proposed architecture-freeze approval statement (for the operator)

> I, the operator, have reviewed AFR-01 (`docs/architecture/freeze-review.md`, 2026-11-09). I approve freezing the Sentinel architecture as documented in `docs/architecture/discovery.md` and decisions D-01–D-38, together with the new decisions I have recorded for X-3, X-4, X-5, X-7 (or its deferral), X-12 and M-6. I confirm that the documentation corrections X-1, X-2 and X-13 have been applied, that the eight diagrams have been rendered and inspected (condition C-4), and that the scheduled gaps X-6 and X-8–X-11 have target milestones. Residual risks listed as accepted in AFR-01 §6 remain accepted. This freeze does not activate production Secure Enclave signing, which still requires H4–H11 and a separate decision record, and does not mark M1 complete. Changes to the frozen architecture after this point need a recorded decision and operator approval.
>
> Signed: ____________________   Date: ____________

**Until the operator gives that approval, the architecture remains unfrozen, and work does not proceed to the Fix-plan.**

---

## 10. Remaining-conditions checklist (revisited 2026-11-09)

**Statuses:**
- **PASS:** resolved with evidence.
- **OPEN:** needs action or a decision before freeze.
- **ACCEPTED:** accepted with documented rationale (not freeze-blocking).

**The architecture is NOT frozen.**

### 10.1 Contradictions (§3)

| ID | Item | Status | Evidence or rationale |
|---|---|---|---|
| X-1 | `discovery.md` status line says "No implementation has started" | **OPEN** | Correction C-a was proposed (`freeze-remediation-proposal.md` Part C) but not yet approved; line 3 is unchanged |
| X-2 | §11 says operator signatures are Ed25519 | **PASS** | The §11 signature row now points to the key's recorded algorithm (D-47); §13.7 has a D-47 note (session 26) |
| X-3 | D-01 says YAML policies; the code uses JSON | **OPEN** | D-40 (JSON only; schemas in M1) is approved in principle but reserved and unrecorded |
| X-4 | The presence prompt shows a hash, not the payload | **PASS** (design) | Superseded by D-47 and Architecture C: the dedicated signing Mac shows every security-relevant field, built by the signer from the validated payload (`separate-signing-device-design.md` §4). Implementation and SD-T tests are pending; they're an activation gate, not a freeze gate. The D-39 helper-dialog proposal is now **obsolete** and should be withdrawn rather than recorded |
| X-5 | The fixture adapter ran unsandboxed | **PASS** | Removed in session 17; tests and mutants cover every path; no exemption remains |
| X-6 | There's no `schemas/` directory | **OPEN** | It needs D-40 recorded. The schemas themselves are M1 implementation work |
| X-7 | Minimum agent versions aren't set | **OPEN** | D-41 (defer to each integration, with mandatory compatibility checks) is approved in principle but unrecorded |
| X-8 | No refusal to run as root | **PASS** | Implemented in session 17 (effective UID 0 and Linux `CapEff`); the §10.2 wording is updated |
| X-9 | No PII detection or live/test secret classification | **ACCEPTED** | Scheduled for M2 by operator direction (2026-11-09); the criteria are proposed as AC-15 and AC-16. The documentation doesn't claim coverage (`redaction.md`) |
| X-10 | No kill switch or pause/resume | **ACCEPTED** | Scheduled for M2 (proposed AC-17); cancellation exists as an engine event |
| X-11 | No retention deletion | **ACCEPTED** | Scheduled for M2 (proposed AC-18); there's no silent deletion |
| X-12 | `allowlist.change` has no consumer | **OPEN** | The operator directed removal; the D-42 removal wording awaits review (`freeze-remediation-round2.md` Part 3) |
| X-13 | The decision-register path in the brief was wrong | **PASS** | No in-repository references to the wrong path |

### 10.2 Missing decisions (§3)

| ID | Item | Status | Evidence or rationale |
|---|---|---|---|
| M-1 | Presence-prompt display rule | **PASS** | D-47 (recorded) |
| M-2 | Fixture adapter isolation exception | **PASS** | No exception: the code now enforces D-32 |
| M-3 | Policy format | **OPEN** | Recording D-40 |
| M-4 | Minimum agent versions | **OPEN** | Recording D-41 |
| M-5 | Secure Enclave activation record | **ACCEPTED** | This is a production-activation gate, not a freeze gate. Production signing stays disabled until D-45 to D-47 are implemented, SD-T01 to SD-T55 pass, the ceremony is done and an activation record exists |
| M-6 | Third-party asset authority | **OPEN** | Recording D-43 (fail-closed refusal in V1, approved in principle) |
| M-7 | Interactive-terminal spoofing | **OPEN** | Recording D-44 (accepted residual, approved in principle) |
| M-8 | Milestones for the scheduled gaps | **ACCEPTED** for targets; **OPEN** for criteria | The M2 targets follow operator direction; AC-15 to AC-18 await approval |

### 10.3 Freeze conditions (§7)

| ID | Condition | Status | Evidence or rationale |
|---|---|---|---|
| C-1 | Record decisions for X-3, X-4, X-5, X-12 and M-6 | **OPEN** | Done: X-4 (D-47) and X-5 (code). Not done: D-40, D-42, D-43 |
| C-2 | Agent versions recorded or formally deferred | **OPEN** | D-41 unrecorded |
| C-3 | Stale documentation corrections | **OPEN** | X-2 is done; X-1 (status line) awaits approval of C-a |
| C-4 | Render and inspect all diagrams | **PASS** | All 11 diagrams `RENDER_OK` with locally installed Mermaid 11.11.0 in headless Edge, offline. Inspected visually; manifest in `docs/architecture/evidence/diagram-render-manifest.json`. Two pre-existing layout overlaps (diagrams 1 and 4) are readable. **Renderer caveat:** the Mermaid build comes from a third-party app bundle (Goodnotes, Mac App Store, notarised); it isn't a pinned Sentinel dependency |
| C-5 | Target milestones for the scheduled gaps | **ACCEPTED** for targets; **OPEN** for AC-15 to AC-18 approval | As for M-8 |
| C-6 | Accept or reject the pty residual | **OPEN** | D-44 unrecorded |

### 10.4 New items since AFR-01

| Item | Status | Evidence or rationale |
|---|---|---|
| Signing architecture (D-45, D-46, D-47, OD-2 to OD-6) | **PASS** (decided) | Recorded in the register on 2026-11-09 |
| Diagrams show the signing Mac, the USB boundary, operator and recovery key separation, the registry state machine and the checkpoint ceremony | **PASS** | Diagram 1 updated; new §11.4 with three diagrams; rendered and inspected |
| Signing hardware tests SD-T01 to SD-T55 | **ACCEPTED** (not freeze-blocking) | Activation gate (M-5) |
| SE-H1 vulnerability (handle-on-disk helper) | **ACCEPTED** (design superseded) | Rejected design; production signing disabled; Architecture C replaces it |

### 10.5 What remains OPEN before a freeze approval can be requested

1. **Record (or withdraw) the reserved decisions:**
   - D-40 (JSON and schemas);
   - D-41 (agent versions);
   - D-42 (`allowlist.change` removal, after wording review);
   - D-43 (third-party authority refused);
   - D-44 (pty residual);
   - **withdraw D-39** (superseded by D-47).
2. **Approve and apply** documentation correction C-a (the X-1 status line).
3. **Approve** M2 acceptance criteria AC-15 to AC-18 (or record them as targets only).
4. **The operator's explicit freeze approval** (statement in §9, which needs updating to cite D-45 to D-47 once item 1 is done).

---

## 11. Final freeze-readiness report (2026-11-09, after AFR-01 remediation)

This report supersedes the §10 statuses wherever they differ.

**Statuses:**
- **PASS:** resolved, with evidence.
- **ACCEPTED WITH RATIONALE:** a documented residual or a later gate, not blocking the freeze.
- **OPEN:** blocking the freeze.

**Architecture decisions are distinguished from hardware validation:** a PASS here means the *architecture is decided and documented consistently*. It does **not** mean the signing architecture is implemented or validated on hardware.

### 11.1 Decisions and contradictions

| ID | Item | Status | Evidence or rationale |
|---|---|---|---|
| X-1 / C-a | `discovery.md` status line | **PASS** | Line 3 now states the factual M1 implementation status, that the signing device isn't implemented, and that production signing is disabled |
| X-2 | §11 operator algorithm | **PASS** | It points to D-47 |
| X-3 / M-3 | Policy format | **PASS** | D-40 recorded (canonical JSON only); a forward pointer on D-01; `discovery.md` §4 note |
| X-4 / M-1 | Approval display | **PASS** (decision) | D-47: the dedicated signing device renders every field. D-39 is **withdrawn** as obsolete. Hardware validation is open (§11.3) |
| X-5 / M-2 | Unsandboxed fixture adapter | **PASS** | Removed in code (session 17); tests and mutants cover every path |
| X-6 | JSON Schemas | **ACCEPTED WITH RATIONALE** | D-40 makes versioned schemas **mandatory in M1**. They are an M1 implementation exit criterion; freezing the architecture doesn't require the schemas to exist yet. Their absence blocks **M1 completion**, not the freeze |
| X-7 / M-4 / C-2 | Agent versions | **PASS** | D-41 recorded (set per integration, with mandatory compatibility checks before activation) |
| X-8 | Root refusal | **PASS** | Implemented and tested (session 17) |
| X-9 | PII and secret classification | **PASS** (criteria) / **ACCEPTED WITH RATIONALE** (implementation in M2) | AC-15 and AC-16 are recorded as **mandatory** M2 exit criteria with zero-raw-instance and zero-misclassification thresholds. Until M2, documents and reports must not claim PII coverage (`redaction.md` states it isn't covered) |
| X-10 | Kill switch, pause and resume | **PASS** (criteria) / **ACCEPTED WITH RATIONALE** (M2) | AC-17 is mandatory for M2 |
| X-11 | Retention deletion | **PASS** (criteria) / **ACCEPTED WITH RATIONALE** (M2) | AC-18 is mandatory for M2 |
| X-12 | `allowlist.change` | **PASS** (decision) | D-42 recorded (removed). **Residual:** the enum value still exists in code (refused by `prepare`); removing it is pending implementation and doesn't block the freeze |
| X-13 | Register path | **PASS** | — |
| M-5 | Secure Enclave activation record | **ACCEPTED WITH RATIONALE** | A production-activation gate, not a freeze gate (§11.3) |
| M-6 | Third-party authority | **PASS** | D-43 recorded; it matches the implementation |
| M-7 / C-6 | Terminal spoofing | **PASS** (decision) / **ACCEPTED WITH RATIONALE** (risk) | D-44 recorded: the tty check isn't presence; a pseudo-terminal can spoof it; residual accepted |
| C-1 | Record decisions | **PASS** | D-39 withdrawn; D-40 to D-47 recorded as dated entries with forward pointers; the decision log stays append-only |
| C-3 | Stale documentation | **PASS** | X-1 and X-2 corrected |
| C-4 | Diagrams rendered and inspected | **PASS** | 11 of 11 `RENDER_OK` with locally installed Mermaid 11.11.0 in headless Edge, offline; inspected. **Renderer caveat:** a third-party app bundle, not a pinned Sentinel dependency. **Layout caveat:** pre-existing overlaps in diagrams 1 and 4 (readable) |
| C-5 / M-8 | Gap milestones | **PASS** | AC-15 to AC-18 recorded as mandatory M2 exit criteria in §15.3 and §16 |
| Signing architecture | D-45, D-46, D-47, OD-2 to OD-6 | **PASS** (decided) | Recorded; diagrams in §11.4 |

### 11.2 Residual risks accepted at the architecture level (unchanged unless noted)

- **D-34:** same-user tampering with run data; a nonce-ledger rollback is bounded by expiry.
- **D-44 (new):** the interactive check is spoofable; presence rests on the signing device.
- **Signing-device design residuals:**
  - the operator can approve a correctly displayed malicious payload;
  - a compromised development Mac can ignore or forge its *own* local verdicts, so assurance needs external verification against the paper-anchored key;
  - APFS kernel-driver bugs on the signing Mac;
  - zero-counter FIDO2 authenticators give no clone detection;
  - changes after the last checkpoint are lost if the signing Mac is lost.
- **Licensing:** LR-1 to LR-4 (`docs/m1/licensing.md`).
- **Redaction blind spots:** G-9; no PII coverage until AC-15.

### 11.3 Not architecture: hardware validation and implementation (production signing stays disabled)

| Item | Status |
|---|---|
| Signing device implementation (signer app, protocol, registry, checkpoints, recovery) | **Not started** |
| Hardware tests SD-T01 to SD-T55 (SD-T05 and SD-T06 deferred) | **None run** |
| SD-T35a (AuthenticationServices offline feasibility) | **Unknown**; libfido2 fallback subject to an OD-4 review |
| First-enrolment ceremony | **Not performed** |
| Production-signing activation decision record | **Not written** |
| SE-H1 | **FAIL** for the rejected handle-on-disk design (verified); this is why Architecture C was chosen |

**The signing architecture is decided but not production-validated.**

### 11.4 OPEN conditions blocking the freeze

**None remain on the reviewer side.** The only remaining step is **the operator's explicit freeze approval**. The architecture is **not frozen** by this report.

### 11.5 Revised freeze approval statement (for the operator; not signed here)

> I, the operator, have reviewed AFR-01 (`docs/architecture/freeze-review.md`, including §10 and §11, 2026-11-09). I approve freezing the Sentinel architecture as documented in `docs/architecture/discovery.md` and decisions D-01 to D-38 and D-40 to D-47 (with D-39 withdrawn) and OD-2 to OD-6, including the mandatory M2 acceptance criteria AC-15 to AC-18.
>
> I accept the residual risks listed in §11.2.
>
> This freeze **does not** validate or activate production signing. Activation requires the signing-device implementation, hardware tests SD-T01 to SD-T55 (QR tests deferred), the first-enrolment ceremony, and a separate activation decision record.
>
> This freeze does not mark M1 complete; the M1 exit criteria, including the D-40 JSON Schemas, remain.
>
> After this point, architecture changes need a new dated decision entry and operator approval.
>
> Signed: ____________________   Date: ____________

---

## 12. Freeze approval recorded (2026-11-09)

The operator approved the freeze per §11.5. It is recorded as **D-48** in `docs/architecture-discovery-plan.md` §4.

**The architecture is frozen as a design baseline.** All §11 PASS and ACCEPTED WITH RATIONALE conditions and the §11.2 residual risks stand.

**Explicitly not covered by the approval:**
- M1 completion;
- production signing;
- any waiver of AC-15 to AC-18;
- any waiver of the Secure Enclave or FIDO2 hardware tests (SD-T01 to SD-T55) or of the enrolment ceremony;
- any implementation shortcut or weakening of security controls.

Later architecture changes need a new dated decision with operator approval.
