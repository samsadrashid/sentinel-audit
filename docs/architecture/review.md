# Sentinel architecture review

**Reviewed:** `docs/architecture/discovery.md` (§1–§17) and `docs/architecture-discovery-plan.md` (D-01–D-24), 2026-11-08.
**Result:** **Not ready to freeze.** The architecture is sound, but 6 corrections are needed before freeze: 4 are security-relevant, 2 are documentation fixes. The freeze decision stays with the owner.

Severity: **High** = an invariant can be bypassed as written. **Medium** = a contradiction or gap that would cause wrong behaviour if built literally. **Low** = stale or unclear text.

---

## 1. Invariant check

| # | Invariant | Where it's enforced | Result |
|---|---|---|---|
| I-1 | An AI-generated finding never becomes verified without deterministic evidence or a named human review | §6.3 promotion rules | ⚠ **Gap (F-01)**: the "named human reviewer" has no way to prove it isn't the agent |
| I-2 | No incomplete audit receives PASS | §8.2, §5, §10.1, §15 AC-03 | ⚠ **Contradiction (F-04)** in the §8.1 diagram label; the rules themselves are correct |
| I-3 | No dynamic testing without engine-enforced authorisation | §11, R-01–R-10, D-21 | ⚠ **Gap (F-02)**: authorisation records can be created through CLI admin commands that an agent can also call |
| I-4 | No untrusted binary execution | §2, §10 B3 [D-15], §4 | ⚠ **Gap (F-03)**: some model and serialisation formats in scope can run code when parsed |
| I-5 | No scanner silently expands its scope | R-08, §14.5, R-02, §10 | ✅ Covered |
| I-6 | No external source-code transmission without opt-in | D-05, §13.1–13.3, §6.4 | ✅ For the engine. ⚠ The agent-side disclosure is recorded by the Skill, which is agent-controlled (F-07) |
| I-7 | No unsupported platform marked as covered | D-09, §15.3 coverage rule, §14.4 | ⚠ **Contradiction (F-06)**: the M5 exit criteria need Windows ACs before Windows host support exists (D-24) |
| I-8 | No security-policy change without approved change control | D-20 | ⚠ **Gap (F-05)**: D-20 covers the repository, not the operator's local policy, suppression and authorisation files |

## 2. Findings by area

| Area | Result | Notes |
|---|---|---|
| Module boundaries (§4) | ✅ | 12 modules, each with one owner and a "must not". Policy, orchestrator and adapters are separated correctly |
| Adapter contracts (§5, §14.4) | ✅ with F-08 | Six methods, a manifest, binary hash checks [R-16]. The lifecycle diagram doesn't show revocation during execution |
| Evidence provenance (§6.1–6.2, §13.8) | ✅ | Content addressing, producer hashes, write-once store, verification on read [R-13], signed manifests [R-14]. Signed evidence is kept separate from verified findings [R-17] |
| Promotion rules (§6.3) | ⚠ F-01, F-09 | |
| Risk and confidence (§7) | ✅ | Two separate scales; CVSS is one input only; suppressions and accepted risks expire and need justification |
| Lifecycle and resume (§8) | ⚠ F-04, F-10 | |
| Threat model (§9) | ✅ with F-03 | T1–T15 cover every requested threat. T8 and B2 should name code-executing formats |
| Privacy and AI boundary (§13) | ✅ with F-07, F-11 | Clear Zone L / Zone X split. The CLI on its own is always local |
| Integrations (§14) | ✅ with F-02 | One CLI contract; the integrations hold no security logic; no provider dependency [D-06, D-23] |
| Testing and acceptance (§15) | ✅ | AC-01–AC-10 are measurable. AC-07 and AC-08 are correctly provisional [D-19] |
| Roadmap (§16) | ⚠ F-06, F-12 | The dependency graph matches D-14. One stale reference |

## 3. Required corrections

| ID | Sev | Where | Issue | Proposed correction |
|---|---|---|---|---|
| F-01 | **High** | §6.3, §14.1 | Human review is recorded as "a reviewer identity in the audit log". An AI agent with shell access can run the same CLI command and claim a human identity. That bypasses I-1 | Human promotions and accepted-risk approvals need an **operator signature made with user presence** (OS keystore prompt or hardware key), which the agent can't produce. Without one, a finding can't move past `suspected` |
| F-02 | **High** | §11, §14.1 | Authorisation records are "written by the operator outside the agent session", but the CLI has admin commands for authorisation and key management, and an agent can call them. Keys in the OS keystore may be usable with no prompt | Signing authorisation records **requires user presence** (keystore access control set to require confirmation, or a hardware key). The engine refuses to create or sign records in non-interactive mode. Add a regression test: an agent-driven sign attempt → refused |
| F-03 | **High** | §10 B2, T8, D13 scope | Some formats in scope (for example pickle-based model files, and some serialisation formats inside archives) **run code when they are loaded**. Parsing them would break the "no untrusted execution" rule (I-4, D-15) | Rule: code-executing formats are **never deserialised**. Only safe structural parsers are used (for example the Safetensors header, GGUF metadata). Unsupported formats are `NOT_RUN` with a reason. Add a fixture |
| F-04 | Medium | §8.1 diagram vs §8.2 | The diagram says `Completed: every planned check has a final status`, but §8.2 says `Completed` needs every check to be PASS, FAIL or NOT_APPLICABLE | Relabel the transition: `Completed: all checks PASS, FAIL or NOT_APPLICABLE` |
| F-05 | Medium | D-20, §7.4, §9 residual risks | D-20 change control covers the repository. Local policy files, suppressions, accepted risks and authorisation records are only "recorded in the audit log", and an agent can edit them | Extend the F-01 and F-02 rule: local policy, suppression and accepted-risk files must carry an operator signature made with user presence. Unsigned or changed files are ignored, and every check they would affect is reported as `BLOCKED` |
| F-06 | Medium | §16 M5, D-24 | M5 needs "domain ACs on each OS", including Windows, but Windows host support only arrives by M10 | Split D06: **static analysis of Windows artifacts** (PE, MSI, Authenticode structure) on macOS and Linux in M5; Windows-native checks in M10. Until then the coverage rule keeps them `NOT_RUN` |
| F-07 | Low | §13.3 | The AI-provider disclosure and confirmation are done by the Skill, which is agent-controlled, so the manifest flag can't be trusted | The engine records `agent_assisted` from the run context (the caller declares it), the report shows "disclosure confirmed by the Skill (not independently verified)", and the CLI prints the disclosure itself whenever the caller is an agent |
| F-08 | Low | §5 diagram | The diagram has no `Running → BLOCKED` transition for revocation or a failed re-check [R-03, R-04], and no binary-hash `NOT_RUN` before execution [R-16] | Add the `Running --> BLOCKED: revoked or re-check denied` transition, and either add the hash check or note it in the text |
| F-09 | Low | §6.3 | The starting state for scanner-produced findings isn't stated. Also, the rules require deterministic evidence even for human verification of agent findings, which is stricter than I-1 | State that a scanner finding starts as `suspected`. Confirm whether a human signature alone may move an agent finding from `unverified` to `verified`. That is an owner decision |
| F-10 | Low | §8.1, D-19 | The 4-hour maximum audit duration has no lifecycle transition | Add `Running --> Incomplete: maximum duration reached` (the remaining checks become `NOT_RUN`) |
| F-11 | Low | §13.3, §6.4 | "External analysis per-run flag" implies an engine feature that sends data off the machine. Whether it's in V1 isn't decided | Mark it out of scope for V1 unless the owner approves it, so the engine has no outbound data path in V1 |
| F-12 | Low | §16 M3 "Excluded" | Says "until O-01 and O-02 are approved"; both are now resolved | Change to "until the dynamic adapter review [D-10]" |

## 4. Remaining contradictions

1. §8.1 diagram vs §8.2 rule on `Completed` (F-04).
2. M5 Windows exit criteria vs D-24 Windows support by M10 (F-06).
3. §11 "default with no record: S1, S2 and B1" vs D-21 "READ supports L1 and L2". L2 includes binary inspection, which may need B2 unpacking. **Owner decision needed:** is B2 allowed in READ without an authorisation record?
4. §16 M3 refers to O-01 and O-02 as pending (F-12).

## 5. Unresolved assumptions

| Source | Assumption | Risk if wrong |
|---|---|---|
| §2 | Sentinel orchestrates existing scanners and doesn't reimplement them | Coverage gaps where no suitable scanner exists |
| §7.4 | Suppression comments in target code are reported, not obeyed | None for security; possible noise |
| §8.3 | Changes in a vulnerability database explain differences between re-runs | Reproducibility (AC-05) needs the database version pinned in the manifest |
| §13.3 | Agent providers process whatever the agent reads, under their own terms | Privacy disclosure must stay accurate as provider terms change |
| §13.6 | The operator's disk is encrypted; backup destinations are the operator's choice | Evidence at rest is exposed if not |
| D-23, D-24 | Minimum agent versions (M1) and package index (M10) are still to be set | Low; scheduled |
| — | Rootless containers and disposable VMs are available on macOS and Linux hosts | M2 and M4 isolation can't be built without them; check at M1 |
| — | The "[P] approved in principle" status: the owner approved the remaining proposals in principle, subject to implementation validation | Labels in discovery.md still say "proposal awaiting approval" |

## 6. Mermaid diagrams

| # | Section | Type | Static check |
|---|---|---|---|
| 1 | §3 components | flowchart | ✅ blocks balanced, labels quoted |
| 2 | §3 pipeline | flowchart | ✅ |
| 3 | §5 check lifecycle | stateDiagram-v2 | ✅ (content gap F-08) |
| 4 | §8.1 audit states | stateDiagram-v2 | ✅ syntax (content contradiction F-04) |
| 5 | §11 enforcement | sequenceDiagram | ✅ participants declared, `alt…end` balanced |
| 6 | §13.1 zones | flowchart | ✅ dotted labelled edges valid |
| 7 | §14 integrations | flowchart | ✅ |
| 8 | §16 roadmap | flowchart | ✅ |

**Renderer validation is still outstanding.** No trusted local renderer is installed. Nothing was installed or downloaded.

## 7. Readiness recommendation

- **Recommendation: conditionally ready.** Apply F-01, F-02, F-03 and F-05, which are security-relevant, and F-04 and F-06, which are contradictions.
- **Owner decisions needed:** contradiction 3 (B2 in READ) and F-09 (human-only verification of agent findings).
- **Relabelling:** change the "approved in principle" `[P]` labels to reflect that status.
- **Render:** the 8 diagrams once.
- After that, the architecture meets the freeze conditions in §17.1, but only on the owner's explicit approval.
- F-07, F-08 and F-10 to F-12 are low severity and can be fixed in the same pass.

---

## 8. Correction status (applied 2026-11-08)

The corrections were applied to `discovery.md` and the plan as D-25–D-32, §10.2, §11.2, T16, T17 and AC-11–AC-13. They are documentation only: nothing is implemented or tested.

| ID | Status | Where |
|---|---|---|
| F-01 | Resolved | §6.3, §11.2, T16, AC-11 [D-27] |
| F-02 | Resolved | §11, §11.2, §14.1, §14.3 [D-27] |
| F-03 | Resolved | §10 B2 rules, T17, AC-12 [D-28] |
| F-04 | Resolved | §8.1 diagram |
| F-05 | Resolved | §7.4, §9, §11.2 [D-27] |
| F-06 | Resolved | §15.3, §16 M5 and M10 [D-30] |
| F-07 | Resolved | §13.3 |
| F-08 | Resolved | §5 diagram and text |
| F-09 | Resolved | §6.3, AC-13 [D-26] |
| F-10 | Resolved | §8.1, §8.2 |
| F-11 | Resolved | §6.4, §13.1, §13.3 [D-31] |
| F-12 | Resolved | §16 M3 |

Contradictions 1–4 are resolved (F-04, F-06, D-25, F-12). Assumptions: the vulnerability database is now pinned [D-29]; host requirements are documented [D-32]; the `[P]` label now means "approved in principle, not implemented".

## 9. Final pre-freeze review (independent pass, 2026-11-08)

### 9.1 Results by area

| # | Area | Result | Evidence |
|---|---|---|---|
| 1 | D-25–D-32 consistent in the plan and the architecture | ✅ | Each is defined in the plan and cited in `discovery.md` (D-25: 6 places, D-26: 6, D-27: 18, D-28: 6, D-29: 4, D-30: 4, D-31: 3, D-32: 4); no conflicting text found |
| 2 | Run key and operator key strictly separated | ✅ duties / ⚠ claims | §11.2 and §13.7 separate the duties, and trust anchors signed with the run key are rejected. **But see B-2**: what a run-key signature proves is overstated |
| 3 | No CLI, shell, agent or unattended workflow can impersonate the operator | ✅ | §11.2 rules, §14.1 (interactive only), §14.3 (CI verifies only), T16, AC-11. Unattended jobs are covered by "refused in non-interactive mode" |
| 4 | Approvals bind the exact action, scope, target and payload | ❌ **B-1** | §11.2 lists the signed fields as identity, key ID, timestamp, subject and rationale. The **action type** and **scope** are shown in the prompt but are not named as signed fields. There is no signature context that would stop one kind of signed object being presented as another |
| 5 | Replay, expiry, revocation, rotation | ⚠ **B-1** | Key revocation, expiry and rotation are covered (§11, §11.2, §13.7, R-04). Records and suppressions expire. **Human review decisions and policy-change approvals have no expiry and no replay binding**: no nonce, and no tie to a source revision or audit, so a decision for one revision could be reused for another revision with the same fingerprint |
| 6 | B2 limits, isolation, failure behaviour | ⚠ **B-3** | Isolation (§10, §10.2) and failure behaviour (`NOT_RUN`, `ERROR`, logged) are defined. Extracted size is 1 GB [D-19]. **The file-count, nesting-depth and compression-ratio limits have no values** (§10.1 note) |
| 7 | Unsafe serialisation formats can't run code | ✅ | §10 B2 rules, T17, AC-12, M8 exclusion [D-28] |
| 8 | No incomplete audit can PASS | ✅ | §5, §8.1 (corrected), §8.2 including the duration limit, §10.1, AC-03 |
| 9 | Unsupported platforms and isolation can't be reported as supported | ✅ | §10.2 (`NOT_RUN`, no fallback), §14.4, §15.3 per-OS coverage rule, D-30 |
| 10 | Vulnerability-database snapshots make runs reproducible | ✅ | §8.3, D-29, AC-05, M3 deliverable; an unpinned run is marked `non_reproducible` |
| 11 | All findings, contradictions and assumptions addressed | ✅ | §8 above. The remaining assumptions (host capabilities, user-presence availability) are scheduled for M1 checks |
| 12 | No planned item presented as done | ✅ | The status line and the `[P]` legend say "not implemented or tested"; §17.1 says "documented". No test result is claimed |

### 9.2 Blockers to freeze

| ID | Type | Issue | Proposed correction (needs owner approval) |
|---|---|---|---|
| B-1 | Gap (areas 4, 5) | Signed approvals don't name the action type, scope or context as signed fields, and have no replay or expiry rule for review decisions and policy changes | Define one **signed-decision payload** for every trust-anchor action, all of it inside the signature: a fixed signature context string per action type (so one kind of object can't pass as another); the action type; the subject hash (record, finding fingerprint plus source revision, or file hash); the full scope; `issued_at`; `expires_at`, required on every decision; a unique nonce, rejected if seen before; and the key ID. A review decision applies only to the source revision it names. The prompt renders this exact payload |
| B-2 | Contradiction (§13.8 and T11 vs §13.7) | The run key is "usable without a prompt", so any process running as the same user, including an AI agent, can rewrite evidence and re-sign the manifest. §13.8 says a signature proves the evidence "hasn't changed since the run", and T11 lists signed checkpoints as the mitigation for tampering. Neither holds against a same-user local process | Either (a) narrow the claims: run-key signatures detect accidental or out-of-band changes, not changes by same-user processes, with stronger protection as a residual risk; or (b) add an **operator-signed report attestation** (user presence) over the manifest hash when results are exported or relied on, and keep the run key in a separate OS account or service. Recommend (a) for V1 plus the optional attestation in (b) |
| B-3 | Gap (area 6) | B2 file-count, nesting-depth and compression-ratio limits have no values | Adopt the provisional limits in §9.3 as a new decision |

### 9.3 Recommended provisional B2 limits [proposal]

Conservative values. Each is changeable only through an operator-signed policy change [D-27], and is reviewed against M4 fixture measurements.

| Limit | Provisional default | When exceeded |
|---|---|---|
| Maximum extracted entries (files and folders) per artifact | 10,000 | Stop extraction; check `ERROR` (`limit_file_count`) |
| Maximum nested archive depth (an archive inside an archive) | 3 levels | Inner archives beyond 3 are not opened; `NOT_RUN` for their contents (`limit_nesting`) |
| Maximum path depth inside an archive | 32 components | Entry refused; logged |
| Maximum compression ratio, per entry | 100 : 1 | Stop extraction; `ERROR` (`limit_ratio`) |
| Maximum compression ratio, whole artifact | 50 : 1 | Stop extraction; `ERROR` (`limit_ratio`) |
| Maximum single extracted file size | 256 MB, within the 1 GB total [D-19] | Entry skipped; logged |

### 9.4 Residual risks acceptable for V1

- **Sandbox escape:** reduced by layered isolation, not removed (§9).
- **What you see is what you sign:** the operator may approve a misleading but correctly displayed request that an agent prepared. Mitigated once B-1 makes the prompt show the exact signed payload.
- **Same-user tampering with run data:** acceptable if B-2 option (a) is taken and the limit is stated clearly.
- **Agent-side provider exposure:** whatever the agent reads goes to its provider. Disclosed, and not controllable by the engine (§13.3).
- **Scanner false negatives:** a `PASS` is not proof of security.
- **Host capabilities** (user presence, rootless isolation) are assumed until checked at M1. Without them the affected features are unavailable, not weakened (§10.2).

### 9.5 Freeze conditions (§17.1)

| Condition | State |
|---|---|
| Decisions D-01–D-32 logged and consistent | ✅ |
| References and tables valid | ✅ |
| Review findings F-01–F-12 and contradictions resolved | ✅ |
| Critical areas 1–12 | ❌ areas 4, 5 and 6 open (B-1, B-3), and the claims in area 2 (B-2) |
| Mermaid diagrams rendered | ❌ static check only; renderer validation still outstanding |
| Owner's explicit freeze approval | ⏸ not given |

### 9.6 Recommendation

**NOT READY TO FREEZE.**

**What it takes:**
- the owner approves corrections for B-1, B-2 and B-3;
- those corrections are applied to `discovery.md` and the plan;
- the diagrams are rendered once.

All three blockers are documentation-level and contained, and need no architectural redesign.

## 10. Blocker resolution (2026-11-08)

The owner approved the B-1, B-2 and B-3 corrections, and they are now recorded as D-33–D-35. They are documented in `discovery.md`, but nothing is implemented or tested.

| ID | Status | Resolution | Where |
|---|---|---|---|
| B-1 | **Resolved** | One canonical approval payload for all nine trust-anchor action types: context, action, subject hash, revision, full scope, issued time, mandatory expiry, single-use nonce *(historical wording; nonce semantics now D-36)*, key ID, rationale, all covered by the signature. Deterministic encoding; the prompt shows the exact payload; rejection of expired, replayed, wrong-context, mismatched or altered approvals; revision binding for reviews and suppressions; policy changes bind the old and new file hashes | §11.3, §6.3, §7.4, §11 `signature`, §15.2 fixture, AC-14, M1 [D-33] |
| B-2 | **Resolved (option a)** | Run-key claims narrowed everywhere: a valid run-key signature shows integrity relative to the key only, and does not protect against a same-user process that can modify evidence and use the run key. Documented as a V1 residual risk. Option (b) not adopted | §4 audit-log row, §6.1, §6.2, T11, §9 residual risks, §11.2, §13.7, §13.8, §15.2 tamper fixture, AC-09 [D-34] |
| B-3 | **Resolved** | Seven provisional limits enforced by the engine, with the result of exceeding each. Checked while extracting; changes need an operator-signed `policy.change`; tuned from M4 measurements | §10.3, §10 B2 rules, T8, §15.2 archive fixture, M4 exit criteria [D-35] |

**Disclosed side effect of B-2 on B-1:**
- The nonce ledger is local run data, so a same-user process could roll it back and replay an approval that **has not yet expired**.
- Operator-signed approvals still can't be forged.
- The mandatory, bounded expiry limits that replay window. This is recorded in §11.3 and §9 as part of the D-34 residual risk.

### 10.1 Validation of this pass

| Check | Result |
|---|---|
| 1. Canonical payload used by every approval type | ✅ Authorisation records, review decisions, accepted risk, suppressions, policy and allowlist changes, key rotation and revocation all reference §11.3. The old "summary" prompt wording is gone |
| 2. Expiry, nonce and context binding | ✅ Mandatory `expires_at`, nonce ledger, per-action `context`, and subject, revision and scope checks; each rejection is `BLOCKED` (§11.3, AC-14) |
| 3. Run-key claims narrowed everywhere | ✅ No remaining text claims evidence is "unchanged since the run" or protected against same-user tampering. The D-27 note in the plan is qualified by D-34 |
| 4. Archive limits consistent | ✅ The §10.3 values match D-35. The 1 GB total matches D-19 and §10.1. Enforcement and change control are stated once and referenced from T8, the fixtures and M4 |
| 5. References, IDs, tables, ACs | See the final validation in the completion report |
| 6. No regression of F-01–F-12 or contradictions 1–4 | ✅ No earlier correction was removed or weakened. B-2 narrows claims only; it doesn't relax any control |

**Remaining before freeze:**
1. Mermaid renderer validation (static check only).
2. The owner's explicit freeze approval.

This review does not declare the architecture frozen.

## 11. Final documentation cleanup (2026-11-08)

| # | Task | Result |
|---|---|---|
| 1 | Reorder §11 subsections | ✅ Now §11.1 → §11.2 → §11.3 (→ §11.3.1, §11.3.2). Section numbers are unchanged, so every reference still resolves. The same defect in §10 (§10.3 before §10.2) is also fixed. All subsections are now in numeric order |
| 2 | Maximum approval expiry for all nine actions | ✅ §11.3.2 sets defaults for all nine (authorisation records split into local/staging and production), with the reasoning for each. Changing a maximum needs an operator-signed `policy.change`. Labelled `[P]` until the owner logs it |
| 3 | Nonce replay and same-user rollback kept explicit | ✅ §11.3, §11.3.2, §9 residual risks and §13.8. The replay window is bounded by the maximum expiry; a same-user process can't forge, alter or extend an approval [D-34] |
| 4 | D-33–D-35 and earlier findings consistent | ✅ with one exception, below |
| 5 | Mermaid render | ❌ **Not possible without installing something.** There is no `mmdc` command and no Mermaid package in any local `node_modules`. Obsidian.app bundles Mermaid but can't be driven from here. All 8 diagrams pass the static check again |

**Genuine contradiction found and corrected (needs owner confirmation):**
- D-33, as first worded, required a "single-use nonce, rejected if seen before". *(Historical: that wording is superseded by D-36.)*
- Standing approvals (authorisation records, review decisions, accepted risk, suppressions, policy and allowlist changes) are re-checked at every run and before every operation [R-03]. Read literally, D-33 would reject them on the second check.
- §11.3.1 now separates **one-time** approvals, whose nonce is consumed on first use, from **standing** approvals, whose nonce is registered and bound to that exact payload. A standing approval can be re-verified until it expires; any different payload carrying a registered nonce is rejected.
- This keeps D-33's intent: no approval can authorise something else, and replays are rejected.
- The correction is marked `[P]`. Its D-33 wording in the plan should be amended by a new decision entry once the owner approves.

**Validation:**
- Sections §1–§17 are sequential, and all subsections are in order.
- All tables in the three files are well-formed.
- D, R, T and AC references all resolve, and every `§` reference resolves, including §11.3.1 and §11.3.2.
- All nine actions appear in both the class table and the expiry table.
- The B2 limits are unchanged and consistent with D-35.
- There are no private names.

### 11.1 Freeze recommendation

**NOT READY TO FREEZE**, pending two owner actions and one external step:
1. **Owner:** approve the §11.3.1 nonce-class correction and the §11.3.2 expiry defaults, and log them as a new decision amending D-33.
2. **External:** render the 8 Mermaid diagrams, either by opening `discovery.md` in Obsidian or by approving a renderer installation.
3. **Owner:** give the explicit freeze approval.

No other blocker remains.

## 12. Owner approval of the nonce model and expiry limits (2026-11-08)

The owner approved §11.3.1 and §11.3.2. They are now decisions:
- **D-36** defines the approval nonce semantics and amends D-33.
- **D-37** sets the maximum approval expiry, including the binding of production authorisation.

D-33's plan entry now refers to D-36 for nonce semantics, so the original "single-use" wording is no longer ambiguous. Statements in §10 and §11 of this review that quote the old wording are historical.

### 12.1 What changed

| Requirement | Where |
|---|---|
| New decision amending D-33 | Plan D-36; D-33 entry reworded and marked "amended by D-36 and D-37" |
| One-time and standing nonce semantics | `discovery.md` §11.3.1 [D-36] |
| Repeated verification only of the identical payload, without consuming the nonce, extending expiry or adding scope | §11.3.1 rules |
| Rejecting changed payloads, reused one-time nonces, expired and revoked approvals | §11.3.1 rules; revocation of any standing approval through `revoke_record` |
| Re-check immediately before every protected operation | §11.3.1 rules [R-03, D-36] |
| Expiry table formal (no longer `[P]`) | §11.3.2 [D-37] |
| Production binds exact assets and operations | §11.3.2 production rules [D-37, R-09]; no A1 on production in V1 [D-21] |
| Fixtures and acceptance | §15.2 approval-misuse fixture extended; AC-14 extended [D-36, D-37] |

### 12.2 Validation

| Check | Result |
|---|---|
| Conflicting "single-use" claims | ✅ None left in `discovery.md` or the plan. The earlier mentions in this review (the §10 B-1 row and §11) are marked historical and superseded by D-36 |
| Every approval type has one-time or standing semantics | ✅ All nine actions are classed in §11.3.1 and listed in D-36 |
| Expiry limits match | ✅ §11.3.2 and D-37 agree: 30 days / 24 hours / 1 hour / 90 days, as applicable |
| References, decision IDs, ACs, tables | ✅ D-01–D-37 defined and none undefined; R, T, AC and `§` references resolve; tables well-formed (see completion report) |
| Same-user nonce-ledger rollback | ✅ Kept in §9, §11.3, §11.3.2 and §13.8 and in D-36. Sentinel claims **no** replay protection beyond the expiry bound |

### 12.3 Freeze status

**NOT READY TO FREEZE**, but only these steps remain:
1. Render the 8 Mermaid diagrams (only statically checked so far).
2. The owner's explicit freeze approval.

No architectural blocker remains.

## 13. Mermaid visual validation (2026-11-08)

**Result: rendering pending.** No diagram has been visually validated.

Obsidian couldn't be used in this environment without changes the owner hasn't approved:
- **Opening the file:** Obsidian only opens files inside a registered vault. The only registered vault is the owner's personal iCloud vault. Opening `discovery.md` would mean either copying it into that synced vault or making the SENTINEL repository a vault, which adds a `.obsidian/` folder and changes Obsidian's configuration.
- **Inspecting the result:** the review environment can't view a desktop application's window. A full-screen capture would need macOS Screen Recording permission and would capture unrelated screen content.

Per the instruction, static validation is **not** substituted for visual validation.

| # | Diagram | Section | Visual result |
|---|---|---|---|
| 1 | Component overview (flowchart) | §3 | ⏳ Pending |
| 2 | Audit pipeline (flowchart) | §3 | ⏳ Pending |
| 3 | Check lifecycle (stateDiagram-v2) | §5 | ⏳ Pending |
| 4 | Audit states (stateDiagram-v2) | §8.1 | ⏳ Pending |
| 5 | Authorisation enforcement (sequenceDiagram) | §11 | ⏳ Pending |
| 6 | Local vs external zones (flowchart) | §13.1 | ⏳ Pending |
| 7 | Integration boundaries (flowchart) | §14 | ⏳ Pending |
| 8 | Roadmap dependencies (flowchart) | §16 | ⏳ Pending |

**Ways to complete it (owner's choice):**
1. The owner opens `docs/architecture/discovery.md` in Obsidian (for example by adding the SENTINEL folder as a vault) and checks each diagram for missing nodes, broken arrows, wrong transitions, clipping and unreadable labels.
2. The owner approves a specific renderer, and visual inspection is done from its output.

No Mermaid content was changed. The architecture is **not frozen**.
