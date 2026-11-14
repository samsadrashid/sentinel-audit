# M3–M10 independent verification (2026-11-10)

**No milestone from M3 to M10 is accepted.** §11 and §12 record the owner-directed correction cycles of 2026-11-10. §12 is the current state. This document is a recommendation for the owner's decision.

Nothing was staged, committed or pushed. The Git index is untouched, and nothing was downloaded.

## 1. Verification summary

I re-inspected the M3–M10 source code, schemas, CLI wiring, adapter registration and policy integration, then probed the boundaries with hostile and malformed inputs.

**What holds:**

- The implementation is real and connected to Sentinel Core.
- The analyzers, plugins, MCP server, compare and self-check are all reachable through the CLI and orchestrator.
- The new adapters appear in `default_adapters` and the native allowlist.
- No new path returns PASS for a missing, unapproved, failed or timed-out check.

**What I fixed:**

- **V-1 (High):** a hostile plugin could abort the entire audit. This was the only security-relevant defect found. I applied a minimal fix and added a regression test.

**Accuracy findings reported for your approval (not fixed):**

- V-2: in M9, a finding that moves lines is reported "resolved".
- V-3: M3 domain coverage is labelled "covered" when only partly covered.

## 2. Tests actually executed (this session, macOS host)

| Check | Result |
|---|---|
| Full suite `pytest --ignore=tests/test_m2_real_scanners.py`, after the V-1 fix | 1483 collected, **exit 0**, 0 failed, 0 skipped |
| `tests/test_plugins.py`, including the 6 new V-1 regression cases and the real-Seatbelt hostile plugin | 27 passed |
| `tests/test_native_analyzers.py` and `tests/test_d10_d11.py`, including 6 real-Seatbelt analyzer runs | pass (exit 0) |
| M3 re-measure with real scanners (`scripts/m3/measure.py --out <scratch>`; recorded `metrics.json` not overwritten) | Identical to the recorded figures (§6) |
| `ruff check .`, `ruff format --check .` (166 files), `mypy --strict` (61 files) | clean |
| `scripts/docs/check_architecture_docs.py .` | PASS |
| `scripts/license_audit.py check --strict` | 0 issues (3 acknowledged ambiguous-licence entries, unchanged) |
| Malformed-input probes against all six analyzers (scratch script, §4) | See V-1, V-4 and V-5 |
| `sentinel history verify` on the real state directory | Not applicable: no run key, so no local history exists |

**Not executed:**

- `tests/test_m2_real_scanners.py`;
- any mutation campaign (no defect justified one);
- the offline wheel test, which ran only as part of the full suite (`test_release.py`).

Previously reported results that I did not re-run separately: the 1477-test figure in the implementation report, superseded by the 1483 above.

## 3. Findings

### Critical

None.

### High

- **V-1: untrusted analyzer or plugin output could crash the whole audit. FIXED.**
  - **Cause:** `NativeAnalyzerAdapter.normalize` called `int(f["line"])` unguarded. A plugin printing `"line": []` or `1e999` raised `TypeError` or `OverflowError`. The orchestrator catches only `BlockedError`, so the audit ended as an internal error and every other check's results were lost.
  - **Impact:** it still failed closed (no PASS), but it contradicted the documented failure isolation and let a third-party plugin deny the entire audit.
  - **Fix** (`src/sentinel/adapters/native.py`): the conversion errors become `ValueError`, which gives that check `ERROR`, and `line` must lie within 0..10,000,000.
  - **Regression test:** `test_malformed_finding_fields_are_check_errors_not_engine_crashes`, 6 cases.
- **V-2: M9 reports moved findings as fixed and "resolved". NOT FIXED; needs approval.**
  - **Cause:** code findings are fingerprinted by `file:line` (M1 `location_key`). Shift a vulnerable line without fixing it and `compare` lists it as fixed plus introduced, and the fix-plan item as `resolved`.
  - **Impact:** a remediation-verification claim can be false.
  - **Options:**
    1. A line-independent key for code findings (rule + file + normalised snippet hash). This changes the M1 fingerprint semantics and needs a new decision.
    2. Downgrade to `unverified` whenever an "introduced" finding shares rule and file with a "fixed" one. This is local to `compare.py`.

### Medium

- **V-3: M3 `domain_coverage.status = "covered"` when only some validated checks completed.**
  - **Example:** with Checkov `NOT_RUN`, D08 still shows `covered`. The `checks_not_completed` list is present, but the status label overstates coverage.
  - **Suggested fix:** add a `partial` status.
- **V-4: one malformed `package-lock.json` disables the whole supply-chain check.** A `"packages"` value that isn't an object raises `AttributeError`. The check becomes `ERROR`, which is fail-closed, but any target can switch the M8 check off with one file. Per-file error handling is needed.
- **V-5: no "unparseable" finding for some malformed inputs.** Malformed `Info.plist` and `.entitlements` (iOS) and `.reg` files (oscfg) are silently skipped, with no finding. Android reports `manifest-unparseable`, so iOS and oscfg are inconsistent and the coverage gap is invisible.
- **V-6: plugin TOCTOU.** The entry hash is verified, then the file is executed by path from the plugin directory. Anyone able to write that directory between the check and the exec can swap the code. That requires local write access to an operator-chosen directory. Mitigation: copy the verified bytes into the disposable workspace and run the copy.
- **V-7: a planted `.py` file in an installed package is reported misleadingly.** `self-check` reports it as `unverifiable` with reason `editable_or_development_install`, rather than as tampering. Planted non-`.py` files are not detected at all. It still never reports `verified`.

### Low

- **V-8: severity label mismatch in risk totals.** `compare.risk` weights `info`, but engine severity is `informational`. Informational findings land under an extra key with weight 0, so totals are correct but the label is inconsistent.
- **V-9: plugin pin name not checked against the manifest.** The pin name isn't compared with the manifest `name`. The pinned hash still binds the content.
- **V-10: the MCP server has no client authentication** (stdio; the trust boundary is the launching process). This is documented; I'm restating it.
- **V-11: overstated M6 claim.** The implementation report says plugin "permissions equal the non-grantable minimum". That is correct, but plugins share the analyzer S1 profile, and there is no Linux or Windows runner.

## 4. Security boundary and fail-closed verification

| Boundary | Evidence | Result |
|---|---|---|
| Scanner unavailable or unapproved | measure run: Trivy, Grype and Checkov `NOT_RUN scanner_not_approved`; never PASS | Holds |
| Analyzer hash mismatch or no isolation | `native.execute`: `binary_hash_mismatch` and `host_isolation_unavailable` give `NOT_RUN`; the orchestrator drops all output from `NOT_RUN` | Holds |
| Plugin network, write and home read | Real Seatbelt hostile plugin: all three denied, target unchanged | Holds |
| Plugin manifest and entry integrity | Hash re-checked before each run; tamper gives `plugin_manifest_hash_mismatch` or `plugin_entry_hash_mismatch` | Holds (TOCTOU V-6) |
| Plugin crash, timeout or bad output | Real-sandbox tests give `ERROR` | Holds, after the V-1 fix |
| Plugin privilege requests | network, write or execute gives `plugin_permission_denied`, not downgraded | Holds |
| MCP tool surface | Trust and state tools give `tool_not_exposed`; no `--output`; caller fixed to `mcp`; agent `caller` argument rejected; D-41 still applies through environment detection | Holds |
| MCP arguments | Relative paths, NUL, non-UUID run IDs and unknown keys are rejected before argv is built | Holds |
| Prompt-injection boundary | MCP results are tagged `untrusted_content` and the verdict is the exit code; D11 findings are `suspected`, and no AI verification | Holds (detection is heuristic) |
| XML attacks (Android) | DOCTYPE and ENTITY refused (`manifest-unsafe-xml`) | Holds |
| Checksum path traversal (M8) | `../../../etc/passwd` gives `checksum-path-outside-target`; symlinks resolved and refused outside root | Holds |
| Secrets in evidence (D11) | Inline secret values are never printed (tested) | Holds |
| Compare | Different assets or the same run are refused; "fixed" needs the producer completed, else `unverified`; tampered run gives `EXIT_INTEGRITY` | Holds (V-2) |
| Self-check | Editable install gives `unverifiable` (exit 2); real wheel gives `verified`; a 1-byte tamper gives `mismatch` | Holds (V-7) |
| Unsupported host | Plugins and analyzers have only the macOS runner; without it, `NOT_RUN` | Holds; no Linux or Windows claim |

## 5. Missing coverage and unverified claims

- M4 iOS, M5 oscfg and M8 analyzers have recall fixtures only from unit tests. There is no measured R and F like M3's.
- M6 D10 and M7 D11 have no recall or false-positive measurement. The T2 set is 6 injections and 3 benign samples: a smoke set, not a benchmark.
- The new M6–M10 code has no mutation coverage (no new mutants, no campaign).
- MCP was tested in process and through a subprocess. It was not tested with a real MCP client (Claude Code or Codex).
- Self-check was tested on a wheel built locally offline. There is no published or signed artifact.
- Linux and Windows: nothing has been executed.

## 6. M3 recall and false-positive results (re-measured this session with real scanners)

| Domain | Recall | False positives | Clean fixtures with false positives | Checks not run |
|---|---|---|---|---|
| D01 | 1.0 (11/11) | 0 | 0/10 | Trivy, Grype |
| D02 | 1.0 (11/11) | 0 | 0/10 | Trivy, Grype |
| D08 | 0.8462 (11/13) | 0 | 0/10 | Checkov, Trivy, Grype |
| D14 | 0.8182 (9/11) | 0 | 0/10 | Checkov, Trivy, Grype |

These are identical to `docs/m3/metrics.json`, so the result is reproducible. All misses are Checkov-designated.

**Decisions still required:**

- R and F per domain (D-63, B-2);
- scanner acquisition (B-1);
- a re-measure after acquisition.

## 7. Outstanding external dependencies, hardware and platforms

| Item | Needed for |
|---|---|
| Trivy 0.76.2, Grype 0.121.2, Checkov 3.4.3, cosign 3.1.4, Trivy and Grype databases (B-1) | M3 |
| MobSF (B-7) | M4 |
| Fix for M2-SA-12, to enable B2 (B-6) | M4 and M8 archive fixtures |
| Linux and Windows hosts (B-4) | M5, M10; D06 |
| Signing device and SD-T01 to SD-T55 (B-5) | Signed release |
| Product specification for domain IDs (B-3) | All milestones |
| Remote CI | Still "not yet executed" |

## 8. Recommended corrections

| Order | Item | Notes |
|---|---|---|
| 1 | V-2 | Option 2 is cheap and local; option 1 needs a decision |
| 2 | V-3 | Add `partial` coverage status (schema change) |
| 3 | V-4, V-5 | Per-file error handling and "unparseable" findings |
| 4 | V-6 | Run the plugin from a copied, verified entry |
| 5 | V-7 | Report non-RECORD package files as `unexpected_file` (integrity) |
| 6 | V-8 | Normalise `informational` |
| 7 | Mutants | Add mutants for the V-1 guard, plugin refusal, MCP allowlist and compare "fixed" rule |

## 9. Milestone acceptance recommendation

| Milestone | Recommendation | Reason |
|---|---|---|
| M3 | **Do not accept yet** | Code INTEGRATION_TESTED and reproducible; blocked on B-1 and B-2; fix V-3 |
| M4 | **Do not accept** | Static analyzers INTEGRATION_TESTED; B2, MobSF and archive fixtures BLOCKED; V-5 |
| M5 | **Do not accept** | Configuration-snapshot analyzer only; PE, MSI and MSIX NOT_IMPLEMENTED; no Linux run (B-4) |
| M6 | **Conditionally acceptable after B-8** | D10 analyzer and plugin system INTEGRATION_TESTED and hostile-tested; fix V-6 first; no measured R and F |
| M7 | **Conditionally acceptable after B-8** | D11 analyzer, T2 smoke set and MCP server INTEGRATION_TESTED; no real-client test; heuristic detection |
| M8 | **Do not accept** | Structural binary extraction NOT_IMPLEMENTED; T8 needs B2; V-4 |
| M9 | **Do not accept until V-2 is fixed** | Compare and remediation INTEGRATION_TESTED, but can falsely report "resolved" |
| M10 | **Do not accept** | Self-check INTEGRATION_TESTED; signed release, cross-platform, Sentinel SBOM and licence review open |

No milestone is VERIFIED.

## 10. Decisions required from the owner

1. **B-1:** approve or amend the M3 scanner and database acquisition.
2. **B-2:** set R and F per domain.
3. **B-8:** keep, move or drop the plugin system and MCP server in M6 and M7.
4. **V-2:** choose option 1 (new fingerprint decision) or option 2 (local `compare` guard).
5. **Corrections:** authorise V-3 to V-8 as a correction cycle, or defer them.
6. **B-7:** MobSF, yes or no.
7. **B-3:** provide the specification, or confirm the provisional domain labels.
8. **B-4 and B-5:** provide hosts and schedule the signing ceremony.
9. **Commit:** whether to authorise a commit of the current working tree, which includes the V-1 fix.

### Files changed in this verification

- `src/sentinel/adapters/native.py`: V-1 guard.
- `tests/test_plugins.py`: V-1 regression test.
- `docs/roadmap/m3-m10-independent-verification.md`: this report.

## 11. Correction cycle (owner decisions, 2026-11-10)

Scope: only the corrections the owner directed. No milestone was reimplemented and no audit was repeated. Nothing was staged, committed, pushed or downloaded.

### 11.1 Corrections made

| ID | Correction | Files |
|---|---|---|
| V-1 | Retained, as accepted | `adapters/native.py`, `tests/test_plugins.py` |
| V-2 | **New append-only decision D-64.** Run comparison matches on a derived issue identity (domain, rule, asset, normalised file path, title); the line is metadata only. The stored `fingerprint` is unchanged. `fixed` and `resolved` need the same issue absent **and** every producer completed. Ambiguous duplicate counts (`ambiguous_identity`), a possible rule change at the same location (`possible_rule_change`) and an incomplete producer (`producer_not_completed`) are reported as `unverified`. Moved findings are `persisting` with `moved: true`. `compare_version` is now 2 | `docs/architecture-discovery-plan.md` (D-64 appended; D-48 and M1 decisions untouched), `compare.py`, cli-output schema, docs checker list |
| V-3 | Coverage states FULL, PARTIAL, NOT_RUN, ERROR and NOT_APPLICABLE. Each domain declares required adapters (D01 and D02: Semgrep; D08: Semgrep, OSV-Scanner, Trivy, Grype, Checkov; D14: Semgrep, Checkov, Trivy). FULL needs every required adapter to complete; one failing check of an adapter spoils it. `required_checks` (adapter, status, reason) is exposed in results (`runs show`, JSON report), the Markdown and HTML reports and `metrics.json` | `domains/__init__.py`, common schema, `reports/__init__.py`, `scripts/m3/measure.py`, mutation catalogue (anchor update plus one new mutant) |
| V-6 | Plugin verified-bytes execution. The manifest hash is computed over the bytes actually parsed. The entry is read once (`O_NOFOLLOW`, at most 256 KiB, UTF-8, no NUL), hashed, and those bytes run as `python -I -c <source> <root>`. The plugin directory isn't readable in the sandbox. New refusals: `plugin_entry_too_large`, `plugin_entry_invalid` | `plugins.py`, `adapters/native.py` (`program()` hook) |
| V-4, V-5 | Explicit `input-unparseable` findings (informational) for malformed `package-lock.json`, iOS `Info.plist` and `.entitlements`, launchd plists and `.reg` exports (a valid header is required). The supply-chain loop now isolates each file, so one bad input can't disable the check | `analyzers/_common.py`, `ios.py`, `oscfg.py`, `supplychain.py` |
| V-7 | A regular install with a file RECORD doesn't list gives `mismatch` / `unexpected_files`. Editable installs are detected through PEP 610 (`direct_url.json`) and reported `unverifiable` / `editable_install`. **New defect found and fixed:** `importlib.metadata` `files` silently drops RECORD entries whose file is gone, so deleted files were never detected. RECORD is now parsed directly | `release.py`, cli-output schema |
| V-8 | Risk totals use the engine label `informational` | `compare.py` |
| V-10 | MCP is documented as local-only, with no client authentication and never on a network or remote transport. No authentication or remote access was added | `mcp.py` docstring, `docs/user/mcp.md` |

### 11.2 Tests actually executed (after all corrections)

| Check | Result |
|---|---|
| Full suite `pytest --ignore=tests/test_m2_real_scanners.py` | **1515 collected, exit 0, 0 failed, 0 skipped** |
| `tests/test_compare.py` (V-2: line movement, genuine fix, incomplete check for four statuses, rule change, asset change, duplicates equal, unequal and exact, different file, informational label) | 14 collected, all pass |
| `tests/test_m3.py` (V-3: FULL, PARTIAL, ERROR, NOT_RUN, NOT_APPLICABLE parametrised; per-adapter spoil; historical labels still validate) | 40, all pass |
| `tests/test_plugins.py` (V-6: swap after verification with a fake runner and with the **real Seatbelt**; the replacement never ran, and the next run refuses it with `plugin_entry_hash_mismatch`; symlink, oversized and NUL entries) | 30, all pass |
| `tests/test_native_analyzers.py` (V-4, V-5: 9 malformed-input cases; bad lockfile doesn't disable other supply-chain findings; valid `.reg` still analysed) | 31, all pass |
| `tests/test_release.py` (V-7 on a real offline-built wheel install: verified; 1-byte tamper gives mismatch; restore gives verified, and `__pycache__` isn't flagged; planted `.py` and planted `schemas/*.json` give `unexpected_files`; deleted file gives `missing`) | 4, all pass |
| `ruff check .`, `ruff format --check .` (168 files), `mypy --strict` (61 files) | clean |
| `scripts/docs/check_architecture_docs.py .` (now includes D-64) | PASS |
| `scripts/license_audit.py check --strict` | 0 issues |
| M3 re-measure with real scanners, after all code changes (`docs/m3/metrics.json` rewritten; `coverage.json` not rewritten) | recall and false positives identical to before (§11.4) |
| Mutation campaign | **Not run.** Mutation coverage of the new code is not claimed. The catalogue anchors are valid, checked by `test_mutation_harness.py` |
| `tests/test_m2_real_scanners.py` | Not run |

### 11.3 Compatibility and migration

- **Fingerprints are unchanged.** Stored runs, suppressions, review decisions and evidence chains keep their meaning. D-64 identity is derived at comparison time from stored fields, so `compare` works on historical runs without migration.
- **Historical coverage labels** (`covered`, `not_covered`, `not_applicable`) are still accepted by the schema, so existing signed results still verify. New runs emit only the V-3 states. `required_checks` is optional, because old results lack it.
- **`compare` output** is now `compare_version: 2`. It has new fields (`identity`, `moved`, `reason`, `ambiguous`), and `open_by_severity` uses `informational`. It is never stored, so no migration is needed.
- **Plugins:**
  - An entry over 256 KiB, or one that isn't UTF-8, is now refused.
  - At run time an entry has no `__file__` and can't read its own directory.
  - Plugins written for the old path-based execution that rely on sibling files will stop working. This is intended.
- **Analyzer output:** inputs that were silently skipped now produce `input-unparseable` findings, so a previously PASS analyzer check on a malformed target is now FAIL with an informational finding.
- **Self-check:** a regular install with extra files now exits 5 (integrity) instead of 2.

### 11.4 Updated coverage states and metrics (real scanners, 20 fixtures per domain)

| Domain | Recall | False positives (findings, fixtures) | Coverage states across fixture runs | Required checks not completed |
|---|---|---|---|---|
| D01 | 1.0 (11/11) | 0, 0/10 | FULL 16, NOT_APPLICABLE 4 | none |
| D02 | 1.0 (11/11) | 0, 0/10 | FULL 20 | none |
| D08 | 0.8462 (11/13) | 0, 0/10 | **PARTIAL 20** | Trivy, Grype: NOT_RUN `scanner_not_approved`; Checkov: NOT_RUN `scanner_not_approved` or `not_planned`; OSV-Scanner `not_planned` where there's no manifest |
| D14 | 0.8182 (9/11) | 0, 0/10 | **PARTIAL 19**, NOT_APPLICABLE 1 | Checkov, Trivy: NOT_RUN |

Recall and false-positive figures are unchanged by V-3.

A required adapter that wasn't planned for a fixture (no inputs of its kind) counts as NOT_RUN, so the domain is PARTIAL, not FULL. A required check that ran and reported NOT_APPLICABLE counts as complete. This is conservative, and is documented in `domains/__init__.py`.

### 11.5 Remaining known defects and limitations

1. **V-9 (Low):** a plugin pin name is not checked against the manifest `name`. Not in this cycle's scope.
2. **Issue identity uses the finding title (D-64).** A scanner whose message embeds line-specific text gives a new identity when a finding moves. That case gives `fixed` plus `introduced` only if the old producer completed, and the "possible rule change" guard doesn't catch a title change. No such message was observed in the shipped rules or analyzers, but it is not proven for third-party scanners.
3. **The fix-plan text** still says "this finding fingerprint must no longer be reported". The wording predates D-64. The behaviour is correct (`compare` decides), but the text is stale.
4. **Coverage for an unplanned check:** required adapters that weren't planned because the input type is absent make a domain PARTIAL (see §11.4). The owner may prefer to treat that as NOT_APPLICABLE.
5. **Built-in analyzers still run from their package path** (the hash is checked, then the path is executed). V-6 was scoped to plugins, and the package directory is the installation's own code, which self-check covers.
6. **Carried over:** MCP has no authentication (documented, local only), D11 detection is heuristic, and no mutation coverage exists for the M6–M10 code.

### 11.6 Remaining decisions and blocked acceptance criteria

1. **B-1:** scanner and database acquisition. Needed for FULL coverage of D08 and D14, and for any change to their recall.
2. **B-2:** R and F thresholds per domain. M3 acceptance is impossible without them.
3. **B-8:** keep, move or drop the plugin system and the MCP server.
4. **§11.5 item 4:** whether an unplanned required check should count as NOT_APPLICABLE.
5. **Mutation campaign:** whether to run a targeted one for the V-1 to V-8 and D-64 code before acceptance.
6. **B-3, B-4, B-5, B-6, B-7:** unchanged (specification, hosts, signing ceremony, M2-SA-12 / B2, MobSF).
7. **Commit:** whether to authorise a commit of the working tree.

| Milestone | Recommendation after the corrections |
|---|---|
| M3 | Not accepted; blocked on B-1 and B-2 |
| M4 | Not accepted; B-6 and B-7 blocked |
| M5 | Not accepted; B-4 blocked; PE, MSI and MSIX not implemented |
| M6 | Conditionally acceptable after B-8 (V-6 is fixed) |
| M7 | Conditionally acceptable after B-8 |
| M8 | Not accepted; binary structural extraction not implemented; B-6 blocked |
| M9 | Conditionally acceptable after owner review of D-64 (V-2 is fixed) |
| M10 | Not accepted; B-4 and B-5 blocked; Sentinel SBOM and licence review open |

## 12. Final targeted corrections and mutation verification (2026-11-10)

**Owner decisions applied:**

- NOT_APPLICABLE needs explicit discovery evidence.
- The plugin system and the MCP server are kept as separate optional capabilities.
- MCP stays local-only, read-only and unauthenticated.
- A targeted mutation campaign was run.
- No commit is authorised.

Nothing was staged, committed, pushed or downloaded. The Git index is as it was at session start: the 3 pre-existing staged files are untouched.

### 12.1 Corrections

| ID | Correction | Tests |
|---|---|---|
| A | **Plugin identity.** The policy pin name must equal the verified manifest `name`. A mismatch gives `plugin_name_mismatch` before any execution. The same verified manifest bytes, hashed as parsed, and the same verified entry bytes, read once and executed as `-c`, are used for the run | Mismatched name; renamed and re-pinned manifest; changed manifest; manifest re-pointed after a swap; entry swapped after the manifest check; entry replaced by a symlink after the check; manifest changing after it was read |
| B | **Fix-plan wording** now follows D-64. Items say the item is resolved only if the same issue (D-64 identity, not the line) is absent and every producing check completed. Items stay keyed by the stored fingerprint for compatibility; `plan_version` is unchanged; `remediation_verified` is always false | `test_plan_uses_d64_resolution_wording_and_stays_keyed_by_fingerprint`; the compare tests cover `resolved` only after a completed check |
| C | **NOT_APPLICABLE with evidence only.** A required adapter is NOT_APPLICABLE only if discovery of every asset is complete (`truncated: false`), reports the adapter's input kinds, and finds none. The input kinds are: Semgrep, languages; OSV-Scanner and Grype, ecosystems; Trivy, ecosystems, container or IaC files; Checkov, IaC or container files. The evidence string goes into `required_checks[].evidence`. An adapter's own NOT_APPLICABLE without that evidence is `NOT_RUN` (`not_applicable_without_evidence`). Missing or unapproved scanners, ERROR (including malformed output and timeouts), BLOCKED and adapters without declared inputs never become NOT_APPLICABLE. FULL needs at least one check that ran, and PARTIAL needs at least one check that ran | Genuine absence gives N/A and FULL; present input with an unplanned check gives NOT_RUN and PARTIAL; empty, truncated, incomplete, missing-kind and multi-asset discovery give NOT_RUN; unsupported N/A claim; missing, unapproved, bad-output, timeout and cancelled; an adapter without inputs; all-N/A is never FULL |
| M2 tests | **Concrete regression found:** `tests/test_m2_real_scanners.py`, which earlier cycles had excluded, had been failing since M3. Its expectations were updated minimally (§12.6) | Now passes in the full run |

### 12.2 Targeted mutation campaign (exact scope)

**Harness.** `scripts/mutation/harness.py`, engine suite, which is the full `tests/` tree per mutant (`-x`), 4 jobs. The unlocked-session preflight passed.

**Mutants.** 43 new mutants (`eng-t-*` in `scripts/mutation/mutations.py`). Only these mutants and this code are covered:

| Area | Mutants |
|---|---|
| D-64 identity and compare (`compare.py`) | title, line-in-identity, rule, asset, producer-completed, rule-change guard, moved pairing, ambiguous duplicates, resolved mapping, completed-status set (10) |
| Risk aggregation | informational weight (1) |
| Coverage (`domains/__init__.py`) | truncated discovery, input present, no discovery, PARTIAL needs ran, N/A claim without evidence, unplanned N/A evidence (6) |
| Plugins (`plugins.py`) | name check, pin name passed, entry re-hash, size cap, NUL, O_NOFOLLOW, run path versus `-c`, extra-read, GRANTABLE, manifest digest over parsed bytes (10) |
| V-1 (`native.py`) | line range (1) |
| MCP (`mcp.py`) | tool allowlist, caller fixed, unknown args, absolute paths, isError (5) |
| Self-check (`release.py`) | missing, hash, editable detection, unexpected files, pycache exclusion (5) |
| Malformed input | supply-chain per-file guard, lockfile shape, iOS Info.plist, `.reg` header (4) |
| Report generation | Markdown domain-coverage section (1) |

**Results:**

| Round | Caught | Survived | Invalid | Infrastructure errors |
|---|---|---|---|---|
| 1: all 43 | 34 | 9 | 0 | 0 |
| 2: the 9 survivors, after focused tests | 8 | 1 | 0 | 0 |
| **Final** | **42 of 43** | **1** | **0** | **0** |

The two failed launches before round 1 are not counted. One was a shell argument error. The other failed its baseline because of the M2 test regression (§12.6), so no mutant ran.

**Round 1 survivors:** all 9 were test gaps, not product defects. Each now has a focused test:

| Mutant | Gap closed |
|---|---|
| `eng-t-d64-title`, `eng-t-d64-asset` | Identity distinctness, including a multi-asset scope |
| `eng-t-risk-informational` | Informational weight |
| `eng-t-plug-entry-hash`, `eng-t-plug-nofollow`, `eng-t-plug-manifest-raw-digest` | Swap and race between the manifest check and the read |
| `eng-t-sc-per-file` | Inputs that really crash a handler: `"dependencies": 5`, and a NUL in a checksum path |
| `eng-t-report-coverage` | Markdown and HTML coverage sections |

**Remaining survivor:** `eng-t-sc-lock-type` is an **equivalent mutant**. Removing the lockfile-shape check leaves the per-file guard to emit the identical `input-unparseable` finding for `package-lock.json`.

**Not covered:**

- The earlier 365 catalogue mutants were not rerun.
- Code outside the scope above has no new mutation evidence: the D10 and D11 analyzers beyond malformed input, HTML escaping, and the analyzers' detection rules.

### 12.3 Final verification (executed after all corrections)

| Check | Result |
|---|---|
| **Full suite, including `tests/test_m2_real_scanners.py`** (real Gitleaks, Semgrep, OSV-Scanner and Syft, Podman and Seatbelt) | **1560 collected, exit 0, 0 failed, 0 skipped** |
| `ruff check .`, `ruff format --check .` (168 files), `mypy --strict` (61 files) | clean |
| `scripts/docs/check_architecture_docs.py .` | PASS |
| `scripts/license_audit.py check --strict` | 0 issues |
| Package checks | Offline wheel build, install, RECORD verification and tamper tests (`test_release.py`); sdist and schema distribution tests in the suite |
| Historical compatibility | Old coverage labels validate; fix-plan stays keyed by fingerprint; D-64 identity is derived from stored fields; M1 and M2 history, evidence and decision tests pass in the full suite |
| M3 re-measure with real scanners (`docs/m3/metrics.json`) | §12.4 |

### 12.4 M3 coverage and metrics (real scanners, 10 vulnerable and 10 clean fixtures per domain)

| Domain | Recall | False positives (findings / clean fixtures) | Coverage states | Required-check evidence |
|---|---|---|---|---|
| D01 Web | **1.0** (11/11) | 0 / 0 of 10 | FULL 16, NOT_APPLICABLE 4 | Semgrep PASS or FAIL |
| D02 API | **1.0** (11/11) | 0 / 0 of 10 | FULL 20 | Semgrep PASS or FAIL |
| D08 Backend | **0.8462** (11/13) | 0 / 0 of 10 | **PARTIAL 20** | Trivy and Grype NOT_RUN `scanner_not_approved`; Checkov NOT_RUN `scanner_not_approved` where IaC exists, else NOT_APPLICABLE `no_input` (discovery evidence); OSV-Scanner PASS, FAIL or NOT_APPLICABLE `no_input` |
| D14 Database | **0.8182** (9/11) | 0 / 0 of 10 | **PARTIAL 19**, NOT_APPLICABLE 1 | Checkov and Trivy NOT_RUN `scanner_not_approved`, or Checkov NOT_APPLICABLE `no_input` |

Recall and false positives are unchanged across all four measurements this session. D08 and D14 cannot reach FULL until Trivy, Grype and Checkov are approved (B-1). No threshold was chosen (B-2).

### 12.5 Remaining defects and risks

1. **D-64 title sensitivity.** A scanner whose message embeds line-specific text gives a new identity when the line moves. The rule-change guard doesn't cover a title change. Not observed in the shipped rules.
2. **Built-in analyzers run from their package path** (hash check, then path execution). This was out of the plugin scope, and self-check covers the installed package.
3. **D11 prompt-injection detection is heuristic.** The T2 set is a smoke set.
4. **The MCP server has no client authentication.** It is local stdio only, by decision.
5. **Equivalent mutant `eng-t-sc-lock-type`** (layered defence).
6. **The plugin entry runs as `-c` source.** No `__file__`, no sibling files, 256 KiB cap (documented in §11.3).
7. **Earlier cycles excluded the real-scanner M2 module from their full-suite runs**, which hid its regression; §12.6 corrects that. All figures in §12.3 include it.

### 12.6 M2 test expectation update (concrete regression)

`test_ac02_real_full_audit_leaves_the_target_unchanged` and `test_no_isolation_means_not_run_never_unsandboxed` predate the M3 adapters. M3 behaviour is correct and fail-closed:

- unapproved Trivy, Grype and Checkov are `NOT_RUN` / `scanner_not_approved`, before any isolation check;
- the full audit's overall result is therefore `INCOMPLETE`, not `FAIL`;
- Checkov plans nothing without IaC input.

The tests now:

- keep the exact M2 expectations for the four M2 scanners;
- require the M3 adapters to be `NOT_RUN` / `scanner_not_approved`;
- expect `INCOMPLETE`.

No engine code changed for this, and no M2 security assertion was weakened.

### 12.7 Readiness for formal owner acceptance review

| Milestone | Recommendation |
|---|---|
| M3 | **Not ready.** Code and measurement are verified and reproducible. Blocked on B-1 (scanners), and on B-2 (thresholds), which only you can set |
| M4 | Not ready: B2 (B-6) and MobSF (B-7) blocked |
| M5 | Not ready: Linux and Windows hosts (B-4); PE, MSI and MSIX not implemented |
| M6 | **Ready for acceptance review** as an optional capability: the D10 analyzer plus the plugin system (identity, verified-bytes execution, hostile-plugin isolation; mutation-tested) |
| M7 | **Ready for acceptance review** as an optional capability: the D11 analyzer plus the local-only MCP server (mutation-tested). Note that detection is heuristic |
| M8 | Not ready: binary structural extraction not implemented; B-6 blocked |
| M9 | **Ready for acceptance review:** D-64 compare, remediation and risk are mutation-tested |
| M10 | Not ready: signed release (B-5), cross-platform (B-4), Sentinel SBOM and licence review open |

No milestone is VERIFIED or accepted.

### 12.8 Outstanding external, hardware and platform dependencies

| Item | Needed for |
|---|---|
| B-1: Trivy 0.76.2, Grype 0.121.2, Checkov 3.4.3, cosign 3.1.4, Trivy and Grype databases | M3 |
| B-2: R and F thresholds | M3 |
| B-3: product specification for domain IDs | All domain labels |
| B-4: Linux and Windows hosts | M5, M10, D06 |
| B-5: signing device and SD-T01 to SD-T55 | Signed release |
| B-6: M2-SA-12, to enable B2 | M4 and M8 archive fixtures |
| B-7: MobSF decision | M4 |
| Remote CI | Still "not yet executed" |
| Commit | Not authorised |
