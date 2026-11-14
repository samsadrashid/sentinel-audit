# M6, M7, M9 formal acceptance review (2026-11-10)

**Status: review findings for the owner. No milestone is accepted by this document.** The "Gap closure" section at the end supersedes the classifications above where they differ. No features or architecture were changed during this review. Nothing was staged, committed, pushed or downloaded. The Git index is as it was at session start: 3 pre-existing staged files, untouched.

Classification:

- **VERIFIED:** the requirement is implemented, connected to Sentinel Core, and demonstrated by named tests that were executed in this review, including where relevant a mutation that the tests caught.
- **PARTIALLY_VERIFIED:** implemented, but evidence is incomplete, or the requirement is only partly met.
- **NOT_VERIFIED:** not implemented, or no acceptance criterion to verify against.
- **BLOCKED:** depends on an external item.

Roadmap rows (`docs/architecture/discovery.md`, milestones table):

| Milestone | Deliverables | Acceptance criteria | Excluded |
|---|---|---|---|
| M6 (D10) | Manifest and permission analysers | Domain ACs | Installing extensions into a live browser or IDE |
| M7 (D11) | Agent and MCP configuration analysers; prompt-injection fixture set | T2 fixtures pass; domain ACs | Live interaction with third-party models |
| M9 | Four report types; severity and confidence model; dedup and signed suppressions; `verify` workflow; signed human review decisions (D-26) | AC-05, AC-06, AC-13; reports state coverage and residual risk | Automatic fixes |

**Owner scope decision of 2026-11-10:** the Sentinel plugin system (M6) and the local MCP server (M7) are kept as optional capabilities. They are reviewed here in addition to the roadmap rows. M9's run comparison and remediation tracking (D-64) are likewise reviewed in addition to the roadmap row.

## Tests executed in this review (macOS host, `.venv`, Python 3.13)

| Test file | Passed | Failed | Skipped |
|---|---|---|---|
| `tests/test_plugins.py` (7 real-Seatbelt tests) | 37 | 0 | 0 |
| `tests/test_d10_d11.py` | 15 | 0 | 0 |
| `tests/test_native_analyzers.py` (real-Seatbelt runs of the D10 and D11 analyzers) | 33 | 0 | 0 |
| `tests/test_mcp.py` (includes a stdio subprocess round trip) | 23 | 0 | 0 |
| `tests/test_compare.py` | 16 | 0 | 0 |
| `tests/test_fixplan.py` | 9 | 0 | 0 |
| `tests/test_findings_reports.py` | 17 | 0 | 0 |
| `tests/test_aud19.py` | 30 | 0 | 0 |
| `tests/test_foundation.py` | 41 | 0 | 0 |
| `tests/test_m2_secret_class.py` | 37 | 0 | 0 |

**Prior evidence**, from the same working tree, not rerun in this review:

- The full suite of 1560 tests, including the M2 real-scanner module, passed with exit 0.
- The targeted mutation campaign caught 42 of 43 mutants. The one survivor is equivalent. Mutant IDs `eng-t-*` are in `scripts/mutation/mutations.py`; scope and results are in `docs/roadmap/m3-m10-independent-verification.md` §12.2.

---

## M6: plugins and extensions (D10)

### M6.1 Roadmap requirements

| # | Requirement | Implementation | Tests | Class |
|---|---|---|---|---|
| R6.1 | Manifest and permission analyser: browser extensions | `src/sentinel/analyzers/extensions.py` `browser()`; registered as `ExtensionsAdapter` in `adapters/native_registry.py`; hash-allowlisted through `builtin_native_allowlist`; reaches audits through `cli.default_adapters` | `test_d10_d11.py::test_browser_extension_manifest`, `::test_minimal_extension_and_ordinary_package_json_are_clean`; `test_native_analyzers.py::test_analyzers_run_inside_the_real_sandbox[ExtensionsAdapter]` | **VERIFIED** (for the implemented rule set) |
| R6.2 | Manifest and permission analyser: IDE extensions | `extensions.py` `vscode()` (VS Code only) | `test_d10_d11.py::test_vscode_extension` | **PARTIALLY_VERIFIED**. VS Code only; JetBrains and other IDEs are not analysed |
| R6.3 | Domain ACs | None are defined for D10. There are no R and F measurements; the domain label `extensions` is provisional (B-3) | — | **NOT_VERIFIED**. There is no AC to verify against |
| R6.4 | Exclusion: no installing into a live browser or IDE | The analyzer only reads JSON, inside Seatbelt, read-only | Real-sandbox test: the target is unchanged | **VERIFIED** |

### M6.2 Plugin system (optional capability)

| # | Requirement | Implementation | Tests (and mutants caught) | Class |
|---|---|---|---|---|
| P6.1 | Pinned or nothing: only plugins in the approved policy load; no auto-discovery | `policy.py` `plugins` field; `plugins.parse_pins` (name regex, absolute path, 64-hex hash); `cli.default_adapters` adds only `plugin_adapters(pol.plugins)` | `test_plugins.py::test_valid_plugin_inspects_and_its_pin_parses`, `::test_unpinned_or_missing_plugins_never_load` | **PARTIALLY_VERIFIED**. Pin parsing is tested, but no end-to-end test runs an audit with a signed policy containing a plugin pin. Policy approval itself is the existing, tested M1 mechanism |
| P6.2 | Verified manifest identity: the pin name equals the manifest name | `plugins.load_manifest(..., expected_name)` returns `plugin_name_mismatch`; `_verified()` passes `pin.name` | `::test_pin_name_must_match_the_verified_manifest_name`, `::test_renamed_manifest_with_repinned_hash_still_needs_matching_pin_name` (mutants `eng-t-plug-name-check` and `eng-t-plug-name-passed` caught) | **VERIFIED** |
| P6.3 | Manifest integrity: the pinned hash is over the bytes parsed | `load_manifest`: `hashlib.sha256(raw)` on the bytes passed to `json.loads` | `::test_manifest_and_entry_tampering_after_pinning`, `::test_changed_manifest_after_pinning_is_refused_even_with_same_name`, `::test_manifest_hash_is_over_the_bytes_that_were_parsed` (`eng-t-plug-manifest-raw-digest` caught) | **VERIFIED** |
| P6.4 | The exact verified bytes are executed | `PluginAdapter.program()`: one read, hash compared with `entry_sha256`, the same bytes passed as `python -I -c <source>`; the plugin directory is not readable at run time (`execute_extra_read() == []`) | `::test_swap_after_verification_does_not_change_the_program`, `::test_swap_after_verification_never_executes_the_replacement` (real Seatbelt), `::test_entry_swapped_between_manifest_check_and_read_is_refused` (`eng-t-plug-run-path`, `-extra-read` and `-entry-hash` caught) | **VERIFIED** |
| P6.5 | Hash and symlink replacement resistance | `O_NOFOLLOW` open; `is_symlink` refusal in `load_manifest`; 256 KiB cap; UTF-8 and no NUL | `::test_symlinked_oversized_or_nul_entries_are_refused`, `::test_entry_replaced_by_symlink_after_manifest_check_is_refused`, `::test_manifest_swapped_between_runs_uses_fresh_verification` (`-nofollow`, `-entry-size` and `-nul` caught) | **VERIFIED** |
| P6.6 | Sandbox restrictions: no network, no writes to the target, no home reads | Runs only through the verified native S1 runner; no runner gives `NOT_RUN host_isolation_unavailable` | `::test_hostile_plugin_gets_no_network_no_writes_and_no_home` (real Seatbelt), `::test_plugin_without_isolation_does_not_run`, `::test_pinned_plugin_runs_isolated_with_provenance` | **VERIFIED on macOS**. **BLOCKED** for Linux and Windows (no plugin runner; B-4) |
| P6.7 | No unauthorised permissions; refused, not downgraded | `GRANTABLE` exact match gives `plugin_permission_denied`; API, activity-class and version window checked | `::test_manifests_that_ask_for_more_are_refused_not_downgraded` (9 cases; `eng-t-plug-grantable` caught) | **VERIFIED** |
| P6.8 | Failure isolation: crash, timeout or bad output gives the plugin's check ERROR, never PASS, without aborting the audit | `NativeAnalyzerAdapter.execute` maps nonzero exit, timeout, truncation and bad output to `ERROR`; V-1 guard in `normalize` (`TypeError`, `OverflowError` and out-of-range line become `ValueError`, giving ERROR) | `::test_failing_plugins_are_error_and_never_pass` (real Seatbelt: exit, bad JSON, wrong tool, timeout), `::test_malformed_finding_fields_are_check_errors_not_engine_crashes` (6 cases; `eng-t-v1-line-range` caught) | **PARTIALLY_VERIFIED**. Proven at adapter level. No orchestrator-level test runs a failing plugin alongside other checks and confirms they complete. The orchestrator catches only `BlockedError`, so isolation depends on the adapter never raising, which is shown for the tested inputs only |
| P6.9 | Provenance: findings prefixed `plugin.<name>.` with the plugin version | `PluginAdapter.normalize`; `program()` returns the manifest version as `scanner_version` | `::test_pinned_plugin_runs_isolated_with_provenance` | **PARTIALLY_VERIFIED**. The manifest hash is in the policy description, but not in each finding's `sources` entry |
| P6.10 | Read-only `plugin inspect` that pins nothing | `plugins.inspect`, `cli.cmd_plugin_inspect`, cli-output contract `plugin_inspect` | `::test_cli_inspect` | **VERIFIED** |

### M6 residual risks and unsupported claims

1. **No D10 recall or false-positive measurement.** The rule set is small: 6 browser rules and 3 VS Code rules.
2. **Isolation is macOS Seatbelt S1 only.** Same-user processes can still alter a plugin directory between runs; each run re-verifies, so a swapped entry is refused rather than run.
3. **Plugin entries are single-file, stdlib only.** No `__file__`, no sibling files, 256 KiB cap. This is by design.
4. **Unsupported claim to avoid:** D10 "domain coverage". There is no AC and no measured coverage.

### M6 recommendation

- **Plugin system (optional capability): acceptable**, with two conditions you may waive:
  1. an end-to-end test of a signed-policy plugin audit (P6.1);
  2. an orchestrator-level failure-isolation test (P6.8).
- **D10 roadmap deliverable: do not accept as a domain.**
  - It is a working static analyser with no defined domain ACs.
  - Either accept it as "analyser delivered, ACs deferred" by a dated decision, or define the D10 ACs and thresholds first.

---

## M7: AI agents and MCP (D11)

### M7.1 Roadmap requirements

| # | Requirement | Implementation | Tests | Class |
|---|---|---|---|---|
| R7.1 | Agent and MCP configuration analyser | `src/sentinel/analyzers/agents.py`: unpinned MCP servers, shell wrappers, inline secrets (named, never printed), plaintext remote, permissive Claude settings, Codex sandbox off or never-approve; registered as `AgentsAdapter` | `test_d10_d11.py::test_mcp_config`, `::test_agent_settings_and_codex`; real Seatbelt `test_analyzers_run_inside_the_real_sandbox[AgentsAdapter]` | **VERIFIED** (for the implemented rule set) |
| R7.2 | Prompt-injection fixture set; T2 fixtures pass | `agents.INJECTION` patterns plus `HIDDEN` (tag, zero-width and bidi characters); applied to instruction files and MCP config text | `::test_t2_injection_fixtures_are_detected` (6), `::test_t2_benign_instructions_are_clean` (3), `::test_hidden_unicode_and_injected_tool_description` | **PARTIALLY_VERIFIED**. All fixtures pass, but the set is a 6-injection and 3-benign smoke set authored alongside the patterns. It is not an independent corpus, and detection is heuristic (§M7.4) |
| R7.3 | Domain ACs | None are defined for D11. The label `ai-agents` is provisional | — | **NOT_VERIFIED** |
| R7.4 | Exclusion: no live interaction with third-party models | No model or network call anywhere; Seatbelt denies network | Real-sandbox hostile test (shared S1 profile) | **VERIFIED** |

### M7.2 MCP server (optional capability)

| # | Requirement | Implementation | Tests (and mutants caught) | Class |
|---|---|---|---|---|
| S7.1 | Read-only tool exposure (allowlist) | `mcp.TOOLS`: status, audit, runs_list, runs_show, evidence_verify, report, fix_plan, policy_validate, plugin_inspect. `report` and `fix_plan` never take `--output` | `test_mcp.py::test_initialize_and_tools_list_expose_only_the_allowlist`, `::test_arguments_are_validated_before_any_argv_is_built[report-…output]` and `[fix_plan-…]` (`eng-t-mcp-allowlist` caught) | **PARTIALLY_VERIFIED**. All tools are read-only except `audit`, which by design writes a new signed run (evidence and manifest) to Sentinel's state directory. It never writes to the target or the trust store |
| S7.2 | Caller identity fixed to `mcp` | The audit builder appends `--caller mcp`; a `caller` argument is rejected as unknown. D-41 agent detection from the environment still applies in `cli._agent_integration` | `::test_audit_caller_is_fixed_and_agent_cannot_override_it` (`eng-t-mcp-caller` caught) | **VERIFIED** |
| S7.3 | No access to trust-store or signing operations | `key`, `approval`, `review`, `suppress`, `decisions`, `policy_change`, `prune`, `init`, `cancel`, `pause`, `resume` and `history` give `tool_not_exposed` | `::test_trust_and_state_operations_are_refused` (8 names), stdio round trip (`key` refused) | **VERIFIED** for the trust store, operator keys and approvals. **Note:** an MCP `audit` makes the engine sign its own run manifest with the run key, as every audit does. That is engine-internal and not caller-controlled |
| S7.4 | Argument validation before argv | `_check_args` (unknown keys, required keys), `_path` (absolute, no NUL, at most 4096), `_run_id` (UUID), `_fmt` (enum). No shell; argv is passed in process to `cli.main` | `::test_arguments_are_validated_before_any_argv_is_built` (9 cases), `::test_malformed_and_oversized_messages` (`eng-t-mcp-unknown-args` and `-abs-path` caught) | **VERIFIED** |
| S7.5 | Same engine checks as the CLI | Every call goes through `cli.main`: D-40 contracts, policy, authorisation, privilege refusal (also for `mcp serve` itself) and output redaction | `::test_real_cli_through_mcp`, `::test_stdio_subprocess_roundtrip` | **PARTIALLY_VERIFIED**. Real-CLI calls are tested for `runs_list` and `runs_show` only. `audit` through MCP is tested with a recording stub (the argv shape), not end to end |
| S7.6 | Local-only transport; no remote exposure | `mcp.serve()` reads stdin and writes stdout only. There is no socket, HTTP or SSE code. Local-only status is documented in the `mcp.py` docstring and `docs/user/mcp.md` | `::test_stdio_subprocess_roundtrip`; code inspection (no network imports in `mcp.py`) | **VERIFIED** as implemented. The guarantee is architectural and documentary: a user can still bridge stdio to a network externally, and nothing in Sentinel prevents that |
| S7.7 | Results treated as data, and the verdict is the exit code | `structuredContent.untrusted_content = true`, a notice, `exit_code`; `isError` when the exit code is above 1 | `::test_results_are_marked_untrusted_and_exit_code_is_the_verdict` (`eng-t-mcp-iserror` caught) | **VERIFIED** |

### M7.3 Prompt-injection limitations

1. **Detection is regex-based.** It covers 5 override, exfiltration and pipe-to-shell patterns plus invisible Unicode. Paraphrased, translated, encoded (for example base64) or multi-step payloads can be missed. Findings are `suspected` and never AI-verified.
2. **The MCP server doesn't sanitise target content.** It labels it untrusted. The consuming agent must honour `untrusted_content`; Sentinel can't enforce that.
3. **There is no client authentication.** Anything that can write to the server's stdin can call its tools: the trust boundary is the launching process. This is by owner decision.

### M7 recommendation

- **MCP server (optional capability): acceptable**, as local-only and read-only apart from the audit-run write noted in S7.1. Recommended but not blocking: an end-to-end MCP `audit` test (S7.5).
- **D11 roadmap deliverable: do not accept as a domain yet.**
  - "T2 fixtures pass" is met only for a small self-authored set, and no D11 ACs exist.
  - Either accept it as "analyser plus smoke fixtures delivered, ACs and corpus deferred" by a dated decision, or define the ACs and an independent T2 corpus first.

---

## M9: reporting, risk, verification

### M9.1 Roadmap requirements

| # | Requirement | Implementation | Tests | Class |
|---|---|---|---|---|
| R9.1 | Four report types | `reports.RENDERERS`: json, sarif, md, html; `cli report --format` | `test_findings_reports.py::test_json_report_is_canonical`, `::test_sarif_structure`, `::test_html_escapes_untrusted_content`, `::test_markdown_escapes_and_never_claims_secure`, `::test_all_renderers_show_incomplete_state` | **VERIFIED** (M1/M2 code, rerun here) |
| R9.2 | Severity and confidence model | `domain/enums.py` Severity and Confidence; `findings.new_finding` starting states; dedup raises confidence for independent producers | `::test_starting_states`, `::test_dedup_merges_evidence_and_raises_confidence` | **VERIFIED** |
| R9.3 | Dedup and signed suppressions | `findings.deduplicate` (D-62 sources kept); `apply_suppression` with operator approval | `::test_suppression_and_accepted_risk_require_approval`; `test_aud19.py` suppression binding and tamper tests | **VERIFIED** |
| R9.4 | `verify` workflow | `cli review verify`, `evidence verify`, `verified_run` | `test_cli.py::test_verify_with_other_run_key_fails` and the M1 review tests (run in the prior full suite) | **VERIFIED** (prior full-suite evidence; not rerun individually here) |
| R9.5 | Signed human review decisions (D-26) | `HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE` state; review bound to finding and revision | `::test_human_review_gives_distinct_state`, `::test_human_review_bound_to_finding_and_revision`; `test_foundation.py::test_human_verified_status_distinct_from_verified` | **VERIFIED** |
| R9.6 | AC-05: two runs with the same inputs give the same fingerprints and check statuses | Deterministic fingerprint (R-12) | `::test_fingerprint_is_deterministic_and_identity_based`; `test_m2_secret_class.py::test_labels_are_identical_across_two_runs`; `test_fixplan.py::test_plan_is_deterministic_…` | **PARTIALLY_VERIFIED**. No single test runs two full audits and compares fingerprint and status sets |
| R9.7 | AC-06: every report validates against its schema and includes coverage, checks not run and limitations | Output contracts (D-40); checks and integrity sections; domain-coverage section added in V-3 | `::test_all_renderers_show_incomplete_state`; `test_m3.py::test_reports_show_domain_coverage_and_required_check_status` (`eng-t-report-coverage` caught) | **PARTIALLY_VERIFIED**. Markdown and HTML show coverage; SARIF has no coverage section; "limitations" appears as the integrity note only |
| R9.8 | AC-13: human-verified findings never counted as `verified` in totals | Distinct state; separate report section | `test_foundation.py::test_human_verified_status_distinct_from_verified`; the report section exists | **PARTIALLY_VERIFIED**. No test asserts report totals and summaries exclude human-verified findings from `verified` counts |
| R9.9 | Reports state coverage and residual risk | `domain_coverage` (FULL, PARTIAL, NOT_RUN, ERROR, NOT_APPLICABLE with evidence) in results, Markdown and HTML; risk totals in `compare` | V-3 tests in `test_m3.py`; `test_compare.py` risk tests | **PARTIALLY_VERIFIED**. "Residual risk" appears only as compare's heuristic open-risk totals, not in single-run reports |
| R9.10 | Exclusion: no automatic fixes | `fix-plan` is read-only (D-50), with `remediation_verified: false` | `test_fixplan.py::test_plan_is_deterministic_and_never_writes_into_the_run`, `::test_plan_uses_d64_resolution_wording_and_stays_keyed_by_fingerprint` | **VERIFIED** |

### M9.2 Comparison and remediation (D-64, optional extension)

| # | Requirement | Implementation | Tests (and mutants caught) | Class |
|---|---|---|---|---|
| C9.1 | D-64 issue identity: domain, rule, asset, normalised file, title; not line; stored fingerprint unchanged | `compare.identity`; decision D-64 appended to `docs/architecture-discovery-plan.md` | `test_compare.py::test_identity_includes_title_and_asset`, `::test_different_title_or_file_is_a_different_issue` (mutants `eng-t-d64-title`, `-rule`, `-asset` and `-line-in-identity` caught) | **VERIFIED** |
| C9.2 | Line movement is persisting, never fixed | Equal-count pairing gives `moved: true` | `::test_line_movement_is_persisting_never_fixed` (`-moved-pairing` caught) | **VERIFIED** |
| C9.3 | Duplicates and ambiguous matches | Exact fingerprints paired first; equal counts paired; unequal counts give `unverified` / `ambiguous_identity` | `::test_duplicates_equal_counts_persist_and_unequal_counts_are_unverified` (`-ambiguous` caught) | **VERIFIED** |
| C9.4 | Incomplete later check gives unverified | `gone()` requires every producer in PASS or FAIL in the later run | `::test_incomplete_later_check_is_unverified` (NOT_RUN, ERROR, TIMEOUT, BLOCKED), `::test_missing_finding_from_a_check_that_did_not_run_is_unverified_not_fixed` (real runs) (`-producer-completed` and `-completed-set` caught) | **VERIFIED** |
| C9.5 | Possible rule change gives unverified | `rule_changed()`: same asset, file and line, a shared producer, a different rule | `::test_changed_rule_identity_at_same_location_is_unverified` (`-rule-change-guard` caught) | **VERIFIED** for a same-location rule rename. A rename that also moves the line isn't detected (§M9.3) |
| C9.6 | Remediation resolved only after successful verification | `remediation` status from the outcome map: `resolved` only for `fixed`; `persisting` gives open or accepted; otherwise `unverified` | `::test_fixed_finding_is_evidence_backed_and_remediation_resolved` (real runs), `::test_genuine_remediation_is_resolved` (`-resolved-mapping` caught) | **VERIFIED** |
| C9.7 | Different asset sets and the same run are refused | Asset digest check; audit-ID check | `::test_changed_asset_is_refused`, `::test_different_targets_and_same_run_are_refused` | **VERIFIED** |
| C9.8 | Inputs are verified runs only | `cli.cmd_compare` calls `verified_run` for both runs (signature, evidence, stored result) | `::test_tampered_run_is_refused` (exit code `EXIT_INTEGRITY`) | **VERIFIED** |
| C9.9 | Accurate risk totals | `compare.risk`: suppressed and accepted findings excluded and counted separately; weights critical 10, high 5, medium 2, low 1, informational 0 | `::test_accepted_findings_stay_visible_and_leave_open_risk`, `::test_informational_findings_add_nothing_to_the_weighted_score`, `::test_informational_severity_is_counted_under_its_engine_label` (`eng-t-risk-informational` caught) | **VERIFIED**. This is a heuristic, not a verdict, and is labelled as such |
| C9.10 | Evidence references | Output binds `before` and `after` `manifest_sha256` and run IDs; the CLI adds `comparison_sha256`; items carry fingerprint, identity and producers | `::test_fixed_finding_is_evidence_backed_and_remediation_resolved` (checked against the `compare` contract) | **PARTIALLY_VERIFIED**. Items don't list their `evidence` IDs; the comparison output is neither signed nor stored |

### M9.3 Residual risks and unsupported claims

1. **Title-dependent identity.** A scanner that embeds line-specific text in its message breaks line-move matching. This is not seen in the shipped rules or analyzers.
2. **A rule rename plus a line move** is reported as fixed plus introduced, provided the old producer completed.
3. **The comparison is not signed or persisted.** Its integrity rests on the two verified runs plus the printed `comparison_sha256`.
4. **AC-05, AC-06 and AC-13** have only partial direct tests (R9.6 to R9.8).
5. **Unsupported claim to avoid:** "single-run reports state residual risk". Only the comparison has risk totals.

### M9 recommendation

- **The comparison and remediation extension (D-64): acceptable.** All its requirements are VERIFIED, except evidence references, which are PARTIALLY_VERIFIED (C9.10).
- **The M9 roadmap row: do not accept yet.** AC-05, AC-06 and AC-13 are PARTIALLY_VERIFIED. Recommended before acceptance, as tests only with no feature change:
  1. a two-run reproducibility test for AC-05;
  2. a SARIF and "limitations" content check for AC-06, or a dated decision that SARIF is exempt;
  3. a totals test for AC-13.
- Alternatively, accept M9 with these recorded as open acceptance-test gaps by a dated decision.

---

## Decisions required from the owner

1. **M6:** accept the plugin system (optional capability), and decide how to treat the D10 analyser without domain ACs (accept as analyser-delivered with ACs deferred, or define the ACs first).
2. **M7:** accept the MCP server (optional capability), and decide how to treat the D11 analyser and its smoke-level T2 set (defer the ACs and corpus, or define them first).
3. **M9:** accept the D-64 comparison extension, and choose between adding the AC-05, AC-06 and AC-13 tests before accepting the roadmap row, or accepting with the gaps recorded.
4. **Optional test-only additions** (no feature changes):
   - P6.1 (signed-policy plugin audit) and P6.8 (orchestrator-level isolation);
   - S7.5 (an end-to-end MCP audit);
   - C9.10 (per-item evidence IDs in compare output; this one would be a small output change).
5. **Commit:** still not authorised. The working tree holds all M3–M10 and correction-cycle changes.

---

## Gap closure (owner instruction, 2026-11-10)

Only the listed gaps were implemented. No architecture changed, and finding identity and fingerprints are unchanged. Nothing was staged, committed, pushed or downloaded. The Git index is unchanged: 3 pre-existing staged files.

### Changes

| Gap | Implementation | Compatibility |
|---|---|---|
| P6.9 (plugin provenance) | `PluginAdapter.program()` records `{name, version, manifest_sha256, entry_sha256}` for the bytes it is about to execute. `normalize()` attaches it to every plugin finding, and refuses (giving ERROR) if no verified provenance exists. The orchestrator copies it into `finding.sources[].plugin`. Schemas: optional `plugin` in `adapter-findings` and in `common#finding.sources` | Additive and optional; historical results validate |
| R9.7 / AC-06 (SARIF) | `reports.to_sarif` run property bag (SARIF 2.1.0 §3.8) now carries `checks_not_finished`, `limitations` (the integrity note) and `domain_coverage` when present. The SARIF profile schema allows them as optional | The historical signed SARIF corpus still validates; a test enforces it |
| C9.10 (compare evidence) | Compare items carry `evidence`. Persisting items also carry `evidence_before`. Remediation entries carry `evidence_before` and `evidence_after` (`after` is empty unless persisting). `compare_version` is now 3 | Output-only and never stored; the cli-output contract was updated |
| S7.6 (MCP wording) | `mcp.py` docstring and `docs/user/mcp.md`: **target-read-only** (an audit writes a new signed run to Sentinel's own state); external stdio-to-network bridges are outside Sentinel's security boundary | Documentation only. The server stays stdio-only |
| D10 / D11 | `docs/roadmap/d10-d11-criteria-proposal.md`: a proposal only; no criteria approved or invented | — |

### New tests (`tests/test_acceptance_gaps.py`, 10 tests, all executed and passed, 0 skipped)

| Test | Demonstrates |
|---|---|
| `test_m6_signed_policy_plugin_audit_end_to_end` | A real audit, run through the CLI with an **operator-signed policy** containing a plugin pin, executed in the **real Seatbelt** sandbox. The run verifies (`verified_run`), the target is unchanged, and the plugin finding's `sources[].plugin.manifest_sha256` equals the pin and the SHA-256 of the manifest file. `entry_sha256` equals the SHA-256 of the exact `-c` source string the sandbox received (spied); the evidence ID is in the signed manifest |
| `test_m6_unsigned_or_edited_plugin_policy_is_refused` | A plugin policy without approval, or edited after approval, gives `EXIT_BLOCKED` |
| `test_m6_failing_plugin_does_not_affect_other_checks[exit3, malformed-line]` | In one real audit, a failing plugin (nonzero exit, or the V-1 malformed `line`) gives ERROR, while the fixture check and the other plugin still run and keep their findings in the verified run. No engine crash, and never PASS |
| `test_m7_real_stdio_server_runs_an_audit_end_to_end` | The real `mcp.serve()`/`Server` in a **subprocess over real stdio pipes**, executing the real `cli.main` with the real host isolation. The `audit` tool produces a run that verifies, `disclosure.declared_caller == "mcp"`, and the target is unchanged. `key`, `approval`, `review`, `suppress`, `decisions`, `policy_change`, `init` and `history` give `tool_not_exposed`, and Sentinel's non-run state files are byte-identical before and after |
| `test_ac05_two_complete_audits_give_identical_fingerprints_and_statuses` | Two complete audits of the same target: identical fingerprint sets and check (ID, status, reason) sets. Their comparison has nothing introduced, fixed or unverified, everything persisting, and remediation open |
| `test_ac06_sarif_carries_coverage_checks_not_finished_and_limitations` and `…historical_sarif_…still_validates` | SARIF from a real run includes coverage, checks not finished and limitations, and is validated against the SARIF profile at generation. Incomplete checks are visible. Older SARIF still validates |
| `test_ac13_human_verified_findings_are_never_counted_as_verified` | `findings.summary` counts `verified` and `human_verified_no_deterministic_evidence` separately. The Markdown totals line shows them separately, and the human-verified section lists only the human-verified finding. HTML has the section, and SARIF keeps the states distinct |
| `test_compare_items_carry_evidence_ids_traceable_to_the_manifest` | Every fixed item's `evidence` and every remediation `evidence_before` ID is in the earlier run's signed `evidence_index`. `resolved` comes only with a completed later run, and the output matches the cli-output contract |

**M7 test substitution, stated plainly:** the launcher replaces only the run-key store (a file in the test directory), so the user's macOS keychain is never written. `serve()`, the JSON-RPC handling, the tool allowlist, argument validation, `cli.main` and the isolation are all real.

### Verification executed after all changes

| Check | Result |
|---|---|
| Full suite `pytest`, including `tests/test_m2_real_scanners.py` | **1570 collected, exit 0, 0 failed, 0 skipped** |
| `ruff check .`, `ruff format --check .` (170 files), `mypy --strict` (61 files) | clean |
| `check_architecture_docs.py .` | PASS |
| `license_audit.py check --strict` | 0 issues |
| Mutation | **No new campaign.** The 43-mutant campaign evidence (`docs/roadmap/m3-m10-independent-verification.md` §12.2) covers the earlier code. The new provenance, SARIF and compare-evidence code has **no mutation evidence** |

One `mcp.py` docstring line was rewrapped after the full suite started. That is a comment-only change; lint, format and mypy were rerun afterwards.

### Updated classification

| ID | Before | Now |
|---|---|---|
| P6.1 signed-policy pinning end to end | PARTIALLY_VERIFIED | **VERIFIED** |
| P6.8 failure isolation | PARTIALLY_VERIFIED | **VERIFIED** (orchestrator level, real sandbox) |
| P6.9 provenance includes the manifest hash, matching the executed bytes | PARTIALLY_VERIFIED | **VERIFIED** |
| P6.6 sandbox | VERIFIED on macOS | Unchanged; Linux and Windows **BLOCKED** (B-4) |
| S7.1 tool exposure | PARTIALLY_VERIFIED | **VERIFIED** as *target-read-only* (audit writes a run to Sentinel's own state, as documented) |
| S7.5 same engine checks, end to end | PARTIALLY_VERIFIED | **VERIFIED** for `audit` and the refused tools via the real stdio server. Other tools were tested in process earlier |
| S7.6 local-only | VERIFIED as implemented | Unchanged. External bridges are documented as out of boundary |
| R9.6 AC-05 | PARTIALLY_VERIFIED | **VERIFIED** for the fixture adapter. Real-scanner reproducibility rests on the M3 re-measurements (identical across 4 runs) |
| R9.7 AC-06 | PARTIALLY_VERIFIED | **VERIFIED**: JSON, SARIF, Markdown and HTML carry coverage, checks not run and limitations |
| R9.8 AC-13 | PARTIALLY_VERIFIED | **VERIFIED** |
| R9.9 reports state coverage and residual risk | PARTIALLY_VERIFIED | **PARTIALLY_VERIFIED**. Coverage is in every report type. "Residual risk" is still only the compare open-risk totals and the per-run limitations text |
| C9.10 compare evidence references | PARTIALLY_VERIFIED | **VERIFIED** for traceability. The comparison output is still unsigned and not persisted |
| R6.2 IDE extensions | PARTIALLY_VERIFIED | Unchanged (VS Code only) |
| R6.3 and R7.3 domain ACs; R7.2 T2 corpus | NOT_VERIFIED / PARTIALLY_VERIFIED | Unchanged. Criteria are proposed in `d10-d11-criteria-proposal.md`, awaiting approval |

### Remaining limitations

1. **No mutation evidence** for the gap-closure code (plugin provenance, SARIF properties, compare evidence fields).
2. **The comparison is not signed or stored.** It is bound to the two verified runs by `manifest_sha256` and printed with `comparison_sha256`.
3. **Plugin isolation exists only on macOS** (B-4).
4. **The MCP server has no client authentication.** It is stdio, target-read-only, and an external bridge defeats local-only. All of this is documented.
5. **D10 and D11 have no approved criteria and no independent corpus.**
6. **"Residual risk" in single-run reports** is limited to coverage states plus the limitations text.

### Acceptance recommendations (owner decides)

| Milestone | Recommendation |
|---|---|
| **M6 plugin system (optional capability)** | **Ready for acceptance.** Every plugin requirement is VERIFIED on macOS; Linux and Windows are BLOCKED (B-4) |
| **M6 D10 analyser** | **Not ready.** Keep unaccepted until the D10 criteria (proposal) are approved and measured |
| **M7 MCP server (optional capability)** | **Ready for acceptance** as stdio-only, target-read-only, unauthenticated by design |
| **M7 D11 analyser and T2** | **Not ready.** Keep unaccepted until the D11 criteria and an independent T2 corpus are approved and measured |
| **M9 roadmap row** | **Ready for acceptance**, with one recorded limitation: R9.9's "residual risk" is coverage plus limitations text, with no separate residual-risk model. Accept that reading, or ask for it to be defined |
| **M9 D-64 comparison and remediation** | **Ready for acceptance** |
