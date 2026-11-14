# M3–M10 implementation report (overnight autonomous run, 2026-11-09)

**Status: pending owner review. No milestone from M3 to M10 is accepted or claimed as accepted.**

Status vocabulary: IMPLEMENTED (code exists), UNIT_TESTED (tests on synthetic input), INTEGRATION_TESTED (exercised end to end through the engine or the real isolation layer on this macOS host), VERIFIED (only with owner acceptance; nothing here is VERIFIED), BLOCKED, NOT_IMPLEMENTED.

## 1. Summary

I implemented real engine code for every milestone from M3 to M10 that can be built and tested on this macOS host without new downloads, hardware or owner decisions:

- M3 domain modules and adapters;
- seven native static analyzers (M4, M5, M6/D10, M7/D11, M8);
- a pinned, sandboxed plugin system;
- an MCP stdio server;
- run comparison and remediation tracking;
- an installed-package integrity self-check.

Every new path fails closed. A missing, failed, timed-out or unsupported check is `NOT_RUN` or `ERROR`, never `PASS`.

Some roadmap deliverables need approval, hardware or a specification. Those are BLOCKED and listed in §6, and not represented as done.

**Scope note for the owner (B-8):** the roadmap defines M6 as D10 analyzers and M7 as D11 analyzers. Both are implemented, and I also built two integration features:

- Sentinel's own plugin system, under M6;
- an MCP server exposing Sentinel to agents, under M7.

These extend the roadmap's text. Keep them, move them or drop them: your call.

## 2. Features per milestone

| Milestone | Feature | Status |
|---|---|---|
| M3 | Domain registry D01, D02, D08, D14 (provisional, D-59); coverage only from validated checks in `coverage.json` | INTEGRATION_TESTED |
| M3 | Pinned domain Semgrep rule files (any unpinned or extra rule file refused) | INTEGRATION_TESTED (real Semgrep) |
| M3 | Trivy, Checkov and Grype adapters; Grype takes the Syft SBOM over stdin; D-29 database pins; snapshot verification | UNIT_TESTED (fake runner); real runs BLOCKED (B-1) |
| M3 | D-62 cross-scanner deduplication with `sources` provenance; `reproducibility`, `domain_coverage`, `vulnerability_db_snapshots` in results and manifests | INTEGRATION_TESTED |
| M3 | 80 synthetic fixtures (10 vulnerable and 10 clean per domain) and the measurement script | INTEGRATION_TESTED |
| M4 | Android static analyzer (manifest: debuggable, backup, cleartext, exported components, and more) | INTEGRATION_TESTED (real Seatbelt) |
| M4 | iOS static analyzer (ATS, entitlements, plist) | INTEGRATION_TESTED (real Seatbelt) |
| M4 | B2 archive unpacking, MobSF adapter, §10.3 limits | BLOCKED (B-6, B-7) |
| M5 | OS-configuration snapshot analyzer (sshd, sudoers, passwd/shadow, sysctl, systemd units, .reg exports) | INTEGRATION_TESTED on macOS |
| M5 | Static PE, MSI, MSIX and Authenticode structure analysis | NOT_IMPLEMENTED |
| M5 | Acceptance on Linux and on its own OS | BLOCKED (B-4) |
| M6 | D10 extension analyzer (browser MV2/MV3 manifests; VS Code `package.json`) | INTEGRATION_TESTED (real Seatbelt) |
| M6 | Plugin system: policy-pinned manifest hash, entry hash re-verified before every run, `GRANTABLE` permissions only, API, version and activity-class checks, run only in S1 isolation, `plugin.<name>.` provenance, `plugin inspect` | INTEGRATION_TESTED (real Seatbelt, including a hostile plugin) |
| M7 | D11 agent and MCP analyzer: unpinned MCP servers, shell wrappers, inline secrets (named, never printed), plaintext remote, permissive agent settings, Codex sandbox-off; T2 prompt-injection and hidden-Unicode fixture set | INTEGRATION_TESTED (real Seatbelt) |
| M7 | MCP stdio server `sentinel mcp serve` (§4) | INTEGRATION_TESTED (subprocess round trip) |
| M8 | Supply-chain analyzer: lockfiles, dependency confusion, typosquat candidates, workflow and Dockerfile hygiene, checksum files (artifacts hashed only) | INTEGRATION_TESTED (real Seatbelt) |
| M8 | Safe structural metadata extraction for binary formats; R-07, T8 and T17 fixtures | NOT_IMPLEMENTED (T8 needs B2: B-6) |
| M9 | `sentinel compare BEFORE AFTER`: introduced, fixed, unverified and persisting findings; fix-plan remediation status; open-risk totals | INTEGRATION_TESTED |
| M9 | Reports, severity and confidence, signed suppressions, verify workflow, signed review decisions | Existing from M1 and M2, unchanged |
| M10 | `sentinel self-check`: installed files against wheel RECORD; `scripts/m10/release_manifest.py` writes SHA256SUMS | INTEGRATION_TESTED (real wheel install and tamper test) |
| M10 | Signed release | BLOCKED (B-5) |
| M10 | Windows-native checks and Windows host; AC-01 on all OSes | BLOCKED (B-4) |
| M10 | SBOM of Sentinel itself; final licence review | NOT_IMPLEMENTED |

## 3. Tests and exact results

Targeted runs, this host (macOS, Python 3.13, `.venv`):

| Test file | Passed | Skipped | Failed |
|---|---|---|---|
| `tests/test_m3.py` | 30 | 0 | 0 |
| `tests/test_native_analyzers.py` (includes 6 real-Seatbelt runs, one per analyzer) | 20 | 0 | 0 |
| `tests/test_d10_d11.py` (T2 fixtures: 6 injections, 3 benign) | 15 | 0 | 0 |
| `tests/test_plugins.py` (includes real-Seatbelt valid, hostile and 4 failure cases) | 21 | 0 | 0 |
| `tests/test_mcp.py` (includes stdio subprocess round trip) | 23 | 0 | 0 |
| `tests/test_compare.py` | 6 | 0 | 0 |
| `tests/test_release.py` (includes offline wheel build, install and tamper) | 4 | 0 | 0 |

**Hostile plugin (real Seatbelt).** The test plugin attempts the following, and all three are denied:

- a network connection to 1.1.1.1:80;
- a write into the target;
- a read of `~/.ssh/known_hosts`.

The target tree is unchanged afterwards.

**M3 measurement with installed scanners** (`docs/m3/metrics.json`):

| Domain | Recall | False positives |
|---|---|---|
| D01 | 1.0 | 0 |
| D02 | 1.0 | 0 |
| D08 | 0.846 | 0 |
| D14 | 0.818 | 0 |

The misses are exactly the Checkov-designated items, and Checkov isn't installed (B-1). No thresholds are set (B-2), so this is a measurement, not an acceptance.

**Full regression:**

- Before the D10/D11 additions: 1 failure, `test_real_catalogue_is_well_formed_and_anchors_exist_once` (anchor `eng-d32-cli-privilege-check`). The cause was a duplicated privilege-check line from the `mcp serve` wiring. Fixed by restructuring `cli.main` so a single privilege check covers both paths. The harness test, CLI and MCP suites were then rerun and pass.
- Final full regression run after all changes: 1477 passed, 0 failed (§3a).
- `tests/test_m2_real_scanners.py` was not rerun (real scanner campaign, M2 baseline).
- No mutation campaign was run, per instruction.

**Static gates:**

- `ruff check .`: clean.
- `ruff format --check .`: clean.
- `mypy --strict` (61 source files): clean.

### 3a. Final full regression

`pytest --ignore=tests/test_m2_real_scanners.py` after all changes: **1477 passed, 0 failed, 0 skipped, exit 0**.

## 4. Integrations

**MCP server (M7).**

- Transport: newline-delimited JSON-RPC 2.0 on stdio.
- Each tool maps to a fixed `sentinel --json …` argv run in process through `cli.main`, with the same validation, policy, authorisation, privilege refusal and redaction as the CLI.
- Exposed tools: `status`, `audit`, `runs_list`, `runs_show`, `evidence_verify`, `report`, `fix_plan`, `policy_validate`, `plugin_inspect`.
- Never exposed: key, approval, review, suppress, decisions, policy change, prune, init, cancel, pause, resume, history. Calling one gives `tool_not_exposed`.
- Audits always run with `--caller mcp`. An agent can't supply a caller.
- `report` and `fix_plan` never take `--output`, so no file is written on an agent's behalf.
- Arguments are validated before argv is built: absolute paths, no NUL bytes, UUID run IDs, no unknown keys.
- Results carry `untrusted_content: true`, a data-not-instructions notice and the engine's exit code, which is the only verdict.

**Plugins (M6).** A plugin is loaded only if all of the following hold:

- it is named in the approved policy (`plugins.<name> = {path, manifest_sha256}`), and the policy is changed only through `policy.change`;
- the manifest hash and entry hash match immediately before each run;
- the permissions equal the non-grantable minimum (no network, no writes, no target execution).

A plugin asking for more is refused (`plugin_permission_denied`), not downgraded. A plugin runs only as a separate process in verified S1 isolation; without isolation it is `NOT_RUN`. A crash, timeout or malformed output gives `ERROR`.

**CLI additions:** `plugin inspect`, `mcp serve`, `compare`, `self-check`. Each has a cli-output contract, except `mcp serve`, which is a stream.

## 5. Dependencies and provenance

- **No new dependency, binary, image, database or service** was downloaded or added. Every analyzer is stdlib-only Python and is allowlisted by script SHA-256 (`builtin_native_allowlist`).
- **Wheel build** for the M10 test used only cached build backends (`uv build --offline`; hatchling 1.33.0 pinned).
- **M3 scanners used** were the M2-approved Semgrep, OSV-Scanner v2.7.0, Syft and Gitleaks, plus the pinned OSV database snapshot `osv-db-20261109`.
- **Proposed but not acquired:** Trivy 0.76.2, Grype 0.121.2, Checkov 3.4.3, cosign 3.1.4 and their databases (`docs/m3/acquisition-request.md`, B-1).

## 6. Blocked features

The full register is in `docs/roadmap/overnight-progress.md`:

| ID | Blocked item |
|---|---|
| B-1 | M3 acquisitions |
| B-2 | R and F thresholds |
| B-3 | Domain-ID specification |
| B-4 | Linux and Windows hosts |
| B-5 | Signing device and SD-T01 to SD-T55; production and release signing stay disabled |
| B-6 | M2-SA-12 (B2 stays disabled; nothing untrusted is unpacked or executed) |
| B-7 | MobSF |
| B-8 | Scope decision on the M6/M7 integration additions |

## 7. Security limitations and residuals

1. **Self-check is not a signature.** RECORD sits beside the files, so it detects corruption and casual tampering, not a determined local attacker. An editable or development install is reported `unverifiable` (exit 2), never verified.
2. **MCP stdio server has no authentication.** The trust boundary is the parent process that launches it. It runs with the invoking user's rights and the CLI's checks; it adds no privilege.
3. **D11 injection detection is heuristic.** It uses a fixed pattern set and can miss paraphrased or encoded payloads. A finding is `suspected`, never verified by any model.
4. **D10 and D11 domain labels are provisional** (`extensions`, `ai-agents`) until the specification is available (B-3).
5. **`compare` refuses runs whose scoped assets differ, but allows different revisions.** A finding absent from a run where its producer didn't complete is `unverified`, never `fixed`.
6. **The risk score is a heuristic.** Its weights are critical 10, high 5, medium 2, low 1, info 0. It is not a verdict.
7. **Plugins share the native sandbox profile.** Their isolation strength is S1 (Seatbelt) as measured in M2. Linux and Windows have no plugin runner yet (B-4).
8. **Mutation catalogue.** No new mutants were added for the M6 to M10 code, and no campaign was run, so mutation coverage of that code is unmeasured.

## 8. Incomplete acceptance criteria

| Milestone | Incomplete criteria |
|---|---|
| M3 | AC-07 and AC-08 need thresholds (B-2) and the Checkov, Trivy and Grype runs (B-1) |
| M4 | Archive fixtures R-07 and T8, and the §10.3 limits, need B2 (B-6); MobSF (B-7) |
| M5 | Domain ACs on Linux (B-4); static D06 needs the PE, MSI and MSIX analyzer (NOT_IMPLEMENTED) |
| M6 and M7 | Domain ACs are not defined beyond the roadmap row; R and F thresholds were never set |
| M8 | AC-12 (R-07, T8, T17 fixtures) is incomplete: no binary structural extraction, and B2 is blocked |
| M9 | AC-05, AC-06 and AC-13 were previously met by M1 and M2 code and were not re-audited; the new compare and remediation features have no formal AC |
| M10 | AC-01 on all OSes (B-4); signed release (B-5); licence review; Sentinel SBOM |

## 9. Files created or modified

**Created:**

- Engine (`src/sentinel/`):
  - `domains/__init__.py`, `domains/coverage.json`
  - `rules/semgrep/D01.yaml`, `D02.yaml`, `D08.yaml`, `D14.yaml`
  - `analyzers/_common.py`, `android.py`, `ios.py`, `oscfg.py`, `supplychain.py`, `extensions.py`, `agents.py`
  - `adapters/native.py`, `adapters/native_registry.py`
  - `analyzers_probe.py`, `plugins.py`, `mcp.py`, `compare.py`, `release.py`
- Scripts: `scripts/m3/make_fixtures.py`, `scripts/m3/measure.py`, `scripts/m10/release_manifest.py`
- Tests and fixtures:
  - `tests/test_m3.py`, `test_native_analyzers.py`, `test_d10_d11.py`, `test_plugins.py`, `test_mcp.py`, `test_compare.py`, `test_release.py`
  - `tests/fixtures/domains/` (80 projects)
- Docs: `docs/m3/scope.md`, `scope-proposal.md`, `acquisition-request.md`, `metrics.json`; `docs/roadmap/overnight-progress.md`, this report

**Modified:**

- Engine (`src/sentinel/`): `adapters/scanners.py`, `adapters/base.py`, `scanner_pins.py`, `isolation/podman.py`, `orchestrator.py`, `findings.py`, `policy.py`, `cli.py`
- Schemas: `common`, `audit-result`, `adapter-findings`, `run-manifest`, `policy`, `cli-output`
- Tests: `tests/m2_fakes.py` and the M2 adapter tests (seven-scanner registry)
- Project and docs:
  - `pyproject.toml` (Ruff fixture exclude, mypy `_common` override, sdist `docs/m2` and `docs/m3`)
  - `docs/architecture-discovery-plan.md` (D-58 to D-63 appended; D-48 and earlier entries untouched)
  - the mutation catalogue (M3 entries, now 365)
  - `docs/m1/progress.md`

Nothing was staged, committed or pushed, and the Git index was not touched.

## 10. Exact owner next actions

1. Decide B-1: approve or amend `docs/m3/acquisition-request.md`. On approval, acquire and pin the scanners, then rerun `scripts/m3/measure.py`.
2. Decide B-2: set R and F per domain (D-63). This is the precondition for any M3 acceptance.
3. Decide B-8: keep, move or drop the plugin system and the MCP server as M6 and M7 scope.
4. Decide B-7: whether MobSF is wanted for M4, or whether static native analyzers suffice.
5. Provide the product specification (B-3), or confirm the provisional domain labels.
6. Provide Linux and Windows hosts for M5 and M10 (B-4).
7. Schedule the signing-device ceremony and SD-T01 to SD-T55 (B-5) before any signed release.
8. Review this report and the diff. Authorise a commit only if satisfied. Remote CI is still "not yet executed".
