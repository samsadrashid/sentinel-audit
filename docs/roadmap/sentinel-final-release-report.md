# Sentinel final release report (2026-11-10, final verification)

## Verdict: NOT RELEASE READY

The one genuine release blocker is **production signing (B-5)**. Releases must be signed, production signing is disabled until the signing-device ceremony and hardware tests SD-T01 to SD-T55, and that ceremony needs physical hardware.

Everything else that can be verified on this host has been verified, and passed. An **unsigned, macOS-only release candidate** is complete and reproducible.

Two other limits do not block that macOS candidate but bound what may be claimed:

- **Linux and Windows (B-4)** are unverified, so the release must not claim those platforms.
- **MobSF (B-7)** runs as 4.6.4 under the owner's recorded risk acceptance (D-72), in the share-free machine only. **M2-SA-12 (B-6) is resolved for every container check** (D-70, D-71). See §10.

Nothing was staged, committed, pushed, tagged or published.

## 1. What was executed, with exit codes

All commands were run on 2026-11-10 on macOS (arm64), with the session unlocked and the Podman machine running.

| Step | Command | Exit | Result |
|---|---|---|---|
| Mutation campaign, round 1 | `scripts/mutation/harness.py --jobs 4 --timeout 3600 --only eng-f-…` (all 24) | 1 (survivors) | Baseline passed in 147 s, including the real-scanner tests. **24 of 24 executed**: 19 caught, 4 survived, 0 invalid, 1 infrastructure failure |
| Mutation campaign, round 2 (after strengthening the tests) | Same harness, `--only` the 5 non-caught | 0 | Baseline passed in 160 s. **5 of 5 caught** |
| Complete test suite | `.venv/bin/pytest -q -rfEs` | **0** | **1672 collected, 1672 passed, 0 failed, 0 skipped**. Includes `test_m2_real_scanners.py`, `test_m3_real_scanners.py` (real Trivy, Grype, Checkov) and `test_se_helper.py` (46 of 46, including the real Secure Enclave helper) |
| Release-artifact check | `scripts/m10/release_check.py OUT` | **0** | Reproducible double build; versions consistent (0.1.0.dev1); clean install; installed-wheel `self-check` **verified** (105 RECORD entries); CycloneDX SBOM validated; SHA256SUMS written |
| Checksums | `shasum -a 256 -c SHA256SUMS` | 0 | Wheel, sdist and SBOM all OK |
| Lint | `ruff check .` | 0 | Clean |
| Format | `ruff format --check .` | 0 | 187 files clean |
| Types | `mypy --strict` | 0 | 63 source files, no issues |
| Architecture docs | `scripts/docs/check_architecture_docs.py .` | 0 | PASS (decisions through D-69) |
| Licence inventory | `scripts/license_audit.py check --strict` | 0 | 3 runtime, 6 build and 12 dev packages; 0 issues |
| D10/D11 metrics | `scripts/d10d11/measure.py --check` | 0 | Current |

**Interruptions and how they were resolved:**

- Two earlier campaign launches died before any mutant ran: the Podman machine had stopped, then the previous session ended.
- An earlier 09:26 result file (`baseline_failed`) was discarded and is not used.
- The final runs were launched detached under `caffeinate`, with the Podman machine restarted first.

## 2. Mutation results (24 targeted mutants, current code)

**Round 1, caught (19):**

| Area | Mutants |
|---|---|
| Binary metadata | `bin-traversal`, `bin-bomb`, `bin-msix-unsigned`, `bin-msi-sig`, `bin-pe-signed`, `bin-pe-wx`, `bin-pe-aslr` |
| SBOM | `sbom-hash`, `sbom-closure` |
| Release manifest | `rel-dotfiles` |
| Rules | `sc-lockfile`, `os-pam-permit`, `ext-dep-unpinned`, `mcp-broad-fs` |
| SARIF | `sarif-limitations`, `sarif-not-finished` |
| Compare | `cmp-evidence-before` |
| Plugin provenance | `plug-prov-entry`, `plug-prov-orch` |

**Round 1, not caught (5).** All were test gaps, not product defects:

| Mutant | Outcome | Gap |
|---|---|---|
| `bin-symlink` | survived | No test for an MSIX symlink entry |
| `bin-entry-limit` | survived | No test for the entry-count limit |
| `cmp-evidence` | survived | The evidence assertion was vacuous: `all()` over an empty list |
| `plug-prov-required` | survived | No test for `normalize` without verified provenance |
| `bin-msi-cycle` | infrastructure failure (exit -9) | The unbounded walk hung and was killed. The test now runs in a subprocess with a deadline |

**Round 2:** all 5 caught, using the new focused tests.

**Final: 24 of 24 caught, 0 survived, 0 invalid, 0 infrastructure failures.** Earlier campaigns (365 catalogue mutants; 43 targeted with 42 caught and 1 equivalent) apply only to their own code.

## 3. Requirement status

| Requirement | Status | Evidence |
|---|---|---|
| M3 scanners: Trivy 0.76.2, Grype 0.121.2, Checkov 3.4.3, plus their databases (D-66) | IMPLEMENTED_AND_TESTED | Images pinned by digest. Trivy cosign-verified; Grype and Checkov have no published signature (digest only). The Trivy DB (`16299b63…`) and Grype DB v6.1.10 (`dcca2472…`) are offline, read-only and manifest-pinned. Real tests pass |
| M3 thresholds (D-67) and domain mapping (D-68) | IMPLEMENTED_AND_TESTED | Recall 1.0 in D01, D02, D08 and D14; false-positive rate 0.0; FULL coverage on every applicable fixture run. Enforced by `test_recorded_m3_metrics_meet_the_d67_thresholds` |
| M4 Android and iOS static analysis | IMPLEMENTED_AND_TESTED | Source-tree analysis |
| M4 MobSF | IMPLEMENTED_AND_TESTED (risk accepted, D-72) | MobSF 4.6.4 in the share-free machine, no mounts and no network, built artifacts only. `test_mobsf.py` and `test_mobsf_real.py` pass. Code analysis is not exercised on a real DEX file. See §10 |
| M5 OS-configuration snapshots (macOS, Linux, Windows) | IMPLEMENTED_NOT_PLATFORM_VERIFIED | Snapshot analysis tested on macOS only |
| M6 plugins; D10 extensions | IMPLEMENTED_AND_TESTED | D10 criteria approved (D-69) and met: non-adversarial recall 1.0, 0 false-positive cases |
| M7 MCP server; D11 agents and MCP | IMPLEMENTED_AND_TESTED | D11 criteria approved (D-69) and met. T2 prompt-injection detection is pattern-based: 0 of 5 adversarial cases detected. **It is not a protection** |
| M8 supply chain, SBOM validation, PE, MSI and MSIX metadata | IMPLEMENTED_AND_TESTED | Signatures reported as present, not verified |
| B2 archive inspection: APK, AAB, IPA (M4, M8; D-70) | IMPLEMENTED_AND_TESTED | Share-free VM, no mounts, stdin in and stdout out. D-25 and D-35 rules. `test_b2.py` (38 tests) and `test_b2_real.py` (4 of 4 in the share-free VM). 20 of 20 mutants caught. Runs only as a separate pass while `sentinel-b2` is the active VM |
| M9 reports, compare, remediation | IMPLEMENTED_AND_TESTED | — |
| M10 SBOM, reproducible build, self-check, checksums | IMPLEMENTED_AND_TESTED | `release_check.py` exit 0 |
| M10 production signing and signed release | **BLOCKED_EXTERNAL (release blocker)** | Hardware ceremony B-5 |
| Linux and Windows hosts; D06 Windows-native checks | BLOCKED_EXTERNAL | B-4 |

## 4. Defects fixed during this final verification

1. **`release_check.py` inherited `PYTHONPATH`**, so a source tree could replace the installed wheel during the clean-install step. It now strips `PYTHONPATH`, `PYTHONHOME` and `PYTHONSTARTUP`. Regression test added.
2. **Snapshot verification could crash an audit.** An oversized database file raised an uncaught `ValidationError`. It now fails closed with `…_file_too_large`. The per-file cap was raised to 8 GiB, because the Grype DB is 3.4 GB. Regression test added.
3. **The Grype orchestrator test failed instead of skipping** when Podman was down. It now uses the Podman precondition fixture.
4. **Tests strengthened from the mutation findings**: the five gaps above.
5. **The `.gitignore` pattern** `.claude/settings.local.json` is now root-anchored, so it no longer matches test fixtures. This is a working-tree edit only.

## 5. Git and security hygiene

**Git:**

- The repository has **no commits**, so there is no history to preserve or alter.
- The index is unchanged: `A .gitignore`, `A README.md`, `A docs/architecture-discovery-plan.md`, as at the start.
- Everything else is unstaged or untracked.
- There are no active Git hooks (only `.sample` files), and no local `core.hooksPath`, filter, URL-rewrite or credential configuration.

**Ignored local material**, which is not distributed and is excluded from the sdist allowlist:

- `.claude/`, `.ecc-src/`, `tools/`, `docs/private/`, `docs/ecc-hook-compatibility.md`;
- caches and `build/`.

**Note for the owner:** your global ignore file (`~/.config/git/ignore`, `**/.claude/settings.local.json`) hides the test fixture `tests/fixtures/d10d11/agent/v-v04/.claude/settings.local.json`. The sdist includes it, but a commit from this Mac needs `git add -f` for that file, or the corpus test fails in a fresh clone.

**Secrets:**

- Gitleaks over every file Git would track, and over the built wheel and sdist, found **6 hits, all deliberate synthetic secrets** in `tests/test_redaction.py`, `tests/test_m2_adapters.py` and `tests/test_m2_secret_class.py`.
- There are no key or credential files.
- The two "PRIVATE KEY" strings in `src` are detection regular expressions.
- No private project names appear in the tree or in the artifacts.

**Network and telemetry:**

- There is no telemetry or analytics, and no network client code, in `src`, `scripts`, `native` or the agent skills. The `requests` strings in `scripts/m3/make_fixtures.py` are fixture file contents.
- `tests/test_no_network.py` passes. The only network-capable code is the sandbox self-test's deliberately denied loopback attempt.

**Licences and attribution:**

- First-party code is MIT (`LICENSE`, shipped in the wheel's dist-info).
- `THIRD_PARTY_NOTICES` is shipped and covers cffi 2.1.1 (MIT-0), cryptography 46.0.7 (Apache-2.0 OR BSD-3-Clause) and pycparser 3.12 (BSD-3-Clause), verified by `license_audit check --strict`.
- External tools (Podman, Gitleaks, Semgrep, OSV-Scanner, Syft, Trivy, Grype, Checkov, cosign and the databases) are documented in `licenses/external-tools.md` and **not redistributed**.
- GPL and LGPL tools run as separate processes. MobSF (GPL-3.0) is not bundled.

## 6. Release artifacts (unsigned)

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `sentinel_audit-0.1.0.dev1-py3-none-any.whl` | 239,652 | `99f242d26d70adcfc0dbcb786682db82744782203fcbacaf1437166dfae6fc21` |
| `sentinel_audit-0.1.0.dev1.tar.gz` | 770,933 | `b0aff1b31a49ae8f4a5491df0b84f9185750c147b9bb36507808f27bee5b9b2f` |
| `sentinel-sbom.cdx.json` | 19,155 | `8acc6c3c764767ff177459e686c7d8e488f13c39319545e454cd8e624d6057bf` |

The build is reproducible with `SOURCE_DATE_EPOCH=1767225600`. Rebuild with `scripts/m10/release_check.py`.

## 7. Remaining blockers

| ID | Blocker | Impact | Owner action |
|---|---|---|---|
| **B-5** | Signing device, SD-T01 to SD-T55, first-enrolment ceremonies | **Blocks release**: no signed artifacts, production signing disabled | Perform the ceremony (`blocked-acquisitions.md` B-5), then sign `SHA256SUMS` |
| B-4 | Linux and Windows test hosts | Release limited to macOS; no Linux or Windows claim | Provide hosts and run the suite there |
| B-6 | M2-SA-12 | **Resolved for every container check (D-70, D-71)** | — |
| B-7 | MobSF 4.6.5 (fix for GHSA-j7g2-gm7j-mfvm) | 4.6.4 runs under the D-72 risk acceptance | Upgrade to 4.6.5 when published |

## 8. Owner commands

```bash
uv sync --frozen
~/.local/share/sentinel-deps/podman/bin/podman machine start sentinel
uv run pytest -q
uv run python scripts/m10/release_check.py /tmp/sentinel-rc
cd /tmp/sentinel-rc/dist && shasum -a 256 -c SHA256SUMS
```

Run the test suite with the Mac unlocked; it includes the Secure Enclave and real-scanner tests.

**Addendum (after the final run):** the owner approved the D10/D11 criteria (D-69). `tests/test_d10_d11_corpus.py::test_recorded_metrics_meet_the_d69_thresholds` was added and passes, together with the rest of the D10/D11 tests (exit 0). The architecture-docs check passes. The full suite wasn't rerun for this documentation-and-test-only change.

## 9. Update: M2-SA-12 fix and B2 archive inspection (2026-11-10, owner chose the separate B2 pass)

**What changed:**

- **A dedicated Podman machine**, `sentinel-b2`, was created from the cached machine image with `--volume ""`. It has no host shares; nothing was downloaded.
- **The interpreter** is `python3 -I` from the approved Checkov image, loaded into that machine by image ID `sha256:45b07200…`, which the runner verifies.
- **New code:**
  - `src/sentinel/b2/`: the unpacker and AXML decoder;
  - `src/sentinel/isolation/b2.py`: the share-free runner and its preconditions;
  - `src/sentinel/adapters/archive.py`: the archive adapter;
  - `scanner_pins.B2Pin`, the policy key `b2`, and decision D-70.
- **Defect found and fixed:** the run manifest calls `detect()` on every adapter, and the MobSF stub lacked it. A real `sentinel audit` with the default adapter set would therefore have crashed. Regression test: `tests/test_default_adapters.py`.

**Executed:**

| Check | Exit | Result |
|---|---|---|
| `pytest tests/test_b2_real.py`, with `sentinel-b2` active | 0 | **4 of 4 passed**: no host-share filesystem in the VM; the M2-SA-12 write-to-host reproduction fails; container self-test (no network, read-only root, no host paths, uid 65534); real APK audit plus a path-traversal rejection with the target unchanged; a timed-out container killed and removed |
| B2 mutation campaign, 20 mutants (`eng-b2-*`), round 1 | 1 | 18 caught, 2 survived (test gaps: per-entry ratio, declared size larger than actual) |
| B2 mutation campaign, round 2 (the 2 survivors) | 0 | 2 of 2 caught. **Final: 20 of 20** |
| Complete suite, `pytest -q -rfEs` (main VM active) | **0** | **1714 collected, 1710 passed, 0 failed, 4 skipped.** The 4 skips are `test_b2_real.py`, which needs the other VM active and passed 4 of 4 there |
| `scripts/m10/release_check.py` | 0 | Reproducible; 0.1.0.dev1; installed-wheel `self-check` verified 110 files; SBOM valid; SHA256SUMS OK |
| ruff check, ruff format (195 files), mypy --strict (68 files), architecture docs, licence audit --strict, D10/D11 metrics | 0 | All clean |

**Artifacts (unsigned):**

| File | SHA-256 |
|---|---|
| wheel | `dd97ff65451ccd92d91035ced91b31b3a827e1add1750d9e40390043cdfb442c` |
| sdist | `9f9c73db41b177af4ddba1a39cc0214aa77cc385aace2e58e139e13dfa73bff9` |
| SBOM | `dea2f9ddd22c1b245683ab44bfe6e6c45787b0be62c9ae2a03d30c3abc287897` |

**Verdict unchanged: NOT RELEASE READY.** The only release blocker is production signing (B-5). The release is still macOS-only (B-4), and MobSF waits for 4.6.5 (B-7).

## 10. Update: D-71, D-72 and D-73 (2026-11-10, owner approved all three fixes)

**What changed:**

- **D-71: share-free isolation for every container check.** One Podman machine (`sentinel-b2`: no host volumes; 5 CPUs, 4 GB, 60 GB disk) runs the M2 and M3 scanners, B2 and MobSF in one pass, with no VM switching.
  - The target is streamed as a normalised tar (regular files and directories only) into a per-run VM-local volume, mounted read-only, and removed afterwards.
  - Databases live in VM-local volumes named after their manifest, and are re-verified with `sha256sum -c` before every use. A mismatch deletes the volume and gives `NOT_RUN database_volume_mismatch`.
  - `podman.machine` is a required pin. The runner refuses a machine with any host-share filesystem, and refuses to run without the pin (`podman_machine_unpinned`); there is no bind-mount fallback.
- **D-72: MobSF 4.6.4.** `adapters/mobsf.py` and the in-container driver `mobsf/driver.py`.
  - Only built APK, AAB and IPA artifacts go in, on stdin.
  - Only MobSF's static-analysis views are loaded, in-process; there is no server and no network.
  - Truncated output, or any failed MobSF stage, gives `ERROR`, never a partial `PASS`.
- **D-73: `native/macos/sentinel-signer`.** Software only: validation, ledger, transport, Secure Enclave signing, the CLI, `build.sh` and the README runbook. Production signing stays disabled.

**Defects found and fixed:**

1. **The policy schema rejected `podman.machine`, which the parser now requires.** An approved policy with a Podman pin would have been refused. The schema now requires the field. Regression test added.
2. **The Podman runner would still bind-mount host paths if the machine pin was missing.** The parser blocked this, but the runner didn't. It now refuses both in its precondition and when a container starts.
3. **Two older tests and six mutation anchors broke** after the D-71 refactor. They were updated.
4. **The stored MobSF image was damaged** (138 zero-byte files; `podman save` reported `file integrity checksum failed`), most likely by the earlier VM disk-full. With owner approval it was deleted and re-pulled by digest. The re-pulled image has the same pinned ID, and all 10 layers match their `diff_id`s. All other 7 images verified intact, twice.
5. **The host disk filled again during the first mutation round.** The VM's XFS recorded write errors, so containers failed with `overlay ... input/output error`. 9 mutants were "caught" by unrelated tests. Those results were discarded. The fix: `fstrim` inside the VM (reclaimed 11 GB), restart, re-verify the images, then rerun.
6. **MobSF compatibility:** the image ships no StaticAnalyzer migrations (`migrate --run-syncdb` is used). Its bundled JADX is linked into the tmpfs home, so MobSF doesn't try to download it.

**Executed (after the fixes):**

| Check | Exit | Result |
|---|---|---|
| M3 re-measure on the D-71 path (`scripts/m3/measure.py --write-coverage`) | 0 | D01, D02, D08, D14: recall 1.0, false positives 0, no checks incomplete; coverage FULL or NOT_APPLICABLE only. `test_m3.py` passes |
| Mutation round 1, 19 new or changed mutants (`eng-d71-*`, `eng-d72-*`, `eng-b2-iso-user`) | 0 | 10 caught by their own tests. 9 discarded as environmental (item 5) |
| Mutation round 2, those 9, on a healthy VM | 0 | Baseline passed (533 s). **9 of 9 caught** by the relevant tests. **Final: 19 of 19** |
| Complete suite `pytest -q -rfEs` | **0** | **1763 collected, 1763 passed, 0 failed, 0 skipped**, including `test_b2_real`, `test_d71_real`, `test_mobsf_real`, the M2/M3 real-scanner tests and the Secure Enclave helper |
| `swift test` (SignerCore, run by `build.sh`) and `test_signer_interop.py` | 0 | 11 of 11 XCTests; 3 of 3 interop tests (software key; wire format only) |
| `scripts/m10/release_check.py` | 0 | Reproducible; 0.1.0.dev1; installed-wheel `self-check` verified 113 files; SBOM valid; `shasum -c` OK |
| ruff check, ruff format (204 files), mypy --strict (71 files), architecture docs, `license_audit.py --strict check`, `d10d11/measure.py --check` | 0 | All clean |
| Git index | — | Unchanged: `A .gitignore`, `A README.md`, `A docs/architecture-discovery-plan.md` |

**Artifacts (unsigned):**

| File | SHA-256 |
|---|---|
| wheel | `13006030a144ddf6d1deed03bb8d350ccc888e5365adbb3416efa84fcabea1cf` |
| sdist | `8b20632d5a683b58f203ee56ae98e048bb5a12052005025f1c5269d438a417d9` |
| SBOM | `2b3180950b88391db34f17cb439fb2e3966e7c4b9eff8ab92f9eef1320bc51cf` |

**Finding fixed: image layer integrity.** Podman checks an image's ID, not its stored files, when a container starts, so a damaged image (item 4) could have run, and a scanner with missing files could under-report. Now, before any container runs (scanner, probe, B2 or MobSF), Sentinel streams `podman save` and checks two things:

- the config hashes to the image ID;
- every layer tar hashes to its `diff_id`.

A failed export, as when Podman's own re-hash fails, also counts as damage. The result is cached per process and image ID. A damaged image is never started, and its check is `NOT_RUN image_integrity_failed: …`.

| Check | Exit | Result |
|---|---|---|
| Unit tests (`test_d71.py`, `test_mobsf.py`): intact export; zero-byte layer file; wrong config; layer count; garbage; no manifest; Podman export failure; no container or volume created; scanner, B2 and MobSF adapters `NOT_RUN`; per-image cache | 0 | Pass |
| `test_d71_real.py::test_every_pinned_image_is_stored_intact` (all 9 pinned images, real exports) | 0 | Pass |
| Mutation campaign, 9 mutants (`eng-img-*`) | 0 | Baseline passed (509 s). **9 of 9 caught**, each by its own test |
| Complete suite `pytest -rfEs` | **0** | **1776 passed, 0 failed, 0 skipped** (470 s) |
| `release_check.py`; ruff; format (205 files); mypy (71 files); architecture docs; licence audit `--strict`; D10/D11 `--check` | 0 | All clean. Git index unchanged |

**Artifacts after this change (unsigned):**

| File | SHA-256 |
|---|---|
| wheel | `bc75f41eb092233972c14d16520d7d02a6d5dd5f0616f95e28e2204573ae0d79` |
| sdist | `d20c0fd80fc57d95ae5847a1ad44c87112cc44c5cf50d29976d23062155b64b3` |
| SBOM | `57878cdf48d3379c5ca248bfbf07446c073d14eeaf0a223d8195cd4916a0a20e` |

The earlier artifact table in this section is superseded.

**Cost:** the first container check in each process exports each image it uses once (the Semgrep image is 1.16 GB). The real-test modules add about a minute.

**Not claimed:**

- Hardware signing: SD-T01 to SD-T55, the ceremony, FIDO2 recovery.
- MobSF code analysis on a real DEX file.
- Linux and Windows.

**Verdict unchanged: NOT RELEASE READY.** The only release blocker is production signing (B-5), which needs the hardware ceremony. The release is macOS-only (B-4).


## 11. Update: signer software completed (2026-11-13, owner asked to complete everything for publishing)

**What changed (D-73 scope, no new decision):**

- **The signer now implements the full design, in software.** That covers:
  - the authoritative registry, with the engine-identical trust projection and fingerprint (design §2.1, §2.2);
  - the R3.1 pending, commit and abandon state machine (no automatic transitions);
  - key-operation checks against the SD's own registry: enrolment, candidates only, no self-revocation, the last operator key kept, recovery limited to a replacement generated in the session;
  - the trust-store audit;
  - recovery assertions: the strict §1.3 checks and the counter policy, with suspect marking;
  - D-46 signed checkpoints, with restore only from the exact paper anchor;
  - `signer.release` records with tree hashes, and installation;
  - APFS, not-encrypted and mount-flag checks before any file access (R3.2);
  - staged intake discarded on interruption, and byte-identical re-issue of a response (R3.1);
  - the SD-T55 clock check;
  - the ceremony and recovery-session commands.
- **The `set-trust-mirror` command was removed.** It took the DM's fingerprint as input, which the design forbids; the SD now computes it.
- **FIDO2 recovery uses AuthenticationServices (F-3).** It compiles but is **unverified**; SD-T35 on the hardware decides.
- **Size:** the signer source is about 2,100 lines, within the design's 3,000-line review limit.

**Defects found and fixed:**

1. **The signer exported the protocol §3.3 envelope, but `sentinel key enrol|rotate --key` accepts only the engine's key-file format.** A real enrolment would have failed. The SD now writes the engine format (`{key_id, algorithm, public_hex}`, plus the D-47 fields for a recovery key).
2. **The engine couldn't carry the first enrolment over protocol v1.** `approval request` and `approval receive` both required the key to be trusted already, so ceremony steps 6–8 couldn't run.
   - **Fix:** `approval request --enrol-key pub.json` accepts only the key's own self-signed `key.rotate` into an empty trust store. The pending record keeps the candidate key; `receive` re-checks the conditions and verifies the response with that key. `key enrol` still verifies the approval in full.
   - **Unchanged:** every other request path.
   - **Tests:** `tests/test_enrolment_request.py`.
3. **A mutation survivor:** a `key.rotate` naming an already-revoked key would have reactivated it on the SD after commit. The test was added, and the mutant is now caught.

**Executed:**

| Check | Exit | Result |
|---|---|---|
| `swift test` (SignerCore) | 0 | 32 of 32 XCTests |
| `tests/test_signer_interop.py` (real Swift `Device` code, software keys and authenticator, against the unchanged engine) | 0 | 8 of 8. Covers the full ceremony, rotation, a second key operation refused while PENDING, recovery enrolment and recovery-signed replacement and revocation. The SD and engine trust fingerprints match at every step, including the recovery counter. Also covers abandon after expiry, checkpoint restore, release install, recovery self-revocation refused, and a tampered response refused |
| New mutation suite `signer` (41 mutants: 37 in Swift, each checked to compile first; 4 in the engine) | 0 | 40 of 41 caught in round 1. Round 2: the survivor caught after the new test. **Final: 41 of 41** |
| Existing engine mutants on `signing_protocol.py` (17, full engine suite) | 0 | 17 of 17 caught |
| Complete suite `pytest -rfEs`, share-free VM running | **0** | **1790 passed, 0 failed, 0 skipped** (472 s). A first run while the VM was stopped skipped 31 tests; those skips were not counted, and the suite was rerun |
| `release_check.py`; ruff; format (208 files); mypy (71 files); architecture docs; licence audit `--strict`; D10/D11 `--check` | 0 | All clean. Git index unchanged |

**Artifacts (unsigned):**

| File | SHA-256 |
|---|---|
| wheel | `9769121c739216db7d42981e25ec5042111a60f930b3e108fcd82c60b5a7359e` |
| sdist | `f18f0909078f85c0c8e62d732b835c8a13bc833b90fa894a2295bea75c460349` (**defective**: it carried the SwiftPM build cache; see §12) |
| SBOM | `a5c3c2b4aa62d64d6a6d04ea429404e9d2b4d467236fe351c719510ecb5f3c60` |

These supersede the earlier artifact tables.

**What publishing still needs:** see `docs/roadmap/publish-runbook.md`.

- **Owner decisions:**
  - A1: commit and remote;
  - A2: the release-signing mechanism (D-20 says signed release tags, but no key or action is defined, and D-45 is frozen);
  - A3: the publication target.
- **Hardware:** SD provisioning, SD-T01 to SD-T55 (SD-T35 decides FIDO2), the first-enrolment ceremony and an activation decision.

**Verdict unchanged: NOT RELEASE READY.** No software work remains that can be done without those decisions and the hardware. The release is macOS-only (B-4).

## 12. Correction: the sdist shipped Swift build caches (2026-11-13, found before the first commit)

**Defect.** Reviewing what the first commit would contain showed `native/macos/sentinel-signer/.build/`
(2,992 files) as untracked. No ignore rule covered it, and the sdist allowlist includes `native`, so the
sdist carried it too. The §11 sdist (`f18f0909…`) was **95 MB with 3,817 members, 2,992 of them SwiftPM
build output**, including Apple SDK precompiled modules (`.pcm`) and index records of SDK headers.
`release_check.py` passed it, because it checked reproducibility, versions, installation and the SBOM,
but never the contents. The §11 row "`release_check.py` … All clean" was therefore wrong for the sdist.
The cache directory appeared on 2026-11-10 at 15:05, so the §10 sdists built after that time probably
carried it as well; those files no longer exist, so this can't be confirmed. Every earlier sdist hash
is superseded. The wheel was never affected.

**Fix.**
- `.gitignore` now ignores `.build/` and `.swiftpm/`.
- The sdist target now has an `exclude` list (`**/.build`, `**/.swiftpm`, `**/__pycache__`, `**/*.pyc`,
  `**/.DS_Store`), which applies whatever the ignore files say.
- `release_check.py` step 6 refuses any wheel or sdist that carries build output, caches, VCS metadata,
  local agent tooling or `docs/private/`, or that is over 10 MiB. The report records
  `artifact_contents: clean`.
- Regression tests: 10 new tests in `tests/test_m10_sbom.py`, and the end-to-end test now asserts the
  contents check. Four hand mutations of the check (forbidden list, match, prefix strip, size cap) were
  all caught.

**Rerun:**

| Check | Exit | Result |
|---|---|---|
| `release_check.py` | 0 | Reproducible; `artifact_contents: clean`; installed-wheel `self-check` verified; SBOM valid |
| sdist | — | **872 KB, 825 members**, with no build output |

**Artifacts (unsigned), superseding §11:**

| File | SHA-256 |
|---|---|
| wheel | `9769121c739216db7d42981e25ec5042111a60f930b3e108fcd82c60b5a7359e` (unchanged) |
| sdist | `12080854e7a2e49a897d63caa970436ee2a9efb6ff1c1499d5a8ee8e8cce229e` |
| SBOM | `a5c3c2b4aa62d64d6a6d04ea429404e9d2b4d467236fe351c719510ecb5f3c60` (unchanged) |

The sdist contains this report and `CHANGELOG.md`, which changed after the check ran, so a rebuild now
gives a different sdist hash. Release hashes come from runbook step C1, not from this table.

## 13. First commit, GitHub remote and the first remote CI run (2026-11-13)

**Owner decisions:** A1 approved a local commit, and A3 chose GitHub. Commit `fe1763f` (828 files,
GitHub no-reply author address) was reviewed before it was made:
- the staged list matched the reviewed list exactly;
- the pinned Gitleaks scan found only the 6 known synthetic test secrets;
- no private portfolio project names appear.

Three files carried the owner's personal email address (from an Apple Development certificate
identity), and two carried session scratch paths; these were redacted first. The owner created the
private repository `samsadrashid/sentinel` and pushed `fe1763f`.

**First remote CI run (on `fe1763f`): failed, for two reasons, both fixed in the working tree.**

| Job | Result | Cause | Fix |
|---|---|---|---|
| `engine (ubuntu-24.04)` | failure at "Strict licence audit" (19 issues, `build_env_missing`) | `engine-ci.yml` never created `build/license-env`; it existed (gitignored) only on the DM. A fresh local clone shows the same 19 issues | The workflow now creates and hash-installs the env before the audit and the suite; regression test |
| `engine (macos-14)`, `license-gate` | cancelled: "The configuration 'macos-14-arm64-us-xl' is not supported" | GitHub retired the macos-14 image on 2026-11-02 | Both workflows use `macos-26` (the DM's OS); regression test refuses older labels |

A fresh clone of `fe1763f` passes `release_check.py` and, once the env step is replayed, the licence
audit and its tests. The Ubuntu job never reached the test suite, so **Linux has still never run the
suite**, and the B-4 macOS-only limit stands.

**Second remote CI run (on `30a6ada`, 2026-11-13): the full suite ran remotely for the first time.**
`license-gate` passed on macos-26. `engine-ci` failed on both platforms:
- `engine (ubuntu-24.04)`: 3 failed, 1699 passed, 100 skipped;
- `engine (macos-26)`: 14 failed, 1738 passed, 50 skipped.

Three genuine defects, none visible on the DM:

| Failure | Cause | Fix |
|---|---|---|
| 12 Seatbelt tests on macos-26 (probe self-test failed; sandboxed checks `ERROR`, audits `INCOMPLETE`) | python.org and Homebrew Pythons are framework builds: `bin/python3.x` re-executes `Resources/Python.app/Contents/MacOS/Python`, and the one-executable profile denied it (`posix_spawn` refused). Reproduced on the DM with Homebrew 3.14. **Every native check failed closed for anyone on python.org or Homebrew Python** | `adapters.base.sandbox_interpreter()` executes the bundle binary directly; the profile is unchanged (still one literal executable). Tests: a unit test plus a real probe under a framework Python found on the host; disabling the fix fails both |
| `release_check` clean install on both platforms (two tests each) | The clean venv used uv's *default* Python (system 3.12 on Ubuntu, another Python on the runner), then re-resolved `cryptography` offline, which depends on what happens to be cached. The error itself was hidden | The venv uses the interpreter running the check, installs the locked, hash-verified closure (`uv export --frozen`, `--require-hashes`), then the wheel `--no-deps`, then `uv pip check`. A failing tool's own error is now printed. Reproduced and fixed on the DM by forcing a different default Python |
| `test_signer_core_xctest_suite_passes` on Ubuntu | The signer is macOS-only (CryptoKit, Secure Enclave); the test tried `swift test` on Linux | The Swift tests skip off macOS with a platform reason. On macOS a failed signer build now **fails** the interop tests (it used to skip them) |

The full suite still hasn't passed remotely. The next push is the test. The framework-Python full suite
couldn't run on the DM: there is no cached `cffi` wheel for Python 3.14, and downloading one wasn't
approved. Only the probe and the unit tests ran under a framework Python here.

**Third remote CI run (on `117ddf6`):** `license-gate` passed. `engine-ci` failed on both platforms:
- `engine (ubuntu-24.04)`: 2 failed, 1700 passed, 104 skipped;
- `engine (macos-26)`: 9 failed, 1766 passed, 31 skipped.

On macos-26, the Seatbelt probe, the adapters, the pipeline and the sandbox-rejection tests now pass.
Two follow-ups remained:

| Failure | Cause | Fix |
|---|---|---|
| 7 `test_isolation.py` tests on macos-26 | The tests' own `run_script` helper still passed the framework launcher (`realpath(sys.executable)`), not what production runs | The helper uses `sandbox_interpreter()` |
| `release_check` on both platforms, now with uv's error shown: "there is no version of cffi==2.1.1" | `uv pip install -r` resolves through package-index pages. A lock-based `uv sync` (what CI ran) never caches them; the DM's cache had them from earlier `uv lock` runs | The clean venv gets the closure from `uv.lock` by `uv sync --frozen --offline --no-dev --no-install-project`, then the wheel `--no-deps`, then `uv pip check`. Reproduced on the DM by hiding the cffi, cryptography and pycparser index entries; the old path failed exactly as on CI, and the new one passes with them hidden, also with a different default Python |

**Fourth remote CI run (on `73791ae`): passed.** Every job succeeded: `license-gate` (macos-26),
`engine (macos-26)` and `engine (ubuntu-24.04)`, with ruff, format, mypy `--strict`, the strict licence
audit, the docs checker and the full suite.

| Job | Passed | Failed | Skipped |
|---|---|---|---|
| `engine (macos-26)` | 1776 | 0 | 31 |
| `engine (ubuntu-24.04)` | 1703 | 0 | 104 |

**The skips are not passes.**
- **macos-26:** all 31 skips are tests that need the DM's pinned real scanners, the share-free Podman
  machine and MobSF, none of which a hosted runner has. They ran on the DM (1807 passed, 0 skipped).
- **ubuntu-24.04:** the same 31, plus 73 macOS-only tests: Seatbelt (37), the Secure Enclave helper (27)
  and the signer (9).

On Linux the engine, the schemas, the reports and the protocol code pass, but **no native sandbox
exists, so every sandboxed check is `NOT_RUN`**. This is not Linux acceptance: B-4 (macOS only) stands.

**Verdict unchanged: NOT RELEASE READY** (see §11 and `publish-runbook.md`).

## 14. Release signing on the signing device (D-74, 2026-11-14)

**Owner decision:** A2 is settled as option (a), "Sign on signing Mac", and recorded as **D-74**. D-74
adds one operator action, `release.publish`, to D-45 and leaves every other permission unchanged.

**Implemented:**
- **Engine:**
  - `ApprovalAction.RELEASE_PUBLISH` is one-time, so it's never a `revoke_record` target, with a 1-hour
    D-37 window;
  - it's in the operator permission set and the trust-store fingerprint, and never in the recovery set;
  - a strict schema branch: subject `{type, name: sentinel-audit, version, commit}`, revision `sums:<sha256>`,
    and scope of 1 to 16 plain artifact names.
- **Release module:**
  - strict `SHA256SUMS` parsing;
  - `release_parts`, which recomputes the payload from the files;
  - `verify_release`, which checks the key, the signature, and with a trust store the D-45 role,
    permission, status and key expiry at `issued_at`, plus the signed digest, the artifact list, every
    file and the wheel version.
- **CLI:** `approval prepare release-publish --dist --commit`, `release attach` (verifies, then writes
  `SHA256SUMS.approval.json` and never overwrites), and `release verify [--key]`.
- **Signer:**
  - Policy and its lifetimes gain the action;
  - subject checks;
  - `releaseSums` recomputes the `SHA256SUMS` bytes from the listed artifacts (sorted, unique, plain names,
    16 at most, never naming `SHA256SUMS` itself) and refuses any digest that differs;
  - the wheel version must match the subject;
  - the review screen shows the version, the commit and every hash, and tells the operator to compare
    them with the remote CI build, never with the DM.

**Fixed during verification:**
- **A flaky Swift test.** `ReleaseTests` forged a `signer.release` record by flipping one byte of the
  base64 signature text. With random keys, that byte could become an invalid base64 character, and the
  record was then refused as malformed before the signature check ever ran. That let `sw-rel-sig`, a D-73
  mutant previously caught, survive this run. The test now corrupts the decoded signature, and separately
  a signed field, and requires `bad_signature` both times; `sw-rel-sig` was caught in two reruns.
- **One mutant anchor.** `eng-f-rel-dotfiles` was re-anchored to the restructured `sha256sums`
  condition; applied by hand, it is caught by `test_release.py`.

**Executed:**

| Check | Exit | Result |
|---|---|---|
| `tests/test_d74_release_signing.py` | 0 | 45 passed |
| `swift test` (SignerCore) | 0 | 39 XCTests (7 new) |
| `tests/test_signer_interop.py` | 0 | 10 of 10. Includes a D-74 round trip through the real SignerCore, and a forged digest that the engine emits and only the SD refuses (`release_sums_mismatch`). Every earlier ceremony still matches fingerprint for fingerprint with the new permission |
| D-74 mutants (35 new, plus the 4 existing `signer.release` mutants rechecked) | 0 after the fix | Round 1: 38 of 39 caught; the survivor `sw-rel-sig` was the flaky test above, not a D-74 defect. After the fix: 39 of 39 |
| `release_check.py`, licence audit `--strict`, D10/D11 `--check`, docs checker, ruff, format, mypy `--strict` | 0 | All clean. The real release directory parses under the D-74 rules |
| Complete suite `pytest -rfEs`, share-free VM running | **0** | **1857 passed, 0 failed, 0 skipped.** A first run had 2 failures: tests that list every action or lifetime didn't include `release.publish` yet. Both were updated, and the suite was rerun in full. A run started while the VM was stopped was stopped and not counted |

**Artifacts (unsigned):**
- wheel: `4266a4166b217d7021f542e5f0cbe974732fd8bbae720e62cbaae1fa93484746`
- sdist: `4b67c6deca21e9e0db87402a0fa40228d35f641af6e42996e17018847a27851c`
- SBOM: `50f192e2a942801ebd486bc0e7c9bd744abc23a8dd2bac056ef37e4475f1048f`

The sdist hash changes with any later doc edit. Release hashes come from runbook step C1.

**Remote CI (on `2ae0fc4`): passed.** `license-gate`, `engine (macos-26)` and `engine (ubuntu-24.04)` all
succeeded.

| Job | Passed | Failed | Skipped |
|---|---|---|---|
| `engine (macos-26)` | 1826 | 0 | 31 |
| `engine (ubuntu-24.04)` | 1751 | 0 | 106 |

Both totals equal the 1857 tests that pass on the DM. On macos-26 the Swift signer tests and the D-74
interop tests ran on the hosted runner. The skips are not passes:
- **macos-26:** the 31 skips need the DM's real scanners, the share-free machine and MobSF.
- **ubuntu-24.04:** the same 31, plus 75 macOS-only tests (Seatbelt 37, Secure Enclave helper 27,
  signer 11).

Linux acceptance is still not claimed (B-4).

**Not done:** no release is signed. Every key here is a software test key. The first real
`release.publish` signature needs SD-T01 to SD-T55, the ceremony and the activation decision. **Verdict
unchanged: NOT RELEASE READY.**
