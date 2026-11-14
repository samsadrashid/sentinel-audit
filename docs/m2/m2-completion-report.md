# M2 completion report

**Date:** 2026-11-09.

**Scope:** frozen M2 row, clarified by D-52 to D-57 (`docs/m2/scope.md`).

**Status:**
- **M2 implementation, real integration and verification are complete. The report awaits owner acceptance.**
- M1 stays accepted and closed. M3 hasn't started.
- Production signing stays disabled.
- Nothing has been staged, committed, pushed or published. Remote CI hasn't run.

## 1. Dependencies: provenance, hashes, licences

Everything listed was approved by the owner, and nothing was substituted. Each artifact was verified before use.

| Artifact | Version | Verification | Pinned identity | Licence |
|---|---|---|---|---|
| Podman installer (`podman-installer-macos-arm64.pkg`) | v6.1.4 | SHA-256 equals the request; `pkgutil` shows it is signed by Developer ID Installer: Red Hat, Inc. (HYSCB8KRL2) and **notarised**; `spctl` accepted; every extracted binary passes `codesign --verify --strict` (team HYSCB8KRL2) | pkg `48f675622f66233ca2116e67fdab41ed9dbcc25b48b78a8e6ef0be6549031d22`; client `9603079ca32a9fa88f0aa2b3f9e41c9365d7db2dc19c75857a1ec40aee6e5837` | Apache-2.0 |
| Podman Machine OS (`quay.io/podman/machine-os:6.1`, Fedora 44, kernel 7.2.7) | 6.1 | Pulled by `podman machine init` (content-addressed OCI artifact) | config `sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`; disk blob `sha256:cd711cd582d301f11616281f0b0098de7cad26b050b7317b8bd3f3ac667c0d21`; tag index at the time of verification `sha256:79d3e544cb66a48646dc32a3076da15c38ef46ea7a670b2cbf014d63b28eaaeb` | Fedora component licences |
| BusyBox (probe only) | 1.37.0 | Pulled by index digest | `docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` (arm64 `…d82c2ab9…`) | GPL-2.0-only |
| Gitleaks | 8.30.1 | Archive SHA-256 equals the request **and** the upstream `checksums.txt`. The binary is ad-hoc signed (not Developer ID); the hash pin is the control | archive `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`; executable `ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f` | MIT |
| Semgrep CE | 1.184.0 | Pulled by the requested index digest (immutable GitHub release) | `docker.io/semgrep/semgrep@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed` (arm64 `…52219acb…`) | LGPL-2.1-or-later |
| OSV-Scanner | **2.7.0** (owner choice) | Index digest from the ghcr manifest; GitHub asset digests recorded | `ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0` (arm64 `…de2dcd79…`) | Apache-2.0 |
| Syft | 1.57.0 | Pulled by the requested index digest (immutable release) | `docker.io/anchore/syft@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a` (arm64 `…8a247397…`) | Apache-2.0 |
| OSV offline database, snapshot 2026-11-09 | PyPI, npm, Go, crates.io, Maven, RubyGems | **The publisher provides no signature and no SHA-256 (limitation, D-56).** Each zip's MD5 was checked against the GCS `x-goog-hash` header (all 6 match), then its SHA-256 computed and written to a snapshot manifest; the manifest's own SHA-256 is pinned. Sentinel verifies the manifest and every file before each run | manifest `c7c1712dcfa67c27566bb3885c201ee6242f05471d826b48201830683e8689aa` | Aggregated advisory data, per-source terms (mostly CC-BY-4.0) |

**Installation:**
- Everything lives in `~/.local/share/sentinel-deps/`, user-owned, with no root and no system changes. The notarised Podman package was **extracted** rather than installed system-wide, because its `postinstall` only adds PATH and man entries and an optional Docker-socket helper.
- `~/.config/containers/containers.conf` sets `helper_binaries_dir` and `provider = "applehv"`. krunkit's `@rpath` points at `/opt/podman/lib`, which exists only in a system install, so vfkit from the same package is used instead.
- Licences for these external tools are recorded in `licenses/external-tools.md`. They are not redistributed; `THIRD_PARTY_NOTICES` is generated from `uv.lock` and covers the Python dependencies.

## 2. Real integration results (no fakes)

From `tests/test_m2_real_scanners.py`, 17 tests, all passed. They skip with an explicit reason, never pass, when the dependencies are absent.

| Item | Result |
|---|---|
| Podman rootless | `host.security.rootless = true`; machine `Rootful=false`; server 6.1.4 |
| Podman functional self-test (BusyBox, exact run profile) | network **denied**, target write **denied**, root write **denied**, workspace write **allowed**, `CapEff=0000000000000000` |
| Network-denial positive control | The same probe with default networking reports `allowed`; with `--network=none`, `denied`. The probe discriminates |
| Container view | Target read-only; `/Users` not visible inside containers |
| Native S1 sandbox probe | passes |
| Gitleaks (Seatbelt) | `FAIL`: the live-format AWS key is labelled `live`, and the raw secret is absent from the evidence and findings |
| Semgrep (Podman) | `FAIL`: three findings, every rule `sentinel-*` (D-55) |
| OSV-Scanner (Podman, offline) | `FAIL`: 14 advisories for `requests==2.19.0` and `PyYAML==5.3` |
| Syft (Podman) | `PASS`: SBOM includes requests and pyyaml |
| Hash or digest before execution | Binary re-hashed every run; Podman client hash and rootless state re-checked; images only `@sha256:` with `--pull=never` |
| No runtime pulls | An unpulled digest is `NOT_RUN` (`image_missing`) and is still absent afterwards |
| No scanner network | `--network=none` in every recorded invocation. OSV-Scanner's attempt to reach `api.deps.dev` was **refused** in a real run; it now runs `--offline` |

**AC-02 (real):** a full S1 and S2 audit with all four real scanners leaves the target tree byte-for-byte, mode- and mtime-identical. Statuses: gitleaks `FAIL`, semgrep `FAIL`, osv-scanner `FAIL`, syft `PASS`. Overall `FAIL`. No containers are left over, and no raw secret appears in the report.

**AC-03 (real), all non-PASS:**

| Case | Result |
|---|---|
| Tampered binary | `NOT_RUN` (`binary_hash_mismatch`) |
| Unpulled image | `NOT_RUN` (`image_missing`), never pulled |
| Wrong Podman hash | `NOT_RUN` (`podman_binary_hash_mismatch`), probe unavailable |
| Unverified OSV database | `NOT_RUN` (`osv_database_manifest_mismatch`) |
| 1 s timeout | `ERROR` (`timeout`), container removed |
| Output overflow | `ERROR` (`output_limit`), container removed |
| Real cancel | `BLOCKED` (`cancelled`), container removed |
| No runner | `NOT_RUN` (`host_isolation_unavailable`) |

## 3. AC-15 to AC-18

| Criterion | Result |
|---|---|
| **AC-15** PII minimisation | 10 classes × 60 synthetic instances (≥50 required). 600 of 600 detected. **0 raw instances** across evidence, findings, json/sarif/md/html reports, `runs show`, `evidence verify`, `fix-plan`, run and admin logs, and CLI output. A detector failure raises `RedactionError`, holding the artifact back as `ERROR`. False positives on the clean corpus: **0** per class out of 18,000 look-alike lines. Uncovered classes are listed in every report. Detection is format-only, never identity verification. Details in `docs/m2/pii.md` |
| **AC-16** Secret classification | 0 live-format values labelled `test`, including live formats containing marker words. 100% of documented test markers labelled `test`. Identical labels across runs. No network (sockets forbidden in the test) |
| **AC-17** Kill switch, pause, resume | 20 of 20 runs with a long-running scanner stopped within 10 s, and 20 of 20 real process trees (parent and child) were killed. A stopped check is `BLOCKED`, the audit `Cancelled`, overall never `PASS` (including when the adapter reports `ERROR` after the kill). Pause starts no new check. Resume re-authorises every remaining check (refusals counted at resume). A source change while paused gives `restart_required`, and the CLI reruns once. Every transition is logged. A real container cancel removes the container. **B2 runs are not measured; B2 is outside M2** |
| **AC-18** Retention | `--list` leaves the tree hash unchanged. `--delete` deletes only expired runs, and only with interactive typed confirmation; it is refused non-interactively and from agents. A hash-only `retention.deleted` entry is written first, 0 files remain, and `history verify` passes. Runs of unknown age are never deleted |

## 4. Test, mutation and static results (final)

The session was unlocked, and the harness preflight passed.

| Check | Result |
|---|---|
| Full `pytest`: M1 + M2, real scanners, Secure Enclave | **1375 passed, 0 failed, 0 skipped** |
| Mutation campaign (catalogue `77f33756`, 340 mutants) | Full run: 337 caught, **3 survived**, 0 invalid, 0 infrastructure-failed, 0 anchor-only. Baseline engine 116.1 s and license 2.5 s, both exit 0 |
| Survivor fixes | All three were test gaps, not equivalent mutants. New tests: (1) kill switch fires while the adapter reports `ERROR`; (2) resume-time refusal count; (3) unknown command against an active audit. Rerun of those three: **3 of 3 caught** |
| **Final mutation result** | **340 of 340 caught by behavioural tests; 0 survived, 0 invalid, 0 infrastructure-failed** (308 engine, 29 license plus the 3 rerun) |
| Ruff, format (136 files), `mypy --strict` (48 files) | clean |
| Strict licence gate | 0 issues |
| Docs checker | PASS (register D-01 to D-57) |
| Wheel and sdist | built offline. `sentinel_audit-0.1.0.dev1-py3-none-any.whl` `566e9291a8e9a757e5d42448a66df6dcfc32f55667ec429653723814957b8047`; `.tar.gz` `a81cb220fb32091709afa1f3aed2bb08c070a0c3bfc8c6a6fbc45e585506b978`. All contracts, Skills and Semgrep rules ship; installed-wheel load passes |
| Historical integrity | `SHA256SUMS` all OK; signatures verify; admin-log chain verifies (`history verify` in the AC-18 tests) |
| Git index | unchanged: `c1a18d46…` / `e0cdc1fa…` |

## 5. Security audit findings (M2)

| ID | Finding | Status |
|---|---|---|
| M2-SA-01 | An S1 scanner pinned as an image (Semgrep) could never run on macOS, because the native sandbox always claimed S1 | Fixed: runner selected by pin kind, with no cross-fallback |
| M2-SA-02 | PII detectors matched digit runs inside hashes, key IDs and UUIDs, randomly breaking contract-checked output | Fixed: token-boundary rules, plus a 60,000-sample property test |
| M2-SA-03 | IPv4 followed by `.` (end of a sentence, or a file name) escaped redaction, a **real leak** caught by the end-to-end test | Fixed, with a mutant |
| M2-SA-04 | The field name `secret_class` triggered credential redaction of its own value | Fixed: renamed to `liveness` |
| M2-SA-05 | OSV-Scanner attempted network resolution (`api.deps.dev`); refused by isolation | Fixed: `--offline`, with a mutant and a test |
| M2-SA-06 | Container scanners had a host-disk workspace, where scanner logs could hold raw content temporarily | Fixed: the workspace is a tmpfs (memory only) |
| M2-SA-08 | Leftover-container checks could cause false catches in parallel mutant runs | Fixed: checks scoped to containers each test created |
| M2-SA-09 | The CLI auto-restart after a source change was documented but not implemented, and a placeholder test existed | Fixed: implemented and tested |
| M2-SA-10 | A corrupt run log made `prune --list` fail instead of reporting `age_unknown` | Fixed |
| M2-SA-11 | Three behaviours had no killing test (§4) | Fixed |
| **M2-SA-12** | **Podman Machine (applehv) host shares are read-write from inside the VM, even when requested `:ro`.** Verified by writing a file to `/Users` from the VM | **Verified residual risk (§6); not resolved** |

## 6. Podman residual risk and its operational impact

- **Fact:** under the applehv provider, the VM mounts `/Users`, `/private` and `/var/folders` read-write via virtiofs, whatever `:ro` is requested. A process with root inside the VM could modify the host's files in those trees. **The VM is not a read-only host boundary,** and this report doesn't claim it is.
- **What protects scans:** the **container** boundary, independently verified by the functional self-test and `test_real_container_sees_only_the_read_only_target`:
  - rootless user namespace;
  - `--network=none` and `--read-only`;
  - all capabilities dropped, plus `no-new-privileges`;
  - only the target, and for OSV the database, bind-mounted read-only;
  - workspace in memory;
  - `/Users` not visible inside the container.

  A scanner must first **escape the container to the VM**, then act as root in the VM, to reach host files.
- **Operational impact:**
  - S1 (Semgrep) and S2 (OSV-Scanner, Syft) read-only scans rely on the container boundary, so they run.
  - **No M2 operation depends on the VM being a read-only host boundary.**
  - B2 (unpacking or handling untrusted artifacts) and A1 would depend on stronger containment. They stay `NOT_RUN` (`runner_for` returns None) until an independently verified boundary exists. A future decision is needed before any VM-dependent class is enabled.
- **Mitigations available but not applied** (each needs an owner decision): run scans from a dedicated macOS user, so the VM's shares expose less; use a Linux host with native rootless Podman (no VM shares); or limit the machine's shares to a dedicated scan directory.

## 7. Outstanding limitations and unverified capabilities

- **CLI use of real scanners:**
  - Pins reach production only through an approved `policy.change`.
  - Production signing is disabled. Real scanners are therefore exercised by tests that load the pins directly; the signed-policy CLI path is exercised with test keys only.
- **Linux:** rootless Podman on Linux and the Linux paths of the adapters weren't run; no Linux host was available. CI is not executed.
- **Podman Machine:** first-run `machine init` downloads the OS image from the tag, which can move. The digest is recorded at download, but `machine init` can't be pinned by digest from Sentinel.
- **Real-scanner tests on other hosts:** they skip on any host without the local dependency set, so other hosts don't re-verify real-scanner behaviour.
- **Gitleaks coverage:** Gitleaks applies its own allowlist; the AWS documentation key is not reported. Detection coverage is the scanner's own.
- **PII:** the limitations in `docs/m2/pii.md`. Clean-corpus false-positive measurement doesn't represent every repository.
- **OSV data trust:** OSV data integrity relies on HTTPS and GCS MD5 at download time. There is no publisher signature.
- **Out of M2 (unchanged):**
  - B2 and A1;
  - M3 domains and adapters;
  - signing-device hardware (SD-T01 to SD-T55);
  - production signing;
  - the official JSON Schema Test Suite (approval pending).

## 8. M2 acceptance criteria assessment

| Criterion (D-52, frozen M2 row) | Status |
|---|---|
| Discovery; adapter registry with manifests and hash checks; isolation manager for S1, S2, B1; Gitleaks, Semgrep, OSV-Scanner, Syft; PII; secret classification; kill switch, pause, resume; prune | **Met** (B1 has the isolation path but no M2 adapter) |
| Contract tests pass | **Met** |
| AC-02 read-only guarantee | **Met**, with real scanners |
| AC-03 failure handling | **Met**, with real failures |
| AC-15 | **Met** |
| AC-16 | **Met** |
| AC-17 | **Met for M2** (B2 measurement deferred with B2, as frozen) |
| AC-18 | **Met** |
| Mandatory conditions: PII before persistence; hash or digest before execution; no network; pause, resume, cancel semantics; pruning keeps history; no unsandboxed fallback; M1 guarantees preserved | **Met.** The VM host-share limitation is recorded as residual risk M2-SA-12 and doesn't affect the container boundary that M2 scans rely on |
| M1 suite green; 0 mutation survivors; gates clean; index unchanged | **Met** |

**Recommendation:** accept M2, with residual risk M2-SA-12 recorded, and the limitations in §7.
