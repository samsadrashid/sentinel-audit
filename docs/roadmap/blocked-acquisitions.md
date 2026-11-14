# Blocked items: exact blockers, minimum actions and remaining tests (2026-11-10)

Each item is recorded once. All implementation that doesn't depend on the item is finished. Nothing listed here has been downloaded, installed, signed or claimed as tested.

## B-1: Trivy, Grype, Checkov and their databases (M3)

- **Blocker:** D-60. Nothing is downloaded without the owner's explicit approval of `docs/m3/acquisition-request.md`. That document holds the exact versions, image index digests, release checksums, sigstore bundles, licences, platforms and the advisories checked.
- **Done without it:**
  - The adapters, pins and offline database mounts exist (`src/sentinel/adapters/scanners.py`, `scanner_pins.py`, D-29).
  - Grype consumes the Syft SBOM over stdin (D-61), and D-62 deduplication is in place.
  - Every check is `NOT_RUN scanner_not_approved`, and D08 and D14 coverage is `PARTIAL`.
- **Minimum action:** approve the request, then follow these steps.
  1. Pull each image **by the listed digest**: `podman pull ghcr.io/aquasecurity/trivy@sha256:8f6b…`, and likewise for Grype and Checkov.
  2. Verify the Trivy and Grype sigstore bundles with the pinned cosign v3.1.4.
  3. Download the database snapshots into new directories, and record their manifest SHA-256.
  4. Add the `scanners`, `trivy_database` and `grype_database` pins to a policy, and approve it with `policy.change`.
  5. Run `python scripts/m3/measure.py --write-coverage`.
- **Cost:** none; all are open-source and free.
- **Licence:** Apache-2.0. The database data is under each advisory source's own terms.
- **Security:** Trivy had a 2026 supply-chain compromise (GHSA-69fq-xp46-6x23). The requested version is after the fix, and it is pinned by digest and verified with cosign.
- **Impossible until done:** real Trivy, Grype and Checkov integration tests; FULL coverage for D08 and D14; final M3 recall.

## B-2: M3 recall and false-positive thresholds

**Measured** (real Semgrep, OSV-Scanner and Syft, 10 vulnerable and 10 clean fixtures per domain, reproduced 5 times):

| Domain | Recall | False positives |
|---|---|---|
| D01 | 1.0 | 0 |
| D02 | 1.0 | 0 |
| D08 | 0.846 | 0 |
| D14 | 0.818 | 0 |

Every miss is a Checkov-designated issue.

**Recommended thresholds** (engineering recommendation only; R and F are set only by the owner, D-63):

| Domain | Recommended R | Recommended F (clean fixtures with a finding) | Why | Consequence |
|---|---|---|---|---|
| D01 Web | ≥ 0.90 | ≤ 0.10 | Semgrep-only domain; 11 of 11 measured; leaves room for one miss as rules evolve | Met today |
| D02 API | ≥ 0.90 | ≤ 0.10 | Same reasoning | Met today |
| D08 Backend | ≥ 0.85, measured **with** Trivy, Grype and Checkov | ≤ 0.10 | Mixed SAST, dependency and IaC domain; the fixtures expect the IaC scanner | Not met until B-1 (0.846 without Checkov). Setting R ≤ 0.84 would accept the domain without IaC coverage, which isn't recommended |
| D14 Database | ≥ 0.80, measured with Checkov and Trivy | ≤ 0.10 | IaC-heavy and has the fewest fixtures (11 issues) | 0.818 today would pass at 0.80, but coverage stays PARTIAL. Recommended: require FULL coverage as well |

**Recommendation:** for every domain, require both the R and F thresholds and FULL coverage. Under that rule M3 can't be accepted before B-1.

## B-3: Product specification for the domain IDs

D-59 labels are provisional. **Action:** supply the specification, or confirm the labels by a dated decision. Nothing else depends on it technically.

## B-4: Linux and Windows hosts

- **Done without it:**
  - The OS-configuration analyser reads **snapshots** of macOS, Linux and Windows configuration on macOS.
  - The binary-metadata analyser parses PE, MSI and MSIX headers.
  - Hosts without verified isolation are `NOT_RUN` or `BLOCKED`.
- **Action:** provide a Linux host (with a native sandbox design decision for that platform) and a Windows host. Run the full suite on each, then the D06 Windows-native checks.
- **Impossible until done:**
  - AC-01 on Linux and Windows;
  - live-host M5 checks;
  - D06 Windows-native checks;
  - plugin and analyser isolation off macOS.

## B-5: Production signing and signed releases

- **Done without it:**
  - the engine side of operator signing (D-49): trust-store roles, the recovery-assertion verifier, and protocol-v1 sign-request and response handling;
  - an unsigned release manifest (`scripts/m10/release_check.py`, SHA256SUMS);
  - the CycloneDX SBOM.
- **Action:** the dedicated signing device, hardware tests SD-T01 to SD-T55, physical FIDO2 recovery and the first-enrolment ceremonies, all as specified in `docs/architecture/separate-signing-device-design.md` and `signing-protocol-v1.md`.
- **Signing the release afterwards:** decided by D-74 (2026-11-14): the signing device signs a one-time `release.publish` approval over the exact `SHA256SUMS` bytes and the artifact list, and `sentinel release verify` checks it. Implemented and tested in software; the first real release signature waits on the ceremony.
- **Signer software (D-73, D-74):** complete and tested in software (`native/macos/sentinel-signer`, 39 XCTests, 10 engine interop tests). It is not hardware-validated.
- **Impossible until done:** production signing; a signed release; real operator-presence validation.

## B-6: M2-SA-12 (container write-to-host): RESOLVED on 2026-11-10 (D-70 for B2, D-71 for every container scanner)

- **Fix:** a dedicated Podman machine with no host volumes, and B2 containers with no mounts. The archive goes in on stdin and the result comes out on stdout.
- **Evidence:** `tests/test_b2_real.py`, run with the share-free machine active, 4 of 4 passed:
  - no host-share filesystem is mounted in the VM;
  - the M2-SA-12 write-to-host reproduction now fails;
  - the container self-test passed: network denied, read-only root, no host paths, uid 65534;
  - a real end-to-end APK audit, plus a path-traversal rejection;
  - a timed-out container is killed and removed.
- **D-71 (all container scanners):** the runner refuses any machine with a host-share filesystem, streams the target into a per-run VM-local volume mounted read-only, and keeps databases in a VM-local volume re-verified against the manifest before each use. Evidence: `tests/test_d71.py` (unit) and `tests/test_d71_real.py` (real: no host file is visible to a container; a tampered database volume is refused, deleted and re-imported), plus the real M2, M3 and B2 scanner tests in one pass on the same machine.
- **Remaining:** macOS only. Linux and Windows hosts are untested.

## B-7: MobSF: RESOLVED on 2026-11-10 with a recorded risk (D-72)

- **Decision:** the owner accepted MobSF 4.6.4 despite GHSA-j7g2-gm7j-mfvm (fixed in the unreleased 4.6.5), on condition that it runs only in the share-free machine with no mounts, no network, a read-only root and a disposable container.
- **Implementation:** `adapters/mobsf.py` and the in-container driver `mobsf/driver.py`. Only built APK, AAB and IPA artifacts are streamed in. Only MobSF's static-analysis views are loaded. Any MobSF stage failure or truncated output is `ERROR`.
- **Evidence:** `tests/test_mobsf.py` (unit, fake runner) and `tests/test_mobsf_real.py` (real image: the container self-test, no network or host paths, and an end-to-end APK scan that finds the debuggable, cleartext and backup issues).
- **Image integrity incident:** the first stored copy of the image was damaged (138 zero-byte files, most likely from the earlier VM disk-full). `podman save` reported `file integrity checksum failed`. With owner approval it was deleted and re-pulled by digest; the re-pulled image has the same pinned ID, and every layer matches its `diff_id`. The other seven images verified intact.
- **Remaining:** upgrade to 4.6.5 when it is published. MobSF's code-analysis stage hasn't been exercised on a real DEX file (no such fixture without a download).

## D10 and D11 acceptance

The measured criteria are in `docs/roadmap/d10-d11-acceptance-criteria.md`. **Action:** approve, amend or reject the criteria, and name an external independent corpus if one is wanted. That would be a separate acquisition.
