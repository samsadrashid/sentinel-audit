# Changelog

## Release candidate (M2 to M10, unreleased, package version 0.1.0.dev1)

Nothing is published. It is not production-ready: production signing is disabled, and only macOS has been tested. See `docs/roadmap/sentinel-final-release-report.md`.

### Added
- **Real scanners** (approved, pinned): Gitleaks, Semgrep, OSV-Scanner and Syft under Seatbelt and rootless Podman. Trivy, Grype and Checkov (approved in D-66), with offline, manifest-pinned databases.
- **M3 domain rules and fixtures** for D01, D02, D08 and D14, with per-domain coverage states (FULL, PARTIAL, NOT_RUN, ERROR, and NOT_APPLICABLE only with discovery evidence).
- **Native static analysers** (Seatbelt only): Android, iOS, OS-configuration snapshots, supply chain, browser and VS Code extensions, and AI-agent and MCP configuration.
- **Pinned, sandboxed plugins** (`plugin inspect`, `plugins` policy key). The verified bytes are what runs, and plugin hashes are recorded in finding provenance.
- **`mcp serve`:** a local stdio MCP server; target-read-only, with no client authentication.
- **`compare`:** comparison of two verified runs, with D-64 issue identity, remediation status, risk totals and evidence IDs.
- **`self-check`:** verifies the installed package against its wheel RECORD.
- **SARIF:** reports carry domain coverage, checks not finished and limitations.
- **Final completion:**
  - **Android:** deep links, scoped storage, dynamic and debug-signed Gradle configuration, WebView mixed content, universal file access and ignored SSL errors, hard-coded keys, seeded SecureRandom.
  - **iOS:** web-content ATS, background modes, file sharing, data protection, keychain groups, plaintext URLs, Podfile and Swift Package pinning.
  - **OS snapshots:** FileVault, SIP, Gatekeeper, the macOS firewall, ufw, SELinux and AppArmor boot flags, PAM, cron and boot persistence, the Windows firewall, Secure Boot, WDigest, LSA and Run keys.
  - **Binary metadata** (`binmeta`, D-65): PE, MSI and MSIX headers.
  - **Supply chain:** SBOM validation, missing lockfiles.
  - **D10 and D11:** additional rules, plus a 78-case evaluation corpus and metrics.
  - **Release:** Sentinel CycloneDX SBOM, and a reproducible release check (`scripts/m10/release_check.py`).
- **Share-free container isolation (D-70, D-71):** every container check runs in a Podman machine with no host share. Targets and databases are copied into VM-local volumes, never bind-mounted (resolves M2-SA-12). `podman.machine` is a required pin.
- **B2 archive inspection (D-70):** APK, AAB and IPA unpacking by Sentinel's own stdlib program, in a no-mount container.
- **MobSF 4.6.4 (D-72):** static analysis of built mobile artifacts in the share-free machine, under the owner's recorded risk acceptance for GHSA-j7g2-gm7j-mfvm.
- **`sentinel-signer` (D-73):** signing-device software (protocol v1 validation, ledger, USB transport, Secure Enclave signing). Software only; production signing stays disabled until the hardware tests and the ceremony.
- **Release signing (D-74):** the signing device signs a one-time `release.publish` approval over the exact
  `SHA256SUMS` bytes and the artifact list (operator keys only, 1-hour window). New `approval prepare
  release-publish`, `release attach` and `release verify`. Tested in software only; no release is signed
  before the ceremony.

### Fixed
- **The sdist shipped SwiftPM build caches:** `native/macos/sentinel-signer/.build/` (2,992 files, 95 MB,
  including Apple SDK precompiled modules) went into the sdist because no ignore rule covered it.
  `.build/` and `.swiftpm/` are now ignored and excluded from the sdist, and `release_check.py` refuses any
  wheel or sdist that carries build output, caches, local agent tooling or private docs, or is over 10 MiB.


## 0.1.0.dev1 (M1, unreleased)

First milestone: the core engine and the agent skill interface. Nothing is published.

### Added
- Engine CLI: audit, runs, evidence verification, reports (JSON, SARIF, Markdown, HTML), policy
  validation, key administration, signed decisions, approval preparation and inspection, history.
- Versioned JSON Schemas (D-40): 24 contracts, an in-house restricted 2020-12 validator, validation at
  every input and output boundary.
- Engine-side operator-signing infrastructure (D-49): D-45 key roles and permitted actions in the
  trust store and its fingerprint; a separate D-47 recovery WebAuthn assertion verifier with the OD-3
  counter policy; protocol-v1 sign-request emission and response reception (`approval request`,
  `approval receive`); software test-key fixtures.
- `fix-plan` (D-50): deterministic, read-only remediation plan for a verified run.
- Claude Code and Codex Skills with the D-41 version check (`agent check`).
- Engine CI workflow for macOS and Linux; actions pinned by commit.

### Removed
- `allowlist.change` approvals (D-42).
- The legacy handle-on-disk Secure Enclave key-file format.

### Security
- Mutation harness counts only behavioural catches; earlier campaign results (including Task 1's
  158/158) were invalid as reported and have been superseded.

### Not included
- Real scanners; production operator signing (disabled); the signing device and its hardware tests;
  Linux isolation; the M9 remediation workflow.
