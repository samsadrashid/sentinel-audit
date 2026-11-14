# Limitations (release candidate)

Status terms: **complete**, **complete with limitations**, **blocked by an external requirement** and **not implemented**. Sentinel never reports a missing, unapproved, failed or unsupported check as `PASS`. Such a check is `NOT_RUN`, `ERROR` or `BLOCKED`, and the audit is `INCOMPLETE`.

## Blocked by an external requirement

| Capability | Behaviour now | Needs |
|---|---|---|
| Trivy, Grype and Checkov scanners, and their vulnerability databases | Adapters exist; every check is `NOT_RUN scanner_not_approved`. Domains D08 and D14 report `PARTIAL` coverage | Owner approval of the acquisition request (`docs/m3/acquisition-request.md`) |
| Production operator signing; signed releases | Disabled. `status` reports it unavailable. Approvals must come from outside Sentinel | Signing device and hardware tests SD-T01 to SD-T55 |
| Linux and Windows hosts | Not tested. On a host without verified isolation, checks are `NOT_RUN` or `BLOCKED`, never run unconfined | Linux and Windows test hosts |
| MobSF 4.6.4 (mobile, D-72) | Runs only on built APK, AAB and IPA artifacts, in the share-free machine, with no mounts and no network, under the owner's risk acceptance for GHSA-j7g2-gm7j-mfvm. Static analysis only (the dynamic analyzer is never loaded). Without the `mobsf` pin it is `NOT_RUN`. Any MobSF stage failure (for example the decompiler) makes the check `ERROR`, never a partial `PASS` | MobSF 4.6.5, once released |

## Not implemented

- **Authenticode or MSI signature verification.** Signature blobs are reported as present, never as verified: verifying them needs a trust store and revocation data.
- **Vulnerability matching for Swift, CocoaPods and Gradle.** It needs Trivy or Grype (B-1). OSV-Scanner covers the ecosystems it supports.
- **Unmaintained-dependency detection.** It needs online registry metadata, and Sentinel is offline by design.
- Dynamic (A1) checks, red-team mode and B3 (running analysed artifacts). These are excluded from V1.

## Complete with limitations

| Capability | Limitation |
|---|---|
| **B2 archive inspection (APK, AAB, IPA; D-70)** | Runs in the share-free Podman machine pinned as `podman.machine` (D-71), in the same pass as the container scanners. Zip-based formats only. Nested archives are counted, not unpacked. AAB manifests (protobuf) aren't decoded. IPA entitlements come from `embedded.mobileprovision`, and the code signature is not verified |
| Native static analysers (Android, iOS, OS configuration snapshots, supply chain, binary metadata, extensions, AI-agent and MCP configuration) | macOS Seatbelt only. Rule sets are fixed. Malformed input is reported as `input-unparseable`. OS checks read **snapshots** (for example a copy of `/etc`, `.reg` exports, or `fdesetup status > fdesetup-status.txt`), never the live host |
| PE, MSI and MSIX metadata (D-65) | Headers and directory tables only. MSIX is read from the zip central directory, with nothing decompressed |
| Sentinel SBOM (`scripts/m10/sbom.py`) | CycloneDX 1.5, validated structurally and against the wheel. The official CycloneDX JSON Schema isn't vendored |
| Prompt-injection detection (D11) | Pattern-based. It misses paraphrased, translated or encoded payloads. Findings are `suspected` only |
| Plugins | Single-file, stdlib-only entry, executed from verified bytes (`python -I -c`). macOS isolation only |
| MCP server | stdio, local only, no client authentication. `audit` writes a new run to Sentinel's own state. External stdio-to-network bridges are outside the security boundary |
| `compare` | Output is neither signed nor stored. Issue identity includes the finding title |
| `self-check` | RECORD sits beside the files, so it detects corruption and casual tampering, not a determined local attacker. It is not a signature |

## Residual risks

- The trust store, ledger and state directory are writable by the same macOS user (AUD-05). Compare the trust-store fingerprint with an out-of-band record.
- Run-manifest signatures prove integrity relative to the run key only (D-34).
- The agent version used by the D-41 check is reported by the agent itself.
- Operator keys must be ECDSA P-256 (D-47).
