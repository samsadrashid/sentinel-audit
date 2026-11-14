# M2 scanner, runtime and database acquisition request (D-54, D-56)

**Status: awaiting owner approval. Nothing has been downloaded.**

Provenance was collected on 2026-11-09 from metadata only:
- the GitHub releases API, whose asset `digest` is GitHub's SHA-256 of the uploaded file;
- OCI registry manifest `HEAD` requests;
- the PyPI JSON API;
- Google Cloud Storage object headers.

Every hash below is re-verified locally after download and before first execution. A mismatch aborts the download and nothing is installed.

## 1. Proposed execution model

| Scanner | Class | How it runs | Pinned by |
|---|---|---|---|
| Gitleaks | S1 | Native binary under the macOS Seatbelt S1 profile, no network; on Linux, in rootless Podman | Binary SHA-256 (D-22) |
| Semgrep CE | S1 | Rootless Podman container (D-53, S1's only alternative). The native install pulls a large Python dependency tree | Image digest |
| OSV-Scanner | S2 | Rootless Podman, `--network=none`, offline database mounted read-only | Image digest |
| Syft | S2 | Rootless Podman, `--network=none` | Image digest |

Native release binaries are also listed below. If you prefer native binaries inside a pinned minimal base image, the adapters support that too, with binary hashes in the allowlist.

## 2. Container runtime: Podman (D-53)

| Item | Value |
|---|---|
| Version | **v6.1.4** (released 2026-10-12) |
| Source | `https://github.com/containers/podman/releases/tag/v6.1.4` |
| Licence | Apache-2.0 |
| macOS arm64 installer | `podman-installer-macos-arm64.pkg`, SHA-256 `48f675622f66233ca2116e67fdab41ed9dbcc25b48b78a8e6ef0be6549031d22` (76,099,040 bytes) |
| Linux | The distribution's rootless Podman package, version 5.x or newer |
| Also needed | A Podman Machine VM image, which `podman machine init` downloads. Its digest is recorded at download time and shown before first use |

### Isolation self-test image

The Podman runner counts as available only after a functional self-test, the same rule as the macOS sandbox probe (D-32). The test runs a tiny program inside the exact container profile and must observe: no network, read-only target, a writable workspace only, a read-only root, and all capabilities dropped. That needs a minimal pinned image:

| Image | Licence | Digest |
|---|---|---|
| `docker.io/library/busybox:1.37.0` | GPL-2.0 (BusyBox) | `sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` |

The image is used only by the probe, never to run a scanner.

## 3. Scanners

| Scanner | Version | Licence | Source |
|---|---|---|---|
| Gitleaks | **v8.30.1** (2026-03-21) | MIT | `github.com/gitleaks/gitleaks/releases/tag/v8.30.1` |
| Semgrep CE | **1.184.0** (2026-11-05; immutable GitHub release) | LGPL-2.1-or-later (engine). **Registry rules are not used (D-55)** | `github.com/semgrep/semgrep`; image `docker.io/semgrep/semgrep:1.184.0` |
| OSV-Scanner | **v2.7.1** (2026-11-09; **published today**, so you may prefer v2.7.0 from 2026-10-12) | Apache-2.0 | `github.com/google/osv-scanner/releases/tag/v2.7.1` |
| Syft | **v1.57.0** (2026-11-05; immutable GitHub release) | Apache-2.0 | `github.com/anchore/syft/releases/tag/v1.57.0` |

### Container image digests (multi-arch index)

| Image | Digest |
|---|---|
| `docker.io/semgrep/semgrep:1.184.0` | `sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed` |
| `ghcr.io/google/osv-scanner:v2.7.1` | `sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde` |
| `docker.io/anchore/syft:v1.57.0` | `sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a` |
| `ghcr.io/gitleaks/gitleaks:v8.30.1` | `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` (Linux path) |

### Native release assets (SHA-256)

| Asset | SHA-256 |
|---|---|
| `gitleaks_8.30.1_darwin_arm64.tar.gz` | `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5` |
| `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| `gitleaks_8.30.1_linux_arm64.tar.gz` | `e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080` |
| `osv-scanner_darwin_arm64` | `b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3` |
| `osv-scanner_linux_amd64` | `fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8` |
| `syft_1.57.0_darwin_arm64.tar.gz` | `17012a5a110323bb1069e513a8665f1ae445905c56b4e3f9a9df4f95c5bb6161` |
| `syft_1.57.0_linux_amd64.tar.gz` | `9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704` |
| `semgrep-1.184.0 … macosx_11_0_arm64.whl` (PyPI) | `0ce3064175a44236dd9fd35603627e3f56139ac61e13ca967bae2b76b2cec9bf` |

The extracted executables inside each archive are hashed after extraction, and those executable hashes are what go into the policy allowlist.

## 4. OSV offline database (D-56)

| Item | Value |
|---|---|
| Source | OSV.dev public bucket: `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`. This is the same source osv-scanner's own `--download-offline-databases` uses |
| Format | One zip per ecosystem holding OSV-schema JSON records (`<id>.json`), read by `osv-scanner --offline-vulnerabilities` |
| Provenance | Published by Google's OSV.dev service over HTTPS. **There is no upstream signature or published SHA-256.** The bucket gives only MD5 and CRC32C object hashes, and the files are rebuilt continuously |
| Checksum procedure | At download, verify the GCS MD5/CRC32C header against the bytes, then compute SHA-256 and record it in a snapshot manifest (ecosystem, URL, size, `last-modified`, MD5, SHA-256, download time). Sentinel refuses any database whose SHA-256 doesn't match the approved manifest |
| Licence | Aggregated advisories, each under its source's terms. Most are CC-BY-4.0 (for example GitHub Advisory Database, PyPA) or similar open terms. The per-source licences are recorded in `THIRD_PARTY_NOTICES`. This is data, not code |
| Proposed ecosystems | PyPI (37.7 MB), npm (220.1 MB), Go (12.8 MB), crates.io (3.8 MB), Maven (10.5 MB), RubyGems (5.2 MB). Current object state: PyPI `md5=oy2kUC/d9BOtj8XidQNQZw==`, last modified 2026-11-09 09:33 GMT |
| Update procedure | Manual and owner-approved only. A new snapshot is downloaded into a fresh directory, verified and recorded, and then becomes the approved snapshot by a policy change (`policy.change`) that pins its manifest SHA-256. Old snapshots stay until pruned. The scanner never fetches data at run time |

## 5. Not requested

- No Semgrep registry rules, and no `--config auto`.
- No Grype or Trivy database (M3).
- No network access during scans.
