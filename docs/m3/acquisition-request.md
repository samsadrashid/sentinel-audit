# M3 scanner and database acquisition request (D-60)

**Status: approved by the owner on 2026-11-10 (D-66). Acquired and verified the same day:**

| Item | Verification |
|---|---|
| Trivy image | Pulled by the listed index digest. **cosign keyless signature verified** against the `github.com/aquasecurity/trivy` workflow identity |
| Grype image | Pulled by digest. **No cosign signature is published**; integrity rests on the approved digest |
| Checkov image | Pulled by digest. No signature published; digest only |
| cosign v3.1.4 | SHA-256 matches both the pinned value and `cosign_checksums.txt` |
| Trivy DB | `ghcr.io/aquasecurity/trivy-db` manifest `sha256:16299b63…`, stable before and after download. No signature published for that digest. Snapshot manifest `93c92137…` |
| Grype DB | v6.1.10, built 2026-11-08. Archive SHA-256 matches the publisher listing (`dcca2472…`). Imported offline. Snapshot manifest `9916b91a…` |

All are pinned in the approved pins file. The record below is unchanged from the request.

Provenance was collected on 2026-11-09 from metadata only: the GitHub releases and security-advisories APIs, OCI registry manifest `HEAD` and `GET` requests, the PyPI JSON API, and the Grype database listing.

Every hash, digest and signature is verified again locally after download and before first execution. A mismatch stops that acquisition, and nothing is installed.

## 1. Security advisories checked (decisive for version choice)

| Tool | Advisory | Affected | Consequence for this request |
|---|---|---|---|
| Trivy | **GHSA-69fq-xp46-6x23 (critical, 2026-03-21): supply chain temporarily compromised.** A malicious v0.69.4 release; Docker Hub images v0.69.5 and v0.69.6; `trivy-action` and `setup-trivy` tags hijacked | v0.69.4 binaries and images; Docker Hub v0.69.5 and v0.69.6 | Request **v0.76.2**: an immutable GitHub release, the image referenced **by digest from GHCR** (not Docker Hub), sigstore bundles verified. No Trivy GitHub Actions are used |
| Trivy | GHSA-mcj4-mphf-j9ff (high): path traversal via a crafted vulnerability database or other downloaded artifacts | < 0.71.0 | v0.76.2 is patched; the database is also verified by digest before use |
| Trivy | GHSA-q3fv-x8vg-qqm4 (medium): Helm chart tar bomb causes OOM | < 0.71.1 | Patched in v0.76.2; container memory and pids caps apply anyway |
| Trivy | GHSA-8rc5-4fr6-64pw (medium): plugin manager path traversal | plugin manager | Plugins are never installed or used |
| Grype | GHSA-6gxw-85q2-q646 (high): credential disclosure in JSON output | < 0.104.1 | v0.121.2 is patched; output is redacted anyway |
| Checkov | none published in the repository's advisory database | — | — |

## 2. Requested artifacts

| Tool | Version | Licence | Form and isolation | Pinned identity (index digest, multi-arch) | Platforms in the index |
|---|---|---|---|---|---|
| Trivy | **v0.76.2** (2026-11-05, immutable release) | Apache-2.0 | Image `ghcr.io/aquasecurity/trivy`, S2 in rootless Podman, offline | `sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb` | linux/amd64, **linux/arm64** (`sha256:6e878e5168fe…`), s390x, ppc64le |
| Grype | **v0.121.2** (2026-11-05, immutable release) | Apache-2.0 | Image `ghcr.io/anchore/grype`, S2 in rootless Podman, offline | `sha256:6a36234da13f9faa327306ac0b3dab3405cfa2b4eb20c8f904125a8707863913` | linux/amd64, **linux/arm64** (`sha256:06ab8591cd63…`), ppc64le, s390x |
| Checkov | **3.4.3** (2026-11-02; GitHub releases aren't immutable) | Apache-2.0 | Image `docker.io/bridgecrew/checkov`, S1 in rootless Podman, no network. There is no macOS arm64 binary, and the PyPI install pulls a large dependency tree | `sha256:bfe9d70bb7f044aba49bd99675813445f106dee6072da583f51008cb667f3a63` | linux/amd64, **linux/arm64** (`sha256:3f1524111563…`) |
| cosign (signature verifier, used only at acquisition) | **v3.1.4** (immutable release) | Apache-2.0 | Native binary, run only to verify the Trivy and Grype sigstore bundles, never by the engine | `cosign-darwin-arm64` SHA-256 `9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4` (also checked against `cosign_checksums.txt` `e70e59b3…`) | macOS arm64 |

**Release checksums and signatures for cross-checking (native assets aren't installed):**
- **Trivy:** `trivy_0.76.2_checksums.txt` (`802e4ac1…`), with sigstore bundle `trivy_0.76.2_checksums.txt.sigstore.json` (`cad63baf…`).
- **Grype:** `grype_0.121.2_checksums.txt` (`031a06d6…`), with sigstore bundle `grype_0.121.2_checksums.txt.sigstore.json`.
- **Checkov:** wheel SHA-256 on PyPI `666f3760…` (reference only).

## 3. Databases (D-29, D-56 process)

| Database | Source and format | Provenance and checksum | Licence | Pinning and update |
|---|---|---|---|---|
| **Trivy DB** (schema v2) | OCI artifact `ghcr.io/aquasecurity/trivy-db:2`, one `db.tar.gz` layer holding `trivy.db` (bbolt) and `metadata.json` | Content-addressed. The current manifest digest is `sha256:60f0ad4cccb63e43c811235be773c4c04cda0b2b32cc7c12cc44475e965bdedd`, but the tag is **rebuilt about every 6 hours**: the digest at download time is recorded and verified, then the layer's SHA-256 is pinned. Signed by Aqua via cosign keyless; the signature is verified with cosign if published for that digest, otherwise recorded as unsigned | Database code Apache-2.0; data aggregated from NVD (public domain), GitHub Advisory Database (CC-BY-4.0), distribution trackers and others, each under its own terms | Extracted to a read-only directory; the manifest pin goes into policy through `policy.change`. Trivy runs with `--skip-db-update --skip-java-db-update --offline-scan`. Updates are manual and owner-approved |
| **Grype DB** (schema v6) | Archive from `grype.anchore.io/databases/v6/latest.json`. Currently `vulnerability-db_v6.1.10_2026-11-08T00:22:04Z_1794118797.tar.zst`, built 2026-11-08T06:19:57Z | **The publisher gives a SHA-256** in the listing: `sha256:dcca24722e16c2bcf4a542a3f7fdd2147baf9215c17b973f5a7d4243fbddacea`. The archive must match it. There's no separate signature; the listing is fetched over HTTPS | Database Apache-2.0 / CC0-style; data aggregated from NVD, GitHub Advisory Database, distribution trackers and others, each under its own terms | Read-only directory, pinned through `policy.change`. Grype runs with `GRYPE_DB_AUTO_UPDATE=false` and `GRYPE_DB_VALIDATE_AGE=false`, and no update check. Updates are manual and owner-approved |
| **Trivy Java DB** | `ghcr.io/aquasecurity/trivy-java-db:1` | — | — | **Not requested.** Java JAR analysis is skipped (`--skip-java-db-update`); recorded as not covered |
| **OSV snapshot** | Already approved and installed (M2, manifest `c7c1712d…`) | — | — | Reused as-is and listed in the M3 run manifests |

## 4. Not requested

- No Trivy GitHub Actions and no Trivy plugins.
- No Checkov platform or API integration (`--skip-download`, no API key).
- No ZAP or other dynamic tools (D-10).
- No other databases.
