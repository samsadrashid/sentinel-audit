# External tools used by Sentinel M2 (D-03, D-54, D-56)

These tools are **not redistributed** in the Sentinel wheel or source distribution. The operator installs them separately; the engine runs them only when they're pinned by hash or digest in an approved policy. `THIRD_PARTY_NOTICES` is generated from `uv.lock` and covers only Python dependencies, so the external tools are recorded here.

| Tool | Version | Licence | How it's used | Source |
|---|---|---|---|---|
| Podman (client, gvproxy, vfkit) | 6.1.4 | Apache-2.0 | Rootless container runtime (Podman Machine, Apple Hypervisor) | `github.com/containers/podman` release v6.1.4 (signed and notarised `.pkg`, Red Hat Developer ID HYSCB8KRL2) |
| Podman Machine OS image | 6.1 (Fedora 44 podman-machine-os) | Fedora/component licences (mostly GPL-2.0, Apache-2.0, MIT) | VM that hosts rootless containers | `quay.io/podman/machine-os`, pulled by `podman machine init` |
| BusyBox image | 1.37.0 | GPL-2.0-only | Isolation self-test only | `docker.io/library/busybox` |
| Gitleaks | 8.30.1 | MIT | S1 secrets scanner (native, Seatbelt) | `github.com/gitleaks/gitleaks` release v8.30.1 |
| Semgrep CE | 1.184.0 | LGPL-2.1-or-later | S1 code scanner (container). **Semgrep registry rules aren't used** (their separate licence restricts use; D-55) | `docker.io/semgrep/semgrep` |
| OSV-Scanner | 2.7.0 | Apache-2.0 | S2 dependency scanner (container, offline) | `ghcr.io/google/osv-scanner` |
| Syft | 1.57.0 | Apache-2.0 | S2 SBOM generator (container) | `docker.io/anchore/syft` |
| OSV database snapshot 2026-11-09 | — | Data aggregated from many advisory sources, each under its own terms (mostly CC-BY-4.0, for example GitHub Advisory Database and PyPA advisory-database; see `osv.dev` source listings) | Offline vulnerability data (D-56) | `osv-vulnerabilities.storage.googleapis.com` |

Sentinel runs these tools as separate programs and never links them. Running GPL or LGPL tools as separate processes places no licence obligation on Sentinel's MIT code. Anyone who redistributes the tools must follow each tool's own licence.

## M3 tools (acquired 2026-11-10 under D-66) and MobSF (approved, not acquired)

Trivy, Grype, Checkov, cosign and both databases are **installed and pinned**. Their verification record is in `docs/m3/acquisition-request.md`. They are not redistributed. **MobSF is approved, but was deliberately not acquired**: its latest release, 4.6.4, is affected by GHSA-j7g2-gm7j-mfvm (patched only in 4.6.5, which isn't yet published), and every MobSF scan unpacks archives, which stays disabled until M2-SA-12 is resolved. Its check reports `NOT_RUN mobsf_blocked_archive_processing_m2_sa_12`.

| Tool | Version | Licence | Planned use | Official source |
|---|---|---|---|---|
| Trivy | 0.76.2 | Apache-2.0 | S2 dependency and IaC scanner (container, offline database) | `github.com/aquasecurity/trivy` releases; image `ghcr.io/aquasecurity/trivy` (digest in the acquisition request) |
| Trivy vulnerability database | snapshot at acquisition | Aggregated advisory data, each source under its own terms | Offline database (D-29) | `ghcr.io/aquasecurity/trivy-db` (OCI artifact) |
| Grype | 0.121.2 | Apache-2.0 | S2 SBOM vulnerability matcher (container) | `github.com/anchore/grype` releases; image `ghcr.io/anchore/grype` (digest in the acquisition request) |
| Grype database | snapshot at acquisition | Aggregated advisory data, each source under its own terms | Offline database (D-29) | `grype.anchore.io` database listing |
| Checkov | 3.4.3 | Apache-2.0 | S1 IaC scanner (container) | `github.com/bridgecrewio/checkov`; image `docker.io/bridgecrew/checkov` |
| cosign | 3.1.4 | Apache-2.0 | Verifying image and artifact signatures at acquisition | `github.com/sigstore/cosign` releases |
| MobSF | to be confirmed at acquisition (4.x series) | **GPL-3.0** | Optional static mobile analysis as a **separate** local service | `github.com/MobSF/Mobile-Security-Framework-MobSF` |

**MobSF licence note.** MobSF is GPL-3.0. Sentinel would only call it as a separate process or local service. It must never be vendored, linked or redistributed inside the Sentinel wheel. Anyone who redistributes MobSF must comply with the GPL-3.0.
