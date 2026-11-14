# M3 scope and acceptance proposal (for owner approval, not yet approved)

**Source:** the frozen roadmap row (`docs/architecture/discovery.md` §16), D-09, D-10, D-12, D-13, D-19, D-22, D-29, the §15.2 fixtures and AC-07 and AC-08. Nothing here changes a frozen decision. Once approved, it will be recorded as new append-only decisions, as for M2 (D-52 to D-57).

> **M3: Web, API, backend, database (D01, D02, D08, D14 static parts)**
> - Deliverables: domain modules and fixtures; Trivy, Checkov and Grype adapters; pinned vulnerability-database snapshots [D-29].
> - Exit: AC-07 and AC-08 for those domains (sets R and F, D-19).
> - Not before: A1 dynamic checks (ZAP), until the dynamic adapter review [D-10].

## 1. Deliverables

| # | Deliverable | Content |
|---|---|---|
| 1 | **Domain modules** for D01, D02, D08 and D14, static parts only | Each module, per §4 and D-09: (a) a check plan from the discovery profile (for example, web: templates and front-end frameworks; API: OpenAPI and GraphQL specs and route definitions; backend: server code and IaC for services; database: schemas, migrations, ORM configuration and connection settings); (b) Sentinel-authored Semgrep rules for the domain (D-55: no registry rules); (c) mapping of scanner findings into the domain; (d) per-domain coverage in the report: what was checked, not run, or not applicable. **No coverage claim until that domain's fixtures pass (D-09)** |
| 2 | **Trivy adapter** | Filesystem and config scanning (S2, container, offline DB). Container-image scanning is out of M3 unless you add it |
| 3 | **Checkov adapter** | IaC static analysis: Terraform, Kubernetes, Dockerfile, CloudFormation (S1, container, no network, no registry or platform API) |
| 4 | **Grype adapter** | Vulnerability matching against the Syft SBOM or the directory (S2, container, offline DB) |
| 5 | **Pinned vulnerability-database snapshots (D-29)** | The Trivy DB, Grype DB and the existing OSV snapshot, each pinned by content digest and listed in the run manifest's `vulnerability_db_snapshots`. **An unpinned database marks the run `non_reproducible`** (§15.2 fixture). Updates only through `policy.change`, as for D-56 |
| 6 | **Domain fixtures** | Synthetic, non-malicious known-vulnerable and known-clean fixture projects per domain (§15.2). Each vulnerable fixture declares the finding fingerprints it must produce |
| 7 | **AC-07 and AC-08 measurement** | A reproducible per-domain recall and false-positive measurement harness over the fixture corpus, run with the real pinned scanners and databases, producing proposed R and F values per domain |

**Not in M3:**
- A1 dynamic checks (ZAP, live endpoints): blocked until the dynamic adapter review (D-10).
- B2 and container-image unpacking; stays `NOT_RUN`, also because of M2-SA-12.
- Other domains (M4 to M8), report types and verification (M9).
- Production signing and signing-device hardware.

## 2. Acceptance criteria (proposed)

1. **Contract tests:** every new adapter and domain module passes the §5 contract and manifest tests, and every new record is schema-validated (D-40).
2. **AC-07** (per domain D01, D02, D08, D14): recall on the known-vulnerable fixtures is ≥ R. R is proposed from the M3 baseline measurement and **fixed by you as a dated decision** (D-19); until then the measurement is reported, not judged.
3. **AC-08** (per domain): findings on the known-clean fixtures are ≤ F, with F set the same way.
4. **D-29:** every run lists each database snapshot it used, with its digest. An unpinned database gives `non_reproducible`, tested.
5. **AC-02 and AC-03 with the real new scanners:**
   - the target tree is unchanged;
   - missing binaries or images, hash or digest mismatches, timeouts, crashes, bad output and unverified databases are never `PASS`;
   - no runtime pulls and no scanner network.
6. **D-09 coverage honesty:** a domain's checks are reported only for what actually ran, and domains or classes not covered are listed.
7. **Regression and verification:** M1 and M2 suites green (including real-scanner and Secure Enclave tests); new M3 mutants; one final campaign with 0 survivors, 0 invalid and 0 infrastructure failures; all gates clean; Git index unchanged.
8. **Residual risks stay visible:** M2-SA-12 and the M2 §7 limitations carry over unchanged unless a dated decision resolves them.

## 3. Owner decisions needed before implementation

| # | Decision | Recommendation |
|---|---|---|
| E1 | **Domain identity.** The product specification defining D01, D02, D08 and D14 isn't in this repository. From the roadmap title, the mapping appears to be D01 = Web, D02 = API, D08 = Backend, D14 = Database | Confirm the mapping, or provide the specification text for these four domains, so the domain checks follow the real definitions |
| E2 | **Acquisition of Trivy, Checkov, Grype and the Trivy and Grype databases** (external dependencies) | The same process as D-54 and D-56: I present exact versions, official sources, digests or hashes, signatures (cosign or attestations where published), licences and the database update procedure; you approve before any download. I'll also check each tool against public security advisories for compromised releases before proposing a version |
| E3 | **Grype input** | Scan the Syft SBOM produced in the same run: one inventory, consistent fingerprints. Fall back to a directory scan only if no SBOM exists |
| E4 | **Overlap between OSV-Scanner, Trivy and Grype** for dependency vulnerabilities | Keep all three as separate producers and deduplicate by fingerprint (§7.4); each scanner's results stay evidence, not automatic truth (D-13) |
| E5 | **Fixture corpus** | The roadmap refers to the spec's test corpus, which isn't here. Use synthetic fixtures I write, at least 10 vulnerable and 10 clean projects per domain, each mapping its expected fingerprints. Your corpus replaces or extends them if you provide one |
| E6 | **Procedure for setting R and F** | M3 reports measured recall and false positives per domain with the pinned versions; you then record R and F as a dated decision (D-19). M3 acceptance needs that decision |

## 4. Execution plan once approved

1. Record the approved scope as append-only decisions.
2. Present the E2 acquisition request.
3. Implement domain modules, adapters, the D-29 snapshot pinning, fixtures and the measurement harness, testing with fakes first.
4. Download only after approval, then integrate the real scanners and databases.
5. Run the measurement and present per-domain R and F for your decision.
6. Run one consolidated audit and one final verification cycle.
7. Write `docs/m3/m3-completion-report.md`, then stop for acceptance.

The process stops only at E2 approval and the R and F decision, both genuine owner decisions or external dependencies.
