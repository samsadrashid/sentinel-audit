# M2 scope and conditions (approved 2026-11-09)

Recorded as append-only decisions **D-52** (scope, acceptance, mandatory conditions), **D-53** (Podman rootless), **D-54** (scanner acquisition), **D-55** (self-authored Semgrep rules), **D-56** (offline OSV database) and **D-57** (national-ID formats) in `docs/architecture-discovery-plan.md`.

## Deliverables and where they live

| # | Deliverable | Implementation |
|---|---|---|
| 1 | Read-only project discovery | `src/sentinel/discovery.py`. Recorded in each result under `discovery` |
| 2 | Adapter registry, manifests, pins | `src/sentinel/adapters/scanners.py` (manifests, D-13 contract), `src/sentinel/scanner_pins.py` (binary SHA-256, image digest, Podman and OSV pins from the approved policy) |
| 3 | Isolation manager for S1, S2, B1 | `src/sentinel/isolation/__init__.py` (`runner_for`, pin-kind pairing), `src/sentinel/isolation/podman.py` (rootless Podman runner and self-test) |
| 4 | Gitleaks, Semgrep, OSV-Scanner, Syft adapters | `src/sentinel/adapters/scanners.py`; Semgrep rules in `src/sentinel/rules/semgrep/` |
| 5 | PII minimisation | `src/sentinel/redaction.py` (`PII_RULES`); `docs/m2/pii.md` |
| 6 | Secret classification | `src/sentinel/secret_class.py`. Findings carry `liveness` (`live`, `test` or `unknown`) |
| 7 | `cancel`, `pause`, `resume` | `src/sentinel/controls.py`, the orchestrator control watcher, and the `sentinel cancel\|pause\|resume <audit_id>` commands |
| 8 | Retention prune | `src/sentinel/retention.py`, `sentinel prune --list\|--delete` |

## Mandatory conditions and how each is enforced

| Condition | Enforcement |
|---|---|
| PII minimised before persistence; a failure blocks persistence | The PII rules are part of the single redaction pass that runs before evidence hashing and writing and before every log, result, report and CLI sink. A `RedactionError` holds the artifact back as `ERROR` (`redaction_failed`) |
| Hash or digest verified before each execution | Binaries are re-hashed immediately before every run. Images run only as `repo@sha256:` with `--pull=never`, after the Podman client's hash and rootless state are re-checked |
| No network during scanning | Seatbelt denies network; containers run with `--network=none`; scanners also get `--metrics=off` and `--offline-vulnerabilities` |
| Pause, resume, cancel | Pause starts no new check. Resume re-authorises every remaining check and restarts if the source changed. Cancel kills the process group and force-removes the container. Interrupted work is `BLOCKED` or `NOT_RUN` and never `PASS` |
| Pruning keeps history | A hash-only `retention.deleted` entry goes into the checkpointed admin log before deletion; earlier entries are never rewritten; `history verify` passes |
| No unsandboxed fallback | A binary pin runs only under the verified Seatbelt profile, an image pin only under verified rootless Podman; anything else is `NOT_RUN` |

## Status of external dependencies

Nothing has been downloaded. The pinned versions, sources, hashes, digests and licences are in `docs/m2/acquisition-request.md`, awaiting owner approval (D-54, D-56). Until they're approved, every third-party scanner check is `NOT_RUN` (`scanner_not_approved` or `osv_database_not_approved`), and so is every container-isolated check (`host_isolation_unavailable`). An audit that includes them is never `PASS`.
