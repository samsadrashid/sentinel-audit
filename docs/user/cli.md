# CLI reference

Every command accepts `--json` (before the command) for machine-readable output. All printed output is
redacted and then checked against its versioned contract (`cli-output`, D-40) before it is printed;
output that fails is withheld (exit 7).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `audit`, overall `PASS` |
| 1 | Audit finished with findings (`FAIL`) |
| 2 | Audit incomplete or any other non-PASS/FAIL/BLOCKED outcome (a check `NOT_RUN` or `ERROR`) |
| 3 | Blocked by policy, authorisation or an approval check |
| 4 | Invalid input (including schema violations) |
| 5 | Integrity failure (signature, hash or log mismatch) |
| 6 | Capability unavailable (for example operator signing) |
| 7 | Internal error, redaction failure or output contract violation |

## Commands

| Command | Purpose |
|---|---|
| `version` | Engine version |
| `init` | Create state and the run key |
| `status [--policy P --policy-approval A]` | Host, key and trust status |
| `audit --config C [--authorization R --approval A] [--policy P --policy-approval A] [--caller X] [--agent-version V]` | Run an audit |
| `runs list` | Unverified listing of runs |
| `runs show RUN` | Summary of a **verified** run |
| `evidence verify RUN` | Verify the manifest signature, evidence hashes, audit log and result binding |
| `report RUN [--format json\|sarif\|md\|html] [--output FILE]` | Render a report of a verified run |
| `fix-plan RUN [--output FILE]` | Read-only remediation plan for a verified run (D-50) |
| `compare BEFORE AFTER` | Read-only comparison of two **verified** runs of the same assets: introduced, fixed, unverified and persisting findings (D-64 issue identity), remediation status, open-risk totals and evidence IDs |
| `release verify DIR [--key FILE] [--approval FILE]` | Verify a signed release directory (D-74): every artifact hash, `SHA256SUMS` and the signed list, version, key and signature. With `--key` the published release key; without it the trust store (role and permission checked too). Fails closed (exit 3, 4 or 5) |
| `release attach --approval FILE --dist DIR` | Verify a received `release.publish` approval against the files and the trust store, then write `SHA256SUMS.approval.json` (never overwrites) |
| `self-check` | Verify the installed package against its wheel RECORD: `verified` (exit 0), `mismatch` or `missing` (exit 5), `unverifiable` for editable or source installs (exit 2) |
| `plugin inspect DIR` | Validate a plugin directory and print the manifest hash to pin. Pins nothing |
| `mcp serve` | Local stdio MCP server for an AI agent: target-read-only, no client authentication. See [mcp.md](mcp.md) |
| `agent check --agent claude-code\|codex [--agent-version V]` | D-41 compatibility check |
| `policy validate --policy P [--policy-approval A]` | Verify a policy without applying it |
| `key list` | Trust store with roles and permitted actions |
| `key enrol --key K --approval A --operator NAME --expires-at T` | First operator key (self-signed) |
| `key rotate --key K --approval A --operator NAME --expires-at T --trust-fingerprint F` | Add a key |
| `key revoke --key-id ID --approval A --trust-fingerprint F` | Revoke a key |
| `review verify --finding FP --revision R --approval A` | Record a human review |
| `review accept-risk --entry E --approval A` | Record an accepted risk |
| `suppress add --entry E --approval A` | Record a suppression |
| `decisions list` / `decisions revoke --decision-id D --approval A` | Signed decisions |
| `approval prepare KIND --key-id ID --lifetime S ...` | Build an **unsigned** payload (`release-publish` takes `--dist DIR --commit SHA`, D-74) |
| `approval inspect FILE` | Show a payload or approval canonically |
| `approval request --payload P --volume V [--enrol-key K]` | Write a sign request for the signing device; `--enrol-key` only for the first, self-signed enrolment |
| `approval receive --volume V` | Read and verify signing-device responses |
| `history verify` | Verify the admin log |

`key`, `review`, `suppress`, `decisions revoke` and the trust-changing paths refuse non-interactive
sessions and AI-agent environments.
