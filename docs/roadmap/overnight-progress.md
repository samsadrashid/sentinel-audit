# Overnight M3–M10 progress (resume point)

**Rules:** CLAUDE.md applies, and no stage, commit or push. Nothing is downloaded without approval. Keep a blocked item visible and move on to the next independent task.

**Final report:** `docs/roadmap/m3-m10-implementation-report.md`. **No milestone from M3 to M10 is accepted.** Acceptance is the owner's decision.

## Blocked items (owner)

| ID | Item | Blocks |
|---|---|---|
| B-1 | Approval of `docs/m3/acquisition-request.md` (Trivy, Checkov, Grype, cosign, Trivy and Grype databases; D-60) | M3 real Trivy, Checkov and Grype runs; Checkov-designated fixture items; final M3 measurement |
| B-2 | R and F thresholds per domain (D-63) | M3 acceptance |
| B-3 | Original product specification for domain identities (D-59) | Definitive domain IDs for M3 to M8 (D03 to D13 labels are provisional) |
| B-4 | Linux and Windows hosts (no hardware) | M5 and M10 host acceptance; D06 Windows-native checks; Windows engine host |
| B-5 | Signing device and SD-T01 to SD-T55 (existing) | Production signing; release signing |
| B-6 | M2-SA-12 (VM shares writable) | B2 artifact unpacking stays NOT_RUN; M4 archive fixtures (R-07, T8) |
| B-7 | MobSF adapter (third-party; acquisition and review not requested) | M4 roadmap deliverable |
| B-8 | Owner scope decision on M6/M7 additions (Sentinel plugin system, MCP server) | Whether they stay in M6/M7 or move to a later milestone |

## State

| Milestone | Status |
|---|---|
| M3 | IMPLEMENTED and INTEGRATION_TESTED with installed scanners; Trivy, Checkov and Grype BLOCKED (B-1); thresholds BLOCKED (B-2) |
| M4 | Static Android and iOS analyzers INTEGRATION_TESTED (real Seatbelt); B2 and MobSF BLOCKED (B-6, B-7) |
| M5 | macOS, Linux and Windows configuration-snapshot analyzer INTEGRATION_TESTED on macOS; static PE/MSI/MSIX NOT_IMPLEMENTED; host acceptance BLOCKED (B-4) |
| M6 | D10 extension analyzer INTEGRATION_TESTED; Sentinel plugin system INTEGRATION_TESTED (B-8) |
| M7 | D11 agent/MCP analyzer and T2 fixture set INTEGRATION_TESTED; MCP stdio server INTEGRATION_TESTED (B-8) |
| M8 | Supply-chain analyzer INTEGRATION_TESTED; safe structural binary metadata extraction NOT_IMPLEMENTED |
| M9 | Run comparison, risk aggregation and remediation tracking INTEGRATION_TESTED |
| M10 | Install self-check and SHA256SUMS INTEGRATION_TESTED; signed release BLOCKED (B-5); cross-platform BLOCKED (B-4) |

**Final regression (after all changes):** 1477 passed, 0 failed, 0 skipped (`tests/test_m2_real_scanners.py` excluded). Ruff, format and mypy --strict clean.

**Next action:** owner review of the report, decisions on B-1, B-2, B-3, B-7 and B-8.
