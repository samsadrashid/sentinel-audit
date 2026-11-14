# ruff: noqa: E501
"""M3 baseline measurement (D-63, AC-07, AC-08): per-domain recall and false positives with REAL scanners.

For every fixture in tests/fixtures/domains/<domain>/ this runs a full Sentinel audit (S1 and S2) with
the approved pinned scanners and databases from ~/.local/share/sentinel-deps/pins.json, on the real
macOS sandbox and rootless Podman. Then:

* **recall (AC-07)**, per domain: expected issues detected by at least one of their designated checks,
  divided by all expected issues in that domain's vulnerable fixtures;
* **false positives (AC-08)**, per domain: findings mapped to that domain on that domain's clean
  fixtures (count, and the share of clean fixtures with any);
* **validated checks (D-58):** a designated check that detected at least one expected issue and
  produced no finding on that domain's clean fixtures. Only these are written to
  `src/sentinel/domains/coverage.json`;
* checks that didn't run (missing or unapproved scanner or database) are listed. Missing data lowers
  recall honestly and is never treated as a detection.

Nothing chooses R or F: the measured values are written to docs/m3/metrics.json for the owner (D-63).

Usage: python scripts/m3/measure.py [--write-coverage]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel import approvals, policy, scanner_pins  # noqa: E402
from sentinel.adapters.scanners import third_party_adapters  # noqa: E402
from sentinel.crypto.signing import Ed25519Signer  # noqa: E402
from sentinel.domain.models import AuditConfig  # noqa: E402
from sentinel.isolation import detect as detect_host  # noqa: E402
from sentinel.keys.operator import TrustStore  # noqa: E402
from sentinel.orchestrator import AuditRequest, run_audit  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "domains"
PINS = Path.home() / ".local/share/sentinel-deps/pins.json"


def detected_checks(result: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(check id, file, domain) for every finding source. Dependency findings also yield vuln:<rule>."""
    out = []
    for f in result["findings"]:
        file = f["location"]["file"]
        for s in f.get("sources", []):
            out.append((f"{s['producer']}:{s['rule']}", file, f["domain"]))
        if f["rule"].startswith("vuln."):
            out.append((f"vuln:{f['rule']}", file, f["domain"]))
    return out


def audit(target: Path, pins: scanner_pins.Pins, work: Path) -> dict[str, Any]:
    cfg = AuditConfig.from_dict(
        {
            "mode": "READ",
            "level": "L2",
            "activity_classes": ["S1", "S2"],
            "scope": {
                "assets": [
                    {"id": target.name, "kind": "local_path", "locator": str(target), "environment": "local"}
                ]
            },
        }
    )
    trust = TrustStore(work / "trust.json")
    out = run_audit(
        AuditRequest(
            config=cfg,
            policy=replace(policy.default_policy(), pins=pins),
            trust=trust,
            ledger=approvals.NonceLedger(work / "ledger.json"),
            run_signer=Ed25519Signer.generate(),
            adapters=third_party_adapters(pins),
            runs_dir=work / "runs",
            host=detect_host(),
            env={},
        )
    )
    return out.result


def measure() -> dict[str, Any]:
    if not PINS.is_file():
        raise SystemExit(f"no approved pins at {PINS}")
    pins = scanner_pins.parse(json.loads(PINS.read_text()))
    metrics: dict[str, Any] = {"pins": pins.describe(), "domains": {}}
    with tempfile.TemporaryDirectory(prefix="sentinel-m3-") as tmp:
        work = Path(tmp)
        for ddir in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
            dom = ddir.name
            expected_total = matched = 0
            designated: dict[str, int] = {}
            clean_hits: dict[str, int] = {}
            fp_findings = fp_fixtures = clean_total = 0
            not_run: set[str] = set()
            states: dict[str, int] = {}
            required: dict[str, set[str]] = {}
            per_fixture = []
            for fx in sorted(p for p in ddir.iterdir() if p.is_dir()):
                spec = json.loads((fx / "expected.json").read_text())
                result = audit(fx, pins, work / fx.name / dom)
                for c in result["checks"]:
                    if c["status"] not in ("PASS", "FAIL", "NOT_APPLICABLE"):
                        not_run.add(f"{c['adapter']}: {c['status']} {c['reason']}")
                cov = (result.get("domain_coverage") or {}).get(dom, {})
                states[cov.get("status", "missing")] = states.get(cov.get("status", "missing"), 0) + 1
                for r in cov.get("required_checks", []):
                    required.setdefault(r["adapter"], set()).add(f"{r['status']} {r['reason']}".strip())
                found = detected_checks(result)
                if spec["kind"] == "vulnerable":
                    items = []
                    for e in spec["expected"]:
                        expected_total += 1
                        hit = [c for c, file, _ in found if c in e["any_of"] and file == e["file"]]
                        if hit:
                            matched += 1
                            for c in set(hit):
                                designated[c] = designated.get(c, 0) + 1
                            producers = {
                                s["producer"]
                                for f in result["findings"]
                                for s in f.get("sources", [])
                                if f["rule"] in {h.split(":", 1)[1] for h in hit}
                            }
                            for p in producers:
                                if e["any_of"][0].startswith("vuln:"):
                                    designated[f"{p}:dependencies"] = (
                                        designated.get(f"{p}:dependencies", 0) + 1
                                    )
                        items.append({"id": e["id"], "detected": bool(hit), "by": sorted(set(hit))})
                    per_fixture.append({"fixture": fx.name, "expected": items})
                else:
                    clean_total += 1
                    mine = [(c, file) for c, file, d in found if d == dom]
                    fp_findings += len({x for x in mine if not x[0].startswith("vuln:")})
                    fp_fixtures += 1 if mine else 0
                    for c, _ in mine:
                        clean_hits[c] = clean_hits.get(c, 0) + 1
                    per_fixture.append({"fixture": fx.name, "false_positives": sorted({c for c, _ in mine})})
            validated = sorted(
                c for c in designated if not c.startswith("vuln:") and clean_hits.get(c, 0) == 0
            )
            metrics["domains"][dom] = {
                "expected_issues": expected_total,
                "detected_issues": matched,
                "recall": round(matched / expected_total, 4) if expected_total else None,
                "clean_fixtures": clean_total,
                "false_positive_findings": fp_findings,
                "clean_fixtures_with_false_positives": fp_fixtures,
                "false_positive_fixture_rate": round(fp_fixtures / clean_total, 4) if clean_total else None,
                "validated_checks": validated,
                "checks_not_completed": sorted(not_run),
                # V-3: the domain's coverage state across its fixture runs and each required check's
                # observed statuses. Recall and false-positive figures above are independent of this.
                "coverage_states": dict(sorted(states.items())),
                "required_checks": {a: sorted(v) for a, v in sorted(required.items())},
                "fixtures": per_fixture,
            }
    return metrics


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-coverage", action="store_true", help="update src/sentinel/domains/coverage.json")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "m3" / "metrics.json")
    args = ap.parse_args()
    m = measure()
    args.out.write_text(json.dumps(m, indent=1, sort_keys=True) + "\n")
    for d, v in m["domains"].items():
        print(
            d,
            "recall",
            v["recall"],
            f"({v['detected_issues']}/{v['expected_issues']})",
            "FP",
            v["false_positive_findings"],
            "validated",
            len(v["validated_checks"]),
        )
    if args.write_coverage:
        cov = {
            "note": "Written by scripts/m3/measure.py from real scanner runs on tests/fixtures/domains (D-58).",
            "pins": m["pins"],
            "validated": {d: v["validated_checks"] for d, v in m["domains"].items()},
        }
        (ROOT / "src" / "sentinel" / "domains" / "coverage.json").write_text(
            json.dumps(cov, indent=1, sort_keys=True) + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
