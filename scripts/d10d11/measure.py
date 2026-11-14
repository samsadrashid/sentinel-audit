"""Measure D10/D11 detection on tests/fixtures/d10d11 and write docs/roadmap/d10-d11-metrics.json.

Recall counts a vulnerable case as detected only when every expected rule is reported. Adversarial cases
are reported separately and also included in the overall figure. A clean case with any finding counts as
a false-positive case. The analyzers run in process here (their sandboxed execution is tested by
tests/test_native_analyzers.py). Thresholds are not decided here (owner decision).

Usage: python scripts/d10d11/measure.py [--check]
"""

# ruff: noqa: E501 - corpus data and report lines

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "fixtures" / "d10d11"
OUT = ROOT / "docs" / "roadmap" / "d10-d11-metrics.json"
sys.path.insert(0, str(ROOT / "src" / "sentinel" / "analyzers"))
ANALYZER = {"ext": "extensions", "mcp": "agents", "agent": "agents", "t2": "agents"}


def measure() -> dict[str, Any]:
    areas: dict[str, Any] = {}
    for case in sorted(p for p in CORPUS.glob("*/*") if p.is_dir()):
        spec = json.loads((case / "expected.json").read_text())
        mod = importlib.import_module(ANALYZER[spec["area"]])
        found = sorted({f["rule"] for f in mod.analyze(case)})
        a = areas.setdefault(
            spec["area"],
            {
                "vulnerable": 0,
                "detected": 0,
                "adversarial": 0,
                "adversarial_detected": 0,
                "clean": 0,
                "clean_with_findings": 0,
                "missed": [],
                "false_positives": [],
            },
        )
        if spec["kind"] == "vulnerable":
            hit = set(spec["expect"]) <= set(found)
            a["vulnerable"] += 1
            a["detected"] += hit
            if spec["adversarial"]:
                a["adversarial"] += 1
                a["adversarial_detected"] += hit
            if not hit:
                a["missed"].append(
                    {"case": case.name, "note": spec["note"], "adversarial": spec["adversarial"]}
                )
        else:
            a["clean"] += 1
            if found:
                a["clean_with_findings"] += 1
                a["false_positives"].append({"case": case.name, "rules": found})
    for a in areas.values():
        a["recall"] = round(a["detected"] / a["vulnerable"], 4) if a["vulnerable"] else None
        base = a["vulnerable"] - a["adversarial"]
        a["recall_non_adversarial"] = (
            round((a["detected"] - a["adversarial_detected"]) / base, 4) if base else None
        )
        a["false_positive_case_rate"] = (
            round(a["clean_with_findings"] / a["clean"], 4) if a["clean"] else None
        )
    return {
        "corpus": "tests/fixtures/d10d11 (synthetic, repository-authored)",
        "areas": dict(sorted(areas.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the recorded metrics differ")
    args = ap.parse_args()
    m = measure()
    body = json.dumps(m, indent=1, sort_keys=True) + "\n"
    if args.check:
        return 0 if OUT.is_file() and OUT.read_text() == body else 1
    OUT.write_text(body)
    for k, a in m["areas"].items():
        print(
            f"{k}: recall {a['recall']} (non-adversarial {a['recall_non_adversarial']}), "
            f"adversarial {a['adversarial_detected']}/{a['adversarial']}, FP cases {a['clean_with_findings']}/{a['clean']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
