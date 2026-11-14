"""D10/D11 evaluation corpus: the recorded metrics are reproducible and current behaviour is locked in.

These assertions describe measured behaviour, not acceptance thresholds (those are the owner's). The
adversarial cases are *expected* to be missed by pattern-based detection; the test fails if the miss
list changes silently in either direction, so improvements and regressions are both visible.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "d10d11"))
import measure  # noqa: E402


def test_recorded_metrics_are_reproducible():
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/d10d11/measure.py"), "--check"], capture_output=True
    )
    assert r.returncode == 0, "docs/roadmap/d10-d11-metrics.json is stale: rerun scripts/d10d11/measure.py"


def test_every_non_adversarial_case_detected_and_no_clean_case_flagged():
    m = measure.measure()["areas"]
    for area, a in m.items():
        assert a["recall_non_adversarial"] == 1.0, (area, a["missed"])
        assert a["clean_with_findings"] == 0, (area, a["false_positives"])


def test_adversarial_misses_are_exactly_the_recorded_ones():
    m = measure.measure()["areas"]
    misses = sorted((area, x["case"]) for area, a in m.items() for x in a["missed"])
    assert all(x["adversarial"] for a in m.values() for x in a["missed"])
    recorded = json.loads((ROOT / "docs/roadmap/d10-d11-metrics.json").read_text())["areas"]
    assert misses == sorted((area, x["case"]) for area, a in recorded.items() for x in a["missed"])


def test_corpus_is_balanced_and_has_adversarial_cases():
    m = measure.measure()["areas"]
    assert set(m) == {"ext", "mcp", "agent", "t2"}
    for a in m.values():
        assert a["vulnerable"] >= 8 and a["clean"] >= 6 and a["adversarial"] >= 1


#: D-69 (owner decision 2026-11-10): (min non-adversarial recall, max clean-case false-positive rate).
D69 = {"ext": (0.95, 0.10), "mcp": (0.95, 0.10), "agent": (0.95, 0.10), "t2": (0.90, 0.15)}


def test_recorded_metrics_meet_the_d69_thresholds():
    recorded = json.loads((ROOT / "docs/roadmap/d10-d11-metrics.json").read_text())["areas"]
    for area, (r, f) in D69.items():
        assert recorded[area]["recall_non_adversarial"] >= r, (area, recorded[area]["recall_non_adversarial"])
        assert recorded[area]["false_positive_case_rate"] <= f, (
            area,
            recorded[area]["false_positive_case_rate"],
        )
