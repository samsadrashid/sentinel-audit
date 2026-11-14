"""`fix-plan` at M1 depth (D-50): a deterministic, read-only remediation plan for a verified run.

* Input is a **verified** run only: the caller passes the manifest and result returned by
  `cli.verified_run`, which checked the manifest signature, every evidence hash, the audit log and the
  result bound to the manifest. Anything else is refused before this module runs.
* Every item references its originating finding (stored fingerprint, unchanged for compatibility;
  resolution is judged by the D-64 issue identity in `compare`) and the supporting `evidence_id`s; each
  referenced evidence id must be in the signed manifest's evidence index.
* The plan **never** applies fixes, changes, promotes or re-states findings, writes into the run, or
  marks remediation as verified. Items carry `remediation_verified: false` as a constant.
* The same verified run always produces the same bytes: no timestamps, no randomness, stable ordering
  (severity, then fingerprint).
* The output is checked against the `fix-plan` contract (D-40) before it is printed or written.

The full remediation-plan report and the `verify` workflow remain in M9 (D-50).
"""

from __future__ import annotations

from typing import Any

from . import canonical
from .errors import IntegrityError

PLAN_KIND = "sentinel/v1/fix-plan"
PLAN_VERSION = "1.0"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
#: Findings already closed by a signed decision are listed, never planned.
CLOSED_STATES = frozenset({"false_positive", "accepted_risk"})
#: D-64: resolution is decided by issue identity (line-independent), never by a vanished fingerprint alone.
CHECK_AFTER_FIX = (
    "Re-run the audit, then `sentinel compare <this run> <new run>`. The item is resolved only if the same "
    "issue (D-64 issue identity: domain, rule, asset, file, title; not the line) is no longer reported AND "
    "every check that produced it completed in the new run. Otherwise it stays open or unverified."
)
NOTE = (
    "READ-ONLY PLAN (D-50). Nothing was applied, no finding was changed or promoted, and no remediation "
    "is verified. Each step needs your review; re-run an audit and `sentinel compare` to check a fix (D-64)."
)

#: Deterministic guidance per rule. Unknown rules get the generic step; nothing is guessed.
GUIDANCE: dict[str, str] = {
    "fixture.marker": "Remove the fixture marker string from the reported file and line.",
}
GENERIC = "Inspect the referenced evidence and remediate the condition described by rule {rule}."


def _item(f: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
    missing = [e for e in f["evidence"] if e not in index]
    if missing:
        raise IntegrityError(
            f"finding {f['fingerprint'][:16]} references evidence outside the signed manifest"
        )
    return {
        "finding": f["fingerprint"],
        "rule": f["rule"],
        "title": f["title"],
        "severity": f["severity"],
        "confidence": f["confidence"],
        "finding_state": f["state"],
        "location": f["location"],
        "component": f["component"],
        "evidence": sorted(f["evidence"]),
        "step": GUIDANCE.get(f["rule"], GENERIC.format(rule=f["rule"])),
        "check_after_fix": CHECK_AFTER_FIX,
        "requires_operator_review": True,
        "remediation_verified": False,
    }


def build(manifest: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Build the plan from an already verified manifest and result. Pure: reads its inputs only."""
    index = manifest.get("evidence_index", {})
    if not isinstance(index, dict):
        raise IntegrityError("manifest has no evidence index")
    items, excluded = [], []
    for f in sorted(
        result["findings"], key=lambda x: (SEVERITY_RANK.get(x["severity"], 9), x["fingerprint"])
    ):
        if f.get("suppression") is not None or f["state"] in CLOSED_STATES:
            reason = f["suppression"]["type"] if f.get("suppression") else f["state"]
            excluded.append({"finding": f["fingerprint"], "reason": str(reason)})
            continue
        items.append(_item(f, index))
    counts: dict[str, int] = {}
    for it in items:
        counts[it["severity"]] = counts.get(it["severity"], 0) + 1
    return {
        "kind": PLAN_KIND,
        "plan_version": PLAN_VERSION,
        "run_id": manifest["audit_id"],
        "manifest_sha256": canonical.digest(manifest),
        "result_sha256": manifest["result_sha256"],
        "run_key_id": manifest["run_key_id"],
        "overall_result": result["overall"],
        "items": items,
        "excluded": excluded,
        "counts": {s: counts.get(s, 0) for s in SEVERITY_RANK},
        "note": NOTE,
    }


def render(plan: dict[str, Any]) -> bytes:
    from .schema import check_output

    check_output(plan, "fix-plan")
    return canonical.encode(plan)
