"""Run comparison, risk aggregation and remediation tracking (M9). Pure and read-only.

Inputs are two runs that the caller has already verified (signature, evidence, stored result); this
module never reads a run on its own. Rules:

* **Issue identity (D-64).** Findings are matched by a derived identity (domain, rule, asset,
  normalised file, title), not by line. A moved finding is `persisting` (`moved: true`), never `fixed`.
  Ambiguous duplicates and possible rule changes are `unverified`. The stored fingerprint is unchanged.
* **Same target only.** Runs whose scoped assets differ are refused; the revision may differ.
* **"Fixed" needs evidence.** A finding missing from the later run is `fixed` only if every adapter that
  produced it completed a check (`PASS` or `FAIL`) in the later run. Otherwise it is `unverified`:
  absence of output from a check that didn't run (NOT_RUN, ERROR, TIMEOUT, BLOCKED…) never counts.
* **Suppressed and accepted-risk findings stay visible.** They are listed as `accepted` with their
  decision type, and they are excluded from the open-risk totals, as in the fix plan (D-50).
* **Risk totals are a heuristic, not a verdict.** The weighted score orders work; the engine's
  overall result and exit code remain the only verdict.
* **Remediation tracking.** Each item of the earlier run's fix plan gets a status from the later run:
  `resolved` (evidence-backed fix), `open`, `accepted` or `unverified`.
"""

from __future__ import annotations

import posixpath
from typing import Any

from . import canonical, fixplan
from .errors import ValidationError

COMPARE_KIND = "sentinel-compare"
COMPARE_VERSION = 3
COMPLETED = {"PASS", "FAIL"}
WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "informational": 0}
SEVERITIES = ("critical", "high", "medium", "low", "informational")
NOTE = (
    "Comparison of two verified runs. 'fixed' requires a completed check by every producer of the "
    "finding in the later run; the risk score is a heuristic for ordering work, not a verdict."
)


def _accepted(f: dict[str, Any]) -> str | None:
    if f.get("suppression") is not None:
        return str(f["suppression"]["type"])
    if f["state"] in fixplan.CLOSED_STATES:
        return str(f["state"])
    return None


def risk(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = dict.fromkeys(SEVERITIES, 0)
    accepted = 0
    for f in findings:
        if _accepted(f) is not None:
            accepted += 1
            continue
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    by_domain: dict[str, int] = {}
    for f in findings:
        if _accepted(f) is None:
            by_domain[f["domain"]] = by_domain.get(f["domain"], 0) + 1
    return {
        "open_by_severity": counts,
        "open_by_domain": dict(sorted(by_domain.items())),
        "accepted": accepted,
        "weighted_score": sum(WEIGHTS.get(s, 0) * n for s, n in counts.items()),
    }


def _completed_adapters(result: dict[str, Any]) -> set[str]:
    return {c["adapter"] for c in result["checks"] if c["status"] in COMPLETED}


def _brief(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "fingerprint": f["fingerprint"],
        "identity": identity(f),
        "domain": f["domain"],
        "rule": f["rule"],
        "severity": f["severity"],
        "location": f["location"],
        "producers": sorted(f["producers"]),
        # Traceability: the signed evidence records (manifest evidence_index) behind this item.
        "evidence": sorted(f["evidence"]),
    }


def identity(f: dict[str, Any]) -> str:
    """D-64 issue identity: stable across line movement. The stored fingerprint is never changed."""
    if str(f["rule"]).startswith("vuln."):
        return "fp:" + str(f["fingerprint"])  # dependency findings: already line-independent (D-62)
    loc = f.get("location") or {}
    path = posixpath.normpath(str(loc.get("file", "")).replace("\\", "/"))
    return canonical.digest(
        {
            "v": 1,
            "domain": f["domain"],
            "rule": f["rule"],
            "component": f["component"],
            "file": "" if path == "." else path,
            "title": f["title"],
        }
    )


def _line(f: dict[str, Any]) -> int:
    loc = f.get("location") or {}
    line = loc.get("line", 0)
    return line if isinstance(line, int) else 0


def compare(
    old_manifest: dict[str, Any],
    old: dict[str, Any],
    new_manifest: dict[str, Any],
    new: dict[str, Any],
) -> dict[str, Any]:
    if canonical.digest(old["target"]["assets"]) != canonical.digest(new["target"]["assets"]):
        raise ValidationError("runs audit different targets; comparison refused")
    if old["audit_id"] == new["audit_id"]:
        raise ValidationError("compare needs two different runs")
    ran = _completed_adapters(new)
    groups: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}
    for f in old["findings"]:
        groups.setdefault(identity(f), ([], []))[0].append(f)
    for f in new["findings"]:
        groups.setdefault(identity(f), ([], []))[1].append(f)

    def rule_changed(f: dict[str, Any]) -> bool:
        loc = f.get("location") or {}
        return any(
            g["rule"] != f["rule"]
            and g["component"] == f["component"]
            and (g.get("location") or {}).get("file") == loc.get("file")
            and _line(g) == _line(f)
            and set(g["producers"]) & set(f["producers"])
            for g in new["findings"]
        )

    fixed: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    introduced: list[dict[str, Any]] = []
    persisting: list[dict[str, Any]] = []
    outcome: dict[str, tuple[str, dict[str, Any] | None]] = {}  # before fingerprint -> (status, after)

    def gone(f: dict[str, Any], why: str | None = None) -> None:
        if why is None:
            if not f["producers"] or not set(f["producers"]) <= ran:
                why = "producer_not_completed"
            elif rule_changed(f):
                why = "possible_rule_change"
        b = _brief(f)
        if why is None:
            fixed.append(b)
            outcome[f["fingerprint"]] = ("fixed", None)
        else:
            b["reason"] = why
            unverified.append(b)
            outcome[f["fingerprint"]] = ("unverified", None)

    for key in sorted(groups):
        bs, as_ = groups[key]
        exact = {f["fingerprint"] for f in bs} & {f["fingerprint"] for f in as_}
        rb = sorted((f for f in bs if f["fingerprint"] not in exact), key=_line)
        ra = sorted((f for f in as_ if f["fingerprint"] not in exact), key=_line)
        pairs = [
            (f, next(g for g in as_ if g["fingerprint"] == f["fingerprint"]))
            for f in bs
            if f["fingerprint"] in exact
        ]
        if rb and ra and len(rb) == len(ra):
            pairs += list(zip(rb, ra, strict=True))  # same issues, moved
            rb, ra = [], []
        if rb and ra:  # duplicate counts differ: which one went away can't be established
            for f in rb:
                gone(f, "ambiguous_identity")
        else:
            for f in rb:
                gone(f)
        for g in ra:
            b = _brief(g)
            if rb:
                b["ambiguous"] = True
            introduced.append(b)
        for f, g in pairs:
            b = _brief(g)
            b["severity_before"] = f["severity"]
            b["evidence_before"] = sorted(f["evidence"])
            b["accepted"] = _accepted(g)
            b["moved"] = _line(f) != _line(g) or f["fingerprint"] != g["fingerprint"]
            persisting.append(b)
            outcome[f["fingerprint"]] = ("persisting", g)

    plan = fixplan.build(old_manifest, old)
    remediation = []
    for item in plan["items"]:
        fp = item["finding"]
        st, match = outcome.get(fp, ("unverified", None))
        if st == "persisting" and match is not None:
            status = "accepted" if _accepted(match) else "open"
        elif st == "fixed":
            status = "resolved"
        else:
            status = "unverified"
        remediation.append(
            {
                "finding": fp,
                "severity": item["severity"],
                "status": status,
                "evidence_before": sorted(item["evidence"]),
                "evidence_after": sorted(match["evidence"]) if st == "persisting" and match else [],
            }
        )

    return {
        "kind": COMPARE_KIND,
        "compare_version": COMPARE_VERSION,
        "before": {
            "run_id": old["audit_id"],
            "manifest_sha256": canonical.digest(old_manifest),
            "overall": old["overall"],
        },
        "after": {
            "run_id": new["audit_id"],
            "manifest_sha256": canonical.digest(new_manifest),
            "overall": new["overall"],
        },
        "introduced": introduced,
        "fixed": fixed,
        "unverified": unverified,
        "persisting": persisting,
        "remediation": remediation,
        "risk": {"before": risk(old["findings"]), "after": risk(new["findings"])},
        "checks_not_completed_after": sorted(
            {c["check_id"] for c in new["checks"] if c["status"] not in COMPLETED}
        ),
        "note": NOTE,
    }
