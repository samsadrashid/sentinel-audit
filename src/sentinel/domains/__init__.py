"""M3 security domains, static parts only (D-58, D-59).

The domain identities are **provisional** (D-59): D01 = Web, D02 = API, D08 = Backend,
D14 = Database, inferred from the roadmap title and subject to the original product specification.
Nothing here adds requirements beyond the frozen M3 row.

Each domain is independent (D-58), with its own:

* **Applicability:** a predicate over the discovery record. When no relevant inputs exist, the domain
  is `NOT_APPLICABLE`.
* **Rules:** the Sentinel-authored Semgrep rule file `rules/semgrep/<id>.yaml` (D-55), hash-pinned.
* **Finding mapping:** which scanner rules and resource types belong to the domain.
* **Fixtures and metrics:** `tests/fixtures/domains/<id>/`, measured by `scripts/m3/measure.py`.
* **Validated coverage:** `domains/coverage.json`, written only by the measurement harness from real
  scanner runs on the domain fixtures. A check counts towards coverage **only** if it is listed
  there (D-09, D-58). Every other check that ran is reported as "ran, not fixture-validated".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

SEMGREP_PREFIX = "semgrep.sentinel-"


@dataclass(frozen=True)
class Domain:
    id: str
    name: str
    #: Semgrep rule-id prefix of this domain's own rules (after `semgrep.`).
    rule_prefix: str
    #: Core rules (`sentinel-core.yaml`) whose findings belong to this domain.
    core_rules: frozenset[str]
    #: Checkov resource-type prefixes and Trivy misconfiguration types that belong here.
    iac_resources: tuple[str, ...]
    #: Whether dependency vulnerabilities (OSV-Scanner, Trivy, Grype) map here.
    dependencies: bool
    #: Scanner adapters this domain needs for FULL coverage (V-3). Any of them missing, unapproved,
    #: failed, timed out or blocked makes the domain PARTIAL, ERROR or NOT_RUN, never FULL.
    required: tuple[str, ...] = ()

    def applicable(self, discovery: dict[str, Any]) -> bool:
        langs = set(discovery.get("languages", {}))
        if self.id == "D01":
            return bool(langs & {"javascript", "typescript", "python", "php", "ruby"})
        if self.id == "D02":
            return bool(langs & {"python", "javascript", "typescript", "go", "java", "kotlin", "php", "ruby"})
        if self.id == "D08":
            return bool(
                langs
                or discovery.get("ecosystems")
                or discovery.get("iac_files")
                or discovery.get("container_files")
            )
        if self.id == "D14":
            return bool(langs or discovery.get("iac_files"))
        return False


DOMAINS: tuple[Domain, ...] = (
    Domain("D01", "Web", "sentinel-web-", frozenset({"sentinel-js-eval"}), (), False, ("semgrep",)),
    Domain(
        "D02",
        "API",
        "sentinel-api-",
        frozenset({"sentinel-python-tls-verify-disabled"}),
        (),
        False,
        ("semgrep",),
    ),
    Domain(
        "D08",
        "Backend",
        "sentinel-backend-",
        frozenset(
            {
                "sentinel-python-eval",
                "sentinel-python-subprocess-shell",
                "sentinel-python-pickle-load",
                "sentinel-python-yaml-unsafe-load",
                "sentinel-js-child-process-exec",
                "sentinel-generic-weak-hash-for-security",
            }
        ),
        (
            "aws_lambda",
            "aws_ecs",
            "aws_instance",
            "aws_s3",
            "aws_security_group",
            "kubernetes",
            "dockerfile",
            "Dockerfile",
        ),
        True,
        ("semgrep", "osv-scanner", "trivy", "grype", "checkov"),
    ),
    Domain(
        "D14",
        "Database",
        "sentinel-db-",
        frozenset(),
        (
            "aws_db_instance",
            "aws_rds",
            "aws_dynamodb",
            "aws_elasticache",
            "google_sql",
            "azurerm_mssql",
            "azurerm_postgresql",
        ),
        False,
        ("semgrep", "checkov", "trivy"),
    ),
)
BY_ID = {d.id: d for d in DOMAINS}
UNMAPPED = "unmapped"


def domain_for(rule: str, resource: str = "", dependency: bool = False) -> str:
    """The single domain a finding belongs to, or "unmapped". Deterministic; first match wins."""
    if dependency:
        return next((d.id for d in DOMAINS if d.dependencies), UNMAPPED)
    if rule.startswith(SEMGREP_PREFIX):
        rid = rule[len("semgrep.") :]
        for d in DOMAINS:
            if rid.startswith(d.rule_prefix) or rid in d.core_rules:
                return d.id
    for d in sorted(DOMAINS, key=lambda d: -max((len(p) for p in d.iac_resources), default=0)):
        if resource and any(resource.startswith(p) for p in d.iac_resources):
            return d.id
    if rule.startswith(("checkov.", "trivy.misconfig.")):
        return "D08"  # IaC and container configuration of the backend platform
    return UNMAPPED


def validated_coverage() -> dict[str, list[str]]:
    """Checks proven on the domain fixtures with real scanners (written by scripts/m3/measure.py)."""
    p = resources.files("sentinel") / "domains" / "coverage.json"
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    for d in DOMAINS:
        checks = data.get("validated", {}).get(d.id, [])
        if isinstance(checks, list) and all(
            isinstance(c, str) and re.fullmatch(r"[a-z0-9._:-]{1,200}", c) for c in checks
        ):
            out[d.id] = sorted(checks)
    return out


#: NOT_APPLICABLE: the check had no inputs of its kind in scope (e.g. Checkov with no IaC files), so
#: nothing it covers was left unexamined. Timeouts are ERROR with reason "timeout".
#: Completed checks. NOT_APPLICABLE also counts, but only with discovery evidence (see below).
COMPLETED = ("PASS", "FAIL", "NOT_APPLICABLE")
FAILED = ("ERROR",)

#: The discovery-record inputs each required adapter consumes. NOT_APPLICABLE is allowed only when the
#: discovery of every asset completed (not truncated) and found none of these inputs.
INPUTS: dict[str, tuple[str, ...]] = {
    "semgrep": ("languages",),
    "osv-scanner": ("ecosystems",),
    "grype": ("ecosystems",),
    "trivy": ("ecosystems", "container_files", "iac_files"),
    "checkov": ("iac_files", "container_files"),
}


def absence_evidence(adapter: str, discovery: list[dict[str, Any]]) -> str | None:
    """Discovery evidence that `adapter` has no input in scope, or None if absence isn't established.

    Missing or truncated discovery, an adapter with no declared input kinds, or any present input all
    give None: then the check is NOT_RUN, never NOT_APPLICABLE."""
    kinds = INPUTS.get(adapter)
    if not kinds or not discovery:
        return None
    for rec in discovery:
        if not isinstance(rec, dict) or rec.get("truncated") is not False:
            return None
        for k in kinds:
            if k not in rec or rec[k]:
                return None
    return f"discovery (complete, {len(discovery)} asset(s)): no {', '.join(kinds)}"


def required_status(
    adapter: str, checks: list[dict[str, Any]], discovery: list[dict[str, Any]] | None = None
) -> dict[str, str]:
    """One required adapter's state in this run. All of its checks must complete for it to count.

    NOT_APPLICABLE is accepted only with explicit discovery evidence that its input is absent: an
    unplanned adapter, or one that reported NOT_APPLICABLE, without that evidence is NOT_RUN."""
    evidence = absence_evidence(adapter, discovery or [])
    mine = [c for c in checks if c["adapter"] == adapter]
    if not mine:
        if evidence is not None:
            return {
                "adapter": adapter,
                "status": "NOT_APPLICABLE",
                "reason": "no_input",
                "evidence": evidence,
            }
        return {"adapter": adapter, "status": "NOT_RUN", "reason": "not_planned"}
    bad = [c for c in mine if c["status"] not in COMPLETED]
    if bad:
        worst = next((c for c in bad if c["status"] in FAILED), bad[0])
        return {
            "adapter": adapter,
            "status": str(worst["status"]),
            "reason": str(worst.get("reason", ""))[:300],
        }
    ran = [c for c in mine if c["status"] in ("PASS", "FAIL")]
    if not ran:  # every check said NOT_APPLICABLE
        if evidence is None:
            return {"adapter": adapter, "status": "NOT_RUN", "reason": "not_applicable_without_evidence"}
        return {"adapter": adapter, "status": "NOT_APPLICABLE", "reason": "no_input", "evidence": evidence}
    return {
        "adapter": adapter,
        "status": "FAIL" if any(c["status"] == "FAIL" for c in ran) else "PASS",
        "reason": "",
    }


def coverage_report(
    discovery: list[dict[str, Any]], findings: list[dict[str, Any]], checks: list[dict[str, Any]]
) -> dict[str, Any]:
    """Per-domain coverage (D-09, D-58, V-3).

    FULL only when every required check of the domain completed (PASS or FAIL); PARTIAL when some did;
    ERROR when none did and at least one failed or timed out; NOT_RUN otherwise. A missing, unapproved,
    failed, timed-out or blocked scanner can never produce FULL. `validated_checks` lists only
    fixture-validated rules whose producing check completed in this run."""
    validated = validated_coverage()
    completed = {c["adapter"] for c in checks if c["status"] in COMPLETED}
    not_completed = sorted({f"{c['adapter']}:{c['status']}" for c in checks if c["status"] not in COMPLETED})
    out: dict[str, Any] = {}
    for d in DOMAINS:
        applicable = any(d.applicable(rec) for rec in discovery)
        covered = sorted(c for c in validated.get(d.id, []) if c.split(":", 1)[0] in completed)
        req = [required_status(a, checks, discovery) for a in d.required]
        done = [r for r in req if r["status"] in COMPLETED]
        ran = [r for r in req if r["status"] in ("PASS", "FAIL")]
        if not applicable:
            status = "NOT_APPLICABLE"
        elif req and ran and len(done) == len(req):
            status = "FULL"
        elif ran:
            status = "PARTIAL"
        elif any(r["status"] in FAILED for r in req):
            status = "ERROR"
        else:
            status = "NOT_RUN"
        out[d.id] = {
            "name": d.name,
            "status": status,
            "required_checks": req,
            "validated_checks": covered,
            "findings": sum(1 for f in findings if f.get("domain") == d.id),
            "checks_not_completed": not_completed,
            "note": "FULL needs every required check completed; validated_checks lists only "
            "fixture-validated checks that completed in this run (D-58, V-3).",
        }
    return out
