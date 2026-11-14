"""M3 (D-58 to D-63): domain modules, Trivy, Checkov and Grype adapters, D-29 snapshot pinning,
cross-scanner deduplication with full provenance, coverage honesty, and the fixture corpus.

Adapter tests use test-only fake runners; real-scanner evidence comes from tests/test_m3_real.py and
scripts/m3/measure.py once the D-60 dependencies are approved and installed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sentinel import domains, schema
from sentinel.adapters.base import BoundedRun
from sentinel.adapters.scanners import (
    RULES_DIR,
    SEMGREP_RULE_PINS,
    CheckovAdapter,
    GrypeAdapter,
    OsvScannerAdapter,
    SemgrepAdapter,
    SyftAdapter,
    TrivyAdapter,
    package_key,
)
from sentinel.domain.enums import ActivityClass, CheckStatus
from sentinel.findings import canonical_advisory
from sentinel.orchestrator import run_audit
from sentinel.scanner_pins import OsvDatabasePin, Pins
from sentinel.scanner_pins import parse as parse_pins

from .isolation_testing import TestHost
from .m2_fakes import DIGEST, FakeRunner, ok, pins_with, podman
from .test_pipeline import cfg, make_target, request

FIXTURES = Path(__file__).parent / "fixtures" / "domains"


def snapshot(tmp_path: Path, name: str) -> OsvDatabasePin:
    db = tmp_path / f"db-{name}"
    db.mkdir()
    (db / "data.bin").write_bytes(name.encode() * 10)
    raw = json.dumps(
        {
            "files": [
                {"path": "data.bin", "sha256": hashlib.sha256((db / "data.bin").read_bytes()).hexdigest()}
            ]
        }
    ).encode()
    (db / "snapshot-manifest.json").write_bytes(raw)
    return OsvDatabasePin(db, hashlib.sha256(raw).hexdigest())


def full_pins(tmp_path: Path, **kinds: str) -> Pins:
    base = pins_with(tmp_path, **kinds)
    return Pins(
        base.scanners,
        base.podman,
        snapshot(tmp_path, "osv"),
        snapshot(tmp_path, "trivy"),
        snapshot(tmp_path, "grype"),
    )


# ── domains (D-58, D-59) ─────────────────────────────────────────────────
def test_four_independent_provisional_domains():
    assert [(d.id, d.name) for d in domains.DOMAINS] == [
        ("D01", "Web"),
        ("D02", "API"),
        ("D08", "Backend"),
        ("D14", "Database"),
    ]
    prefixes = [d.rule_prefix for d in domains.DOMAINS]
    assert len(set(prefixes)) == 4
    for d in domains.DOMAINS:
        text = (RULES_DIR / f"{d.id}.yaml").read_text()
        ids = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.strip().startswith("- id:")]
        assert ids and all(i.startswith(d.rule_prefix) for i in ids), d.id


@pytest.mark.parametrize(
    "rule, resource, dep, domain",
    [
        ("semgrep.sentinel-web-innerhtml-assignment", "", False, "D01"),
        ("semgrep.sentinel-api-debug-server", "", False, "D02"),
        ("semgrep.sentinel-python-pickle-load", "", False, "D08"),
        ("semgrep.sentinel-db-sql-built-from-strings", "", False, "D14"),
        ("checkov.CKV_AWS_17", "aws_db_instance.main", False, "D14"),
        ("checkov.CKV_AWS_24", "aws_security_group.web", False, "D08"),
        ("osv.GHSA-x", "", True, "D08"),
        ("gitleaks.aws", "", False, "unmapped"),
    ],
)
def test_finding_to_domain_mapping(rule, resource, dep, domain):
    assert domains.domain_for(rule, resource, dep) == domain


def test_coverage_is_reported_only_for_fixture_validated_completed_checks(monkeypatch):
    monkeypatch.setattr(
        domains,
        "validated_coverage",
        lambda: {
            "D01": ["semgrep:semgrep.sentinel-web-document-write"],
            "D14": ["checkov:checkov.CKV_AWS_17"],
        },
    )
    disc = [{"languages": {"javascript": 1}, "ecosystems": {}, "iac_files": ["rds.tf"]}]
    checks = [{"adapter": "semgrep", "status": "PASS"}, {"adapter": "checkov", "status": "NOT_RUN"}]
    rep = domains.coverage_report(disc, [], checks)
    assert rep["D01"]["status"] == "FULL" and rep["D01"]["validated_checks"] == [
        "semgrep:semgrep.sentinel-web-document-write"
    ]
    # D14 needs semgrep, checkov and trivy: checkov NOT_RUN and trivy unplanned -> PARTIAL, never FULL
    assert rep["D14"]["status"] == "PARTIAL"
    assert {r["adapter"]: r["status"] for r in rep["D14"]["required_checks"]} == {
        "semgrep": "PASS",
        "checkov": "NOT_RUN",
        "trivy": "NOT_RUN",
    }
    assert rep["D02"]["status"] == "FULL" and rep["D02"]["validated_checks"] == []
    assert "checkov:NOT_RUN" in rep["D14"]["checks_not_completed"]
    schema.validate(rep, "common", "domain_coverage")


def test_shipped_coverage_claims_nothing_that_was_not_measured():
    data = json.loads((Path(domains.__file__).parent / "coverage.json").read_text())
    assert "measure.py" in data["note"]
    for d, checks in data.get("validated", {}).items():
        assert d in domains.BY_ID and isinstance(checks, list)


# ── Semgrep rule pinning (D-55) ──────────────────────────────────────────
def test_every_rule_file_is_pinned_and_loaded():
    assert set(SEMGREP_RULE_PINS) == {"sentinel-core.yaml", "D01.yaml", "D02.yaml", "D08.yaml", "D14.yaml"}
    for name, digest in SEMGREP_RULE_PINS.items():
        assert hashlib.sha256((RULES_DIR / name).read_bytes()).hexdigest() == digest
    args = SemgrepAdapter(Pins()).args("/target", "/data")
    assert {a for a in args if a.startswith("--config=")} == {
        f"--config=/data/{n}" for n in SEMGREP_RULE_PINS
    }


def test_an_extra_unpinned_rule_file_is_refused(tmp_path, monkeypatch):
    import shutil

    import sentinel.adapters.scanners as sc

    rules = tmp_path / "rules"
    shutil.copytree(RULES_DIR, rules)
    (rules / "extra.yaml").write_text("rules: []\n")
    monkeypatch.setattr(sc, "RULES_DIR", rules)
    monkeypatch.setattr(sc, "SEMGREP_RULES", rules / "sentinel-core.yaml")
    assert SemgrepAdapter(Pins()).extra_mount() == (None, "semgrep_rules_mismatch")


# ── Trivy ────────────────────────────────────────────────────────────────
TRIVY_OUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2018-18074",
                    "PkgName": "requests",
                    "InstalledVersion": "2.19.0",
                    "Severity": "HIGH",
                    "Title": "x",
                }
            ],
        },
        {
            "Target": "main.tf",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0107",
                    "Title": "SG open",
                    "Severity": "CRITICAL",
                    "Status": "FAIL",
                    "CauseMetadata": {"StartLine": 3, "Resource": "aws_security_group.web"},
                }
            ],
        },
    ]
}


def test_trivy_is_offline_and_needs_its_pinned_database(tmp_path):
    t = make_target(tmp_path, "t", "x")
    args = TrivyAdapter(Pins()).args("/target", "/data")
    for flag in (
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--offline-scan",
        "--cache-dir=/data",
    ):
        assert flag in args
    no_db = TrivyAdapter(pins_with(tmp_path, trivy="image"))
    r = podman(ok(json.dumps(TRIVY_OUT).encode()))
    res = no_db.execute(no_db.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "trivy_database_not_approved" and not r.calls
    a = TrivyAdapter(full_pins(tmp_path, trivy="image"))
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.FAIL and res.db_snapshot == a.pins.trivy_database.manifest_sha256  # type: ignore[union-attr]
    vuln, mis = res.findings
    assert vuln["package"] == "pypi/requests@2.19.0" and vuln["aliases"] == ["CVE-2018-18074"]
    assert mis["rule"] == "trivy.misconfig.AVD-AWS-0107" and mis["resource"] == "aws_security_group.web"
    schema.validate(res.findings, "adapter-findings")


def test_tampered_trivy_database_is_not_run(tmp_path):
    t = make_target(tmp_path, "t", "x")
    pins = full_pins(tmp_path, trivy="image")
    assert pins.trivy_database is not None
    (pins.trivy_database.path / "data.bin").write_bytes(b"changed")
    a = TrivyAdapter(pins)
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(b"{}")))
    assert res.status == CheckStatus.NOT_RUN and res.reason == "trivy_database_file_mismatch"


# ── Checkov ──────────────────────────────────────────────────────────────
CHECKOV_OUT = [
    {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_17",
                    "check_name": "RDS public",
                    "file_path": "/rds.tf",
                    "file_line_range": [1, 8],
                    "resource": "aws_db_instance.main",
                    "severity": None,
                }
            ]
        },
    },
    {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0},
]


def test_checkov_runs_only_with_iac_inputs_and_offline(tmp_path):
    empty = make_target(tmp_path, "e", "x")
    assert CheckovAdapter(Pins()).plan(empty) == []
    t = make_target(tmp_path, "t", "x")
    (t / "rds.tf").write_text('resource "aws_db_instance" "main" {}\n')
    args = CheckovAdapter(Pins()).args("/target", None)
    assert "--skip-download" in args and "--soft-fail" in args and not any("api-key" in a for a in args)
    a = CheckovAdapter(pins_with(tmp_path, checkov="image"))
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(json.dumps(CHECKOV_OUT).encode())))
    assert res.status == CheckStatus.FAIL and res.findings[0]["file"] == "rds.tf"
    assert domains.domain_for(res.findings[0]["rule"], res.findings[0]["resource"]) == "D14"
    bad = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(b'[{"weird": 1}]')))
    assert bad.status == CheckStatus.ERROR


# ── Grype (D-61) ─────────────────────────────────────────────────────────
GRYPE_OUT = {
    "matches": [
        {
            "vulnerability": {
                "id": "GHSA-x84v-xcm2-53pg",
                "severity": "Medium",
                "description": "requests leaks",
            },
            "relatedVulnerabilities": [{"id": "CVE-2018-18074"}],
            "artifact": {
                "name": "requests",
                "version": "2.19.0",
                "type": "python",
                "locations": [{"path": "/requirements.txt"}],
            },
        }
    ]
}


def test_grype_prefers_the_sbom_on_stdin_and_records_a_directory_fallback(tmp_path):
    t = make_target(tmp_path, "t", "x")
    a = GrypeAdapter(full_pins(tmp_path, grype="image"))
    r = podman(ok(json.dumps(GRYPE_OUT).encode()))
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r, sbom=b'{"artifacts": []}')
    assert res.notes == {"grype_input": "sbom"} and r.calls[-1]["stdin_data"] == b'{"artifacts": []}'
    assert not any(x.startswith("dir:") for x in r.calls[-1]["args"])
    res2 = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r, sbom=None)
    assert res2.notes == {"grype_input": "directory_fallback"} and "dir:/target" in r.calls[-1]["args"]
    assert "stdin_data" not in r.calls[-1]
    f = res.findings[0]
    assert (
        f["aliases"] == ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"] and f["package"] == "pypi/requests@2.19.0"
    )
    env = a.env()
    assert env["GRYPE_DB_AUTO_UPDATE"] == "false" and env["GRYPE_DB_VALIDATE_AGE"] == "false"


def test_grype_decision_is_per_call_not_shared_state(tmp_path):
    a = GrypeAdapter(Pins())
    assert a.run_args("/target", None, {"grype_input": "sbom"}) == ["--output=json", "--quiet"]
    assert a.run_args("/target", None, {"grype_input": "directory_fallback"})[0] == "dir:/target"


# ── cross-scanner deduplication with provenance (D-62) and D-29 ──────────
def test_canonical_advisory_and_package_identity():
    assert canonical_advisory(["GHSA-b", "CVE-2020-2", "CVE-2019-9"]) == "CVE-2019-9"
    assert canonical_advisory(["PYSEC-1", "GHSA-z"]) == "GHSA-z"
    assert (
        package_key("pip", "Requests", "2.19.0")
        == package_key("python", "requests", "2.19.0")
        == "pypi/requests@2.19.0"
    )


class _Host(TestHost):
    __test__ = False

    def runner_for(self, cls: ActivityClass, limits: Any, pins: Any = None, kind: Any = None) -> Any:
        return RUNNER[0] if kind == "container" and cls in (ActivityClass.S1, ActivityClass.S2) else None


RUNNER: list[Any] = [None]
SYFT_OUT = {"artifacts": [{"type": "python", "name": "requests", "version": "2.19.0"}]}
OSV_OUT = {
    "results": [
        {
            "source": {"path": "/target/requirements.txt"},
            "packages": [
                {
                    "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "PYSEC-2018-28",
                            "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
                            "summary": "s",
                        }
                    ],
                }
            ],
        }
    ]
}


def respond(target: Any, args: list[str], runner: FakeRunner) -> BoundedRun:
    if "fs" in args[:1]:
        return BoundedRun(0, json.dumps(TRIVY_OUT).encode(), False, False, 1)
    if args[:2] == ["scan", "source"]:
        return BoundedRun(1, json.dumps(OSV_OUT).encode(), False, False, 1)
    if args and args[0].startswith("scan") and any(a.startswith("dir:") for a in args):
        return BoundedRun(0, json.dumps(SYFT_OUT).encode(), False, False, 1)
    return BoundedRun(0, json.dumps(GRYPE_OUT).encode(), False, False, 1)


def test_three_scanners_one_finding_every_source_kept_and_snapshots_recorded(tmp_path, trust, ledger):
    from sentinel import policy

    t = make_target(tmp_path, "t", "x")
    (t / "requirements.txt").write_text("requests==2.19.0\n")
    pins = full_pins(tmp_path, osv_scanner="image", syft="image", trivy="image", grype="image")
    RUNNER[0] = podman(respond)
    pol = replace(policy.default_policy(), pins=pins)
    adapters = [OsvScannerAdapter(pins), SyftAdapter(pins), TrivyAdapter(pins), GrypeAdapter(pins)]
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, classes=("S2",)),
            adapters=adapters,
            pol=pol,
            host=_Host("darwin", None, None, None, False),
        )
    )
    vulns = [f for f in out.result["findings"] if f["rule"] == "vuln.CVE-2018-18074"]
    assert len(vulns) == 1, [f["rule"] for f in out.result["findings"]]
    f = vulns[0]
    assert f["domain"] == "D08" and set(f["producers"]) == {"osv-scanner", "trivy", "grype"}
    rules = {s["producer"]: s["rule"] for s in f["sources"]}
    assert rules == {
        "osv-scanner": "osv.PYSEC-2018-28",
        "trivy": "trivy.CVE-2018-18074",
        "grype": "grype.GHSA-x84v-xcm2-53pg",
    }
    assert all(s["db_snapshot"] and s["evidence"] in f["evidence"] for s in f["sources"])
    assert out.result["check_notes"][t.name]["grype.grype_input"] == "sbom"  # Syft ran first (D-61)
    rep = out.result["reproducibility"]
    assert rep["status"] == "reproducible" and set(rep["snapshots"]) == {"osv", "trivy", "grype"}
    manifest = json.loads((out.run_dir / "manifest.json").read_text())
    assert manifest["vulnerability_db_snapshots"] == rep["snapshots"]


def test_missing_database_makes_the_run_non_reproducible_and_never_pass(tmp_path, trust, ledger):
    from sentinel import policy

    t = make_target(tmp_path, "t", "x")
    (t / "requirements.txt").write_text("requests==2.19.0\n")
    base = full_pins(tmp_path, trivy="image")
    pins = Pins(base.scanners, base.podman, base.osv_database, None, base.grype_database)  # trivy DB unpinned
    RUNNER[0] = podman(respond)
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, classes=("S2",)),
            adapters=[TrivyAdapter(pins)],
            pol=replace(policy.default_policy(), pins=pins),
            host=_Host("darwin", None, None, None, False),
        )
    )
    assert out.result["reproducibility"]["status"] == "non_reproducible"
    assert "trivy: trivy_database_not_approved" in out.result["reproducibility"]["reasons"]
    assert out.overall != "PASS" and out.checks[0].status == CheckStatus.NOT_RUN


def test_database_pins_are_parsed_and_content_addressed():
    from sentinel.errors import ValidationError

    p = parse_pins(
        {
            "trivy_database": {"path": "/x/trivy", "manifest_sha256": "a" * 64},
            "grype_database": {"path": "/x/g", "manifest_sha256": "b" * 64},
        }
    )
    assert p.database("trivy") is not None and p.database("grype") is not None and p.database("osv") is None
    with pytest.raises(ValidationError):
        parse_pins({"grype_database": {"path": "relative", "manifest_sha256": "b" * 64}})
    schema.validate({"trivy_database": {"path": "/x/t", "manifest_sha256": "a" * 64}}, "policy")


# ── fixtures (D-63) ──────────────────────────────────────────────────────
@pytest.mark.parametrize("dom", ["D01", "D02", "D08", "D14"])
def test_each_domain_has_at_least_10_vulnerable_and_10_clean_fixtures(dom):
    d = FIXTURES / dom
    vuln = sorted(p for p in d.iterdir() if p.name.startswith("vuln-"))
    clean = sorted(p for p in d.iterdir() if p.name.startswith("clean-"))
    assert len(vuln) >= 10 and len(clean) >= 10
    for v in vuln:
        spec = json.loads((v / "expected.json").read_text())
        assert spec["domain"] == dom and spec["kind"] == "vulnerable" and spec["expected"]
        for e in spec["expected"]:
            assert (v / e["file"]).is_file() and e["any_of"]
    for c in clean:
        assert json.loads((c / "expected.json").read_text())["expected"] == []


def test_fixture_generator_reproduces_the_committed_corpus(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mk", Path(__file__).parents[1] / "scripts/m3/make_fixtures.py"
    )
    assert spec and spec.loader
    mk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mk)
    mk.write(tmp_path / "out")

    def tree(r: Path) -> dict[str, bytes]:
        return {str(p.relative_to(r)): p.read_bytes() for p in sorted(r.rglob("*")) if p.is_file()}

    assert tree(tmp_path / "out") == tree(FIXTURES)


def test_designated_semgrep_checks_exist_in_the_pinned_rules():
    ids = set()
    for name in SEMGREP_RULE_PINS:
        ids |= {
            ln.split(":", 1)[1].strip()
            for ln in (RULES_DIR / name).read_text().splitlines()
            if ln.strip().startswith("- id:")
        }
    for spec_file in FIXTURES.rglob("expected.json"):
        for e in json.loads(spec_file.read_text())["expected"]:
            for c in e["any_of"]:
                if c.startswith("semgrep:"):
                    assert c.split("semgrep.", 1)[1] in ids, c


_ = (DIGEST,)


def test_malformed_coverage_entries_are_never_trusted(tmp_path, monkeypatch):
    import sentinel.domains as dm

    bad = tmp_path / "coverage.json"
    bad.write_text(
        json.dumps({"validated": {"D01": ["semgrep:ok", "../../etc/passwd"], "D02": ["semgrep:fine"]}})
    )

    class _Files:
        def __truediv__(self, other: str) -> Any:
            return self if other != "coverage.json" else bad

    monkeypatch.setattr(dm.resources, "files", lambda pkg: _Files())
    got = dm.validated_coverage()
    assert "D01" not in got and got["D02"] == ["semgrep:fine"]


def test_stdin_is_passed_only_with_interactive_flag(tmp_path):
    from sentinel.isolation import podman as pm

    with_stdin = pm.container_args("n", "x@" + DIGEST, [], target=tmp_path, interactive=True)
    without = pm.container_args("n", "x@" + DIGEST, [], target=tmp_path)
    assert "--interactive" in with_stdin and "--interactive" not in without
    assert "--network=none" in with_stdin  # stdin never relaxes isolation


@pytest.mark.parametrize(
    "statuses, expected",
    [
        (
            {"semgrep": "PASS", "osv-scanner": "FAIL", "trivy": "PASS", "grype": "PASS", "checkov": "FAIL"},
            "FULL",
        ),
        (
            {
                "semgrep": "PASS",
                "osv-scanner": "PASS",
                "trivy": "PASS",
                "grype": "PASS",
                "checkov": "ERROR",
            },
            "PARTIAL",
        ),
        ({"semgrep": "PASS", "osv-scanner": "PASS", "trivy": "NOT_RUN", "grype": "NOT_RUN"}, "PARTIAL"),
        ({"semgrep": "ERROR", "osv-scanner": "NOT_RUN", "trivy": "NOT_RUN"}, "ERROR"),
        ({"semgrep": "ERROR"}, "ERROR"),
        ({"semgrep": "NOT_RUN", "osv-scanner": "BLOCKED"}, "NOT_RUN"),
        ({}, "NOT_RUN"),
        (
            {
                "semgrep": "PASS",
                "osv-scanner": "PASS",
                "trivy": "PASS",
                "grype": "PASS",
                "checkov": "NOT_APPLICABLE",
            },
            "FULL",
        ),
    ],
)
def test_coverage_states_never_full_unless_every_required_check_completed(statuses, expected):
    disc = [
        {
            "languages": {"python": 1},
            "ecosystems": {"pypi": 1},
            "iac_files": [],
            "container_files": [],
            "truncated": False,
        }
    ]
    checks = [{"adapter": a, "status": s, "reason": "r"} for a, s in statuses.items()]
    rep = domains.coverage_report(disc, [], checks)
    assert rep["D08"]["status"] == expected
    schema.validate(rep, "common", "domain_coverage")


def test_one_failed_check_of_an_adapter_spoils_it():
    checks = [
        {"adapter": "semgrep", "status": "PASS", "reason": ""},
        {"adapter": "semgrep", "status": "ERROR", "reason": "exit_2"},
    ]
    rep = domains.coverage_report([{"languages": {"python": 1}}], [], checks)
    assert rep["D01"]["status"] == "ERROR"
    assert rep["D01"]["required_checks"] == [{"adapter": "semgrep", "status": "ERROR", "reason": "exit_2"}]


def test_historical_coverage_labels_still_validate():
    old = {
        "D01": {
            "name": "Web",
            "status": "covered",
            "validated_checks": [],
            "findings": 0,
            "checks_not_completed": [],
            "note": "x",
        }
    }
    schema.validate(old, "common", "domain_coverage")


# ── Owner decision 2026-11-10: NOT_APPLICABLE only with explicit discovery evidence ─────────────
COMPLETE = {
    "languages": {"python": 3},
    "ecosystems": {"pypi": {"manifest": ["requirements.txt"]}},
    "iac_files": [],
    "container_files": [],
    "truncated": False,
}
ALL_RAN = [
    {"adapter": a, "status": "PASS", "reason": ""} for a in ("semgrep", "osv-scanner", "trivy", "grype")
]


def d08(disc, checks):  # type: ignore[no-untyped-def]
    rep = domains.coverage_report(disc, [], checks)
    schema.validate(rep, "common", "domain_coverage")
    return rep["D08"], {r["adapter"]: r for r in rep["D08"]["required_checks"]}


def test_genuine_absence_with_complete_discovery_is_not_applicable_and_full():
    cov, req = d08([COMPLETE], ALL_RAN)  # Checkov unplanned, and discovery saw no IaC or container files
    assert (
        req["checkov"]["status"] == "NOT_APPLICABLE"
        and "no iac_files, container_files" in req["checkov"]["evidence"]
    )
    assert cov["status"] == "FULL"


def test_present_input_with_unplanned_check_is_not_run():
    cov, req = d08([{**COMPLETE, "iac_files": ["main.tf"]}], ALL_RAN)
    assert req["checkov"] == {"adapter": "checkov", "status": "NOT_RUN", "reason": "not_planned"}
    assert cov["status"] == "PARTIAL"


@pytest.mark.parametrize(
    "disc",
    [
        [],  # discovery failed or produced nothing
        [{**COMPLETE, "truncated": True}],  # discovery hit its limits
        [{k: v for k, v in COMPLETE.items() if k != "truncated"}],  # incomplete record
        [{k: v for k, v in COMPLETE.items() if k != "iac_files"}],  # input kind not reported
        [COMPLETE, {**COMPLETE, "truncated": True}],  # one of several assets incomplete
    ],
)
def test_failed_or_incomplete_discovery_never_gives_not_applicable(disc):
    _, req = d08(disc, ALL_RAN)
    assert req["checkov"]["status"] == "NOT_RUN"


def test_adapter_claiming_not_applicable_without_evidence_is_not_run():
    checks = [*ALL_RAN, {"adapter": "checkov", "status": "NOT_APPLICABLE", "reason": "nothing"}]
    cov, req = d08([{**COMPLETE, "iac_files": ["main.tf"]}], checks)
    assert req["checkov"]["reason"] == "not_applicable_without_evidence" and cov["status"] == "PARTIAL"
    cov, req = d08([COMPLETE], checks)  # with evidence it is accepted
    assert req["checkov"]["status"] == "NOT_APPLICABLE" and cov["status"] == "FULL"


@pytest.mark.parametrize(
    "status, reason",
    [
        ("NOT_RUN", "scanner_missing"),
        ("NOT_RUN", "scanner_not_approved"),
        ("ERROR", "bad_output"),
        ("ERROR", "timeout"),
        ("BLOCKED", "cancelled"),
    ],
)
def test_missing_scanner_malformed_output_and_failures_are_never_not_applicable(status, reason):
    checks = [*ALL_RAN, {"adapter": "checkov", "status": status, "reason": reason}]
    cov, req = d08([COMPLETE], checks)  # even when discovery would support absence
    assert req["checkov"]["status"] == status and req["checkov"]["reason"] == reason
    assert cov["status"] == "PARTIAL"


def test_adapter_without_declared_inputs_never_gets_not_applicable():
    assert domains.absence_evidence("gitleaks", [COMPLETE]) is None
    assert domains.absence_evidence("unknown-scanner", [COMPLETE]) is None


def test_all_required_not_applicable_is_not_full():
    empty = {"languages": {}, "ecosystems": {}, "iac_files": [], "container_files": [], "truncated": False}
    rep = domains.coverage_report([{**empty, "languages": {"python": 1}}], [], [])
    assert rep["D08"]["status"] != "FULL"


def test_reports_show_domain_coverage_and_required_check_status():
    """Mutation survivor eng-t-report-coverage."""
    from sentinel import reports

    from .test_findings_reports import result as _rr

    def _minimal_result():  # type: ignore[no-untyped-def]
        return _rr()

    cov = {
        "D08": {
            "name": "Backend",
            "status": "PARTIAL",
            "required_checks": [
                {"adapter": "semgrep", "status": "PASS", "reason": ""},
                {"adapter": "checkov", "status": "NOT_RUN", "reason": "scanner_not_approved"},
            ],
        }
    }
    md = reports.to_markdown({**_minimal_result(), "domain_coverage": cov}).decode()
    assert (
        "## Domain coverage" in md
        and "**PARTIAL**" in md
        and "checkov NOT_RUN (scanner\\_not\\_approved)" in md
    )
    html = reports.to_html({**_minimal_result(), "domain_coverage": cov}).decode()
    assert "<h2>Domain coverage</h2>" in html and "<b>PARTIAL</b>" in html


def test_oversized_database_file_is_not_run_not_an_exception(tmp_path, monkeypatch):
    """Regression (2026-11-10): an oversized snapshot file must refuse the database, not crash the audit."""
    import hashlib

    from sentinel.adapters import scanners

    d = tmp_path / "db"
    d.mkdir()
    (d / "big.db").write_bytes(b"x" * 64)
    manifest = json.dumps(
        {"files": [{"path": "big.db", "sha256": hashlib.sha256(b"x" * 64).hexdigest()}]}
    ).encode()
    (d / "snapshot-manifest.json").write_bytes(manifest)
    pin = hashlib.sha256(manifest).hexdigest()
    assert scanners.verify_snapshot(d, pin) is None
    monkeypatch.setattr(scanners, "OSV_MAX_DB_BYTES", 10)
    assert scanners.verify_snapshot(d, pin) == "osv_database_file_too_large"


#: D-67 (owner decision 2026-11-10): per-domain thresholds, measured with every required scanner.
D67 = {"D01": 0.90, "D02": 0.90, "D08": 0.85, "D14": 0.80}


def test_recorded_m3_metrics_meet_the_d67_thresholds():
    m = json.loads((Path(__file__).resolve().parents[1] / "docs/m3/metrics.json").read_text())["domains"]
    for dom, r in D67.items():
        d = m[dom]
        assert d["recall"] >= r, (dom, d["recall"])
        assert d["false_positive_fixture_rate"] <= 0.10, (dom, d["false_positive_fixture_rate"])
        states = d["coverage_states"]
        assert set(states) <= {"FULL", "NOT_APPLICABLE"}, (dom, states)  # FULL on every applicable run
        assert d["checks_not_completed"] == [], (dom, d["checks_not_completed"])
