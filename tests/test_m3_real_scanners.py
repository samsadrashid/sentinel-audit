"""M3 real-scanner integration (D-66): Trivy, Grype and Checkov from the approved pins, offline.

Runs only when the approved pins (~/.local/share/sentinel-deps/pins.json) include the scanner and its
database, and rootless Podman passes its self-test. Otherwise the tests are SKIPPED with the reason; a
skip is never a pass. Fixture projects are synthetic (tests/fixtures/domains).
"""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel import policy
from sentinel.adapters.scanners import CheckovAdapter, GrypeAdapter, SyftAdapter, TrivyAdapter
from sentinel.domain.enums import CheckStatus
from sentinel.isolation import detect as detect_host
from sentinel.isolation import podman as pm
from sentinel.orchestrator import run_audit
from sentinel.scanner_pins import OsvDatabasePin

from .test_m2_real_scanners import PINS, _run, leftover_containers, tree
from .test_pipeline import cfg, request

FIX = Path(__file__).parent / "fixtures" / "domains"
M3 = PINS is not None and {"trivy", "grype", "checkov"} <= set(PINS.scanners)
pytestmark = pytest.mark.skipif(not M3, reason="Trivy/Grype/Checkov not in the approved pins (not a pass)")


@pytest.fixture(scope="module")
def podman_runner() -> pm.PodmanRunner:
    assert PINS is not None and PINS.podman is not None
    r = pm.PodmanRunner(PINS.podman)
    if r.precondition() is not None:
        pytest.skip(f"Podman unavailable: {r.precondition()} (not a pass)")
    return r


def copy_fixture(tmp_path: Path, rel: str) -> Path:
    dst = tmp_path / "t"
    shutil.copytree(FIX / rel, dst, ignore=shutil.ignore_patterns("expected.json"))
    return dst


def test_trivy_finds_known_cves_offline_with_pinned_db(tmp_path, podman_runner):
    t = copy_fixture(tmp_path, "D08/vuln-10")
    before = tree(t)
    res = _run(TrivyAdapter(PINS), t, podman_runner)
    assert res.status == CheckStatus.FAIL, res.reason
    ids = {a for f in res.findings for a in f.get("aliases", [])}
    assert {"CVE-2018-18074", "CVE-2019-11324", "CVE-2019-10906"} <= ids
    assert res.db_snapshot == PINS.database("trivy").manifest_sha256
    assert tree(t) == before and not leftover_containers()


def test_checkov_finds_iac_misconfiguration(tmp_path, podman_runner):
    t = copy_fixture(tmp_path, "D14/vuln-10")
    res = _run(CheckovAdapter(PINS), t, podman_runner)
    assert res.status == CheckStatus.FAIL, res.reason
    rules = {f["rule"] for f in res.findings}
    assert {"checkov.CKV_AWS_16", "checkov.CKV_AWS_17"} <= rules
    assert all(
        f["file"] == "rds.tf"
        for f in res.findings
        if f["rule"] in ("checkov.CKV_AWS_16", "checkov.CKV_AWS_17")
    )


def test_grype_matches_the_syft_sbom_offline_and_dedups_with_provenance(
    tmp_path, trust, ledger, podman_runner
):
    t = copy_fixture(tmp_path, "D08/vuln-10")
    pol = replace(policy.default_policy(), pins=PINS)
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, classes=("S1", "S2")),
            adapters=[SyftAdapter(PINS), GrypeAdapter(PINS), TrivyAdapter(PINS)],
            pol=pol,
            host=detect_host(),
        )
    )
    by = {c.adapter: c for c in out.checks}
    assert by["grype"].status == CheckStatus.FAIL and by["trivy"].status == CheckStatus.FAIL, by
    import json

    result = json.loads((out.run_dir / "reports" / "report.json").read_text())
    assert result["check_notes"].get("grype", {}).get("grype_input") in (None, "sbom"), result["check_notes"]
    cve = [f for f in result["findings"] if f["rule"] == "vuln.CVE-2018-18074"]
    assert len(cve) == 1, "D-62: one finding per package + advisory across scanners"
    producers = {s["producer"] for s in cve[0]["sources"]}
    assert {"grype", "trivy"} <= producers
    snaps = {s["producer"]: s["db_snapshot"] for s in cve[0]["sources"]}
    assert snaps["grype"] == PINS.database("grype").manifest_sha256
    assert snaps["trivy"] == PINS.database("trivy").manifest_sha256
    assert result["reproducibility"]["snapshots"]["grype"] == PINS.database("grype").manifest_sha256


def test_unpinned_or_mismatched_database_is_not_run(tmp_path, podman_runner):
    t = copy_fixture(tmp_path, "D08/vuln-10")
    assert PINS is not None
    no_db = replace(PINS, trivy_database=None)
    res = _run(TrivyAdapter(no_db), t, podman_runner)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "trivy_database_not_approved"
    good = PINS.database("grype")
    bad = replace(PINS, grype_database=OsvDatabasePin(good.path, "0" * 64))
    a = GrypeAdapter(bad)
    res = a.execute(a.plan(t)[0], t, 600, 64 << 20, runner=podman_runner, sbom=None)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "grype_database_manifest_mismatch"
