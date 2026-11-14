"""M2 adapter and registry contract tests (D-13, D-22, D-52 to D-56, AC-03). No real scanner runs here."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import schema
from sentinel.adapters.base import BoundedRun
from sentinel.adapters.scanners import (
    SEMGREP_RULES,
    GitleaksAdapter,
    OsvScannerAdapter,
    SemgrepAdapter,
    SyftAdapter,
    rules_sha256,
    third_party_adapters,
    verify_osv_database,
)
from sentinel.domain.enums import CheckStatus
from sentinel.scanner_pins import OsvDatabasePin, Pins, file_sha256
from sentinel.scanner_pins import parse as parse_pins

from .m2_fakes import DIGEST, FakeRunner, ok, pins_with, podman, seatbelt, slow_until_cancelled

ALL = (GitleaksAdapter, SemgrepAdapter, OsvScannerAdapter, SyftAdapter)


def target(tmp_path: Path) -> Path:
    t = tmp_path / "target"
    t.mkdir()
    (t / "app.py").write_text("x = 1\n")
    (t / "requirements.txt").write_text("requests==2.0.0\n")
    return t


# ── manifests and registry ────────────────────────────────────────────────
@pytest.mark.parametrize("cls", ALL)
def test_manifests_are_complete_and_offline(cls):
    m = cls.manifest
    assert m.name and m.version and m.scanner and m.scanner_versions and m.licence and m.check_ids
    assert m.needs_network is False and m.engine_owned is False


def test_registry_lists_every_m2_scanner():
    names = [a.manifest.name for a in third_party_adapters(Pins())]
    assert names == [
        "gitleaks",
        "semgrep",
        "osv-scanner",
        "syft",
        "trivy",
        "checkov",
        "grype",
    ]  # M2 + M3 (D-58)


@pytest.mark.parametrize("cls", ALL)
def test_unpinned_scanner_is_not_run(cls, tmp_path):
    t = target(tmp_path)
    a = cls(Pins())
    from sentinel.adapters.base import PlannedCheck

    r = a.execute(
        PlannedCheck(a.manifest.check_ids[0], (str(t),)), t, 10, 1 << 20, runner=seatbelt(ok(b"[]"))
    )
    assert r.status == CheckStatus.NOT_RUN and r.reason == "scanner_not_approved"
    assert a.health()


@pytest.mark.parametrize(
    "spec, msg",
    [
        ({"scanners": {"zap": {"kind": "image", "image": "x@" + DIGEST}}}, "unknown scanner"),  # no A1 (D-10)
        ({"scanners": {"syft": {"kind": "image", "image": "anchore/syft:v1.57.0"}}}, "digest"),
        ({"scanners": {"syft": {"kind": "binary", "path": "relative/syft", "sha256": "a" * 64}}}, "absolute"),
        ({"scanners": {"syft": {"kind": "binary", "path": "/x/syft", "sha256": "A" * 64}}}, "hex"),
        (
            {
                "podman": {
                    "path": "/x/podman",
                    "sha256": "a" * 64,
                    "probe_image": "busybox:1.37",
                    "machine": "m",
                }
            },
            "digest",
        ),
    ],
)
def test_pins_refuse_anything_not_content_addressed(spec, msg):
    from sentinel.errors import ValidationError

    with pytest.raises(ValidationError, match=msg):
        parse_pins(spec)


def test_policy_schema_refuses_tag_only_images():
    with pytest.raises(schema.SchemaError):
        schema.validate({"scanners": {"syft": {"kind": "image", "image": "anchore/syft:latest"}}}, "policy")


# ── isolation pairing (no unsandboxed fallback) ───────────────────────────
def test_binary_pin_needs_the_native_sandbox_and_image_pin_needs_podman(tmp_path):
    t = target(tmp_path)
    g = GitleaksAdapter(pins_with(tmp_path, gitleaks="binary"))
    assert (
        g.execute(g.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(b"[]"))).reason
        == "host_isolation_unavailable"
    )
    s = SyftAdapter(pins_with(tmp_path, syft="image"))
    assert (
        s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=seatbelt(ok(b"{}"))).reason
        == "host_isolation_unavailable"
    )
    for a in (g, s):
        assert a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=None).reason == "host_isolation_unavailable"
    other = FakeRunner("test-only-runner", ok(b"[]"))
    assert g.execute(g.plan(t)[0], t, 10, 1 << 20, runner=other).status == CheckStatus.NOT_RUN


def test_binary_is_rehashed_immediately_before_execution(tmp_path):
    t = target(tmp_path)
    pins = pins_with(tmp_path, gitleaks="binary")
    g = GitleaksAdapter(pins)
    r = seatbelt(ok(b"[]"))
    assert g.execute(g.plan(t)[0], t, 10, 1 << 20, runner=r).status == CheckStatus.PASS
    path = pins.scanners["gitleaks"].path
    assert path is not None
    path.write_bytes(b"#!/bin/sh\necho tampered\n")
    res = g.execute(g.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "binary_hash_mismatch" and len(r.calls) == 1


def test_image_runtime_precondition_and_presence_are_checked_first(tmp_path):
    t = target(tmp_path)
    s = SyftAdapter(pins_with(tmp_path, syft="image"))
    r = podman(ok(b'{"artifacts": []}'))
    r.precondition_result = "podman_not_rootless"
    assert s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=r).reason == "podman_not_rootless" and not r.calls
    r.precondition_result = None
    r.images = set()
    assert s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=r).reason == "image_missing" and not r.calls


def test_images_are_run_only_by_digest(tmp_path):
    t = target(tmp_path)
    s = SyftAdapter(pins_with(tmp_path, syft="image"))
    r = podman(ok(b'{"artifacts": []}'))
    s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert r.calls[0]["target"].endswith("@" + DIGEST)


# ── failure handling never yields PASS (AC-03) ────────────────────────────
@pytest.mark.parametrize(
    "run, reason, status",
    [
        (BoundedRun(None, b"", True, False, 1), "timeout", CheckStatus.ERROR),
        (BoundedRun(None, b"x" * 10, False, True, 1), "output_limit", CheckStatus.ERROR),
        (BoundedRun(2, b"[]", False, False, 1), "exit_2", CheckStatus.ERROR),
        (BoundedRun(0, b"not json", False, False, 1), "bad_output", CheckStatus.ERROR),
        (BoundedRun(0, b'{"weird": 1}', False, False, 1), "bad_output", CheckStatus.ERROR),
        (BoundedRun(None, b"", False, False, 1, cancelled=True), "cancelled", CheckStatus.BLOCKED),
    ],
)
@pytest.mark.parametrize("cls, kind", [(GitleaksAdapter, "binary"), (SyftAdapter, "image")])
def test_every_failure_maps_to_a_non_pass_status(tmp_path, run, reason, status, cls, kind):
    t = target(tmp_path)
    a = cls(pins_with(tmp_path, **{cls.pin_name.replace("-", "_"): kind}))
    r = (seatbelt if kind == "binary" else podman)(lambda *x: run)
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r)
    if cls is GitleaksAdapter and run.stdout == b'{"weird": 1}':
        assert res.status == CheckStatus.ERROR
        return
    assert res.status == status and res.reason.startswith(reason) and res.status != CheckStatus.PASS


# ── Gitleaks: secrets classified in memory, never kept ────────────────────
GITLEAKS_OUT = json.dumps(
    [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS key",
            "File": "/target/app/config.py",
            "StartLine": 3,
            "Secret": "AKIAZ7Q4HN2KV9PLM3XT",
            "Match": "key = AKIAZ7Q4HN2KV9PLM3XT",
        },
        {
            "RuleID": "aws-access-token",
            "Description": "AWS doc key",
            "File": "/target/docs/README.md",
            "StartLine": 9,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "AKIAIOSFODNN7EXAMPLE",
        },
    ]
).encode()


def test_gitleaks_findings_are_classified_and_the_secret_is_never_stored(tmp_path):
    t = target(tmp_path)
    g = GitleaksAdapter(pins_with(tmp_path, gitleaks="image"))
    res = g.execute(g.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(GITLEAKS_OUT)))
    assert res.status == CheckStatus.FAIL
    assert [f["liveness"] for f in res.findings] == ["live", "test"]
    assert res.findings[0]["file"] == "app/config.py"
    blob = res.raw_output + json.dumps(res.findings).encode()
    assert b"AKIAZ7Q4HN2KV9PLM3XT" not in blob and b"AKIAIOSFODNN7EXAMPLE" not in blob
    schema.validate(res.findings, "adapter-findings")


def test_gitleaks_arguments_never_write_files_or_use_git(tmp_path):
    a = GitleaksAdapter(Pins()).args("/target", None)
    assert a[:2] == ["dir", "/target"] and "--report-path=-" in a and "git" not in a


# ── Semgrep: self-authored rules only (D-55) ──────────────────────────────
def test_semgrep_uses_only_the_pinned_local_rule_file(tmp_path):
    assert file_sha256(SEMGREP_RULES) == rules_sha256()
    args = SemgrepAdapter(Pins()).args("/target", "/data")
    joined = " ".join(args)
    assert f"--config=/data/{SEMGREP_RULES.name}" in args and "--metrics=off" in args
    for forbidden in ("auto", "p/", "r/", "http", "registry", "--config=auto"):
        assert forbidden not in joined.replace("/data/sentinel-core.yaml", "").replace("/target", "")


def test_semgrep_refuses_a_changed_rule_file(tmp_path, monkeypatch):
    import sentinel.adapters.scanners as sc

    monkeypatch.setattr(sc, "SEMGREP_RULES_SHA256", "0" * 64)
    t = target(tmp_path)
    s = SemgrepAdapter(pins_with(tmp_path, semgrep="image"))
    r = podman(ok(b'{"results": [], "errors": []}'))
    res = s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "semgrep_rules_mismatch" and not r.calls


def test_semgrep_rule_file_is_well_formed_and_offline():
    text = SEMGREP_RULES.read_text()
    assert "rules:" in text and "http" not in text.lower()
    ids = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.strip().startswith("- id:")]
    assert len(ids) == len(set(ids)) >= 6 and all(i.startswith("sentinel-") for i in ids)


def test_semgrep_output_parsing_and_errors(tmp_path):
    t = target(tmp_path)
    s = SemgrepAdapter(pins_with(tmp_path, semgrep="image"))
    out = {
        "results": [
            {
                "check_id": "data.sentinel-python-eval",
                "path": "/target/app.py",
                "start": {"line": 4},
                "extra": {"message": "eval", "severity": "ERROR"},
            }
        ],
        "errors": [],
    }
    res = s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(json.dumps(out).encode())))
    assert res.status == CheckStatus.FAIL and res.findings[0]["severity"] == "high"
    assert res.findings[0]["file"] == "app.py" and res.findings[0]["rule"] == "semgrep.sentinel-python-eval"
    bad = {"results": [], "errors": [{"message": "x"}]}
    res = s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(json.dumps(bad).encode())))
    assert res.status == CheckStatus.ERROR


# ── OSV-Scanner: offline database only (D-56) ─────────────────────────────
def make_db(tmp_path: Path) -> tuple[Path, str]:
    db = tmp_path / "osvdb"
    (db / "PyPI").mkdir(parents=True)
    (db / "PyPI" / "all.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
    manifest = {
        "files": [
            {
                "path": "PyPI/all.zip",
                "sha256": hashlib.sha256((db / "PyPI" / "all.zip").read_bytes()).hexdigest(),
            }
        ]
    }
    raw = json.dumps(manifest).encode()
    (db / "snapshot-manifest.json").write_bytes(raw)
    return db, hashlib.sha256(raw).hexdigest()


def test_osv_without_an_approved_database_is_not_run(tmp_path):
    t = target(tmp_path)
    o = OsvScannerAdapter(pins_with(tmp_path, osv_scanner="image"))
    r = podman(ok(b"{}"))
    res = o.execute(o.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "osv_database_not_approved" and not r.calls


def test_osv_database_is_verified_file_by_file(tmp_path):
    db, digest = make_db(tmp_path)
    assert verify_osv_database(db, digest) is None
    assert verify_osv_database(db, "0" * 64) == "osv_database_manifest_mismatch"
    (db / "PyPI" / "all.zip").write_bytes(b"changed")
    assert verify_osv_database(db, digest) == "osv_database_file_mismatch"


def test_osv_runs_offline_with_the_database_mounted_read_only(tmp_path):
    t = target(tmp_path)
    db, digest = make_db(tmp_path)
    base = pins_with(tmp_path, osv_scanner="image")
    pins = Pins(base.scanners, base.podman, OsvDatabasePin(db, digest))
    out = {
        "results": [
            {
                "source": {"path": "/target/requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {"id": "GHSA-x", "summary": "bad", "database_specific": {"severity": "HIGH"}}
                        ],
                    }
                ],
            }
        ]
    }
    r = podman(ok(json.dumps(out).encode(), rc=1))
    o = OsvScannerAdapter(pins)
    res = o.execute(o.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.FAIL and res.findings[0]["rule"] == "osv.GHSA-x"
    call = r.calls[0]
    assert {"--offline", "--offline-vulnerabilities"} <= set(call["args"]) and call["extra_ro"] == db
    assert call["env"]["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == "/data"


def test_osv_plans_nothing_without_lockfiles(tmp_path):
    empty = tmp_path / "e"
    empty.mkdir()
    (empty / "a.py").write_text("x")
    assert OsvScannerAdapter(Pins()).plan(empty) == []


# ── Syft: SBOM inventory ─────────────────────────────────────────────────
def test_syft_produces_an_inventory_and_passes_only_on_success(tmp_path):
    t = target(tmp_path)
    s = SyftAdapter(pins_with(tmp_path, syft="image"))
    out = {"artifacts": [{"type": "python", "name": "requests", "version": "2.0.0"}]}
    res = s.execute(s.plan(t)[0], t, 10, 1 << 20, runner=podman(ok(json.dumps(out).encode())))
    assert res.status == CheckStatus.PASS and res.findings == [] and b"requests" in res.raw_output
    assert "dir:/target" in s.args("/target", None)


def test_long_running_scanner_is_stopped_by_the_kill_switch(tmp_path):
    import threading

    t = target(tmp_path)
    s = SyftAdapter(pins_with(tmp_path, syft="image"))
    r = podman(slow_until_cancelled(60))
    r.cancel_event = threading.Event()
    threading.Timer(0.2, r.cancel_event.set).start()
    res = s.execute(s.plan(t)[0], t, 120, 1 << 20, runner=r)
    assert res.status == CheckStatus.BLOCKED and res.reason == "cancelled"


def test_policy_file_pins_reach_the_adapters(tmp_path, operator, trust, ledger):
    from sentinel import approvals, canonical, policy
    from sentinel.domain.enums import ApprovalAction as A

    from .conftest import NOW

    body = {
        "scanners": {
            "syft": {"kind": "image", "image": "anchore/syft@" + DIGEST},
            "gitleaks": {"kind": "binary", "path": "/opt/sentinel/bin/gitleaks", "sha256": "c" * 64},
        },
        "podman": {
            "path": "/opt/podman/bin/podman",
            "sha256": "d" * 64,
            "probe_image": "library/busybox@" + DIGEST,
            "machine": "sentinel-b2",
        },
    }
    raw = canonical.encode(body)
    pf, af = tmp_path / "p.json", tmp_path / "p.ap.json"
    pf.write_bytes(raw)
    ap = operator.approve(
        A.POLICY_CHANGE, {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}, "policy-prev:none"
    )
    approvals.save_approval_file(af, ap)
    pol = policy.validate_policy_file(pf, af, trust, ledger, NOW + 1)
    assert pol.pins.scanners["syft"].image == "anchore/syft@" + DIGEST
    assert pol.pins.scanners["gitleaks"].sha256 == "c" * 64 and pol.pins.podman is not None
    names = {a.manifest.name: a.pin for a in third_party_adapters(pol.pins)}
    assert names["syft"] is not None and names["semgrep"] is None
