"""M2 acceptance with the REAL scanners, real rootless Podman and the real macOS sandbox (D-52 to D-56).

No fakes: these tests run the approved, pinned Gitleaks binary, the Semgrep, OSV-Scanner and Syft images,
and the BusyBox probe, using the pins in ~/.local/share/sentinel-deps/pins.json (written at acquisition,
see docs/m2/m2-completion-report.md). If those dependencies are absent (CI runners, other hosts) the
tests are SKIPPED with an explicit reason; a skip is never counted as a pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel import policy, scanner_pins
from sentinel.adapters.scanners import (
    GitleaksAdapter,
    OsvScannerAdapter,
    SemgrepAdapter,
    SyftAdapter,
    third_party_adapters,
)
from sentinel.domain.enums import CheckStatus
from sentinel.isolation import detect as detect_host
from sentinel.isolation import podman as pm
from sentinel.isolation import sandbox
from sentinel.orchestrator import run_audit
from sentinel.scanner_pins import OsvDatabasePin, Pins, RuntimePin, ScannerPin

from .test_pipeline import cfg, request

PINS_FILE = Path.home() / ".local/share/sentinel-deps/pins.json"

#: M2-approved scanners; M3 adds Trivy, Grype and Checkov, pending approval (B-1).
M2_SCANNERS = {"gitleaks", "semgrep", "osv-scanner", "syft"}
M3_SCANNERS = {"trivy", "grype", "checkov"}


def _load() -> Pins | None:
    if not PINS_FILE.is_file():
        return None
    return scanner_pins.parse(json.loads(PINS_FILE.read_text()))


PINS = _load()
pytestmark = pytest.mark.skipif(
    PINS is None or PINS.podman is None or pm.PodmanRunner(PINS.podman).precondition() is not None,
    reason="real M2 dependencies not installed or Podman machine not running (environmental; not a pass)",
)

AWS_LIVE = "AKIAZ7Q4HN2KV9PLM3XT"


def project(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "app.py").write_text(
        "import subprocess, pickle\n\ndef run(cmd, data):\n    subprocess.run(cmd, shell=True)\n"
        "    return pickle.loads(data), eval(cmd)\n"
    )
    (root / "requirements.txt").write_text("requests==2.19.0\nPyYAML==5.3\n")
    (root / "config.env").write_text(f"AWS_KEY={AWS_LIVE}\n")
    return root


def tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        h.update(f"{p.relative_to(root)}:{st.st_mode}:{st.st_size}:{st.st_mtime_ns}".encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


_CREATED: list[str] = []


@pytest.fixture(autouse=True)
def _track_container_names(monkeypatch):
    """Record the names of containers this test starts, so leftover checks never see another
    process's containers (the mutation harness runs suites in parallel on one Podman machine)."""
    real = pm.container_args

    def spy(name, *a, **kw):  # type: ignore[no-untyped-def]
        _CREATED.append(name)
        return real(name, *a, **kw)

    _CREATED.clear()
    monkeypatch.setattr(pm, "container_args", spy)


def leftover_containers() -> list[str]:
    assert PINS is not None and PINS.podman is not None
    out = subprocess.run(
        [str(PINS.podman.path), "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        env=pm.client_env(PINS.podman.path),
        timeout=60,
    ).stdout
    return [n for n in out.split() if n in _CREATED]


@pytest.fixture(scope="module")
def podman_runner() -> pm.PodmanRunner:
    assert PINS is not None and PINS.podman is not None
    return pm.PodmanRunner(PINS.podman)


# ── isolation ────────────────────────────────────────────────────────────
def test_real_podman_is_rootless_and_passes_the_functional_self_test(podman_runner):
    assert podman_runner.precondition() is None
    p = podman_runner.probe()
    assert p.available, p.reason
    assert p.observations == {
        "network": "denied",
        "write_target": "denied",
        "write_root": "denied",
        "write_workspace": "allowed",
        "cap_eff": "0000000000000000",
    }


def test_real_native_sandbox_probe_passes():
    assert sandbox.probe(force=True).available


# ── each real adapter ────────────────────────────────────────────────────
def _run(adapter, root: Path, runner, **kw):  # type: ignore[no-untyped-def]
    return adapter.execute(
        adapter.plan(root)[0], root, kw.get("timeout", 600), kw.get("max_output", 64 << 20), runner=runner
    )


def test_real_gitleaks_under_seatbelt_classifies_and_never_stores_the_secret(tmp_path):
    t = project(tmp_path / "p")
    res = _run(GitleaksAdapter(PINS), t, sandbox.MacSeatbeltRunner(workspaces=tmp_path / "ws"))
    assert res.status == CheckStatus.FAIL and res.isolation == "s1-macos-seatbelt"
    assert any(f["file"] == "config.env" and f["liveness"] == "live" for f in res.findings)
    assert AWS_LIVE.encode() not in res.raw_output and AWS_LIVE not in json.dumps(res.findings)


def test_real_semgrep_in_podman_uses_only_sentinel_rules(tmp_path, podman_runner):
    t = project(tmp_path / "p")
    res = _run(SemgrepAdapter(PINS), t, podman_runner)
    assert res.status == CheckStatus.FAIL and res.isolation == "podman-rootless"
    rules = {f["rule"] for f in res.findings}
    assert {"semgrep.sentinel-python-eval", "semgrep.sentinel-python-pickle-load"} <= rules
    assert all(r.startswith("semgrep.sentinel-") for r in rules)


def test_real_osv_scanner_works_fully_offline(tmp_path, podman_runner):
    t = project(tmp_path / "p")
    res = _run(OsvScannerAdapter(PINS), t, podman_runner)
    assert res.status == CheckStatus.FAIL and len(res.findings) >= 5
    assert all(f["file"] == "requirements.txt" and f["rule"].startswith("osv.") for f in res.findings)


def test_real_syft_produces_an_sbom(tmp_path, podman_runner):
    t = project(tmp_path / "p")
    res = _run(SyftAdapter(PINS), t, podman_runner)
    assert res.status == CheckStatus.PASS and res.findings == []
    pkgs = json.loads(res.raw_output)["packages"]
    assert {"requests", "pyyaml"} <= {p["name"].lower() for p in pkgs}


# ── AC-02: the target is never modified, by any real scanner ─────────────
def test_ac02_real_full_audit_leaves_the_target_unchanged(tmp_path, trust, ledger):
    t = project(tmp_path / "p")
    before = tree(t)
    assert PINS is not None
    pol = replace(policy.default_policy(), pins=PINS)
    host = detect_host()
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, classes=("S1", "S2")),
            adapters=third_party_adapters(PINS),
            pol=pol,
            host=host,
        )
    )
    assert tree(t) == before
    by = {c.adapter: c.status for c in out.checks if c.adapter in M2_SCANNERS}
    assert by == {
        "gitleaks": CheckStatus.FAIL,
        "semgrep": CheckStatus.FAIL,
        "osv-scanner": CheckStatus.FAIL,
        "syft": CheckStatus.PASS,
    }, by
    # M3 adapters: once pinned in the approved policy (D-66) they must complete; unpinned ones are never run.
    m3 = {c.adapter: (c.status, c.reason) for c in out.checks if c.adapter not in M2_SCANNERS}
    assert set(m3) <= M3_SCANNERS, m3
    for name, (status, reason) in m3.items():
        if name in PINS.scanners:
            assert status in (CheckStatus.PASS, CheckStatus.FAIL), (name, status, reason)
        else:
            assert (status, reason) == (CheckStatus.NOT_RUN, "scanner_not_approved"), (name, status, reason)
    unpinned = M3_SCANNERS - set(PINS.scanners)
    assert out.overall == ("INCOMPLETE" if unpinned & set(m3) else "FAIL") and not leftover_containers()
    assert AWS_LIVE not in (out.run_dir / "reports" / "report.json").read_text()


# ── AC-03: real failures are never PASS ─────────────────────────────────
def test_ac03_tampered_binary_is_not_run(tmp_path):
    assert PINS is not None
    real = PINS.scanners["gitleaks"].path
    assert real is not None
    copy = tmp_path / "gitleaks"
    shutil.copy2(real, copy)
    pin = ScannerPin("gitleaks", "binary", copy, PINS.scanners["gitleaks"].sha256)
    copy.chmod(0o755)
    with copy.open("ab") as fh:
        fh.write(b"\0")
    a = GitleaksAdapter(Pins({"gitleaks": pin}))
    t = project(tmp_path / "p")
    res = _run(a, t, sandbox.MacSeatbeltRunner(workspaces=tmp_path / "ws"))
    assert res.status == CheckStatus.NOT_RUN and res.reason == "binary_hash_mismatch"


def test_ac03_unpulled_image_is_not_run_and_never_pulled(tmp_path, podman_runner):
    missing = "docker.io/anchore/syft@sha256:" + "0" * 64
    a = SyftAdapter(Pins({"syft": ScannerPin("syft", "image", image=missing)}, PINS.podman if PINS else None))
    t = project(tmp_path / "p")
    res = _run(a, t, podman_runner)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "image_missing"
    assert not podman_runner.image_present(missing)


def test_ac03_wrong_podman_hash_is_not_run(tmp_path):
    assert PINS is not None and PINS.podman is not None
    bad = RuntimePin(PINS.podman.path, "0" * 64, PINS.podman.probe_image)
    runner = pm.PodmanRunner(bad)
    res = _run(SyftAdapter(PINS), project(tmp_path / "p"), runner)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "podman_binary_hash_mismatch"
    assert pm.PodmanRunner(bad).probe().available is False


def test_ac03_unverified_osv_database_is_not_run(tmp_path, podman_runner):
    assert PINS is not None and PINS.osv_database is not None
    wrong = Pins(PINS.scanners, PINS.podman, OsvDatabasePin(PINS.osv_database.path, "0" * 64))
    res = _run(OsvScannerAdapter(wrong), project(tmp_path / "p"), podman_runner)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "osv_database_manifest_mismatch"


def test_ac03_real_timeout_is_error_and_the_container_is_removed(tmp_path, podman_runner):
    res = _run(SemgrepAdapter(PINS), project(tmp_path / "p"), podman_runner, timeout=1)
    assert res.status == CheckStatus.ERROR and res.reason == "timeout"
    assert not leftover_containers()


def test_ac03_real_output_overflow_is_error(tmp_path, podman_runner):
    res = _run(SyftAdapter(PINS), project(tmp_path / "p"), podman_runner, max_output=16)
    assert res.status == CheckStatus.ERROR and res.reason == "output_limit"
    assert not leftover_containers()


def test_ac17_real_cancel_stops_the_container_and_blocks_the_check(tmp_path, podman_runner):
    ev = threading.Event()
    podman_runner.cancel_event = ev
    threading.Timer(0.5, ev.set).start()
    try:
        res = _run(SemgrepAdapter(PINS), project(tmp_path / "p"), podman_runner)
    finally:
        podman_runner.cancel_event = None
    assert res.status == CheckStatus.BLOCKED and res.reason == "cancelled"
    assert not leftover_containers()


def test_no_isolation_means_not_run_never_unsandboxed(tmp_path):
    t = project(tmp_path / "p")
    for a in third_party_adapters(PINS or Pins()):
        plans = a.plan(t)
        if not plans:  # e.g. Checkov with no IaC input: nothing is planned, so nothing can run
            continue
        res = a.execute(plans[0], t, 60, 1 << 20, runner=None)
        # Approved M2 scanners reach the isolation check; unapproved M3 scanners are refused even earlier.
        name = a.manifest.name
        pinned = PINS is not None and name in PINS.scanners
        expected = "host_isolation_unavailable" if pinned else "scanner_not_approved"
        assert res.status == CheckStatus.NOT_RUN and res.reason == expected, (name, res.reason)


def test_no_runtime_pull_or_network_flags_in_real_invocations(tmp_path, podman_runner, monkeypatch):
    seen: list[list[str]] = []
    real = pm.run_bounded

    def spy(argv, **kw):  # type: ignore[no-untyped-def]
        seen.append(list(argv))
        return real(argv, **kw)

    monkeypatch.setattr(pm, "run_bounded", spy)
    _run(SyftAdapter(PINS), project(tmp_path / "p"), podman_runner)
    argv = seen[0]
    assert "--pull=never" in argv and "--network=none" in argv and "--read-only" in argv
    assert any(a.endswith(":/target:ro") for a in argv)
    assert os.environ.get("SENTINEL_HOME")  # tests never touch the real state directory


def test_real_container_sees_only_the_read_only_target(tmp_path, podman_runner):
    assert PINS is not None and PINS.podman is not None
    t = project(tmp_path / "p")
    res = podman_runner.run(
        PINS.podman.probe_image,
        ["-c", "touch /target/x 2>/dev/null && echo tw || echo tr; [ -e /Users ] && echo hv || echo hn"],
        target_root=t,
        timeout_s=60,
        max_output=1000,
        entrypoint="/bin/sh",
    )
    assert res.run.stdout.decode().split() == ["tr", "hn"]
    assert not (t / "x").exists()
