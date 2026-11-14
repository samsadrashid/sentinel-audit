"""Real B2 execution in the share-free Podman machine (D-70): the evidence that M2-SA-12 is resolved for B2.

Runs only when the approved pins include `b2` and the share-free machine is the *active* Podman VM
(`podman machine stop sentinel && podman machine start sentinel-b2`). Otherwise every test is SKIPPED
with the precondition reason; a skip is never a pass.
"""

# ruff: noqa: E501
from __future__ import annotations

import json
import subprocess
from dataclasses import replace

import pytest

from sentinel import policy
from sentinel.adapters.archive import ArchiveAdapter
from sentinel.domain.enums import CheckStatus
from sentinel.isolation import b2 as b2iso
from sentinel.isolation import detect as detect_host
from sentinel.orchestrator import run_audit

from .test_b2 import MANIFEST, axml_doc, zbytes
from .test_m2_real_scanners import PINS, tree
from .test_pipeline import cfg, request

RUNNER = b2iso.B2Runner(PINS.podman, PINS.b2) if PINS is not None and PINS.podman and PINS.b2 else None
WHY = "no b2 pin" if RUNNER is None else RUNNER.precondition()
pytestmark = pytest.mark.skipif(
    WHY is not None, reason=f"share-free B2 machine not usable: {WHY} (not a pass)"
)


def test_vm_has_no_host_share_and_m2_sa_12_write_is_impossible():
    assert RUNNER is not None
    mounts = RUNNER._client(["machine", "ssh", RUNNER.pin.machine, "--", "cat", "/proc/mounts"]).stdout
    assert not [ln for ln in mounts.splitlines() if ln.split()[2:3] and ln.split()[2] in b2iso.SHARE_FS]
    # The M2-SA-12 reproduction: try to write to the host home from inside the VM. There is no share.
    home = str(__import__("pathlib").Path.home())
    r = RUNNER._client(
        [
            "machine",
            "ssh",
            RUNNER.pin.machine,
            "--",
            "sh",
            "-c",
            f"touch {home}/sentinel-m2-sa-12-probe 2>&1; echo rc=$?",
        ]
    )
    assert "rc=0" not in r.stdout
    assert not (__import__("pathlib").Path.home() / "sentinel-m2-sa-12-probe").exists()


def test_container_self_test_observations():
    p = RUNNER.probe()  # type: ignore[union-attr]
    assert p.available, p.reason
    assert p.observations == b2iso.EXPECTED


def test_real_apk_inspection_end_to_end(tmp_path, trust, ledger):
    t = tmp_path / "t"
    t.mkdir()
    (t / "app.apk").write_bytes(zbytes([("AndroidManifest.xml", axml_doc(MANIFEST))]))
    (t / "evil.apk").write_bytes(zbytes([("../../etc/evil", b"x")]))
    before = tree(t)
    pol = replace(policy.default_policy(), pins=PINS)
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, classes=("S1", "B2")),
            adapters=[ArchiveAdapter()],
            pol=pol,
            host=detect_host(),
        )
    )
    assert tree(t) == before
    by = {c.adapter: c for c in out.checks}
    assert by["archive"].status == CheckStatus.FAIL, by
    result = json.loads((out.run_dir / "reports" / "report.json").read_text())
    rules = {(f["rule"], f["location"]["file"]) for f in result["findings"]}
    assert ("archive.debuggable", "app.apk!/AndroidManifest.xml") in rules
    assert ("archive.archive-path-traversal", "evil.apk") in rules
    assert not (tmp_path / "etc").exists()


def test_container_is_killed_and_removed_on_timeout():
    assert RUNNER is not None
    res = RUNNER.run("import time; time.sleep(60)", [], b"", timeout_s=3, max_output=1000)
    assert res.run.timed_out
    left = subprocess.run(
        [str(RUNNER.podman.path), "--connection", RUNNER.pin.machine, "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    ).stdout
    assert "sentinel-b2-" not in left
