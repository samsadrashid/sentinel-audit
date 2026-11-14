"""D-71 real evidence: scanner containers in the share-free machine see no host files, and a tampered
VM-local database volume is refused, deleted and re-imported clean. Skips (never passes) when the pinned
share-free machine isn't usable."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sentinel.adapters.scanners import OsvScannerAdapter
from sentinel.domain.enums import CheckStatus
from sentinel.isolation import podman as pm

from .test_m2_real_scanners import PINS, project

RUNNER = pm.PodmanRunner(PINS.podman) if PINS is not None and PINS.podman is not None else None
WHY = (
    "no podman pin"
    if RUNNER is None
    else (RUNNER.precondition() or (None if PINS.podman.machine else "no machine pin"))
)
pytestmark = pytest.mark.skipif(WHY is not None, reason=f"share-free machine not usable: {WHY} (not a pass)")


def test_scanner_container_sees_no_host_files(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "probe.txt").write_text("hello")
    home = str(Path.home())
    res = RUNNER.run(  # type: ignore[union-attr]
        PINS.podman.probe_image,  # type: ignore[union-attr]
        ["-c", f"cat /target/probe.txt; ls {home} >/dev/null 2>&1 && echo HOST_VISIBLE || echo no_host"],
        target_root=t,
        timeout_s=120,
        max_output=10_000,
        entrypoint="/bin/sh",
    )
    out = res.run.stdout.decode()
    assert "hello" in out and "no_host" in out and "HOST_VISIBLE" not in out


def test_tampered_database_volume_is_refused_then_reimported(tmp_path):
    db = PINS.database("osv")  # type: ignore[union-attr]
    assert db is not None
    raw = (db.path / "snapshot-manifest.json").read_bytes()
    vol = f"sentinel-db-{hashlib.sha256(raw).hexdigest()[:32]}"
    t = project(tmp_path / "p")
    a = OsvScannerAdapter(PINS)
    first = a.execute(a.plan(t)[0], t, 900, 64 << 20, runner=RUNNER)  # creates and verifies the volume
    assert first.status == CheckStatus.FAIL, first.reason
    tamper = RUNNER._client(  # type: ignore[union-attr]
        [
            "run",
            "--rm",
            f"--volume={vol}:/data",
            "--entrypoint=/bin/sh",
            PINS.podman.probe_image,
            "-c",
            "f=$(find /data -type f -name '*.zip' | head -1); echo x >> \"$f\"",
        ],  # type: ignore[union-attr]
        timeout=300,
    )
    assert tamper.returncode == 0, tamper.stderr
    second = a.execute(a.plan(t)[0], t, 900, 64 << 20, runner=RUNNER)
    assert second.status == CheckStatus.NOT_RUN and second.reason == "database_volume_mismatch"
    assert RUNNER._client(["volume", "exists", vol]).returncode != 0  # type: ignore[union-attr]  # deleted
    third = a.execute(
        a.plan(t)[0], t, 900, 64 << 20, runner=RUNNER
    )  # re-imported from the verified host copy
    assert third.status == CheckStatus.FAIL, third.reason


def test_every_pinned_image_is_stored_intact():
    """The 2026-11-10 incident: a stored MobSF layer was damaged after the VM disk filled. Every pinned
    image's stored layers must hash to its config diff_ids before Sentinel runs it."""
    conn = ["--connection", PINS.podman.machine]  # type: ignore[union-attr]
    images = [PINS.podman.probe_image]  # type: ignore[union-attr]
    images += [p.image for p in PINS.scanners.values() if p.image]  # type: ignore[union-attr]
    images += [p.image_id for p in (PINS.b2, PINS.mobsf) if p is not None]  # type: ignore[union-attr]
    results = {i: pm.verify_image_layers(PINS.podman.path, conn, i) for i in images}  # type: ignore[union-attr]
    assert results == {i: None for i in images}
