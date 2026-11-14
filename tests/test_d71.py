"""D-71: every container runs in the share-free Podman machine; targets and databases are VM-local volumes."""

# ruff: noqa: E501
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from sentinel import scanner_pins
from sentinel.errors import ValidationError
from sentinel.isolation import podman as pm
from sentinel.scanner_pins import RuntimePin

from .image_archive import docker_archive, layer, write_archive

DIGEST = "sha256:" + "b" * 64
GOOD = "network=denied;write_target=denied;write_root=denied;write_workspace=allowed;cap_eff=0000000000000000"


def test_tar_contains_only_regular_files_and_directories(tmp_path):
    src = tmp_path / "t"
    (src / "d").mkdir(parents=True)
    (src / "d" / "a.py").write_text("x")
    (src / "secret-link").symlink_to("/etc/hosts")
    (src / "dirlink").symlink_to(src / "d")
    os.mkfifo(src / "pipe")
    out = tmp_path / "x.tar"
    assert pm.write_tar(src, out) == 3
    with tarfile.open(out) as t:
        members = {m.name: m for m in t.getmembers()}
    assert set(members) == {"d", "d/a.py"}
    assert members["d/a.py"].mode == 0o644 and members["d/a.py"].uid == 0 and members["d"].isdir()


def test_tar_size_limit(tmp_path, monkeypatch):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "big").write_bytes(b"x" * 100)
    monkeypatch.setattr(pm, "MAX_TARGET_BYTES", 10)
    with pytest.raises(pm.VolumeError, match="target_too_large"):
        pm.write_tar(tmp_path / "t", tmp_path / "x.tar")


def fake_client(machines, mounts):  # type: ignore[no-untyped-def]
    def c(args, timeout=60):  # type: ignore[no-untyped-def]
        if args[:2] == ["machine", "list"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(machines), "")
        return subprocess.CompletedProcess(args, 0, mounts, "")

    return c


@pytest.mark.parametrize(
    "machines, mounts, expected",
    [
        ([{"Name": "m", "Running": True}], "overlay / overlay rw 0 0\n", None),
        ([{"Name": "m", "Running": True}], "vfs /Users virtiofs rw 0 0\n", "podman_host_share_present"),
        ([{"Name": "m", "Running": True}], "h /mnt 9p rw 0 0\n", "podman_host_share_present"),
        ([{"Name": "m", "Running": False}], "", "podman_machine_not_active"),
        ([{"Name": "other", "Running": True}], "", "podman_machine_missing"),
        ([{"Name": "m", "Running": True}], "", "podman_mounts_unreadable"),
    ],
)
def test_machine_share_problem(machines, mounts, expected):
    assert pm.machine_share_problem(fake_client(machines, mounts), "m") == expected


def test_policy_requires_the_share_free_machine():
    base = {"path": "/bin/podman", "sha256": "a" * 64, "probe_image": f"x/busybox@{DIGEST}"}
    with pytest.raises(ValidationError, match="machine"):
        scanner_pins.parse({"podman": base})
    assert scanner_pins.parse({"podman": {**base, "machine": "sentinel-b2"}}).podman.machine == "sentinel-b2"


def test_policy_schema_accepts_and_requires_the_machine_pin():
    from sentinel.schema import SchemaError, validate

    base = {"path": "/bin/podman", "sha256": "a" * 64, "probe_image": f"x/busybox@{DIGEST}"}
    validate({"podman": {**base, "machine": "sentinel-b2"}}, "policy")
    for bad in (base, {**base, "machine": "Bad Name"}):
        with pytest.raises(SchemaError):
            validate({"podman": bad}, "policy")


def fake_podman(
    tmp: Path, *, mounts: str = "overlay / overlay rw 0 0", verify_rc: int = 0
) -> tuple[RuntimePin, Path]:
    log = tmp / "calls.log"
    archive, image_id = write_archive(tmp)
    info = json.dumps({"host": {"security": {"rootless": True}}})
    machines = json.dumps([{"Name": "m", "Running": True}])
    script = f"""#!/bin/sh
echo "$@" >> {log}
[ "$1" = "--connection" ] && shift 2
case "$1" in
  machine) if [ "$2" = list ]; then echo '{machines}'; else echo '{mounts}'; fi ;;
  info) echo '{info}' ;;
  image) [ "$2" = inspect ] && echo sha256:{image_id}; exit 0 ;;
  save) cat {archive} ;;
  volume) [ "$2" = import ] && cat > /dev/null; [ "$2" = exists ] && exit 1; exit 0 ;;
  rm) exit 0 ;;
  run) case "$*" in *sha256sum*) cat > /dev/null; exit {verify_rc} ;; *) echo '{GOOD}' ;; esac ;;
  *) exit 9 ;;
esac
"""
    p = tmp / "podman"
    p.write_text(script)
    p.chmod(0o755)
    return RuntimePin(p, hashlib.sha256(p.read_bytes()).hexdigest(), f"x/busybox@{DIGEST}", "m"), log


def test_runner_never_passes_a_host_path_and_removes_its_volumes(tmp_path):
    pin, log = fake_podman(tmp_path)
    r = pm.PodmanRunner(pin, workspaces=tmp_path / "ws")
    assert r.precondition() is None
    t = tmp_path / "target-dir-on-host"
    t.mkdir()
    (t / "a.txt").write_text("x")
    res = r.run(f"x/y@{DIGEST}", ["scan"], target_root=t, timeout_s=30, max_output=1000)
    calls = log.read_text().splitlines()
    run_line = next(c for c in calls if " run " in f" {c} " and "sha256sum" not in c)
    assert str(t) not in run_line and str(tmp_path) not in run_line  # no host path in the container argv
    assert "--connection m" in run_line and ":/target:ro" in run_line
    created = [c.split()[-1] for c in calls if "volume create" in c]
    assert created and all(any(f"volume rm --force {v}" in c for c in calls) for v in created)
    assert res.workspace_removed


def test_runner_refuses_a_machine_with_a_host_share(tmp_path):
    pin, _ = fake_podman(tmp_path, mounts="vfs /Users virtiofs rw 0 0")
    assert pm.PodmanRunner(pin).precondition() == "podman_host_share_present"


def test_database_volume_failing_verification_is_refused_and_deleted(tmp_path):
    pin, log = fake_podman(tmp_path, verify_rc=1)
    db = tmp_path / "db"
    db.mkdir()
    (db / "f.bin").write_bytes(b"data")
    m = json.dumps({"files": [{"path": "f.bin", "sha256": hashlib.sha256(b"data").hexdigest()}]}).encode()
    (db / "snapshot-manifest.json").write_bytes(m)
    t = tmp_path / "t"
    t.mkdir()
    r = pm.PodmanRunner(pin, workspaces=tmp_path / "ws")
    with pytest.raises(pm.VolumeError, match="database_volume_mismatch"):
        r.run(f"x/y@{DIGEST}", ["scan"], target_root=t, timeout_s=30, max_output=1000, extra_ro=db)
    vol = f"sentinel-db-{hashlib.sha256(m).hexdigest()[:32]}"
    assert any(f"volume rm --force {vol}" in c for c in log.read_text().splitlines())
    assert not any(
        " run " in f" {c} " and "sha256sum" not in c for c in log.read_text().splitlines()
    )  # scanner never started


def test_database_volume_mismatch_is_not_run_in_the_adapter(tmp_path, monkeypatch):
    from sentinel.adapters.scanners import OsvScannerAdapter
    from sentinel.domain.enums import CheckStatus
    from sentinel.scanner_pins import OsvDatabasePin, Pins, ScannerPin

    pin, _ = fake_podman(tmp_path, verify_rc=1)
    db = tmp_path / "db"
    db.mkdir()
    (db / "f.bin").write_bytes(b"data")
    m = json.dumps({"files": [{"path": "f.bin", "sha256": hashlib.sha256(b"data").hexdigest()}]}).encode()
    (db / "snapshot-manifest.json").write_bytes(m)
    pins = Pins(
        {"osv-scanner": ScannerPin("osv-scanner", "image", image=f"x/osv@{DIGEST}")},
        pin,
        OsvDatabasePin(db, hashlib.sha256(m).hexdigest()),
    )
    t = tmp_path / "t"
    t.mkdir()
    (t / "requirements.txt").write_text("flask==1.0\n")
    a = OsvScannerAdapter(pins)
    res = a.execute(a.plan(t)[0], t, 30, 1 << 20, runner=pm.PodmanRunner(pin, workspaces=tmp_path / "ws"))
    assert res.status == CheckStatus.NOT_RUN and res.reason == "database_volume_mismatch"


def test_intact_image_export_is_accepted():
    data, image_id = docker_archive([layer({"a": b"1"}), layer({"b": b"2"})])
    import io

    assert pm.check_docker_archive(io.BytesIO(data), image_id) is None
    assert pm.check_docker_archive(io.BytesIO(data), "sha256:" + image_id) is None


@pytest.mark.parametrize(
    "case, reason",
    [
        ("zeroed_file", "image_layer_corrupt"),
        ("wrong_id", "image_config_mismatch"),
        ("count", "image_layer_count_mismatch"),
        ("garbage", "image_export_unreadable"),
        ("no_manifest", "image_export_malformed"),
    ],
)
def test_damaged_image_export_is_refused(case, reason):
    """The 2026-11-10 incident: files in a stored layer became zero bytes after the VM disk filled."""
    import io

    good = layer({"PIL/__init__.py": b"x" * 2035})
    zeroed = layer({"PIL/__init__.py": b""})
    image_id = ""
    if case == "zeroed_file":
        data, image_id = docker_archive([good], stored=[zeroed])
    elif case == "wrong_id":
        data, _ = docker_archive([good])
        image_id = "0" * 64
    elif case == "count":
        data, image_id = docker_archive([good], diff_ids=["sha256:" + "1" * 64, "sha256:" + "2" * 64])
    elif case == "garbage":
        data, image_id = b"not a tar archive" * 100, "0" * 64
    else:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            info = tarfile.TarInfo("x.tar")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
        data, image_id = buf.getvalue(), "0" * 64
    assert pm.check_docker_archive(io.BytesIO(data), image_id) == reason


def test_runner_refuses_a_damaged_image_and_never_starts_it(tmp_path):
    pin, log = fake_podman(tmp_path)
    damaged, damaged_id = docker_archive([layer({"a": b"1" * 10})], stored=[layer({"a": b""})])
    (tmp_path / "image.tar").write_bytes(damaged)
    p = tmp_path / "podman"
    text = p.read_text()
    old_id = text.split("echo sha256:")[1].split(";")[0]
    p.write_text(text.replace(old_id, damaged_id))
    pin = RuntimePin(p, hashlib.sha256(p.read_bytes()).hexdigest(), pin.probe_image, "m")
    assert pm.verify_image_layers(pin.path, ["--connection", "m"], "x") == "image_layer_corrupt"
    r = pm.PodmanRunner(pin, workspaces=tmp_path / "ws")
    t = tmp_path / "t"
    t.mkdir()
    with pytest.raises(pm.VolumeError, match="image_integrity_failed: image_layer_corrupt"):
        r.run(f"x/y@{DIGEST}", ["scan"], target_root=t, timeout_s=30, max_output=1000)
    calls = [c.removeprefix("--connection m ") for c in log.read_text().splitlines()]
    assert not any(c.startswith("run ") for c in calls)  # no container was started
    assert not any(c.startswith("volume create") for c in calls)


def test_export_failure_from_podman_is_refused(tmp_path):
    """Podman's own export re-hash ("file integrity checksum failed") exits non-zero."""
    pin, _ = fake_podman(tmp_path)
    p = tmp_path / "podman"
    p.write_text(p.read_text().replace("  save) cat ", "  save) exit 125; cat "))
    pin = RuntimePin(p, hashlib.sha256(p.read_bytes()).hexdigest(), pin.probe_image, "m")
    assert pm.verify_image_layers(pin.path, ["--connection", "m"], "x") == "image_integrity_failed"


def test_verification_is_cached_per_image_id(tmp_path):
    pin, log = fake_podman(tmp_path)
    assert pm.verify_image_layers(pin.path, ["--connection", "m"], "a") is None
    assert pm.verify_image_layers(pin.path, ["--connection", "m"], "b") is None  # same image ID
    assert sum(" save " in f" {c} " for c in log.read_text().splitlines()) == 1


def test_scanner_adapter_reports_a_damaged_image_as_not_run(tmp_path):
    from sentinel.adapters.scanners import SyftAdapter
    from sentinel.domain.enums import CheckStatus
    from sentinel.scanner_pins import Pins, ScannerPin

    pin, _ = fake_podman(tmp_path)
    damaged, damaged_id = docker_archive([layer({"a": b"1"})], stored=[layer({"a": b""})])
    (tmp_path / "image.tar").write_bytes(damaged)
    p = tmp_path / "podman"
    text = p.read_text()
    p.write_text(text.replace(text.split("echo sha256:")[1].split(";")[0], damaged_id))
    pin = RuntimePin(p, hashlib.sha256(p.read_bytes()).hexdigest(), pin.probe_image, "m")
    pins = Pins({"syft": ScannerPin("syft", "image", image=f"x/syft@{DIGEST}")}, pin)
    t = tmp_path / "t"
    t.mkdir()
    (t / "requirements.txt").write_text("flask==1.0\n")
    a = SyftAdapter(pins)
    plan = a.plan(t)
    res = a.execute(plan[0], t, 30, 1 << 20, runner=pm.PodmanRunner(pin, workspaces=tmp_path / "ws"))
    assert res.status == CheckStatus.NOT_RUN and res.reason.startswith("image_integrity_failed"), res
