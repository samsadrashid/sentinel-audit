"""Rootless Podman runner (D-53) and read-only discovery (D-52 item 1). A fake `podman` script stands
in for the real client; no container runs here."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel.domain.enums import ActivityClass
from sentinel.isolation import HostCapabilities
from sentinel.isolation import podman as pm
from sentinel.policy import Limits
from sentinel.scanner_pins import RuntimePin

from .image_archive import write_archive

DIGEST = "sha256:" + "b" * 64
GOOD = "network=denied;write_target=denied;write_root=denied;write_workspace=allowed;cap_eff=0000000000000000"


def fake_podman(
    tmp: Path, *, rootless: bool = True, probe_line: str | None = None, exists: bool = True
) -> RuntimePin:
    line = probe_line or GOOD
    info = json.dumps({"host": {"security": {"rootless": rootless}}})
    machines = json.dumps([{"Name": "m", "Running": True}])
    archive, image_id = write_archive(tmp)
    script = f"""#!/bin/sh
[ "$1" = "--connection" ] && shift 2
case "$1" in
  machine) if [ "$2" = list ]; then echo '{machines}'; else echo 'overlay / overlay rw 0 0'; fi ;;
  info) echo '{info}' ;;
  image) [ "$2" = inspect ] && [ "{int(exists)}" = 1 ] && echo sha256:{image_id}; [ "{int(exists)}" = 1 ] ;;
  save) cat {archive} ;;
  volume) [ "$2" = import ] && cat > /dev/null; exit 0 ;;
  rm) exit 0 ;;
  run) echo '{line}' ;;
  *) exit 9 ;;
esac
"""
    p = tmp / "podman"
    p.write_text(script)
    p.chmod(0o755)
    return RuntimePin(p, hashlib.sha256(p.read_bytes()).hexdigest(), f"x/busybox@{DIGEST}", "m")


def test_container_arguments_are_fully_hardened(tmp_path):
    args = pm.container_args(
        "sentinel-x",
        f"x/y@{DIGEST}",
        ["scan"],
        target=tmp_path / "t",
        workspace=tmp_path / "w",
        extra_ro=tmp_path / "d",
        env={"A": "1"},
    )
    for flag in (
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={pm.PIDS_LIMIT}",
        f"--memory={pm.MEMORY}",
        f"--volume={tmp_path / 't'}:/target:ro",
        "--tmpfs=/work:rw,nosuid,nodev,size=1g",
        f"--volume={tmp_path / 'd'}:/data:ro",
        "--env=A=1",
    ):
        assert flag in args, flag
    assert args[-2:] == [f"x/y@{DIGEST}", "scan"]
    assert not any(a.startswith(("--privileged", "--network=host", "--cap-add", "--volume=/:")) for a in args)
    assert not any(a.startswith("--volume=") and ":/work" in a for a in args)  # workspace never on disk
    with pytest.raises(ValueError):
        pm.container_args("n", "i", [], target=tmp_path, workspace=tmp_path, extra_ro=None, env={"A": "x\ny"})


def test_precondition_requires_the_pinned_binary_and_rootless_mode(tmp_path):
    pin = fake_podman(tmp_path)
    assert pm.PodmanRunner(pin).precondition() is None
    assert pm.PodmanRunner(fake_podman(tmp_path, rootless=False)).precondition() == "podman_not_rootless"
    wrong = RuntimePin(pin.path, "0" * 64, pin.probe_image)
    assert pm.PodmanRunner(wrong).precondition() == "podman_binary_hash_mismatch"
    missing = RuntimePin(tmp_path / "nope", pin.sha256, pin.probe_image, "m")
    assert pm.PodmanRunner(missing).precondition() == "podman_scanner_missing"
    # D-71: without the share-free machine pin there is no runner (never a host bind-mount fallback)
    (tmp_path / "u").mkdir()
    fresh = fake_podman(tmp_path / "u")
    unpinned = RuntimePin(fresh.path, fresh.sha256, fresh.probe_image)
    assert pm.PodmanRunner(unpinned).precondition() == "podman_machine_unpinned"
    with pytest.raises(pm.VolumeError, match="unpinned"):
        pm.PodmanRunner(unpinned, workspaces=tmp_path / "ws").run(
            f"x/y@{DIGEST}", ["scan"], target_root=tmp_path / "u", timeout_s=5, max_output=10
        )


def test_probe_needs_every_expected_observation(tmp_path):
    assert pm.PodmanRunner(fake_podman(tmp_path)).probe().available is True
    bad = GOOD.replace("network=denied", "network=allowed")
    assert pm.PodmanRunner(fake_podman(tmp_path, probe_line=bad)).probe().available is False
    caps = GOOD.replace("cap_eff=0000000000000000", "cap_eff=00000000a80425fb")
    assert pm.PodmanRunner(fake_podman(tmp_path, probe_line=caps)).probe().available is False
    assert pm.PodmanRunner(fake_podman(tmp_path, exists=False)).probe().reason == "probe_image_missing"


def test_no_runner_without_a_pin_or_a_passing_probe(tmp_path):
    pm._probe_cache.clear()
    assert pm.available_runner(None) is None
    bad = "network=allowed;write_target=denied;write_root=denied;write_workspace=allowed;cap_eff=0"
    assert pm.available_runner(fake_podman(tmp_path, probe_line=bad)) is None


def _host(native: str | None) -> HostCapabilities:
    return HostCapabilities("darwin", native, "podman", None, False)


def test_class_to_runner_mapping_has_no_unsandboxed_fallback(tmp_path, monkeypatch):
    lim = Limits()
    monkeypatch.setattr(pm, "available_runner", lambda pin: None)
    host = _host("s1-macos-seatbelt")
    assert host.runner_for(ActivityClass.S1, lim).name == "s1-macos-seatbelt"
    for cls in (ActivityClass.S2, ActivityClass.B1, ActivityClass.B2, ActivityClass.A1):
        assert host.runner_for(cls, lim) is None
    assert _host(None).runner_for(ActivityClass.S1, lim) is None
    sentinel_runner = object()
    monkeypatch.setattr(pm, "available_runner", lambda pin: sentinel_runner)
    assert _host(None).runner_for(ActivityClass.S1, lim) is sentinel_runner  # S1's only alternative
    assert host.runner_for(ActivityClass.S2, lim) is sentinel_runner
    assert host.runner_for(ActivityClass.B2, lim) is None and host.runner_for(ActivityClass.A1, lim) is None
    root = HostCapabilities("darwin", "s1-macos-seatbelt", "podman", None, True)
    assert all(root.runner_for(c, lim) is None for c in ActivityClass)


# ── discovery ────────────────────────────────────────────────────────────
def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p).encode())
        if p.is_file() and not p.is_symlink():
            h.update(p.read_bytes())
    return h.hexdigest()


def test_discovery_finds_ecosystems_and_never_writes(tmp_path):
    from sentinel import schema
    from sentinel.discovery import discover

    r = tmp_path / "proj"
    (r / "svc").mkdir(parents=True)
    (r / "node_modules" / "dep").mkdir(parents=True)
    for rel, body in {
        "pyproject.toml": "",
        "uv.lock": "",
        "svc/package.json": "{}",
        "svc/package-lock.json": "{}",
        "go.mod": "",
        "Dockerfile": "FROM x",
        "infra/main.tf": "",
        "a.py": "",
        "svc/b.ts": "",
        "requirements-dev.txt": "",
        "node_modules/dep/package.json": "{}",
    }.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(body)
    (r / "link").symlink_to("/etc")
    before = tree_hash(r)
    d = discover(r)
    assert tree_hash(r) == before
    j = d.to_json()
    assert j["ecosystems"]["PyPI"] == {
        "lockfile": ["requirements-dev.txt", "uv.lock"],
        "manifest": ["pyproject.toml"],
    }
    assert j["ecosystems"]["npm"]["lockfile"] == ["svc/package-lock.json"]
    assert "node_modules/dep/package.json" not in json.dumps(j)
    assert j["container_files"] == ["Dockerfile"] and j["iac_files"] == ["infra/main.tf"]
    assert j["skipped_links"] == 1 and d.has_lockfiles and not j["truncated"]
    schema.validate({"asset": "a", **j}, "common", "discovery_record")


def test_discovery_bounds_are_reported(tmp_path):
    from sentinel.discovery import discover

    r = tmp_path / "deep"
    p = r
    for i in range(5):
        p = p / f"d{i}"
    p.mkdir(parents=True)
    (p / "x.py").write_text("")
    assert discover(r, max_depth=2).truncated is True
    for i in range(30):
        (r / f"f{i}.py").write_text("")
    assert discover(r, max_entries=10).truncated is True


def test_pin_kind_selects_the_only_acceptable_runner(monkeypatch):
    lim = Limits()
    pod = object()
    monkeypatch.setattr(pm, "available_runner", lambda pin: pod)
    host = _host("s1-macos-seatbelt")
    assert host.runner_for(ActivityClass.S1, lim, kind="container") is pod  # image pin: never Seatbelt
    assert host.runner_for(ActivityClass.S1, lim, kind="native").name == "s1-macos-seatbelt"
    assert host.runner_for(ActivityClass.S2, lim, kind="native") is None  # binaries never run unconfined
    assert host.runner_for(ActivityClass.S2, lim, kind="container") is pod
    assert host.runner_for(ActivityClass.B2, lim, kind="container") is None
    monkeypatch.setattr(pm, "available_runner", lambda pin: None)
    assert host.runner_for(ActivityClass.S1, lim, kind="container") is None
    assert _host(None).runner_for(ActivityClass.S1, lim, kind="native") is None


def test_cancel_kills_the_client_and_force_removes_the_container(tmp_path):
    import threading

    log = tmp_path / "calls.log"
    archive, image_id = write_archive(tmp_path)
    script = f"""#!/bin/sh
echo "$@" >> {log}
[ "$1" = "--connection" ] && shift 2
case "$1" in
  image) echo sha256:{image_id} ;;
  save) cat {archive} ;;
  volume) [ "$2" = import ] && cat > /dev/null; exit 0 ;;
  run) sleep 300 ;;
  rm) exit 0 ;;
esac
"""
    p = tmp_path / "podman"
    p.write_text(script)
    p.chmod(0o755)
    pin = RuntimePin(p, hashlib.sha256(p.read_bytes()).hexdigest(), f"x/busybox@{DIGEST}", "m")
    runner = pm.PodmanRunner(pin, workspaces=tmp_path / "ws")
    ev = threading.Event()

    def cancel_once_started() -> None:
        from sentinel import controls

        controls.wait_until(lambda: log.exists() and "run" in log.read_text(), 30)
        ev.set()

    threading.Thread(target=cancel_once_started, daemon=True).start()
    t = tmp_path / "t"
    t.mkdir()
    res = runner.run(f"x/y@{DIGEST}", ["scan"], target_root=t, timeout_s=300, max_output=1000, cancel=ev)
    assert res.run.cancelled and res.workspace_removed
    calls = [c.removeprefix("--connection m ") for c in log.read_text().splitlines()]
    name = next(c.split("--name ")[1].split()[0] for c in calls if c.startswith("run"))
    assert any(c.startswith("rm --force") and name in c for c in calls)
