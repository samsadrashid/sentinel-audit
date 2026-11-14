"""D-72: the MobSF 4.6.4 adapter. Unit tests with a fake runner; the real run is in test_mobsf_real.py."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from sentinel import mobsf
from sentinel.adapters.base import BoundedRun
from sentinel.adapters.mobsf import MobsfAdapter
from sentinel.domain.enums import ActivityClass, CheckStatus
from sentinel.errors import BlockedError
from sentinel.isolation import HostCapabilities
from sentinel.isolation import b2 as b2iso
from sentinel.scanner_pins import parse as parse_pins

GOOD = {
    "tool": "mobsf",
    "findings": [
        {"level": "high", "section": "manifest", "title": "Debug Enabled", "description": "debuggable=true"},
        {"level": "warning", "section": "code", "title": "Weak Hash", "description": "MD5 used"},
        {"level": "hotspot", "section": "permissions", "title": "Camera", "description": "review"},
    ],
    "security_score": 40,
    "truncated": False,
    "stage_errors": [],
}


class FakeMobsf:
    name = "mobsf-podman-share-free"

    def __init__(self, out: bytes, rc: int = 0, *, timed_out: bool = False, truncated: bool = False):
        self.out, self.rc, self.timed_out, self.truncated, self.calls = out, rc, timed_out, truncated, []
        self.pin = type("P", (), {"image_id": "sha256:" + "c" * 64})()

    def run(self, program, argv, data, *, timeout_s, max_output):  # type: ignore[no-untyped-def]
        self.calls.append((program, argv, data))
        return b2iso.B2Run(BoundedRun(self.rc, self.out, self.timed_out, self.truncated, 7), self.name)


def app(tmp: Path) -> Path:
    (tmp / "build").mkdir(parents=True)
    (tmp / "build" / "app.apk").write_bytes(b"PK\x03\x04apk")
    (tmp / "App.ipa").write_bytes(b"PK\x03\x04ipa")
    (tmp / "AndroidManifest.xml").write_text("<manifest/>")
    return tmp


def test_plans_only_built_artifacts_never_source_trees_or_symlinks(tmp_path):
    a = MobsfAdapter()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "AndroidManifest.xml").write_text("<manifest/>")
    (tmp_path / "src" / "Info.plist").write_text("<plist/>")
    assert a.plan(tmp_path / "src") == []
    root = app(tmp_path / "t")
    (root / "evil.apk").symlink_to("/etc/hosts")
    plan = a.plan(root)
    assert sorted(Path(t).name for t in plan[0].targets) == ["App.ipa", "app.apk"]
    with pytest.raises(BlockedError):
        a.validate_scope([type(plan[0])("mobile.mobsf", (str(root / "evil.apk"),))], root)
    with pytest.raises(BlockedError):
        a.validate_scope([type(plan[0])("mobile.mobsf", ("/etc/hosts",))], root)


def test_streams_each_artifact_on_stdin_and_maps_the_scorecard(tmp_path):
    root = app(tmp_path)
    a = MobsfAdapter()
    runner = FakeMobsf(json.dumps(GOOD).encode())
    res = a.execute(a.plan(root)[0], root, 60, 1 << 20, runner=runner)
    assert res.status == CheckStatus.FAIL and res.isolation == "mobsf-podman-share-free"
    program, digest = mobsf.program()
    assert res.binary_sha256 == digest and res.scanner_version == "4.6.4"
    assert res.notes["mobsf_image_id"] == "sha256:" + "c" * 64 and "D-72" in res.notes["risk_acceptance"]
    assert [(c[1][1], c[2]) for c in runner.calls] == [("ipa", b"PK\x03\x04ipa"), ("apk", b"PK\x03\x04apk")]
    assert all(c[0] == program for c in runner.calls)
    sev = {(f["rule"], f["file"]): f["severity"] for f in res.findings}
    assert sev[("mobsf.manifest.debug-enabled", "build/app.apk")] == "high"
    assert sev[("mobsf.code.weak-hash", "App.ipa")] == "medium"
    assert sev[("mobsf.permissions.camera", "App.ipa")] == "low"


def test_clean_scorecard_is_pass(tmp_path):
    root = app(tmp_path)
    a = MobsfAdapter()
    clean = json.dumps({**GOOD, "findings": []}).encode()
    assert a.execute(a.plan(root)[0], root, 60, 1 << 20, runner=FakeMobsf(clean)).status == CheckStatus.PASS


@pytest.mark.parametrize(
    "runner, reason",
    [
        (None, "host_isolation_unavailable"),
        (type("R", (), {"name": "b2-podman-share-free"})(), "host_isolation_unavailable"),
        (type("R", (), {"name": "podman-rootless"})(), "host_isolation_unavailable"),
    ],
)
def test_only_the_mobsf_share_free_runner_is_accepted(tmp_path, runner, reason):
    root = app(tmp_path)
    a = MobsfAdapter()
    res = a.execute(a.plan(root)[0], root, 60, 1 << 20, runner=runner)
    assert res.status == CheckStatus.NOT_RUN and res.reason == reason


@pytest.mark.parametrize(
    "out, kw, reason",
    [
        (b"not json", {}, "bad_output"),
        (json.dumps({"tool": "other", "findings": []}).encode(), {}, "bad_output"),
        (json.dumps({**GOOD, "truncated": True}).encode(), {}, "bad_output"),
        (json.dumps({**GOOD, "stage_errors": ["Decompiling to Java with jadx"]}).encode(), {}, "bad_output"),
        (json.dumps({k: v for k, v in GOOD.items() if k != "stage_errors"}).encode(), {}, "bad_output"),
        (json.dumps({**GOOD, "findings": [{"level": "high"}]}).encode(), {}, "bad_output"),
        (
            json.dumps({**GOOD, "findings": [{**GOOD["findings"][0], "level": "critical"}]}).encode(),
            {},
            "bad_output",
        ),
        (json.dumps({"tool": "mobsf", "error": "scan_500"}).encode(), {"rc": 3}, "exit_3: scan_500"),
        (json.dumps({"tool": "mobsf", "error": "x; rm -rf"}).encode(), {"rc": 3}, "exit_3"),
        (b"", {"timed_out": True}, "timeout"),
        (b"", {"truncated": True}, "output_limit"),
    ],
)
def test_fails_closed_on_any_bad_run(tmp_path, out, kw, reason):
    root = app(tmp_path)
    a = MobsfAdapter()
    res = a.execute(a.plan(root)[0], root, 60, 1 << 20, runner=FakeMobsf(out, **kw))
    assert res.status == CheckStatus.ERROR and res.reason.startswith(reason), res.reason
    if reason == "exit_3":
        assert res.reason == "exit_3"
    assert res.findings == []


def test_oversized_artifact_is_refused_before_any_run(tmp_path, monkeypatch):
    root = app(tmp_path)
    monkeypatch.setattr(mobsf, "MAX_ARTIFACT_BYTES", 4)
    runner = FakeMobsf(json.dumps(GOOD).encode())
    res = MobsfAdapter().execute(MobsfAdapter().plan(root)[0], root, 60, 1 << 20, runner=runner)
    assert res.status == CheckStatus.ERROR and res.reason.startswith("artifact_too_large")
    assert runner.calls == []


def test_container_args_have_no_mounts_and_full_hardening():
    args = b2iso.b2_args("n", "sha256:" + "a" * 64, "print(1)", ["1", "apk"], b2iso.MOBSF_PROFILE)
    joined = " ".join(args)
    assert "--volume" not in joined and "--mount" not in joined and " -v " not in joined
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pull=never",
        "--interactive",
        "--user=9901:9901",
        "--memory=3584m",
    ):
        assert flag in args
    assert args[args.index("--entrypoint=python3") + 2 : args.index("--entrypoint=python3") + 4] == [
        "-I",
        "-c",
    ]


def test_runner_selection_is_b2_class_and_pin_only():
    pins = parse_pins(
        {"mobsf": {"machine": "sentinel-b2", "image_id": "sha256:" + "d" * 64}}
    )  # no podman pin → no runner
    host = HostCapabilities("darwin", None, None, None, False)
    assert host.runner_for(ActivityClass.B2, None, pins, "mobsf") is None
    assert host.runner_for(ActivityClass.S2, None, pins, "mobsf") is None
    with pytest.raises(Exception, match="image_id"):
        parse_pins({"mobsf": {"machine": "sentinel-b2", "image_id": "fb61635da56e"}})


def test_driver_is_stdlib_plus_mobsf_and_never_opens_sockets():
    """The in-container driver imports nothing that talks to a network and reads only stdin."""
    tree = ast.parse(mobsf.DRIVER.read_text())
    mods = {
        (n.module if isinstance(n, ast.ImportFrom) else a.name).split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, ast.Import | ast.ImportFrom)
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert mods <= {"io", "json", "logging", "os", "secrets", "sys", "typing", "django", "mobsf"}
    assert not {"socket", "urllib", "http", "ssl", "subprocess"} & mods
    assert '"MOBSF_ASYNC_ANALYSIS": "0"' in mobsf.DRIVER.read_text()


@pytest.mark.parametrize("user", ["0:0", "0:9901", "9901:0", "root", "9901"])
def test_share_free_profiles_never_run_as_root_or_unnumbered(user):
    with pytest.raises(ValueError, match="root"):
        b2iso.Profile("x", "1g", 1, "1m", user)


def test_mobsf_runner_is_offered_only_for_class_b2(monkeypatch):
    calls = []

    def fake(podman, pin, profile):  # type: ignore[no-untyped-def]
        calls.append(profile.name)
        return "RUNNER"

    monkeypatch.setattr(b2iso, "available_runner", fake)
    pins = parse_pins(
        {
            "podman": {
                "path": "/x/podman",
                "sha256": "a" * 64,
                "probe_image": "x/busybox@sha256:" + "b" * 64,
                "machine": "sentinel-b2",
            },
            "mobsf": {"machine": "sentinel-b2", "image_id": "sha256:" + "d" * 64},
        }
    )
    host = HostCapabilities("darwin", None, None, None, False)
    assert host.runner_for(ActivityClass.B2, None, pins, "mobsf") == "RUNNER"
    for cls in (ActivityClass.S1, ActivityClass.S2, ActivityClass.B1, ActivityClass.A1):
        assert host.runner_for(cls, None, pins, "mobsf") is None
    assert calls == ["mobsf-podman-share-free"]


class DamagedImageRunner(FakeMobsf):
    def run(self, program, argv, data, *, timeout_s, max_output):  # type: ignore[no-untyped-def]
        raise b2iso.VolumeError("image_integrity_failed: image_layer_corrupt")


def test_damaged_image_is_not_run_by_mobsf_and_archive_adapters(tmp_path):
    from sentinel.adapters.archive import ArchiveAdapter

    root = app(tmp_path)
    m = MobsfAdapter()
    res = m.execute(m.plan(root)[0], root, 60, 1 << 20, runner=DamagedImageRunner(b""))
    assert res.status == CheckStatus.NOT_RUN and res.reason.startswith("image_integrity_failed")
    a = ArchiveAdapter()
    runner = DamagedImageRunner(b"")
    runner.name = "b2-podman-share-free"
    res = a.execute(a.plan(root)[0], root, 60, 1 << 20, runner=runner)
    assert res.status == CheckStatus.NOT_RUN and res.reason.startswith("image_integrity_failed")


def test_share_free_probe_and_run_refuse_a_damaged_image(monkeypatch):
    from sentinel.scanner_pins import B2Pin, RuntimePin

    r = b2iso.B2Runner(
        RuntimePin(Path("/bin/sh"), "0" * 64, "x@sha256:" + "0" * 64, "sentinel-b2"),
        B2Pin("sentinel-b2", "sha256:" + "c" * 64),
        b2iso.MOBSF_PROFILE,
    )
    monkeypatch.setattr(r, "precondition", lambda: None)
    seen = []
    monkeypatch.setattr(
        b2iso, "verify_image_layers", lambda path, conn, image: seen.append(image) or "image_layer_corrupt"
    )
    p = r.probe()
    assert not p.available and p.reason == "image_integrity_failed: image_layer_corrupt"
    with pytest.raises(b2iso.VolumeError, match="image_integrity_failed"):
        r.run("print(1)", [], b"", timeout_s=5, max_output=10)
    assert seen == ["sha256:" + "c" * 64] * 2
