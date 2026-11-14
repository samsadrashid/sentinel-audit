"""B2 archive inspection (D-25, D-35, D-70): unpacker rules, AXML decoding, adapter fail-closed behaviour.

The unpacker runs in-process here on synthetic archives. Its real execution in the share-free Podman
machine is tested by tests/test_b2_real.py, which skips (never passes) when that machine isn't active.
"""

# ruff: noqa: E501
from __future__ import annotations

import io
import json
import plistlib
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from sentinel import b2
from sentinel.adapters.archive import ArchiveAdapter
from sentinel.adapters.base import BoundedRun
from sentinel.domain.enums import CheckStatus
from sentinel.errors import BlockedError
from sentinel.isolation import b2 as b2iso

sys.path[:0] = [str(b2.ANALYZERS), str(b2.HERE)]
import axml  # noqa: E402
import unpack  # noqa: E402

ANDROID = "http://schemas.android.com/apk/res/android"


# ── a minimal AXML encoder (test only) ─────────────────────────────────────
def axml_doc(root: tuple) -> bytes:  # type: ignore[type-arg]
    """root = (tag, {attr: value}, [children]); attr values: str, bool or int; attrs are android:-namespaced."""
    strings: list[str] = []

    def s(x: str) -> int:
        if x not in strings:
            strings.append(x)
        return strings.index(x)

    s(ANDROID), s("android")
    body = b""

    def elem(node) -> bytes:  # type: ignore[no-untyped-def]
        tag, attrs, kids = node
        out = b""
        ab = b""
        for k, v in attrs.items():
            if isinstance(v, bool):
                raw, dtype, data = -1, 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                raw, dtype, data = -1, 0x10, v
            else:
                raw, dtype, data = s(v), 0x03, s(v)
            ab += struct.pack("<iiiHBBI", s(ANDROID), s(k), raw, 8, 0, dtype, data)
        ext = struct.pack("<iiHHHHHH", -1, s(tag), 20, 20, len(attrs), 0, 0, 0)
        out += struct.pack("<HHIII", 0x0102, 16, 16 + len(ext) + len(ab), 1, 0xFFFFFFFF) + ext + ab
        for k in kids:
            out += elem(k)
        out += struct.pack("<HHIIIii", 0x0103, 16, 24, 1, 0xFFFFFFFF, -1, s(tag))
        return out

    ns_start = struct.pack("<HHIIIii", 0x0100, 16, 24, 1, 0xFFFFFFFF, 1, 0)
    elements = elem(root)
    ns_end = struct.pack("<HHIIIii", 0x0101, 16, 24, 1, 0xFFFFFFFF, 1, 0)
    data = b""
    offsets = []
    for x in strings:
        offsets.append(len(data))
        enc = x.encode("utf-16-le")
        data += struct.pack("<H", len(x)) + enc + b"\0\0"
    while len(data) % 4:
        data += b"\0"
    hdr = 28
    pool = (
        struct.pack("<IIIII", len(strings), 0, 0, hdr + 4 * len(strings), 0)
        + struct.pack(f"<{len(strings)}I", *offsets)
        + data
    )
    pool = struct.pack("<HHI", 0x0001, hdr, 8 + len(pool)) + pool
    body = pool + ns_start + elements + ns_end
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


MANIFEST = (
    "manifest",
    {"package": "com.example.app"},
    [
        ("uses-permission", {"name": "android.permission.READ_SMS"}, []),
        (
            "application",
            {"debuggable": True, "allowBackup": True, "usesCleartextTraffic": True},
            [("provider", {"name": ".Data", "exported": True}, [])],
        ),
    ],
)
SAFE_MANIFEST = ("manifest", {"package": "com.example.safe"}, [("application", {"allowBackup": False}, [])])


def zbytes(
    entries: list[tuple[str, bytes]], *, method: int = zipfile.ZIP_DEFLATED, symlink: str | None = None
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for name, data in entries:
            z.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = 0o120777 << 16
            z.writestr(info, "/etc/passwd")
    return buf.getvalue()


def run(data: bytes, tmp_path: Path, name: str = "app.apk") -> dict:  # type: ignore[type-arg]
    w = tmp_path / "work" / "x"
    w.mkdir(parents=True, exist_ok=True)
    return unpack.inspect(data, name, w)


def rules(res: dict) -> set[str]:  # type: ignore[type-arg]
    return {f["rule"] for f in res["findings"]}


# ── AXML ──────────────────────────────────────────────────────────────────
def test_axml_decodes_to_parseable_android_xml():
    text = axml.decode(axml_doc(MANIFEST))
    assert 'android:debuggable="true"' in text and 'android:name="android.permission.READ_SMS"' in text
    import xml.etree.ElementTree as ET

    root = ET.fromstring(text)
    assert root.tag == "manifest" and root.find("application") is not None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:20],
        lambda b: b"\x00\x00" + b[2:],
        lambda b: b[:8] + b"\xff" * 8 + b[16:],
        lambda b: b[:-24],  # missing end element -> unbalanced
        lambda b: struct.pack("<HHI", 3, 8, 10**9) + b[8:],
    ],
)
def test_malformed_axml_raises_value_error(mutate):
    with pytest.raises((ValueError, struct.error)):
        axml.decode(mutate(axml_doc(MANIFEST)))


# ── APK / IPA analysis ────────────────────────────────────────────────────
def test_apk_manifest_is_decoded_and_analysed(tmp_path):
    res = run(
        zbytes([("AndroidManifest.xml", axml_doc(MANIFEST)), ("classes.dex", b"dex\n035" + b"\0" * 100)]),
        tmp_path,
    )
    r = rules(res)
    assert {"debuggable", "cleartext-traffic", "exported-provider-unprotected", "dangerous-permission"} <= r
    assert all(f["file"].startswith("app.apk!/") for f in res["findings"])
    assert res["summary"]["analysed"] is True and res["summary"]["entries"] == 2


def test_clean_apk_has_no_manifest_findings(tmp_path):
    res = run(zbytes([("AndroidManifest.xml", axml_doc(SAFE_MANIFEST))]), tmp_path)
    assert not rules(res) & {"debuggable", "cleartext-traffic", "allow-backup"}


def test_ipa_plist_and_provisioning_entitlements_are_analysed(tmp_path):
    info = plistlib.dumps(
        {"CFBundleName": "App", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
        fmt=plistlib.FMT_BINARY,
    )
    prof = b"\x30\x82junk" + plistlib.dumps({"Entitlements": {"get-task-allow": True}}) + b"\x00sig"
    res = run(
        zbytes([("Payload/App.app/Info.plist", info), ("Payload/App.app/embedded.mobileprovision", prof)]),
        tmp_path,
        "app.ipa",
    )
    assert {"ats-arbitrary-loads", "get-task-allow"} <= rules(res)
    assert "missing-privacy-manifest" not in rules(res)


# ── D-25 / D-35 rejection rules ───────────────────────────────────────────
BOMB = b"\0" * (4 << 20)


@pytest.mark.parametrize(
    "data, rule",
    [
        (b"MZ not an archive", "archive-unsupported-format"),
        (b"PK\x03\x04garbage", "archive-malformed"),
        (zbytes([("../../etc/evil", b"x")]), "archive-path-traversal"),
        (zbytes([("/abs/evil", b"x")]), "archive-path-traversal"),
        (zbytes([("C:/evil", b"x")]), "archive-path-traversal"),
        (zbytes([("a\\..\\b", b"x")]), "archive-bad-entry-name"),
        (zbytes([("/".join(["d"] * 40) + "/f", b"x")]), "archive-path-too-deep"),
        (zbytes([("a.txt", b"1"), ("A.TXT", b"2")]), "archive-duplicate-entry"),
        (zbytes([("ok", b"x")], symlink="link"), "archive-symlink-entry"),
        (zbytes([("bomb.bin", BOMB)]), "archive-compression-bomb"),
    ],
)
def test_unsafe_archives_are_rejected_and_not_analysed(tmp_path, data, rule):
    res = run(data, tmp_path)
    assert rule in rules(res) and "archive-not-analysed" in rules(res)
    assert res["summary"]["analysed"] is False
    assert not (tmp_path / "work" / "etc").exists() and not (tmp_path.parent / "evil").exists()


def test_entry_count_total_size_and_largest_file_limits(tmp_path, monkeypatch):
    monkeypatch.setitem(unpack.LIMITS, "max_entries", 3)
    assert "archive-too-many-entries" in rules(run(zbytes([(f"f{i}", b"x") for i in range(4)]), tmp_path))
    monkeypatch.setitem(unpack.LIMITS, "max_entries", 10_000)
    monkeypatch.setitem(unpack.LIMITS, "max_file_bytes", 10)
    assert "archive-entry-too-large" in rules(
        run(zbytes([("f", b"x" * 11)], method=zipfile.ZIP_STORED), tmp_path)
    )
    monkeypatch.setitem(unpack.LIMITS, "max_file_bytes", 256 << 20)
    monkeypatch.setitem(unpack.LIMITS, "max_total_bytes", 15)
    assert "archive-too-large-expanded" in rules(
        run(zbytes([("a", b"x" * 8), ("b", b"y" * 8)], method=zipfile.ZIP_STORED), tmp_path)
    )
    monkeypatch.setitem(unpack.LIMITS, "max_artifact_bytes", 10)
    assert "archive-too-large" in rules(run(zbytes([("a", b"x")]), tmp_path))


def test_declared_size_mismatch_is_rejected(tmp_path):
    data = bytearray(zbytes([("f.txt", b"hello world")], method=zipfile.ZIP_STORED))
    # lower the declared uncompressed size in both the local header and the central directory
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = data.find(sig)
        off = 22 if sig == b"PK\x03\x04" else 24
        struct.pack_into("<I", data, i + off, 5)
    res = run(bytes(data), tmp_path)
    assert {"archive-size-mismatch", "archive-malformed"} & rules(res) and res["summary"]["analysed"] is False


def test_encrypted_entry_is_rejected(tmp_path):
    data = bytearray(zbytes([("f.txt", b"x")], method=zipfile.ZIP_STORED))
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = data.find(sig)
        struct.pack_into("<H", data, i + off, 1)
    assert "archive-encrypted-entry" in rules(run(bytes(data), tmp_path))


def test_nested_archives_are_counted_not_unpacked(tmp_path):
    inner = zbytes([("AndroidManifest.xml", axml_doc(MANIFEST))])
    res = run(zbytes([("base/inner.apk", inner)]), tmp_path, "app.aab")
    assert "archive-nested-not-unpacked" in rules(res) and "debuggable" not in rules(res)


def test_undecodable_manifest_is_explicitly_unparseable(tmp_path):
    res = run(zbytes([("AndroidManifest.xml", b"\x03\x00\x08\x00\xff\xff\xff\xff")]), tmp_path)
    assert ("input-unparseable", "app.apk!/AndroidManifest.xml") in {
        (f["rule"], f["file"]) for f in res["findings"]
    }


# ── bundled program, adapter and runner ───────────────────────────────────
def test_bundled_program_runs_standalone_from_stdin_only(tmp_path):
    prog, digest = b2.program()
    assert len(prog.encode()) <= b2.MAX_PROGRAM and len(digest) == 64
    data = zbytes([("AndroidManifest.xml", axml_doc(MANIFEST))])
    r = subprocess.run(
        [sys.executable, "-I", "-c", prog, "app.apk"],
        input=data,
        capture_output=True,
        env={"B2_WORK": str(tmp_path)},
        cwd=tmp_path,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["tool"] == "archive" and "debuggable" in {f["rule"] for f in out["findings"]}


def test_b2_container_args_have_no_mounts_and_full_hardening():
    args = b2iso.b2_args("n", "sha256:" + "a" * 64, "print(1)", ["x.apk"])
    joined = " ".join(args)
    assert "--volume" not in joined and "--mount" not in joined and " -v " not in joined
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pull=never",
        "--user=65534:65534",
        "--interactive",
    ):
        assert flag in args
    assert any(a.startswith("--tmpfs=/work:") and "noexec" in a for a in args)


class FakeB2:
    name = "b2-podman-share-free"

    def __init__(self, out: bytes, rc: int = 0):
        self.out, self.rc, self.calls = out, rc, []
        self.pin = type("P", (), {"image_id": "sha256:" + "b" * 64})()

    def run(self, program, argv, data, *, timeout_s, max_output):  # type: ignore[no-untyped-def]
        self.calls.append((argv, len(data)))
        return b2iso.B2Run(BoundedRun(self.rc, self.out, False, False, 5), self.name)


def test_adapter_plans_only_artifacts_and_refuses_symlinks(tmp_path):
    a = ArchiveAdapter()
    (tmp_path / "x.txt").write_text("x")
    assert a.plan(tmp_path) == []
    (tmp_path / "app.apk").write_bytes(b"PK")
    (tmp_path / "evil.ipa").symlink_to("/etc/hosts")
    plan = a.plan(tmp_path)
    assert [Path(t).name for t in plan[0].targets] == ["app.apk"]
    with pytest.raises(BlockedError):
        a.validate_scope([type(plan[0])("b2.archive", (str(tmp_path / "evil.ipa"),))], tmp_path)


def test_adapter_fails_closed(tmp_path):
    a = ArchiveAdapter()
    (tmp_path / "app.apk").write_bytes(zbytes([("AndroidManifest.xml", axml_doc(MANIFEST))]))
    plan = a.plan(tmp_path)[0]
    assert a.execute(plan, tmp_path, 10, 1 << 20, runner=None).reason == "host_isolation_unavailable"
    wrong = type("R", (), {"name": "podman-rootless"})()
    assert a.execute(plan, tmp_path, 10, 1 << 20, runner=wrong).status == CheckStatus.NOT_RUN
    assert a.execute(plan, tmp_path, 10, 1 << 20, runner=FakeB2(b"not json")).status == CheckStatus.ERROR
    assert a.execute(plan, tmp_path, 10, 1 << 20, runner=FakeB2(b"{}", rc=2)).reason == "exit_2"
    bad_line = json.dumps(
        {
            "tool": "archive",
            "findings": [{"rule": "r", "file": "f", "line": [], "message": "m", "severity": "low"}],
        }
    ).encode()
    assert a.execute(plan, tmp_path, 10, 1 << 20, runner=FakeB2(bad_line)).status == CheckStatus.ERROR


def test_adapter_success_records_provenance(tmp_path):
    a = ArchiveAdapter()
    (tmp_path / "app.apk").write_bytes(b"PK")
    out = json.dumps(
        {
            "tool": "archive",
            "findings": [
                {
                    "rule": "debuggable",
                    "file": "app.apk!/AndroidManifest.xml",
                    "line": 0,
                    "message": "m",
                    "severity": "high",
                }
            ],
            "summary": {},
        }
    ).encode()
    r = FakeB2(out)
    res = a.execute(a.plan(tmp_path)[0], tmp_path, 10, 1 << 20, runner=r)
    assert res.status == CheckStatus.FAIL and res.findings[0]["rule"] == "archive.debuggable"
    assert res.isolation == "b2-podman-share-free" and res.notes["b2_program_sha256"] == b2.program()[1]
    assert r.calls == [(["app.apk"], 2)]


def test_host_gives_b2_only_to_b2_and_never_a_fallback():
    from sentinel.domain.enums import ActivityClass
    from sentinel.isolation import detect
    from sentinel.policy import default_policy

    h, pol = detect(), default_policy()
    assert h.runner_for(ActivityClass.B2, pol.limits, pol.pins, "b2") is None  # default policy has no b2 pin
    assert h.runner_for(ActivityClass.B2, pol.limits, pol.pins, "container") is None
    assert h.runner_for(ActivityClass.B2, pol.limits, pol.pins, "native") is None
    assert h.runner_for(ActivityClass.S1, pol.limits, pol.pins, "b2") is None


def test_precondition_refuses_a_vm_with_host_shares(monkeypatch):
    from sentinel.scanner_pins import B2Pin, RuntimePin

    r = b2iso.B2Runner(
        RuntimePin(Path("/bin/sh"), "0" * 64, "x@sha256:" + "0" * 64),
        B2Pin("sentinel-b2", "sha256:" + "c" * 64),
    )
    monkeypatch.setattr(b2iso, "verify_binary", lambda p, h: None)
    calls = []

    def fake(args, timeout=60):  # type: ignore[no-untyped-def]
        calls.append(args)
        if args[:2] == ["machine", "list"]:
            return subprocess.CompletedProcess(
                args, 0, json.dumps([{"Name": "sentinel-b2", "Running": True}]), ""
            )
        if args[:2] == ["machine", "ssh"]:
            return subprocess.CompletedProcess(
                args, 0, "proc /proc proc rw 0 0\nvfsd /Users virtiofs rw 0 0\n", ""
            )
        raise AssertionError(args)

    monkeypatch.setattr(r, "_client", fake)
    assert r.precondition() == "b2_host_share_present"
    monkeypatch.setattr(
        r,
        "_client",
        lambda args, timeout=60: subprocess.CompletedProcess(
            args, 0, json.dumps([{"Name": "sentinel-b2", "Running": False}]), ""
        ),
    )
    assert r.precondition() == "b2_machine_not_active"


def test_every_default_adapter_supports_the_run_manifest_interface():
    """Regression: the run manifest calls detect() on every adapter; a default audit must not crash."""
    from sentinel import cli
    from sentinel.policy import default_policy

    for a in cli.default_adapters(default_policy()):
        ok, version, ident = a.detect()
        assert isinstance(ok, bool) and isinstance(version, str) and isinstance(ident, str), a
        for attr in ("plan", "execute", "validate_scope", "health", "manifest"):
            assert hasattr(a, attr), (a, attr)


def test_precondition_refuses_a_wrong_image_id(monkeypatch):
    from sentinel.scanner_pins import B2Pin, RuntimePin

    r = b2iso.B2Runner(
        RuntimePin(Path("/bin/sh"), "0" * 64, "x@sha256:" + "0" * 64),
        B2Pin("sentinel-b2", "sha256:" + "c" * 64),
    )
    monkeypatch.setattr(b2iso, "verify_binary", lambda p, h: None)

    def fake(args, timeout=60):  # type: ignore[no-untyped-def]
        if args[:2] == ["machine", "list"]:
            return subprocess.CompletedProcess(
                args, 0, json.dumps([{"Name": "sentinel-b2", "Running": True}]), ""
            )
        if args[:2] == ["machine", "ssh"]:
            return subprocess.CompletedProcess(
                args, 0, "proc /proc proc rw 0 0\noverlay / overlay rw 0 0\n", ""
            )
        if "info" in args:
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"host": {"security": {"rootless": True}}}), ""
            )
        if "inspect" in args:
            return subprocess.CompletedProcess(args, 0, "d" * 64 + "\n", "")  # a different image
        raise AssertionError(args)

    monkeypatch.setattr(r, "_client", fake)
    assert r.precondition() == "b2_image_missing"


def test_only_class_b2_can_obtain_the_b2_runner(monkeypatch):
    from sentinel.domain.enums import ActivityClass
    from sentinel.isolation import detect
    from sentinel.policy import default_policy

    token = object()
    monkeypatch.setattr(b2iso, "available_runner", lambda podman, pin: token)
    h, pol = detect(), default_policy()
    assert h.runner_for(ActivityClass.B2, pol.limits, pol.pins, "b2") is token
    for cls in (ActivityClass.S1, ActivityClass.S2, ActivityClass.B1, ActivityClass.A1):
        assert h.runner_for(cls, pol.limits, pol.pins, "b2") is None


def test_per_entry_ratio_bomb_inside_a_mostly_incompressible_archive(tmp_path):
    """One 1000:1 entry next to incompressible data: whole-archive ratio < 50, per-entry ratio > 100."""
    import os

    data = zbytes([("noise.bin", os.urandom(400_000)), ("bomb.bin", b"\0" * (4 << 20))])
    assert len(data) * 50 > 400_000 + (4 << 20)  # the whole-archive rule alone would not trigger
    res = run(data, tmp_path)
    assert any("bomb.bin" in f["message"] for f in res["findings"] if f["rule"] == "archive-compression-bomb")


def test_declared_size_larger_than_actual_is_rejected(tmp_path):
    data = bytearray(zbytes([("f.txt", b"hello world")], method=zipfile.ZIP_STORED))
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        i = data.find(sig)
        struct.pack_into("<I", data, i + off, 20)  # declares 20 bytes; the stored data has 11
    res = run(bytes(data), tmp_path)
    assert "archive-size-mismatch" in rules(res), rules(res)
