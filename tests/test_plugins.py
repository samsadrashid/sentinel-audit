"""M6 plugin ecosystem: pinning, compatibility, capability refusal, isolation and failure isolation."""

# ruff: noqa: E501 - embedded analyzer and plugin sources are test data

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sentinel import __version__, plugins, schema
from sentinel.domain.enums import CheckStatus
from sentinel.errors import ValidationError
from sentinel.isolation import sandbox

GOOD = """import json, os, sys
root = sys.argv[1]
out = []
for dp, dn, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f)
        with open(p, errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if "SECURITY-TODO" in line:
                    out.append({"rule": "todo", "file": os.path.relpath(p, root), "line": i, "message": "open security TODO", "severity": "low"})
print(json.dumps({"tool": "todo-scan", "findings": out}))
"""
HOSTILE = """import json, os, socket, sys
root = sys.argv[1]
obs = {}
def t(name, fn):
    try:
        fn(); obs[name] = "allowed"
    except OSError:
        obs[name] = "denied"
t("write_target", lambda: open(os.path.join(root, "pwned"), "w").write("x"))
t("network", lambda: socket.create_connection(("1.1.1.1", 80), timeout=2))
t("read_home", lambda: open(os.path.expanduser("~/.ssh/known_hosts")).read())
print(json.dumps({"tool": "hostile", "findings": [{"rule": k + "-" + v, "file": "-", "line": 0, "message": k, "severity": "low"} for k, v in sorted(obs.items())]}))
"""


def make_plugin(base: Path, name: str, source: str = GOOD, **over: object) -> tuple[Path, str]:
    d = base / name
    d.mkdir(parents=True)
    (d / "plugin.py").write_text(source)
    manifest = {
        "name": name,
        "version": "1.2.3",
        "api": "sentinel-plugin/1",
        "entry": "plugin.py",
        "entry_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "activity_class": "S1",
        "permissions": {"network": False, "filesystem_write": False, "execute_target": False},
        "min_sentinel": "0.1.0",
        "max_sentinel": "9.0.0",
        "description": "test plugin",
        "licence": "MIT",
        **over,
    }
    (d / "sentinel-plugin.json").write_text(json.dumps(manifest))
    return d, hashlib.sha256((d / "sentinel-plugin.json").read_bytes()).hexdigest()


def adapter(d: Path, digest: str) -> plugins.PluginAdapter:
    return plugins.PluginAdapter(plugins.PluginPin(d.name, d, digest))


def target(tmp: Path) -> Path:
    t = tmp / "target"
    t.mkdir()
    (t / "a.py").write_text("x = 1  # SECURITY-TODO validate input\n")
    return t


def test_valid_plugin_inspects_and_its_pin_parses(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    info = plugins.inspect(d)
    assert info["valid"] and info["manifest_sha256"] == digest and info["refusal"] is None
    pins = plugins.parse_pins({"plugins": {"todo-scan": {"path": str(d), "manifest_sha256": digest}}})
    assert pins["todo-scan"].manifest_sha256 == digest
    schema.validate({"plugins": {"todo-scan": {"path": str(d), "manifest_sha256": digest}}}, "policy")


@pytest.mark.parametrize(
    "over, reason",
    [
        (
            {"permissions": {"network": True, "filesystem_write": False, "execute_target": False}},
            "plugin_permission_denied",
        ),
        (
            {"permissions": {"network": False, "filesystem_write": True, "execute_target": False}},
            "plugin_permission_denied",
        ),
        ({"permissions": {"network": False}}, "plugin_permission_denied"),
        ({"api": "sentinel-plugin/2"}, "plugin_incompatible_api"),
        ({"activity_class": "A1"}, "plugin_activity_class_denied"),
        ({"min_sentinel": "9.0.0", "max_sentinel": "9.9.9"}, "plugin_version_incompatible"),
        ({"entry_sha256": "0" * 64}, "plugin_entry_hash_mismatch"),
        ({"entry": "../escape.py"}, "plugin_manifest_invalid"),
        ({"extra": 1}, "plugin_manifest_invalid"),
    ],
)
def test_manifests_that_ask_for_more_are_refused_not_downgraded(tmp_path, over, reason):
    d, digest = make_plugin(tmp_path, "plug", **over)
    a = adapter(d, digest)
    res = a.execute(a.plan(target(tmp_path))[0], tmp_path / "target", 10, 1 << 20, runner=object())
    assert res.status == CheckStatus.NOT_RUN and res.reason == reason


def test_manifest_and_entry_tampering_after_pinning(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    t = target(tmp_path)
    (d / "sentinel-plugin.json").write_text(
        (d / "sentinel-plugin.json").read_text().replace("test plugin", "changed")
    )
    res = adapter(d, digest).execute(adapter(d, digest).plan(t)[0], t, 10, 1 << 20, runner=object())
    assert res.reason == "plugin_manifest_hash_mismatch"
    d2, digest2 = make_plugin(tmp_path, "other")
    (d2 / "plugin.py").write_text(GOOD + "\n# changed\n")
    res = adapter(d2, digest2).execute(adapter(d2, digest2).plan(t)[0], t, 10, 1 << 20, runner=object())
    assert res.reason == "plugin_entry_hash_mismatch"


def test_unpinned_or_missing_plugins_never_load(tmp_path):
    with pytest.raises(ValidationError):
        plugins.parse_pins({"plugins": {"Bad Name": {"path": "/x", "manifest_sha256": "a" * 64}}})
    with pytest.raises(ValidationError):
        plugins.parse_pins({"plugins": {"ok": {"path": "relative", "manifest_sha256": "a" * 64}}})
    a = adapter(tmp_path / "nope", "a" * 64)
    assert a.execute(a.plan(tmp_path)[0], tmp_path, 10, 1 << 20, runner=object()).reason == "plugin_missing"


def test_plugin_without_isolation_does_not_run(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    t = target(tmp_path)
    res = adapter(d, digest).execute(adapter(d, digest).plan(t)[0], t, 10, 1 << 20, runner=None)
    assert res.status == CheckStatus.NOT_RUN and res.reason == "host_isolation_unavailable"


needs_sandbox = pytest.mark.skipif(
    not sandbox.probe().available, reason="native sandbox unavailable (not a pass)"
)


@needs_sandbox
def test_pinned_plugin_runs_isolated_with_provenance(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    t = target(tmp_path)
    a = adapter(d, digest)
    res = a.execute(
        a.plan(t)[0], t, 60, 1 << 20, runner=sandbox.MacSeatbeltRunner(workspaces=tmp_path / "ws")
    )
    assert res.status == CheckStatus.FAIL and res.isolation == "s1-macos-seatbelt"
    assert res.findings[0]["rule"] == "plugin.todo-scan.todo" and res.scanner_version == "1.2.3"


@needs_sandbox
def test_hostile_plugin_gets_no_network_no_writes_and_no_home(tmp_path):
    d, digest = make_plugin(tmp_path, "hostile", source=HOSTILE)
    t = target(tmp_path)
    before = sorted(p.name for p in t.iterdir())
    a = adapter(d, digest)
    res = a.execute(
        a.plan(t)[0], t, 60, 1 << 20, runner=sandbox.MacSeatbeltRunner(workspaces=tmp_path / "ws")
    )
    got = {f["rule"] for f in res.findings}
    assert got == {
        "plugin.hostile.network-denied",
        "plugin.hostile.read_home-denied",
        "plugin.hostile.write_target-denied",
    }
    assert sorted(p.name for p in t.iterdir()) == before


@needs_sandbox
@pytest.mark.parametrize(
    "entry, reason",
    [
        ("import sys\nsys.exit(3)\n", "exit_3"),
        ("print('not json')\n", "bad_output"),
        ("import json\nprint(json.dumps({'tool': 'someone-else', 'findings': []}))\n", "bad_output"),
        ("import time\ntime.sleep(30)\n", "timeout"),
    ],
)
def test_failing_plugins_are_error_and_never_pass(tmp_path, entry, reason):
    d, digest = make_plugin(tmp_path, "flaky", source=entry)
    t = target(tmp_path)
    a = adapter(d, digest)
    res = a.execute(a.plan(t)[0], t, 2, 1 << 20, runner=sandbox.MacSeatbeltRunner(workspaces=tmp_path / "ws"))
    assert res.status == CheckStatus.ERROR and res.reason.startswith(reason)


def test_cli_inspect(tmp_path, capsys):
    from sentinel import cli

    from .test_cli import deps  # noqa: F401

    d, digest = make_plugin(tmp_path, "todo-scan")
    assert cli.main(["--json", "plugin", "inspect", str(d)], cli.Deps(env={})) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["manifest_sha256"] == digest and out["valid"] is True
    bad, _ = make_plugin(
        tmp_path, "net", permissions={"network": True, "filesystem_write": False, "execute_target": False}
    )
    assert cli.main(["--json", "plugin", "inspect", str(bad)], cli.Deps(env={})) == cli.EXIT_INVALID


def test_version_window_uses_the_running_version():
    assert plugins._ver(__version__) >= (0, 1, 0)


@pytest.mark.parametrize("line", ["[]", "1e999", '"x"', "-1", "{}", "null"])
def test_malformed_finding_fields_are_check_errors_not_engine_crashes(tmp_path, line):
    """Regression (independent verification): hostile output must raise ValueError -> check ERROR."""
    d, digest = make_plugin(tmp_path, "todo-scan")
    raw = (
        '{"tool": "todo-scan", "findings": [{"rule": "r", "file": "f", "line": '
        + line
        + ', "message": "m", "severity": "low"}]}'
    ).encode()
    with pytest.raises(ValueError):
        adapter(d, digest).normalize(raw)


# ── V-6: the verified bytes are the executed bytes ───────────────────────────
SWAPPED = 'import json\nprint(json.dumps({"tool": "todo-scan", "findings": [{"rule": "swapped", "file": "-", "line": 0, "message": "replacement ran", "severity": "high"}]}))\n'


class SwapRunner:
    """Replaces the plugin entry on disk after verification, just before the process starts."""

    def __init__(self, entry: Path, inner=None):  # type: ignore[no-untyped-def]
        self.entry, self.inner, self.calls = entry, inner, []
        self.name = inner.name if inner is not None else "fake"

    def run(self, exe, args, **kw):  # type: ignore[no-untyped-def]
        self.entry.write_text(SWAPPED)
        self.calls.append(list(args))
        if self.inner is None:
            raise AssertionError("stop here")
        return self.inner.run(exe, args, **kw)


def test_swap_after_verification_does_not_change_the_program(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    t = target(tmp_path)
    a = adapter(d, digest)
    r = SwapRunner(d / "plugin.py")
    with pytest.raises(AssertionError):
        a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r)
    args = r.calls[0]
    assert args[:2] == ["-I", "-c"] and args[2] == GOOD and str(d) not in " ".join(args[3:])
    assert (d / "plugin.py").read_text() == SWAPPED  # the swap did happen
    assert a.execute_extra_read() == []  # the plugin directory is not even readable at run time


@needs_sandbox
def test_swap_after_verification_never_executes_the_replacement(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    t = target(tmp_path)
    a = adapter(d, digest)
    r = SwapRunner(d / "plugin.py", sandbox.MacSeatbeltRunner(workspaces=tmp_path / "ws"))
    res = a.execute(a.plan(t)[0], t, 60, 1 << 20, runner=r)
    assert res.status == CheckStatus.FAIL
    assert {f["rule"] for f in res.findings} == {"plugin.todo-scan.todo"}
    # The next run re-verifies and refuses the swapped entry.
    again = a.execute(a.plan(t)[0], t, 60, 1 << 20, runner=r)
    assert again.status == CheckStatus.NOT_RUN and again.reason == "plugin_entry_hash_mismatch"


def test_symlinked_oversized_or_nul_entries_are_refused(tmp_path):
    real = tmp_path / "real.py"
    real.write_text(GOOD)
    d, digest = make_plugin(tmp_path, "linked")
    (d / "plugin.py").unlink()
    (d / "plugin.py").symlink_to(real)
    a = adapter(d, digest)
    assert (
        a.execute(a.plan(tmp_path)[0], tmp_path, 10, 1 << 20, runner=object()).reason
        == "plugin_entry_hash_mismatch"
    )
    big = "#" * (plugins.MAX_ENTRY + 10) + "\n"
    d2, digest2 = make_plugin(tmp_path, "big", source=big)
    a2 = adapter(d2, digest2)
    assert (
        a2.execute(a2.plan(tmp_path)[0], tmp_path, 10, 1 << 20, runner=object()).reason
        == "plugin_entry_too_large"
    )
    d3, digest3 = make_plugin(tmp_path, "nul", source="x = 1\x00\n")
    a3 = adapter(d3, digest3)
    assert (
        a3.execute(a3.plan(tmp_path)[0], tmp_path, 10, 1 << 20, runner=object()).reason
        == "plugin_entry_invalid"
    )


# ── Owner correction A: pin name == verified manifest name ───────────────────
def test_pin_name_must_match_the_verified_manifest_name(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    other = plugins.PluginAdapter(plugins.PluginPin("other-name", d, digest))
    t = target(tmp_path)
    res = other.execute(other.plan(t)[0], t, 10, 1 << 20, runner=object())
    assert res.status == CheckStatus.NOT_RUN and res.reason == "plugin_name_mismatch"
    assert other.health() == ["plugin other-name: plugin_name_mismatch"]


def test_renamed_manifest_with_repinned_hash_still_needs_matching_pin_name(tmp_path):
    d, _ = make_plugin(tmp_path, "todo-scan")
    m = json.loads((d / "sentinel-plugin.json").read_text())
    m["name"] = "evil-scan"
    (d / "sentinel-plugin.json").write_text(json.dumps(m))
    new_digest = hashlib.sha256((d / "sentinel-plugin.json").read_bytes()).hexdigest()
    a = plugins.PluginAdapter(plugins.PluginPin("todo-scan", d, new_digest))
    t = target(tmp_path)
    assert a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=object()).reason == "plugin_name_mismatch"


def test_changed_manifest_after_pinning_is_refused_even_with_same_name(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    m = json.loads((d / "sentinel-plugin.json").read_text())
    m["description"] = "changed"
    (d / "sentinel-plugin.json").write_text(json.dumps(m))
    a = adapter(d, digest)
    t = target(tmp_path)
    assert a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=object()).reason == "plugin_manifest_hash_mismatch"


def test_manifest_swapped_between_runs_uses_fresh_verification(tmp_path):
    d, digest = make_plugin(tmp_path, "todo-scan")
    t = target(tmp_path)
    a = adapter(d, digest)
    r = SwapRunner(d / "plugin.py")
    with pytest.raises(AssertionError):
        a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r)
    m = json.loads((d / "sentinel-plugin.json").read_text())
    m["entry_sha256"] = hashlib.sha256(SWAPPED.encode()).hexdigest()  # attacker re-points the manifest
    (d / "sentinel-plugin.json").write_text(json.dumps(m))
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=r)
    assert res.reason == "plugin_manifest_hash_mismatch"  # the pin still holds the original manifest hash


# ── Mutation survivors: re-verification of the bytes actually executed ─────────────
def _swap_after_manifest_check(monkeypatch, d, new_entry=None, link_to=None):  # type: ignore[no-untyped-def]
    real = plugins.load_manifest

    def racing(*a, **k):  # type: ignore[no-untyped-def]
        out = real(*a, **k)
        e = d / "plugin.py"
        e.unlink()
        if link_to is not None:
            e.symlink_to(link_to)
        else:
            e.write_text(new_entry)
        return out

    monkeypatch.setattr(plugins, "load_manifest", racing)


def test_entry_swapped_between_manifest_check_and_read_is_refused(tmp_path, monkeypatch):
    """eng-t-plug-entry-hash: the bytes read for execution are hashed again; a swap after the
    manifest check never reaches the interpreter."""
    d, digest = make_plugin(tmp_path, "todo-scan")
    _swap_after_manifest_check(monkeypatch, d, new_entry=SWAPPED)
    a = adapter(d, digest)
    t = target(tmp_path)
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=object())
    assert res.status == CheckStatus.NOT_RUN and res.reason == "plugin_entry_hash_mismatch"


def test_entry_replaced_by_symlink_after_manifest_check_is_refused(tmp_path, monkeypatch):
    """eng-t-plug-nofollow: even a symlink to identical bytes is refused at read time."""
    d, digest = make_plugin(tmp_path, "todo-scan")
    same = tmp_path / "same.py"
    same.write_text(GOOD)
    _swap_after_manifest_check(monkeypatch, d, link_to=same)
    a = adapter(d, digest)
    t = target(tmp_path)
    res = a.execute(a.plan(t)[0], t, 10, 1 << 20, runner=object())
    assert res.status == CheckStatus.NOT_RUN and res.reason == "plugin_entry_hash_mismatch"


def test_manifest_hash_is_over_the_bytes_that_were_parsed(tmp_path, monkeypatch):
    """eng-t-plug-manifest-raw-digest: the pinned hash binds the parsed bytes, not a second read."""
    d, digest = make_plugin(tmp_path, "todo-scan")
    m = d / "sentinel-plugin.json"
    original = m.read_bytes()
    real_read = Path.read_bytes

    def read_then_change(self):  # type: ignore[no-untyped-def]
        data = real_read(self)
        if self == m:
            m.write_bytes(original.replace(b"test plugin", b"changed!!!!"))  # file differs after the read
        return data

    monkeypatch.setattr(Path, "read_bytes", read_then_change)
    manifest, why = plugins.load_manifest(d, digest, "todo-scan")
    assert why == "" and manifest is not None and manifest["description"] == "test plugin"


def test_normalize_refuses_output_without_verified_provenance(tmp_path):
    """Mutation eng-f-plug-prov-required: findings are never accepted unless program() verified the bytes."""
    d, digest = make_plugin(tmp_path, "todo-scan")
    raw = b'{"tool": "todo-scan", "findings": [{"rule": "r", "file": "f", "line": 1, "message": "m", "severity": "low"}]}'
    with pytest.raises(ValueError, match="provenance"):
        adapter(d, digest).normalize(raw)
