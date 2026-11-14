"""Adapter contract, fixture adapter and bounded execution (§5, R-05, R-06, R-16)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sentinel.adapters.base import run_bounded
from sentinel.adapters.fixture import FIXTURE_SCRIPT, FixtureAdapter, script_sha256
from sentinel.domain.enums import CheckStatus
from sentinel.errors import BlockedError

from .isolation_testing import TestOnlyRunner

ALLOW = script_sha256(FIXTURE_SCRIPT)


def target(tmp_path: Path, content: str) -> Path:
    root = tmp_path / "target"
    root.mkdir()
    (root / "src.txt").write_text(content)
    return root


def run(root: Path, adapter: FixtureAdapter | None = None, timeout=10, max_output=1 << 20):
    a = adapter or FixtureAdapter(allowlisted_sha256=ALLOW)
    return a.execute(a.plan(root)[0], root, timeout, max_output, runner=TestOnlyRunner())


def test_clean_target_passes(tmp_path):
    r = run(target(tmp_path, "nothing here\n"))
    assert r.status == CheckStatus.PASS and r.findings == [] and r.binary_sha256 == ALLOW


def test_findings_give_fail_with_normalised_output(tmp_path):
    r = run(target(tmp_path, "a\nSENTINEL-FIXTURE-FINDING\n"))
    assert r.status == CheckStatus.FAIL
    assert r.findings == [
        {
            "rule": "fixture.marker",
            "file": "src.txt",
            "line": 2,
            "message": "fixture marker present",
            "severity": "medium",
        }
    ]


@pytest.mark.parametrize(
    "marker,reason", [("SENTINEL-FIXTURE-CRASH", "exit_1"), ("SENTINEL-FIXTURE-GARBAGE", "bad_output")]
)
def test_crash_and_malformed_output_are_error_never_pass(tmp_path, marker, reason):
    r = run(target(tmp_path, marker))
    assert r.status == CheckStatus.ERROR and r.reason.startswith(reason)


def test_timeout_is_error(tmp_path):
    r = run(target(tmp_path, "SENTINEL-FIXTURE-HANG"), timeout=1)
    assert r.status == CheckStatus.ERROR and r.reason == "timeout"


def test_output_limit_is_error_and_bounded(tmp_path):
    r = run(target(tmp_path, "SENTINEL-FIXTURE-FINDING\n" * 200), max_output=100)
    assert r.status == CheckStatus.ERROR and r.reason == "output_limit" and len(r.raw_output) <= 100


def test_hash_mismatch_and_missing_scanner_are_not_run(tmp_path):
    root = target(tmp_path, "x")
    assert run(root, FixtureAdapter(allowlisted_sha256="0" * 64)).reason == "binary_hash_mismatch"
    assert run(root, FixtureAdapter(allowlisted_sha256=None)).status == CheckStatus.NOT_RUN
    missing = FixtureAdapter(script=tmp_path / "nope.py", allowlisted_sha256=ALLOW)
    r = run(root, missing)
    assert r.status == CheckStatus.NOT_RUN and r.reason == "scanner_missing"


def test_modified_scanner_script_rejected(tmp_path):
    copy = tmp_path / "scanner.py"
    copy.write_bytes(FIXTURE_SCRIPT.read_bytes() + b"\n# tampered\n")
    r = run(target(tmp_path, "x"), FixtureAdapter(script=copy, allowlisted_sha256=ALLOW))
    assert r.status == CheckStatus.NOT_RUN and r.reason == "binary_hash_mismatch"


def test_scope_expansion_blocked(tmp_path):
    root = target(tmp_path, "x")
    a = FixtureAdapter(allowlisted_sha256=ALLOW)
    plan = a.plan(root)
    a.validate_scope(plan, root)
    plan[0] = type(plan[0])(plan[0].check_name, (str(tmp_path),))
    with pytest.raises(BlockedError):
        a.validate_scope(plan, root)


@pytest.mark.parametrize(
    "payload,ok",
    [
        (b'{"tool":"other","findings":[]}', False),
        (b'{"tool":"sentinel-fixture"}', False),
        (b'{"tool":"sentinel-fixture","findings":[{"rule":"r"}]}', False),
        (b"\xff\xfe", False),
        (b'{"tool":"sentinel-fixture","findings":[]}', True),
    ],
)
def test_normalize_rejects_unexpected_formats(payload, ok):
    a = FixtureAdapter(allowlisted_sha256=ALLOW)
    if ok:
        assert a.normalize(payload) == []
    else:
        with pytest.raises(ValueError):
            a.normalize(payload)


def test_health_reports_problems(tmp_path):
    assert FixtureAdapter(allowlisted_sha256=ALLOW).health() == []
    assert FixtureAdapter(allowlisted_sha256="0" * 64).health() == ["binary hash not allowlisted"]


def test_bounded_run_does_not_inherit_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_TEST_SECRET", "do-not-leak")
    script = tmp_path / "env.py"
    script.write_text("import os,sys; sys.stdout.write(','.join(sorted(os.environ)))")
    r = run_bounded(
        [sys.executable, "-I", str(script)],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        timeout_s=10,
        max_output=10_000,
    )
    assert r.returncode == 0 and b"SENTINEL_TEST_SECRET" not in r.stdout


def test_bounded_run_kills_on_timeout(tmp_path):
    script = tmp_path / "sleep.py"
    script.write_text("import time; time.sleep(60)")
    r = run_bounded([sys.executable, "-I", str(script)], cwd=tmp_path, env={}, timeout_s=0.5, max_output=10)
    assert r.timed_out and r.returncode is None and r.duration_ms < 10_000


def test_bounded_run_stops_runaway_output(tmp_path):
    script = tmp_path / "spam.py"
    script.write_text("import sys\nwhile True: sys.stdout.write('x'*65536)")
    r = run_bounded(
        [sys.executable, "-I", str(script)], cwd=tmp_path, env={}, timeout_s=10, max_output=100_000
    )
    assert r.truncated and len(r.stdout) == 100_000
