"""AC-02 and AC-03 with every M2 adapter in one audit (fake runners; real scanners after D-54 approval)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sentinel.adapters.base import BoundedRun
from sentinel.adapters.scanners import third_party_adapters
from sentinel.domain.enums import ActivityClass, CheckStatus
from sentinel.orchestrator import run_audit

from .isolation_testing import TestHost
from .m2_fakes import FakeRunner, pins_with, podman
from .test_pipeline import cfg, make_target, request


def tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


class _Host(TestHost):
    __test__ = False

    def runner_for(self, cls: ActivityClass, limits: Any, pins: Any = None, kind: Any = None) -> Any:
        if kind == "container" and cls in (ActivityClass.S1, ActivityClass.S2):
            return PODMAN_RUNNER[0]
        if kind == "native" and cls == ActivityClass.S1:
            return self.runner
        return None


PODMAN_RUNNER: list[Any] = [None]
OUT = {
    "gitleaks": b"[]",
    "semgrep": b'{"results": [], "errors": []}',
    "syft": b'{"artifacts": []}',
}


def respond(target: Any, args: list[str], runner: FakeRunner) -> BoundedRun:
    name = "gitleaks" if "dir" in args[:1] else "semgrep" if "--metrics=off" in args else "syft"
    return BoundedRun(0, OUT[name], False, False, 1)


def test_target_tree_is_unchanged_and_unapproved_osv_is_not_run(tmp_path, trust, ledger):
    t = make_target(tmp_path, "t", "x")
    (t / "requirements.txt").write_text("requests==2.0.0\n")
    before = tree(t)
    pins = pins_with(tmp_path, gitleaks="binary", semgrep="image", syft="image", osv_scanner="image")
    host = _Host(
        "darwin", "s1-macos-seatbelt", None, None, False, runner=FakeRunner("s1-macos-seatbelt", respond)
    )
    PODMAN_RUNNER[0] = podman(respond)
    out = run_audit(
        request(
            tmp_path,
            trust,
            ledger,
            cfg(t, classes=("S1", "S2")),
            adapters=third_party_adapters(pins),
            host=host,
        )
    )
    assert tree(t) == before
    by = {c.adapter: c for c in out.checks}
    assert (
        by["osv-scanner"].status == CheckStatus.NOT_RUN
        and by["osv-scanner"].reason == "osv_database_not_approved"
    )
    assert by["semgrep"].status == by["gitleaks"].status == by["syft"].status == CheckStatus.PASS
    assert out.overall != "PASS"  # one check didn't run, so the audit is incomplete (AC-03)
    assert json.dumps(out.result["discovery"]) and out.result["discovery"][0]["ecosystems"]["PyPI"]
