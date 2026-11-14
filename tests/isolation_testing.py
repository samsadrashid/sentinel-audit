"""TEST-ONLY isolation runner (X-5). Never importable from `src/`; a test enforces that.

Production code has no unsandboxed path: without a verified isolation layer every adapter check is
NOT_RUN. Tests that need a check to actually execute on hosts without the macOS sandbox use this
runner. It runs the process with the same bounded, credential-free environment, records that it was
used, and identifies itself under a name production never accepts. It is NOT isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.adapters.base import run_bounded
from sentinel.domain.enums import ActivityClass
from sentinel.isolation import HostCapabilities
from sentinel.isolation.sandbox import IsolatedRun

TEST_RUNNER_NAME = "test-only-runner (NOT isolation)"


@dataclass
class TestOnlyRunner:
    __test__ = False  # not a pytest test class
    name: str = TEST_RUNNER_NAME
    calls: list[list[str]] = field(default_factory=list)

    def run(
        self,
        executable: Path,
        args: list[str],
        *,
        target_root: Path,
        extra_read: list[Path],
        timeout_s: float,
        max_output: int,
    ) -> IsolatedRun:
        argv = [str(executable), *args]
        self.calls.append(argv)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        run = run_bounded(argv, cwd=target_root, env=env, timeout_s=timeout_s, max_output=max_output)
        return IsolatedRun(run, self.name, True)


@dataclass(frozen=True)
class TestHost(HostCapabilities):
    """A host whose only 'isolation' for S1 is the test-only runner. Tests only."""

    __test__ = False
    runner: Any = None

    def isolation_for(self, cls: ActivityClass) -> str | None:
        if cls == ActivityClass.S1 and not self.running_as_root:
            return TEST_RUNNER_NAME
        return None

    def runner_for(self, cls: ActivityClass, limits: Any, pins: Any = None, kind: Any = None) -> Any:
        if self.isolation_for(cls) is None:
            return None
        return self.runner if self.runner is not None else TestOnlyRunner()


def make_test_host(*, running_as_root: bool = False, **kw: Any) -> TestHost:
    return TestHost("test", TEST_RUNNER_NAME, None, None, running_as_root, **kw)
