"""Scanner adapter contract (§5, D-13, D-22, R-16).

The engine calls adapter methods; adapters never call each other. Every failure path maps to an
explicit CheckStatus and is never PASS.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
import sysconfig
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ..domain.enums import ActivityClass, CheckStatus


@dataclass(frozen=True)
class AdapterManifest:
    name: str
    version: str
    scanner: str
    scanner_versions: str
    licence: str
    activity_class: ActivityClass
    needs_network: bool
    check_ids: tuple[str, ...]
    output_schema: str
    #: True only for adapters that run Sentinel's own reviewed code (the fixture adapter). Metadata only:
    #: it grants no exemption. Every adapter runs only inside a verified isolation layer (D-32, X-5).
    engine_owned: bool = False


@dataclass(frozen=True)
class PlannedCheck:
    check_name: str
    targets: tuple[str, ...]


@dataclass
class ExecutionResult:
    status: CheckStatus
    reason: str = ""
    raw_output: bytes = b""
    findings: list[dict[str, Any]] = field(default_factory=list)
    scanner_version: str = ""
    binary_sha256: str = ""
    duration_ms: int = 0
    truncated: bool = False
    #: Isolation actually used for this execution, e.g. 's1-macos-seatbelt' or 'none'.
    isolation: str = "none"
    workspace_removed: bool | None = None
    #: D-29: manifest SHA-256 of the vulnerability-database snapshot this run used, if any.
    db_snapshot: str | None = None
    #: In-memory product for a later check in the same run (Syft SBOM for Grype, D-61). Never persisted.
    artifact: bytes = b""
    #: Recorded execution notes, e.g. {"grype_input": "sbom" | "directory_fallback"} (D-61).
    notes: dict[str, str] = field(default_factory=dict)


class ScannerAdapter(Protocol):
    manifest: AdapterManifest

    def detect(self) -> tuple[bool, str, str]:
        """(available, version, binary_sha256)."""
        ...

    def plan(self, root: Path) -> list[PlannedCheck]: ...

    def validate_scope(self, plan: list[PlannedCheck], root: Path) -> None: ...

    def execute(
        self, check: PlannedCheck, root: Path, timeout_s: int, max_output: int, runner: Any = None
    ) -> ExecutionResult: ...

    def normalize(self, raw: bytes) -> list[dict[str, Any]]: ...

    def health(self) -> list[str]: ...


def sandbox_interpreter() -> Path:
    """The real interpreter binary to execute inside a sandbox, symlinks resolved.

    A macOS framework build (python.org, Homebrew) installs `bin/pythonX.Y` as a launcher that
    re-executes `Resources/Python.app/Contents/MacOS/Python`. A sandbox profile that allows exactly one
    executable denies that re-exec, so every sandboxed check would fail. For a framework build the
    bundle binary itself is returned; it lives under `sys.base_prefix`, which callers already allow
    for reading.
    """
    framework = str(sysconfig.get_config_var("PYTHONFRAMEWORK") or "")
    if sys.platform == "darwin" and framework:
        bundle = Path(sys.base_prefix).resolve() / "Resources" / f"{framework}.app"
        app = bundle / "Contents" / "MacOS" / framework
        if app.is_file() and os.access(app, os.X_OK):
            return app.resolve()
    return Path(os.path.realpath(sys.executable))


@dataclass(frozen=True)
class BoundedRun:
    returncode: int | None
    stdout: bytes
    timed_out: bool
    truncated: bool
    duration_ms: int
    #: AC-17: the kill switch stopped this process tree.
    cancelled: bool = False


def run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_s: float,
    max_output: int,
    preexec: Callable[[], None] | None = None,
    cancel: threading.Event | None = None,
    on_kill: Callable[[], None] | None = None,
    stdin_data: bytes | None = None,
) -> BoundedRun:
    """Run argv without a shell, streaming stdout with a hard size cap and wall-clock timeout.

    Output beyond max_output, or the timeout, kills the process. Memory use is bounded by max_output.
    """
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL if stdin_data is None else subprocess.PIPE,
        preexec_fn=preexec,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    assert proc.stdout is not None
    if stdin_data is not None:
        assert proc.stdin is not None

        def feed() -> None:
            try:
                proc.stdin.write(stdin_data)  # type: ignore[union-attr]
                proc.stdin.close()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError):
                pass

        threading.Thread(target=feed, daemon=True).start()
    buf = bytearray()
    timed_out = truncated = cancelled = False
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    fd = proc.stdout.fileno()
    try:
        while True:
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            remaining = timeout_s - (time.monotonic() - start)
            if remaining <= 0:
                timed_out = True
                break
            if not sel.select(timeout=min(remaining, 0.5)):
                if proc.poll() is not None:
                    break
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > max_output:
                truncated = True
                del buf[max_output:]
                break
    finally:
        sel.close()
        if timed_out or truncated or cancelled or proc.poll() is None:
            try:
                os.killpg(proc.pid, 9)  # the whole process tree (new session, R-04)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            if on_kill is not None:
                on_kill()  # e.g. remove a container the client process no longer controls
        proc.wait()
        proc.stdout.close()
    rc = None if (timed_out or truncated or cancelled) else proc.returncode
    return BoundedRun(rc, bytes(buf), timed_out, truncated, int((time.monotonic() - start) * 1000), cancelled)
