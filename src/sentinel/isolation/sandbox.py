"""S1 native-sandbox isolation for scanner processes (D-04, D-15, D-32, R-05, R-06, §10, §10.2).

macOS: Seatbelt profile via /usr/bin/sandbox-exec, deny-by-default.
Linux: not implemented in M1 (no host to verify on). Reported as unavailable, never assumed.

A mechanism counts as available only after `probe()` has run a self-test under the real profile on
this host and observed every expected denial. Finding the executable is not enough.

Guarantees of the `s1-macos-seatbelt` profile, as verified by probe() and the test suite on the host:
- reads: only system libraries (/usr/lib, /System, dyld cache, /dev), the approved interpreter's
  install prefix, the scanner's own directory, the target root and the workspace;
- writes: only the per-check disposable workspace (and /dev/null);
- exec: only the single approved interpreter or scanner binary;
- network: all network access denied;
- environment: minimal fixed set, nothing inherited (no credentials or tokens);
- resources: CPU-seconds, max file size, open files and core dumps limited via setrlimit;
- lifetime: wall-clock timeout and output cap kill the whole process group.
Not guaranteed: file *metadata* (stat) is readable host-wide; memory (RLIMIT_AS) is not enforced by
macOS; Seatbelt is an Apple-private, deprecated-but-shipping interface and is not a VM boundary.
"""

from __future__ import annotations

import os
import resource
import shutil
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters.base import BoundedRun, run_bounded, sandbox_interpreter
from ..paths import ensure_private_dir, state_dir

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
PROFILE_NAME = "s1-macos-seatbelt"
SYSTEM_READ = ("/usr/lib", "/System", "/private/var/db/dyld", "/dev")
MIN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"}


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 15 * 60
    max_file_bytes: int = 256 * 1024 * 1024
    max_open_files: int = 256

    def apply(self) -> None:  # runs in the child before exec
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds, self.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (self.max_file_bytes, self.max_file_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (self.max_open_files, self.max_open_files))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _quote(path: Path) -> str:
    s = str(path)
    if any(c in s for c in '"\\\n\r\0()'):
        raise ValueError(f"path not allowed in sandbox profile: {s!r}")
    return f'"{s}"'


def build_profile(executable: Path, read_roots: list[Path], workspace: Path) -> str:
    """Deny-by-default Seatbelt profile. All paths must already be real (symlink-resolved)."""
    reads = " ".join(f"(subpath {_quote(p)})" for p in [*map(Path, SYSTEM_READ), *read_roots, workspace])
    return "\n".join(
        [
            "(version 1)",
            "(deny default)",
            f"(allow process-exec (literal {_quote(executable)}))",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow file-read-metadata)",
            '(allow file-read* (literal "/"))',
            f"(allow file-read* {reads})",
            f'(allow file-write* (subpath {_quote(workspace)}) (literal "/dev/null"))',
        ]
    )


@dataclass
class IsolatedRun:
    run: BoundedRun
    profile: str
    workspace_removed: bool


@dataclass
class ProbeResult:
    available: bool
    mechanism: str | None
    reason: str
    observations: dict[str, str] = field(default_factory=dict)


class MacSeatbeltRunner:
    """Runs one approved executable inside a deny-by-default Seatbelt profile with a fresh workspace."""

    name = PROFILE_NAME

    def __init__(self, limits: ResourceLimits | None = None, workspaces: Path | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self.workspaces = workspaces or (state_dir() / "workspaces")

    def run(
        self,
        executable: Path,
        args: list[str],
        *,
        target_root: Path,
        extra_read: list[Path],
        timeout_s: float,
        max_output: int,
        cancel: threading.Event | None = None,
        env: dict[str, str] | None = None,
    ) -> IsolatedRun:
        cancel = cancel if cancel is not None else getattr(self, "cancel_event", None)
        exe = executable.resolve()
        ensure_private_dir(self.workspaces)
        ws = Path(tempfile.mkdtemp(prefix="ws-", dir=self.workspaces)).resolve()
        os.chmod(ws, 0o700)
        try:
            profile = build_profile(exe, [p.resolve() for p in (*extra_read, target_root)], ws)
            run = run_bounded(
                [SANDBOX_EXEC, "-p", profile, str(exe), *args],
                cwd=ws,
                env={**MIN_ENV, **(env or {})},
                timeout_s=timeout_s,
                max_output=max_output,
                preexec=self.limits.apply,
                cancel=cancel,
            )
        finally:
            shutil.rmtree(ws, ignore_errors=True)
        return IsolatedRun(run, self.name, not ws.exists())


_PROBE_SCRIPT = r"""
import os, socket, sys
root, secret = sys.argv[1], sys.argv[2]
def t(fn):
    try:
        fn(); return "allowed"
    except OSError:
        return "denied"
r = {
 "read_target": t(lambda: open(os.path.join(root, "target", "probe.txt")).read()),
 "read_outside": t(lambda: open(secret).read()),
 "write_target": t(lambda: open(os.path.join(root, "target", "w"), "w").write("x")),
 "write_workspace": t(lambda: open("ws-probe", "w").write("x")),
 "network": t(lambda: socket.create_connection(("127.0.0.1", 9), timeout=1)),
 "env_home": os.environ.get("HOME", ""),
}
print(";".join(f"{k}={v}" for k, v in sorted(r.items())))
"""

EXPECTED = {
    "read_target": "allowed",
    "read_outside": "denied",
    "write_target": "denied",
    "write_workspace": "allowed",
    "network": "denied",
    "env_home": "/nonexistent",
}

_probe_cache: ProbeResult | None = None


def probe(force: bool = False) -> ProbeResult:
    """Functional self-test of the native sandbox on this host. Cached per process."""
    global _probe_cache
    if _probe_cache is not None and not force:
        return _probe_cache
    if sys.platform != "darwin":
        _probe_cache = ProbeResult(False, None, f"no native sandbox implemented for {sys.platform} in M1")
        return _probe_cache
    if not os.access(SANDBOX_EXEC, os.X_OK):
        _probe_cache = ProbeResult(False, None, "sandbox-exec not present")
        return _probe_cache
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        _probe_cache = ProbeResult(False, None, "refusing to run as root (D-32)")
        return _probe_cache
    base = Path(tempfile.mkdtemp(prefix="sentinel-probe-")).resolve()
    outside = Path(tempfile.mkdtemp(prefix="sentinel-probe-outside-")).resolve()
    try:
        (base / "target").mkdir()
        (base / "target" / "probe.txt").write_text("probe")
        (base / "probe.py").write_text(_PROBE_SCRIPT)
        secret = outside / "secret.txt"
        secret.write_text("must not be readable")
        interp = sandbox_interpreter()
        runner = MacSeatbeltRunner(workspaces=base / "ws")
        res = runner.run(
            interp,
            ["-I", str(base / "probe.py"), str(base), str(secret)],
            target_root=base / "target",
            extra_read=[Path(sys.base_prefix).resolve(), base],
            timeout_s=30,
            max_output=10_000,
        )
        line = res.run.stdout.decode(errors="replace").strip()
        obs = dict(kv.split("=", 1) for kv in line.split(";") if "=" in kv)
        bad = {k: obs.get(k) for k, v in EXPECTED.items() if obs.get(k) != v}
        if res.run.returncode != 0 or bad or not res.workspace_removed:
            _probe_cache = ProbeResult(False, None, f"self-test failed: {bad or res.run.returncode}", obs)
        else:
            _probe_cache = ProbeResult(True, PROFILE_NAME, "self-test passed", obs)
    except (OSError, ValueError) as exc:
        _probe_cache = ProbeResult(False, None, f"self-test error: {exc}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)
    return _probe_cache
