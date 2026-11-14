"""Host capability detection (D-32, §10.2).

Every capability is reported from evidence, never from the presence of an executable alone:
- native sandbox: available only if `sandbox.probe()` passed its self-test on this host;
- container runtime: used only as a hash-pinned rootless Podman that passed its functional self-test
  (D-53); otherwise S2/B1 (and S1 without a native sandbox) are NOT_RUN;
- VM isolation: not implemented;
- user presence for operator keys: not implemented (D-38 helper pending).
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..domain.enums import ActivityClass


@dataclass(frozen=True)
class HostCapabilities:
    platform: str
    native_sandbox: str | None
    container_runtime: str | None
    user_presence: str | None
    running_as_root: bool
    os_version: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def isolation_for(self, cls: ActivityClass) -> str | None:
        """The native layer that runs `cls`, or None. S1 only; S2/B1 need rootless Podman (D-53)."""
        if cls == ActivityClass.S1 and not self.running_as_root:
            return self.native_sandbox
        return None

    def runner_for(self, cls: ActivityClass, limits: Any, pins: Any = None, kind: str | None = None) -> Any:
        """The isolation runner for `cls`, or None (→ NOT_RUN). There is deliberately no unsandboxed
        runner in production code (D-32, D-52, D-53, X-5):

        - S1: the verified macOS Seatbelt profile; otherwise a verified rootless Podman runner;
        - S2 and B1: a verified rootless Podman runner only;
        - anything else (B2, A1): None in M2.

        `kind` is what the adapter's approved pin needs: "native" (a hash-pinned binary, only the native
        S1 sandbox) or "container" (a digest-pinned image, only rootless Podman). Neither substitutes
        for the other.
        """
        from .sandbox import PROFILE_NAME, MacSeatbeltRunner, ResourceLimits

        if self.running_as_root:
            return None
        if kind == "b2":
            # D-70: B2 only in the share-free Podman machine (M2-SA-12 resolved there); nothing else.
            if cls != ActivityClass.B2:
                return None
            from .b2 import available_runner as b2_runner

            return b2_runner(getattr(pins, "podman", None), getattr(pins, "b2", None))
        if kind == "mobsf":
            # D-72: MobSF 4.6.4 only in the share-free machine, no mounts, under the recorded risk acceptance.
            if cls is not ActivityClass.B2:
                return None
            from .b2 import MOBSF_PROFILE
            from .b2 import available_runner as share_free_runner

            return share_free_runner(
                getattr(pins, "podman", None), getattr(pins, "mobsf", None), MOBSF_PROFILE
            )
        if kind in ("b2", "mobsf") or cls == ActivityClass.B2:
            return None
        if kind == "container":
            if cls not in (ActivityClass.S1, ActivityClass.S2, ActivityClass.B1):
                return None
            from .podman import available_runner

            return available_runner(getattr(pins, "podman", None))
        if kind == "native" and cls != ActivityClass.S1:
            return None
        if cls == ActivityClass.S1 and self.isolation_for(cls) == PROFILE_NAME:
            return MacSeatbeltRunner(
                ResourceLimits(
                    cpu_seconds=limits.scanner_timeout_s, max_file_bytes=limits.max_extracted_file_bytes
                )
            )
        if kind != "native" and cls in (ActivityClass.S1, ActivityClass.S2, ActivityClass.B1):
            from .podman import available_runner

            return available_runner(getattr(pins, "podman", None))
        return None

    def report(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "os_version": self.os_version,
            "native_sandbox": self.native_sandbox,
            "container_runtime": self.container_runtime,
            "user_presence": self.user_presence,
            "running_as_root": self.running_as_root,
            **self.details,
        }


#: Linux proc status file: `CapEff` lists the effective capabilities of this process (hex bitmask).
PROC_STATUS = Path("/proc/self/status")


def privilege_problem(proc_status: Path | None = None) -> str | None:
    """D-32 / §10.2: why this process must not run, or None.

    Refused: effective UID 0 on any POSIX host (catches sudo and setuid wrappers), and on Linux any
    non-zero effective capability set, or an unreadable capability set (fail closed). Membership of
    the macOS `admin` group is NOT refused: an administrator is unprivileged until it elevates.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "running with effective UID 0 (root); run Sentinel as an unprivileged user"
    if sys.platform.startswith("linux"):
        path = proc_status or PROC_STATUS
        try:
            text = path.read_text(encoding="ascii", errors="strict")
        except (OSError, UnicodeDecodeError):
            return "cannot read effective capabilities from /proc/self/status; refusing (fail closed)"
        caps = [ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.startswith("CapEff:")]
        if len(caps) != 1:
            return "cannot determine effective capabilities; refusing (fail closed)"
        try:
            value = int(caps[0], 16)
        except ValueError:
            return "malformed effective capability set; refusing (fail closed)"
        if value != 0:
            return f"running with elevated Linux capabilities (CapEff={caps[0]}); drop them and retry"
    return None


def detect(run_probe: bool = True) -> HostCapabilities:
    from . import sandbox

    root = hasattr(os, "geteuid") and os.geteuid() == 0
    probe = sandbox.probe() if run_probe else sandbox.ProbeResult(False, None, "probe not run")
    container = shutil.which("docker") or shutil.which("podman")
    ver = platform.mac_ver()[0] if sys.platform == "darwin" else platform.release()
    details = {
        "native_sandbox_probe": {
            "passed": probe.available,
            "reason": probe.reason,
            "observations": probe.observations,
        },
        "container_note": (
            "used only through an approved, hash-pinned rootless Podman that passes its self-test (D-53)"
        )
        if container
        else "no container runtime found",
        "rootless_containers": "verified per policy pin at first use (see `status --policy`)",
        "vm_isolation": "not implemented",
        "resource_limits": {
            "cpu_seconds": True,
            "max_file_size": True,
            "open_files": True,
            "core_dumps": True,
            "memory": False if sys.platform == "darwin" else "not verified",
        },
        "network_isolation": "denied for S1 via sandbox profile" if probe.available else "unavailable",
        "filesystem_isolation": "deny-by-default reads and writes for S1"
        if probe.available
        else "unavailable",
        "known_gaps": [
            "file metadata (stat) readable host-wide inside S1 sandbox",
            "memory limit not enforced on macOS",
            "Seatbelt is not a VM boundary",
        ],
    }
    return HostCapabilities(
        platform=sys.platform,
        native_sandbox=probe.mechanism if probe.available else None,
        container_runtime=os.path.basename(container) if container else None,
        user_presence=None,
        running_as_root=root,
        os_version=ver,
        details=details,
    )
