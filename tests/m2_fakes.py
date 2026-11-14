"""TEST-ONLY fakes for M2: runners that return canned scanner output, and pin builders.

They execute nothing and isolate nothing. They let adapter, orchestrator, PII and control logic be
tested without real scanners or Podman. Real-scanner evidence comes only from runs with approved,
pinned binaries and images (D-54).
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.adapters.base import BoundedRun
from sentinel.isolation.podman import PROFILE_NAME as PODMAN
from sentinel.isolation.sandbox import PROFILE_NAME as SEATBELT
from sentinel.scanner_pins import Pins, RuntimePin, ScannerPin

DIGEST = "sha256:" + "a" * 64


@dataclass
class _Iso:
    run: BoundedRun
    profile: str
    workspace_removed: bool = True


@dataclass
class FakeRunner:
    """Answers `run()` with `respond(argv_or_image, args)`; records every call."""

    name: str
    respond: Callable[..., BoundedRun]
    calls: list[dict[str, Any]] = field(default_factory=list)
    precondition_result: str | None = None
    images: set[str] = field(default_factory=set)
    cancel_event: threading.Event | None = None

    def run(self, exe_or_image: Any, args: list[str], **kw: Any) -> _Iso:
        self.calls.append({"target": exe_or_image, "args": list(args), **kw})
        return _Iso(self.respond(exe_or_image, args, self), self.name)

    # podman-only surface
    def precondition(self) -> str | None:
        return self.precondition_result

    def image_present(self, image: str) -> bool:
        return image in self.images


def ok(stdout: bytes, rc: int = 0) -> Callable[..., BoundedRun]:
    return lambda *a: BoundedRun(rc, stdout, False, False, 5)


def slow_until_cancelled(seconds: float = 120) -> Callable[..., BoundedRun]:
    """A 'long-running scanner': blocks until the kill switch fires (then reports cancelled)."""

    def respond(target: Any, args: list[str], runner: FakeRunner) -> BoundedRun:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if runner.cancel_event is not None and runner.cancel_event.is_set():
                return BoundedRun(None, b"", False, False, 1, cancelled=True)
            time.sleep(0.02)
        return BoundedRun(0, b"[]", False, False, int(seconds * 1000))

    return respond


def seatbelt(respond: Callable[..., BoundedRun]) -> FakeRunner:
    return FakeRunner(SEATBELT, respond)


def podman(respond: Callable[..., BoundedRun], images: set[str] | None = None) -> FakeRunner:
    return FakeRunner(
        PODMAN,
        respond,
        images=set(
            images
            or {
                f"x/{n}@{DIGEST}" for n in ("semgrep", "osv", "syft", "gitleaks", "trivy", "grype", "checkov")
            }
        ),
    )


def fake_binary(tmp: Path, name: str, body: bytes = b"#!/bin/sh\nexit 0\n") -> tuple[Path, str]:
    p = tmp / f"bin-{name}"
    p.write_bytes(body)
    p.chmod(0o755)
    return p, hashlib.sha256(body).hexdigest()


def pins_with(tmp: Path, **kinds: str) -> Pins:
    """pins_with(tmp, gitleaks="binary", semgrep="image", ...)."""
    scanners = {}
    for name, kind in kinds.items():
        key = name.replace("_", "-")
        if kind == "binary":
            path, digest = fake_binary(tmp, key)
            scanners[key] = ScannerPin(key, "binary", path, digest)
        else:
            short = {"osv-scanner": "osv"}.get(key, key)
            scanners[key] = ScannerPin(key, "image", image=f"x/{short}@{DIGEST}")
    rt_path, rt_hash = fake_binary(tmp, "podman")
    return Pins(scanners, RuntimePin(rt_path, rt_hash, f"x/busybox@{DIGEST}"))
