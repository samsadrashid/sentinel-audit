"""B2 archive adapter (M4/M8, D-25, D-35, D-70): APK, AAB and IPA inspection in the share-free container.

Each artifact in scope is read from the target (read-only, no symlinks, size-capped) and streamed to
the B2 runner's stdin. The program is Sentinel's own unpacker (`sentinel.b2`), and its SHA-256 is
recorded. Only well-formed `{"tool": "archive", "findings": [...]}` output is accepted. Without the B2
runner the check is NOT_RUN: there is no fallback to another isolation layer.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .. import b2
from ..domain.enums import ActivityClass, CheckStatus
from ..errors import BlockedError
from ..isolation.podman import VolumeError
from .base import AdapterManifest, ExecutionResult, PlannedCheck

SUFFIXES = (".apk", ".aab", ".ipa")
MAX_ARTIFACTS = 50
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__"}


class ArchiveAdapter:
    name = "archive"
    manifest = AdapterManifest(
        name="archive",
        version="1.0.0",
        scanner="sentinel-b2-unpack",
        scanner_versions="1.0.0",
        licence="MIT",
        activity_class=ActivityClass.B2,
        needs_network=False,
        check_ids=("b2.archive",),
        output_schema="sentinel-analyzer/1",
        engine_owned=True,
    )

    def isolation_kind(self) -> str:
        return "b2"

    def detect(self) -> tuple[bool, str, str]:
        """(available, version, identity) for the run manifest: the SHA-256 of the bundled B2 program."""
        try:
            return True, "1.0.0", b2.program()[1]
        except (OSError, ValueError):
            return False, "", ""

    def artifacts(self, root: Path) -> list[Path]:
        out: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP)
            for f in sorted(filenames):
                p = Path(dirpath) / f
                if f.lower().endswith(SUFFIXES) and stat.S_ISREG(p.lstat().st_mode):
                    out.append(p)
                    if len(out) >= MAX_ARTIFACTS:
                        return out
        return out

    def plan(self, root: Path) -> list[PlannedCheck]:
        arts = self.artifacts(root)
        return [PlannedCheck("b2.archive", tuple(str(p) for p in arts))] if arts else []

    def validate_scope(self, plan: list[PlannedCheck], root: Path) -> None:
        r = root.resolve()
        for c in plan:
            for t in c.targets:
                p = Path(t)
                if p.is_symlink() or (r not in p.resolve().parents):
                    raise BlockedError(f"archive outside scope or a symlink: {t}", "scope_expansion")

    def execute(
        self, check: PlannedCheck, root: Path, timeout_s: int, max_output: int, runner: Any = None
    ) -> ExecutionResult:
        if runner is None or getattr(runner, "name", "") != "b2-podman-share-free":
            return ExecutionResult(CheckStatus.NOT_RUN, "host_isolation_unavailable")
        try:
            program, digest = b2.program()
        except (OSError, ValueError):
            return ExecutionResult(CheckStatus.NOT_RUN, "b2_program_unavailable")
        findings: list[dict[str, Any]] = []
        raws: list[bytes] = []
        duration = 0
        rr = root.resolve()
        for t in check.targets:
            p = Path(t)
            rel = str(p.resolve().relative_to(rr))
            try:
                fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    data = fh.read(b2.unpack.LIMITS["max_artifact_bytes"] + 1)
            except OSError:
                return ExecutionResult(CheckStatus.ERROR, f"artifact_unreadable: {rel[:200]}")
            try:
                res = runner.run(program, [rel], data, timeout_s=timeout_s, max_output=max_output)
            except VolumeError as exc:  # the stored image is damaged: never run it
                return ExecutionResult(CheckStatus.NOT_RUN, str(exc)[:200])
            run = res.run
            duration += run.duration_ms
            if getattr(run, "cancelled", False):
                return ExecutionResult(CheckStatus.BLOCKED, "cancelled", isolation=res.profile)
            if run.timed_out or run.truncated or run.returncode != 0:
                why = (
                    "timeout"
                    if run.timed_out
                    else "output_limit"
                    if run.truncated
                    else f"exit_{run.returncode}"
                )
                return ExecutionResult(CheckStatus.ERROR, why, isolation=res.profile, duration_ms=duration)
            try:
                findings += self.normalize(run.stdout)
            except ValueError as exc:
                return ExecutionResult(
                    CheckStatus.ERROR, f"bad_output: {str(exc)[:200]}", isolation=res.profile
                )
            raws.append(run.stdout)
        return ExecutionResult(
            CheckStatus.FAIL if findings else CheckStatus.PASS,
            "",
            b"[" + b",".join(raws) + b"]",
            findings,
            "1.0.0",
            digest,
            duration,
            False,
            "b2-podman-share-free",
            True,
            notes={"b2_program_sha256": digest, "b2_image_id": runner.pin.image_id},
        )

    def normalize(self, raw: bytes) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("output is not valid JSON") from exc
        if (
            not isinstance(data, dict)
            or data.get("tool") != "archive"
            or not isinstance(data.get("findings"), list)
        ):
            raise ValueError("unexpected output format")
        out = []
        for f in data["findings"]:
            if not isinstance(f, dict) or not {"rule", "file", "line", "message", "severity"} <= set(f):
                raise ValueError("finding missing fields")
            try:
                line = int(f["line"])
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError("finding line is not an integer") from exc
            if not 0 <= line <= 10_000_000:
                raise ValueError("finding line out of range")
            sev = str(f["severity"])
            out.append(
                {
                    "rule": f"archive.{str(f['rule'])[:100]}",
                    "file": str(f["file"])[:1000],
                    "line": line,
                    "message": str(f["message"])[:500],
                    "severity": sev if sev in SEVERITIES else "medium",
                }
            )
        return out

    def health(self) -> list[str]:
        try:
            b2.program()
        except (OSError, ValueError) as exc:
            return [f"archive: {exc}"]
        return []
