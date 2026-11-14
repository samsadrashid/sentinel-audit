"""MobSF 4.6.4 adapter (B-7, D-66, D-72): APK, AAB and IPA artifacts in the share-free machine only.

D-72 records the owner's risk acceptance for MobSF 4.6.4, whose own extractor has GHSA-j7g2-gm7j-mfvm
(an unzip symlink bypass, fixed in the unreleased 4.6.5). The acceptance holds only under these
conditions, all enforced here and in the runner:

* MobSF runs only in the share-free Podman machine (D-71): no host volume exists in that VM;
* the container has **no mounts**, `--network=none`, a read-only root, no capabilities and
  `no-new-privileges`, and is removed after each artifact;
* the artifact goes in on stdin and one JSON document comes out on stdout, so anything MobSF's
  extractor writes stays in the container's tmpfs;
* only built artifacts are submitted, never a source tree or anything else from the host.

Without the MobSF runner the check is NOT_RUN: there is no fallback.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .. import mobsf
from ..domain.enums import ActivityClass, CheckStatus
from ..errors import BlockedError
from ..isolation.podman import VolumeError
from .base import AdapterManifest, ExecutionResult, PlannedCheck

SUFFIXES = (".apk", ".aab", ".ipa")
MAX_ARTIFACTS = 20
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__"}
PROFILE = "mobsf-podman-share-free"
#: MobSF scorecard level → Sentinel severity. MobSF's "info" and "secure" entries are not findings.
LEVELS = {"high": "high", "warning": "medium", "hotspot": "low"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80] or "untitled"


class MobsfAdapter:
    name = "mobsf"
    manifest = AdapterManifest(
        name="mobsf",
        version="1.0.0",
        scanner="mobsf",
        scanner_versions=mobsf.VERSION,
        licence="GPL-3.0 (separate container image; never bundled)",
        activity_class=ActivityClass.B2,
        needs_network=False,
        check_ids=("mobile.mobsf",),
        output_schema="sentinel-analyzer/1",
    )

    def isolation_kind(self) -> str:
        return "mobsf"

    def detect(self) -> tuple[bool, str, str]:
        """(available, version, identity): the SHA-256 of the bundled in-container driver."""
        try:
            return True, mobsf.VERSION, mobsf.program()[1]
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
        return [PlannedCheck("mobile.mobsf", tuple(str(p) for p in arts))] if arts else []

    def validate_scope(self, plan: list[PlannedCheck], root: Path) -> None:
        r = root.resolve()
        for c in plan:
            for t in c.targets:
                p = Path(t)
                if p.is_symlink() or (r not in p.resolve().parents):
                    raise BlockedError(f"artifact outside scope or a symlink: {t}", "scope_expansion")

    def execute(
        self, check: PlannedCheck, root: Path, timeout_s: int, max_output: int, runner: Any = None
    ) -> ExecutionResult:
        if runner is None or getattr(runner, "name", "") != PROFILE:
            return ExecutionResult(CheckStatus.NOT_RUN, "host_isolation_unavailable")
        try:
            program, digest = mobsf.program()
        except (OSError, ValueError):
            return ExecutionResult(CheckStatus.NOT_RUN, "mobsf_driver_unavailable")
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
                    data = fh.read(mobsf.MAX_ARTIFACT_BYTES + 1)
            except OSError:
                return ExecutionResult(CheckStatus.ERROR, f"artifact_unreadable: {rel[:200]}")
            if len(data) > mobsf.MAX_ARTIFACT_BYTES:
                return ExecutionResult(CheckStatus.ERROR, f"artifact_too_large: {rel[:200]}")
            kind = p.suffix.lower().lstrip(".")
            try:
                res = runner.run(
                    program,
                    [str(mobsf.MAX_ARTIFACT_BYTES), kind],
                    data,
                    timeout_s=timeout_s,
                    max_output=max_output,
                )
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
                    else f"exit_{run.returncode}{self._error(run.stdout)}"
                )
                return ExecutionResult(CheckStatus.ERROR, why, isolation=res.profile, duration_ms=duration)
            try:
                findings += self.normalize(run.stdout, rel)
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
            mobsf.VERSION,
            digest,
            duration,
            False,
            PROFILE,
            True,
            notes={
                "mobsf_driver_sha256": digest,
                "mobsf_image_id": runner.pin.image_id,
                "risk_acceptance": "D-72 GHSA-j7g2-gm7j-mfvm",
            },
        )

    @staticmethod
    def _error(raw: bytes) -> str:
        try:
            err = json.loads(raw.decode("utf-8")).get("error")
        except (UnicodeDecodeError, ValueError, AttributeError):
            return ""
        return f": {err}" if isinstance(err, str) and re.fullmatch(r"[a-z0-9_]{1,40}", err) else ""

    def normalize(self, raw: bytes, artifact: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("output is not valid JSON") from exc
        if (
            not isinstance(data, dict)
            or data.get("tool") != "mobsf"
            or "error" in data
            or not isinstance(data.get("findings"), list)
        ):
            raise ValueError("unexpected output format")
        if data.get("truncated") is True:
            raise ValueError("MobSF output was truncated in the container")
        errors = data.get("stage_errors")
        if not isinstance(errors, list):
            raise ValueError("stage_errors missing")
        if errors:  # a partial analysis is never a PASS (or a complete FAIL)
            raise ValueError(f"MobSF analysis stage failed: {str(errors[0])[:120]}")
        out = []
        for f in data["findings"]:
            if not isinstance(f, dict) or not {"level", "section", "title", "description"} <= set(f):
                raise ValueError("finding missing fields")
            level = f["level"]
            if level not in LEVELS:
                raise ValueError("unknown MobSF level")
            section, title = _slug(str(f["section"])), str(f["title"])
            out.append(
                {
                    "rule": f"mobsf.{section}.{_slug(title)}",
                    "file": artifact[:1000],
                    "line": 0,
                    "message": f"{title[:200]}: {str(f['description'])[:290]}",
                    "severity": LEVELS[level],
                }
            )
        return out

    def health(self) -> list[str]:
        try:
            mobsf.program()
        except (OSError, ValueError) as exc:
            return [f"mobsf: {exc}"]
        return []
