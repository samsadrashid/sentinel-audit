"""Fixture adapter: a real adapter implementation around the deterministic fixture scanner.

It is not a production scanner integration. It exists so the adapter contract, hash allowlisting,
timeouts, output limits, malformed-output handling and normalisation are exercised end to end.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from ..domain.enums import ActivityClass, CheckStatus
from ..errors import BlockedError
from .base import AdapterManifest, ExecutionResult, PlannedCheck, sandbox_interpreter

FIXTURE_SCRIPT = Path(__file__).with_name("fixture_scanner.py")


def script_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FixtureAdapter:
    manifest = AdapterManifest(
        name="fixture",
        version="1.0.0",
        scanner="sentinel-fixture",
        scanner_versions="1.0.0",
        licence="MIT",
        activity_class=ActivityClass.S1,
        needs_network=False,
        check_ids=("fixture.marker",),
        output_schema="sentinel-fixture/1",
        engine_owned=True,
    )

    def __init__(self, script: Path = FIXTURE_SCRIPT, allowlisted_sha256: str | None = None) -> None:
        self.script = script
        self.allowlisted = allowlisted_sha256

    def detect(self) -> tuple[bool, str, str]:
        if not self.script.is_file():
            return False, "", ""
        return True, "1.0.0", script_sha256(self.script)

    def plan(self, root: Path) -> list[PlannedCheck]:
        return [PlannedCheck("fixture.marker", (str(root),))]

    def validate_scope(self, plan: list[PlannedCheck], root: Path) -> None:
        r = root.resolve()
        for c in plan:
            for t in c.targets:
                if Path(t).resolve() != r:
                    raise BlockedError(f"adapter planned a target outside scope: {t}", "scope_expansion")

    def execute(
        self, check: PlannedCheck, root: Path, timeout_s: int, max_output: int, runner: Any = None
    ) -> ExecutionResult:
        """Run the fixture scanner inside the given isolation runner. Without one it does not run at all
        (D-32, X-5): there is no unsandboxed path, even for engine-owned code."""
        ok, version, digest = self.detect()
        if not ok:
            return ExecutionResult(CheckStatus.NOT_RUN, "scanner_missing")
        if not self.allowlisted or digest != self.allowlisted:
            return ExecutionResult(CheckStatus.NOT_RUN, "binary_hash_mismatch", binary_sha256=digest)
        if runner is None:
            return ExecutionResult(CheckStatus.NOT_RUN, "host_isolation_unavailable", binary_sha256=digest)
        interpreter = sandbox_interpreter()
        args = ["-I", str(self.script.resolve()), str(root.resolve())]
        iso = runner.run(
            interpreter,
            args,
            target_root=root,
            timeout_s=timeout_s,
            max_output=max_output,
            extra_read=[Path(sys.base_prefix).resolve(), self.script.resolve().parent],
        )
        run, isolation, removed = iso.run, iso.profile, iso.workspace_removed

        def res(
            status: CheckStatus, reason: str, findings: list[dict[str, Any]] | None = None
        ) -> ExecutionResult:
            return ExecutionResult(
                status,
                reason,
                run.stdout,
                findings or [],
                version,
                digest,
                run.duration_ms,
                run.truncated,
                isolation,
                removed,
            )

        if getattr(run, "cancelled", False):
            return res(CheckStatus.BLOCKED, "cancelled")
        if run.timed_out:
            return res(CheckStatus.ERROR, "timeout")
        if run.truncated:
            return res(CheckStatus.ERROR, "output_limit")
        if run.returncode != 0:
            return res(CheckStatus.ERROR, f"exit_{run.returncode}")
        try:
            findings = self.normalize(run.stdout)
        except ValueError as exc:
            return res(CheckStatus.ERROR, f"bad_output: {exc}")
        return res(CheckStatus.FAIL if findings else CheckStatus.PASS, "", findings)

    def normalize(self, raw: bytes) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("output is not valid JSON") from exc
        if (
            not isinstance(data, dict)
            or data.get("tool") != "sentinel-fixture"
            or not isinstance(data.get("findings"), list)
        ):
            raise ValueError("unexpected output format")
        out = []
        for f in data["findings"]:
            if not isinstance(f, dict) or not {"rule", "file", "line", "message", "severity"} <= set(f):
                raise ValueError("finding missing fields")
            out.append(
                {
                    "rule": str(f["rule"]),
                    "file": str(f["file"]),
                    "line": int(f["line"]),
                    "message": str(f["message"])[:500],
                    "severity": str(f["severity"]),
                }
            )
        return out

    def health(self) -> list[str]:
        ok, _, digest = self.detect()
        issues = [] if ok else ["fixture script missing"]
        if ok and digest != self.allowlisted:
            issues.append("binary hash not allowlisted")
        return issues
