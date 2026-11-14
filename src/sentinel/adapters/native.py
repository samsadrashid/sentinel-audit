"""Adapters for Sentinel's native static analyzers (M4 mobile, M5 OS configuration, M8 supply chain).

Each analyzer is a stdlib-only script in `sentinel/analyzers/`, run with the approved interpreter as
`python -I <script> <root>` inside the verified native S1 sandbox (no network, read-only target,
disposable workspace). It is allowlisted by the SHA-256 of the script, re-checked immediately before
every run, like the fixture adapter. There is no unsandboxed path: without a runner it never starts.
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

ANALYZERS_DIR = Path(__file__).resolve().parent.parent / "analyzers"
SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def script_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeAnalyzerAdapter:
    #: subclasses set: name, script, domain, check_id, applies(discovery_like root) -> bool
    name = ""
    script = ""
    domain = ""
    check_id = ""
    description = ""

    def __init__(self, allowlisted_sha256: str | None = None) -> None:
        self.path = ANALYZERS_DIR / self.script
        self.allowlisted = allowlisted_sha256
        self.manifest = AdapterManifest(
            name=self.name,
            version="1.0.0",
            scanner=f"sentinel-{self.name}",
            scanner_versions="1.0.0",
            licence="MIT",
            activity_class=ActivityClass.S1,
            needs_network=False,
            check_ids=(self.check_id,),
            output_schema="sentinel-analyzer/1",
            engine_owned=True,
        )

    def isolation_kind(self) -> str:
        return "native"

    def applies(self, root: Path) -> bool:
        return True

    def execute_extra_read(self) -> list[Path]:
        """Directories the analyzer process may read besides the interpreter and the target."""
        return [ANALYZERS_DIR]

    def detect(self) -> tuple[bool, str, str]:
        if not self.path.is_file() or self.path.is_symlink():
            return False, "", ""
        return True, "1.0.0", script_sha256(self.path)

    def program(self) -> tuple[str, str, str, list[str]]:
        """(refusal, version, digest, interpreter args). Built-in analyzers run from the package."""
        ok, version, digest = self.detect()
        if not ok:
            return "scanner_missing", "", "", []
        if not self.allowlisted or digest != self.allowlisted:
            return "binary_hash_mismatch", version, digest, []
        return "", version, digest, [str(self.path.resolve())]

    def plan(self, root: Path) -> list[PlannedCheck]:
        return [PlannedCheck(self.check_id, (str(root),))] if self.applies(root) else []

    def validate_scope(self, plan: list[PlannedCheck], root: Path) -> None:
        r = root.resolve()
        for c in plan:
            for t in c.targets:
                if Path(t).resolve() != r:
                    raise BlockedError(f"adapter planned a target outside scope: {t}", "scope_expansion")

    def execute(
        self, check: PlannedCheck, root: Path, timeout_s: int, max_output: int, runner: Any = None
    ) -> ExecutionResult:
        refusal, version, digest, program = self.program()  # immediately before execution
        if refusal:
            return ExecutionResult(CheckStatus.NOT_RUN, refusal, binary_sha256=digest)
        if runner is None:
            return ExecutionResult(CheckStatus.NOT_RUN, "host_isolation_unavailable", binary_sha256=digest)
        interpreter = sandbox_interpreter()
        iso = runner.run(
            interpreter,
            ["-I", *program, str(root.resolve())],
            target_root=root,
            timeout_s=timeout_s,
            max_output=max_output,
            extra_read=[Path(sys.base_prefix).resolve(), *self.execute_extra_read()],
        )
        run = iso.run

        def res(
            status: CheckStatus, reason: str, findings: list[dict[str, Any]] | None = None, raw: bytes = b""
        ) -> ExecutionResult:
            return ExecutionResult(
                status,
                reason,
                raw,
                findings or [],
                version,
                digest,
                run.duration_ms,
                run.truncated,
                iso.profile,
                iso.workspace_removed,
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
            return res(CheckStatus.ERROR, f"bad_output: {str(exc)[:200]}")
        return res(CheckStatus.FAIL if findings else CheckStatus.PASS, "", findings, run.stdout)

    def normalize(self, raw: bytes) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("output is not valid JSON") from exc
        if (
            not isinstance(data, dict)
            or data.get("tool") != self.name
            or not isinstance(data.get("findings"), list)
        ):
            raise ValueError("unexpected output format")
        out = []
        for f in data["findings"]:
            if not isinstance(f, dict) or not {"rule", "file", "line", "message", "severity"} <= set(f):
                raise ValueError("finding missing fields")
            sev = str(f["severity"])
            try:
                line = int(f["line"])
            except (TypeError, ValueError, OverflowError) as exc:
                # Analyzer and plugin output is untrusted: a bad field is this check's ERROR, never an
                # exception that escapes into the orchestrator and aborts the whole audit.
                raise ValueError("finding line is not an integer") from exc
            if not 0 <= line <= 10_000_000:
                raise ValueError("finding line out of range")
            out.append(
                {
                    "rule": f"{self.name}.{str(f['rule'])[:100]}",
                    "file": str(f["file"])[:1000],
                    "line": line,
                    "message": str(f["message"])[:500],
                    "severity": sev if sev in SEVERITIES else "medium",
                }
            )
        return out

    def health(self) -> list[str]:
        ok, _, digest = self.detect()
        if not ok:
            return [f"{self.name}: analyzer missing"]
        return [] if digest == self.allowlisted else [f"{self.name}: hash not allowlisted"]


def builtin_native_allowlist() -> dict[str, str]:
    from . import native_registry

    return {
        cls.name: script_sha256(ANALYZERS_DIR / cls.script)
        for cls in native_registry.ALL
        if (ANALYZERS_DIR / cls.script).is_file()
    }
