"""Third-party scanner adapters for M2: Gitleaks, Semgrep (S1), OSV-Scanner and Syft (S2) (D-13, D-52).

Shared rules, enforced in `PinnedScannerAdapter.execute` for every scanner:

* **Pinned or nothing (D-22, D-54).** A scanner runs only if the approved policy pins it. A native
  binary is re-hashed immediately before every execution; an image is referenced only by digest, and
  the Podman runtime's own hash and rootless state are re-checked first (`PodmanRunner.precondition`).
  A mismatch or a missing pin is `NOT_RUN`.
* **Isolated or nothing (D-32, D-53).** A native pin needs the native S1 sandbox; an image pin needs the
  verified rootless Podman runner. Any other combination is `NOT_RUN` (`host_isolation_unavailable`).
  There is no unsandboxed path.
* **No network.** The sandbox profile denies it, containers run with `--network=none`, and every
  scanner is also told to stay offline (`--metrics=off`, `--offline-vulnerabilities`).
* **Never PASS on failure (AC-03).** Timeouts, output overflow, unexpected exit codes and unparseable
  output are `ERROR`. A stopped scanner is `BLOCKED` (`cancelled`, AC-17).
* **No raw secrets (AC-15, AC-16).** Gitleaks' matched secret is classified in memory and discarded;
  the stored evidence is rebuilt from the sanitised findings, never from Gitleaks' own report.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..domain.enums import ActivityClass, CheckStatus
from ..errors import BlockedError, ValidationError
from ..scanner_pins import Pins, ScannerPin, file_sha256, verify_binary
from ..secret_class import classify
from .base import AdapterManifest, ExecutionResult, PlannedCheck

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
SEMGREP_RULES = RULES_DIR / "sentinel-core.yaml"
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
MAX_MESSAGE = 500


def _sev(value: Any, default: str = "medium") -> str:
    v = str(value or "").lower()
    mapping = {"error": "high", "warning": "medium", "info": "low", "moderate": "medium", "note": "low"}
    v = mapping.get(v, v)
    return v if v in SEVERITIES else default


def _rel(path: Any, root: Path, mount: str) -> str:
    p = str(path or "")
    for prefix in (mount + "/", str(root) + "/"):
        if p.startswith(prefix):
            return p[len(prefix) :]
    return p.lstrip("/") if p.startswith(mount) else p


class PinnedScannerAdapter:
    """Base for pinned third-party scanners. Subclasses define the manifest, arguments and parsing."""

    manifest: AdapterManifest
    pin_name: str
    domain: str = "code"
    #: Exit codes that mean "completed"; anything else is ERROR.
    ok_exit_codes: tuple[int, ...] = (0,)
    #: Container entrypoint when the image doesn't start the scanner itself.
    entrypoint: str | None = None
    #: D-29: the vulnerability database this scanner needs ("osv", "trivy", "grype"), or None.
    database: str | None = None
    #: D-61: True if the scanner consumes the SBOM produced earlier in the same run.
    needs_sbom: bool = False

    def __init__(self, pins: Pins | None = None) -> None:
        self.pins = pins or Pins()

    # ── contract ─────────────────────────────────────────────────────────
    @property
    def pin(self) -> ScannerPin | None:
        return self.pins.scanners.get(self.pin_name)

    def isolation_kind(self) -> str | None:
        """What the approved pin needs: "native" (binary) or "container" (image); None if unpinned."""
        pin = self.pin
        return None if pin is None else ("container" if pin.kind == "image" else "native")

    def detect(self) -> tuple[bool, str, str]:
        pin = self.pin
        if pin is None:
            return False, "", ""
        if pin.kind == "binary":
            assert pin.path is not None and pin.sha256 is not None
            ok = verify_binary(pin.path, pin.sha256) is None
            return ok, self.manifest.scanner_versions, pin.sha256 if ok else ""
        return True, self.manifest.scanner_versions, str(pin.image)

    def plan(self, root: Path) -> list[PlannedCheck]:
        return [PlannedCheck(self.manifest.check_ids[0], (str(root),))]

    def validate_scope(self, plan: list[PlannedCheck], root: Path) -> None:
        r = root.resolve()
        for c in plan:
            for t in c.targets:
                if Path(t).resolve() != r:
                    raise BlockedError(f"adapter planned a target outside scope: {t}", "scope_expansion")

    def health(self) -> list[str]:
        pin = self.pin
        if pin is None:
            return [f"{self.pin_name}: not pinned in the approved policy (D-54)"]
        if pin.kind == "binary":
            assert pin.path is not None and pin.sha256 is not None
            bad = verify_binary(pin.path, pin.sha256)
            return [f"{self.pin_name}: {bad}"] if bad else []
        return []

    # ── subclass hooks ───────────────────────────────────────────────────
    def args(self, target: str, extra: str | None) -> list[str]:
        raise NotImplementedError

    def extra_mount(self) -> tuple[Path | None, str | None]:
        """(host directory mounted read-only for the scanner, reason it is unavailable)."""
        return None, None

    def env(self) -> dict[str, str]:
        return {}

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        """(normalised findings, sanitised evidence bytes). Raises ValueError on bad output."""
        raise NotImplementedError

    def normalize(self, raw: bytes) -> list[dict[str, Any]]:
        return self.parse(raw, Path("/target"), "/target")[0]

    # ── execution ────────────────────────────────────────────────────────
    def stdin_and_notes(self, sbom: bytes | None) -> tuple[bytes | None, dict[str, str]]:
        return None, {}

    def artifact_from(self, raw: bytes) -> bytes:
        return b""

    def run_args(self, target: str, extra: str | None, notes: dict[str, str]) -> list[str]:
        return self.args(target, extra)

    def execute(
        self,
        check: PlannedCheck,
        root: Path,
        timeout_s: int,
        max_output: int,
        runner: Any = None,
        sbom: bytes | None = None,
    ) -> ExecutionResult:
        pin = self.pin
        if pin is None:
            return ExecutionResult(CheckStatus.NOT_RUN, "scanner_not_approved")
        if runner is None:
            return ExecutionResult(CheckStatus.NOT_RUN, "host_isolation_unavailable")
        extra, extra_problem = self.extra_mount()
        if extra_problem is not None:
            return ExecutionResult(CheckStatus.NOT_RUN, extra_problem)
        db_pin = self.pins.database(self.database) if self.database else None
        db_snapshot = db_pin.manifest_sha256 if db_pin is not None else None
        stdin_data, notes = self.stdin_and_notes(sbom)
        from ..isolation.podman import PROFILE_NAME as PODMAN
        from ..isolation.sandbox import PROFILE_NAME as SEATBELT

        if pin.kind == "binary" and getattr(runner, "name", None) == SEATBELT:
            assert pin.path is not None and pin.sha256 is not None
            bad = verify_binary(pin.path, pin.sha256)  # immediately before execution
            if bad is not None:
                return ExecutionResult(CheckStatus.NOT_RUN, bad)
            mount = str(root.resolve())
            iso = runner.run(
                pin.path.resolve(),
                self.run_args(mount, str(extra.resolve()) if extra else None, notes),
                target_root=root,
                extra_read=[pin.path.resolve().parent, *([extra.resolve()] if extra else [])],
                timeout_s=timeout_s,
                max_output=max_output,
                env=self.env(),
            )
            identity = pin.sha256
        elif pin.kind == "image" and getattr(runner, "name", None) == PODMAN:
            assert pin.image is not None
            bad = runner.precondition()  # runtime hash and rootless state, immediately before execution
            if bad is not None:
                return ExecutionResult(CheckStatus.NOT_RUN, bad)
            if not runner.image_present(pin.image):
                return ExecutionResult(CheckStatus.NOT_RUN, "image_missing")
            mount = "/target"
            from ..isolation.podman import VolumeError

            try:
                iso = runner.run(
                    pin.image,
                    self.run_args(mount, "/data" if extra else None, notes),
                    target_root=root,
                    timeout_s=timeout_s,
                    max_output=max_output,
                    extra_ro=extra,
                    env=self.env(),
                    entrypoint=self.entrypoint,
                    **({"stdin_data": stdin_data} if stdin_data is not None else {}),
                )
            except VolumeError as exc:
                # D-71: the VM-local copy of the target or database couldn't be made or verified.
                why = str(exc)
                refused = why == "database_volume_mismatch" or why.startswith("image_integrity_failed")
                status = CheckStatus.NOT_RUN if refused else CheckStatus.ERROR
                return ExecutionResult(status, why)
            identity = pin.image
        else:
            return ExecutionResult(CheckStatus.NOT_RUN, "host_isolation_unavailable")
        run = iso.run

        def res(
            status: CheckStatus,
            reason: str,
            findings: list[dict[str, Any]] | None = None,
            raw: bytes = b"",
            artifact: bytes = b"",
        ) -> ExecutionResult:
            return ExecutionResult(
                status,
                reason,
                raw,
                findings or [],
                self.manifest.scanner_versions,
                identity,
                run.duration_ms,
                run.truncated,
                iso.profile,
                iso.workspace_removed,
                db_snapshot,
                artifact,
                dict(notes),
            )

        if getattr(run, "cancelled", False):
            return res(CheckStatus.BLOCKED, "cancelled")
        if run.timed_out:
            return res(CheckStatus.ERROR, "timeout")
        if run.truncated:
            return res(CheckStatus.ERROR, "output_limit")
        if run.returncode not in self.ok_exit_codes:
            return res(CheckStatus.ERROR, f"exit_{run.returncode}")
        try:
            findings, evidence = self.parse(run.stdout, root.resolve(), mount)
        except (ValueError, KeyError, TypeError) as exc:
            return res(CheckStatus.ERROR, f"bad_output: {str(exc)[:200]}")
        for f in findings:
            if db_snapshot is not None:
                f["db_snapshot"] = db_snapshot
        return res(
            CheckStatus.FAIL if findings else CheckStatus.PASS,
            "",
            findings,
            evidence,
            self.artifact_from(run.stdout),
        )


# ── Gitleaks (S1, secrets) ────────────────────────────────────────────────
class GitleaksAdapter(PinnedScannerAdapter):
    pin_name = "gitleaks"
    domain = "secrets"
    manifest = AdapterManifest(
        name="gitleaks",
        version="1.0.0",
        scanner="gitleaks",
        scanner_versions="8.30.1",
        licence="MIT",
        activity_class=ActivityClass.S1,
        needs_network=False,
        check_ids=("secrets.gitleaks",),
        output_schema="gitleaks-json/8",
    )

    def args(self, target: str, extra: str | None) -> list[str]:
        return [
            "dir",
            target,
            "--report-format=json",
            "--report-path=-",
            "--no-banner",
            "--no-color",
            "--exit-code=0",
            "--log-level=error",
        ]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        data = json.loads(raw.decode("utf-8") or "[]")
        if not isinstance(data, list):
            raise ValueError("gitleaks report is not a list")
        out = []
        for f in data:
            if not isinstance(f, dict):
                raise ValueError("gitleaks finding is not an object")
            label = classify(str(f.get("Secret") or ""))  # in memory only; the value is never kept
            out.append(
                {
                    "rule": f"gitleaks.{str(f['RuleID'])[:100]}",
                    "file": _rel(f.get("File"), root, mount),
                    "line": int(f.get("StartLine") or 0),
                    "message": str(f.get("Description") or f["RuleID"])[:MAX_MESSAGE],
                    "severity": "high" if label == "live" else "medium" if label == "unknown" else "low",
                    "liveness": label,
                }
            )
        evidence = json.dumps({"tool": "gitleaks", "findings": out}, sort_keys=True).encode()
        return out, evidence


# ── Semgrep CE (S1, code; self-authored rules only, D-55) ─────────────────
class SemgrepAdapter(PinnedScannerAdapter):
    pin_name = "semgrep"
    domain = "code"
    entrypoint = "semgrep"  # the image's default command is `semgrep --help`
    ok_exit_codes = (0,)
    manifest = AdapterManifest(
        name="semgrep",
        version="1.0.0",
        scanner="semgrep",
        scanner_versions="1.184.0",
        licence="LGPL-2.1-or-later",
        activity_class=ActivityClass.S1,
        needs_network=False,
        check_ids=("code.semgrep",),
        output_schema="semgrep-json/1",
    )

    def extra_mount(self) -> tuple[Path | None, str | None]:
        if not SEMGREP_RULES.is_file() or file_sha256(SEMGREP_RULES) != rules_sha256():
            return None, "semgrep_rules_mismatch"
        present = {p.name for p in RULES_DIR.iterdir() if p.suffix in (".yaml", ".yml")}
        if present != set(SEMGREP_RULE_PINS):
            return None, "semgrep_rules_mismatch"  # no unpinned or missing rule files
        for name, digest in SEMGREP_RULE_PINS.items():
            f = RULES_DIR / name
            if f.is_symlink() or file_sha256(f) != digest:
                return None, "semgrep_rules_mismatch"
        return RULES_DIR, None

    def env(self) -> dict[str, str]:
        return {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}

    def args(self, target: str, extra: str | None) -> list[str]:
        assert extra is not None
        return [
            "scan",
            *(f"--config={extra}/{name}" for name in SEMGREP_RULE_PINS),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            "--no-rewrite-rule-ids",
            target,
        ]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError("semgrep output has no results list")
        if data.get("errors"):
            raise ValueError(f"semgrep reported {len(data['errors'])} error(s)")
        out = []
        for r in data["results"]:
            extra = r.get("extra") or {}
            out.append(
                {
                    "rule": f"semgrep.{str(r['check_id']).rsplit('.', 1)[-1][:100]}",
                    "file": _rel(r.get("path"), root, mount),
                    "line": int((r.get("start") or {}).get("line") or 0),
                    "message": str(extra.get("message") or r["check_id"])[:MAX_MESSAGE],
                    "severity": _sev(extra.get("severity")),
                }
            )
        evidence = json.dumps({"tool": "semgrep", "findings": out}, sort_keys=True).encode()
        return out, evidence


#: D-55: SHA-256 of every configuration Semgrep may load (core rules plus one file per M3 domain,
#: D-58). A changed or extra rule file is refused until these pins change in the same reviewed change.
SEMGREP_RULE_PINS: dict[str, str] = {
    "sentinel-core.yaml": "1fdc7be2c3678a1351d9e7c962f4c8d49887499177757c79e8a7a4a8db8cb84c",
    "D01.yaml": "53b89ddb4a23f12a85b6e63661a76532fb1371577ece88af969420a7462b791e",
    "D02.yaml": "d4e546bbb644e3006bb55cb74e545d33756ea6499eb4bc286b061b34749128e9",
    "D08.yaml": "c4b33d5dc3514b9abca8cf2bdbc43f45d9c382279c00bf245611658305f32dce",
    "D14.yaml": "870bb6311c4157b90ff7eb1310d1634e9f6e0a8915697d1a313192ab1297e08d",
}
SEMGREP_RULES_SHA256 = SEMGREP_RULE_PINS["sentinel-core.yaml"]


def rules_sha256() -> str:
    return SEMGREP_RULES_SHA256


# ── OSV-Scanner (S2, dependencies; offline database only, D-56) ───────────
OSV_MANIFEST_NAME = "snapshot-manifest.json"
#: Per-file cap while hashing a snapshot. The Grype v6 database is over 2 GiB (measured 2026-11-10).
OSV_MAX_DB_BYTES = 8 * 1024**3


def verify_osv_database(path: Path, manifest_sha256: str) -> str | None:
    """None if the snapshot manifest matches its pin and every listed file matches the manifest."""
    m = path / OSV_MANIFEST_NAME
    try:
        if path.is_symlink() or not path.is_dir() or m.is_symlink() or not m.is_file():
            return "osv_database_missing"
        raw = m.read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest_sha256:
            return "osv_database_manifest_mismatch"
        manifest = json.loads(raw)
        files = manifest["files"]
        if not isinstance(files, list) or not files:
            return "osv_database_manifest_invalid"
        for entry in files:
            rel = Path(str(entry["path"]))
            if rel.is_absolute() or ".." in rel.parts:
                return "osv_database_manifest_invalid"
            f = path / rel
            if f.is_symlink() or not f.is_file() or file_sha256(f, OSV_MAX_DB_BYTES) != entry["sha256"]:
                return "osv_database_file_mismatch"
    except ValidationError:
        return "osv_database_file_too_large"  # fail closed: NOT_RUN, never an exception in the audit
    except (OSError, ValueError, KeyError, TypeError):
        return "osv_database_manifest_invalid"
    return None


def verify_snapshot(path: Path, manifest_sha256: str) -> str | None:
    """D-29: same verification for every vulnerability-database snapshot (manifest pinned, files hashed)."""
    return verify_osv_database(path, manifest_sha256)


def database_mount(pins: Pins, name: str) -> tuple[Path | None, str | None]:
    db = pins.database(name)
    if db is None:
        return None, f"{name}_database_not_approved"
    bad = verify_snapshot(db.path, db.manifest_sha256)
    return (None, bad.replace("osv_", f"{name}_", 1)) if bad else (db.path, None)


class OsvScannerAdapter(PinnedScannerAdapter):
    pin_name = "osv-scanner"
    domain = "dependencies"
    ok_exit_codes = (0, 1, 128)  # 1: vulnerabilities found; 128: no packages found
    manifest = AdapterManifest(
        name="osv-scanner",
        version="1.0.0",
        scanner="osv-scanner",
        scanner_versions="2.7.0",
        licence="Apache-2.0",
        activity_class=ActivityClass.S2,
        needs_network=False,
        check_ids=("deps.osv",),
        output_schema="osv-scanner-json/2",
    )

    def plan(self, root: Path) -> list[PlannedCheck]:
        from ..discovery import discover

        return super().plan(root) if discover(root).has_lockfiles else []

    database = "osv"

    def extra_mount(self) -> tuple[Path | None, str | None]:
        return database_mount(self.pins, "osv")

    def env(self) -> dict[str, str]:
        return {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/data"}

    def args(self, target: str, extra: str | None) -> list[str]:
        # --offline: local database only and no transitive resolution (no deps.dev or OSV API calls).
        return [
            "scan",
            "source",
            "--offline",
            "--offline-vulnerabilities",
            "--format=json",
            "--recursive",
            target,
        ]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        text = raw.decode("utf-8").strip()
        data = json.loads(text) if text else {"results": []}
        if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
            raise ValueError("osv-scanner output has no results list")
        out = []
        for result in data.get("results", []):
            src = _rel((result.get("source") or {}).get("path"), root, mount)
            for pkg in result.get("packages") or []:
                info = pkg.get("package") or {}
                for v in pkg.get("vulnerabilities") or []:
                    sev = (v.get("database_specific") or {}).get("severity")
                    out.append(
                        {
                            "rule": f"osv.{str(v['id'])[:100]}",
                            "file": src,
                            "line": 0,
                            "package": package_key(
                                info.get("ecosystem"), info.get("name"), info.get("version")
                            ),
                            "aliases": sorted({str(v["id"]), *map(str, v.get("aliases") or [])})[:50],
                            "message": (
                                f"{info.get('ecosystem', '?')}/{info.get('name', '?')}@"
                                f"{info.get('version', '?')}: {str(v.get('summary') or v['id'])}"
                            )[:MAX_MESSAGE],
                            "severity": _sev(sev, "medium"),
                        }
                    )
        evidence = json.dumps({"tool": "osv-scanner", "findings": out}, sort_keys=True).encode()
        return out, evidence


# ── Syft (S2, SBOM inventory) ────────────────────────────────────────────
class SyftAdapter(PinnedScannerAdapter):
    pin_name = "syft"
    domain = "sbom"
    manifest = AdapterManifest(
        name="syft",
        version="1.0.0",
        scanner="syft",
        scanner_versions="1.57.0",
        licence="Apache-2.0",
        activity_class=ActivityClass.S2,
        needs_network=False,
        check_ids=("sbom.syft",),
        output_schema="syft-json/16",
    )

    def env(self) -> dict[str, str]:
        return {"SYFT_CHECK_FOR_APP_UPDATE": "false"}

    def artifact_from(self, raw: bytes) -> bytes:
        return raw  # the full Syft JSON SBOM, kept in memory for Grype in the same run (D-61)

    def args(self, target: str, extra: str | None) -> list[str]:
        return ["scan", f"dir:{target}", "--output=json", "--quiet"]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("artifacts"), list):
            raise ValueError("syft output has no artifacts list")
        inventory = sorted(
            {
                (str(a.get("type", "")), str(a.get("name", "")), str(a.get("version", "")))
                for a in data["artifacts"]
                if isinstance(a, dict)
            }
        )
        evidence = json.dumps(
            {"tool": "syft", "packages": [{"type": t, "name": n, "version": v} for t, n, v in inventory]},
            sort_keys=True,
        ).encode()
        return [], evidence  # an inventory, not findings: PASS means "SBOM produced"


def package_key(ecosystem: Any, name: Any, version: Any) -> str:
    """Scanner-independent package identity for cross-scanner deduplication (D-62)."""
    eco = str(ecosystem or "").lower().replace("python", "pypi").replace("pip", "pypi")
    return f"{eco}/{str(name or '').lower()}@{version or ''}"[:300]


# ── Trivy (S2, dependencies and configuration; offline, D-29) ─────────────
class TrivyAdapter(PinnedScannerAdapter):
    pin_name = "trivy"
    domain = "dependencies"
    database = "trivy"
    manifest = AdapterManifest(
        name="trivy",
        version="1.0.0",
        scanner="trivy",
        scanner_versions="0.76.2",
        licence="Apache-2.0",
        activity_class=ActivityClass.S2,
        needs_network=False,
        check_ids=("deps.trivy",),
        output_schema="trivy-json/2",
    )

    def extra_mount(self) -> tuple[Path | None, str | None]:
        return database_mount(self.pins, "trivy")

    def args(self, target: str, extra: str | None) -> list[str]:
        return [
            "fs",
            "--scanners=vuln,misconfig",
            "--format=json",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
            "--cache-dir=/data",
            "--cache-backend=memory",
            "--exit-code=0",
            "--quiet",
            target,
        ]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("Results", []) or [], list):
            raise ValueError("trivy output has no Results list")
        out = []
        for r in data.get("Results") or []:
            target = _rel(r.get("Target"), root, mount)
            eco = r.get("Type")
            for v in r.get("Vulnerabilities") or []:
                out.append(
                    {
                        "rule": f"trivy.{str(v['VulnerabilityID'])[:100]}",
                        "file": target,
                        "line": 0,
                        "message": (
                            f"{v.get('PkgName', '?')}@{v.get('InstalledVersion', '?')}: "
                            f"{v.get('Title') or v['VulnerabilityID']}"
                        )[:MAX_MESSAGE],
                        "severity": _sev(v.get("Severity"), "medium"),
                        "package": package_key(eco, v.get("PkgName"), v.get("InstalledVersion")),
                        "aliases": sorted({str(v["VulnerabilityID"]), *map(str, v.get("VendorIDs") or [])})[
                            :50
                        ],
                    }
                )
            for m in r.get("Misconfigurations") or []:
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                cause = m.get("CauseMetadata") or {}
                out.append(
                    {
                        "rule": f"trivy.misconfig.{str(m.get('ID') or m.get('AVDID'))[:100]}",
                        "file": target,
                        "line": int(cause.get("StartLine") or 0),
                        "message": str(m.get("Title") or m.get("ID"))[:MAX_MESSAGE],
                        "severity": _sev(m.get("Severity"), "medium"),
                        "resource": str(cause.get("Resource") or "")[:200],
                    }
                )
        evidence = json.dumps({"tool": "trivy", "findings": out}, sort_keys=True).encode()
        return out, evidence


# ── Checkov (S1, IaC static analysis; no network) ─────────────────────────
class CheckovAdapter(PinnedScannerAdapter):
    pin_name = "checkov"
    domain = "iac"
    entrypoint = "checkov"
    manifest = AdapterManifest(
        name="checkov",
        version="1.0.0",
        scanner="checkov",
        scanner_versions="3.4.3",
        licence="Apache-2.0",
        activity_class=ActivityClass.S1,
        needs_network=False,
        check_ids=("iac.checkov",),
        output_schema="checkov-json/3",
    )

    def plan(self, root: Path) -> list[PlannedCheck]:
        from ..discovery import discover

        d = discover(root)
        return super().plan(root) if (d.iac_files or d.container_files) else []

    def env(self) -> dict[str, str]:
        return {"BC_SKIP_MAPPING": "TRUE", "LOG_LEVEL": "ERROR", "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false"}

    def args(self, target: str, extra: str | None) -> list[str]:
        return [
            f"--directory={target}",
            "--output=json",
            "--quiet",
            "--compact",
            "--skip-download",
            "--soft-fail",
            "--framework=terraform,kubernetes,dockerfile,cloudformation",
        ]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        data = json.loads(raw.decode("utf-8") or "[]")
        reports = data if isinstance(data, list) else [data]
        out = []
        for rep in reports:
            if not isinstance(rep, dict):
                raise ValueError("checkov report is not an object")
            if "results" not in rep:
                if {"passed", "failed"} <= set(rep):  # summary-only report: nothing scanned
                    continue
                raise ValueError("checkov report has no results")
            for c in rep["results"].get("failed_checks") or []:
                lines = c.get("file_line_range") or [0, 0]
                out.append(
                    {
                        "rule": f"checkov.{str(c['check_id'])[:100]}",
                        "file": _rel(c.get("file_path"), root, mount).lstrip("/"),
                        "line": int(lines[0] or 0),
                        "message": str(c.get("check_name") or c["check_id"])[:MAX_MESSAGE],
                        "severity": _sev(c.get("severity"), "medium"),
                        "resource": str(c.get("resource") or "")[:200],
                    }
                )
        evidence = json.dumps({"tool": "checkov", "findings": out}, sort_keys=True).encode()
        return out, evidence


# ── Grype (S2, dependencies; SBOM first, D-61; offline, D-29) ────────────
class GrypeAdapter(PinnedScannerAdapter):
    pin_name = "grype"
    domain = "dependencies"
    database = "grype"
    needs_sbom = True
    manifest = AdapterManifest(
        name="grype",
        version="1.0.0",
        scanner="grype",
        scanner_versions="0.121.2",
        licence="Apache-2.0",
        activity_class=ActivityClass.S2,
        needs_network=False,
        check_ids=("deps.grype",),
        output_schema="grype-json/6",
    )

    def extra_mount(self) -> tuple[Path | None, str | None]:
        return database_mount(self.pins, "grype")

    def env(self) -> dict[str, str]:
        return {
            "GRYPE_DB_CACHE_DIR": "/data",
            "GRYPE_DB_AUTO_UPDATE": "false",
            "GRYPE_DB_VALIDATE_AGE": "false",
            "GRYPE_DB_REQUIRE_UPDATE_CHECK": "false",
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        }

    def stdin_and_notes(self, sbom: bytes | None) -> tuple[bytes | None, dict[str, str]]:
        if sbom:
            return sbom, {"grype_input": "sbom"}
        return None, {"grype_input": "directory_fallback"}

    def args(self, target: str, extra: str | None) -> list[str]:
        return self.run_args(target, extra, {"grype_input": "directory_fallback"})

    def run_args(self, target: str, extra: str | None, notes: dict[str, str]) -> list[str]:
        """SBOM on stdin when one exists (D-61); `dir:` only as the recorded fallback."""
        source = [] if notes.get("grype_input") == "sbom" else [f"dir:{target}"]
        return [*source, "--output=json", "--quiet"]

    def parse(self, raw: bytes, root: Path, mount: str) -> tuple[list[dict[str, Any]], bytes]:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
            raise ValueError("grype output has no matches list")
        out = []
        for m in data["matches"]:
            v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
            locs = a.get("locations") or [{}]
            out.append(
                {
                    "rule": f"grype.{str(v['id'])[:100]}",
                    "file": _rel(locs[0].get("path"), root, mount).lstrip("/"),
                    "line": 0,
                    "message": (
                        f"{a.get('name', '?')}@{a.get('version', '?')}: "
                        + str(v.get("description") or v["id"])
                    )[:MAX_MESSAGE],
                    "severity": _sev(v.get("severity"), "medium"),
                    "package": package_key(a.get("type"), a.get("name"), a.get("version")),
                    "aliases": sorted(
                        {
                            str(v["id"]),
                            *(str(r.get("id")) for r in m.get("relatedVulnerabilities") or [] if r.get("id")),
                        }
                    )[:50],
                }
            )
        evidence = json.dumps({"tool": "grype", "findings": out}, sort_keys=True).encode()
        return out, evidence


def third_party_adapters(pins: Pins) -> list[PinnedScannerAdapter]:
    return [
        GitleaksAdapter(pins),
        SemgrepAdapter(pins),
        OsvScannerAdapter(pins),
        SyftAdapter(pins),
        TrivyAdapter(pins),
        CheckovAdapter(pins),
        GrypeAdapter(pins),
    ]
