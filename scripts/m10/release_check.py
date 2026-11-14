"""Release-candidate check (M10). Offline; never publishes or signs anything.

Steps, each fail-closed:

1. **Version consistency:** `pyproject.toml`, `sentinel.__version__` and the built wheel and sdist
   metadata must match.
2. **Reproducible build:** wheel and sdist are built twice with the same SOURCE_DATE_EPOCH; both builds
   must be byte-identical.
3. **Clean install:** a fresh venv on the interpreter running this check gets the locked, hash-verified
   runtime closure (`uv sync --frozen --no-dev --no-install-project`), then the wheel with `--no-deps`, then
   `uv pip check` (all offline).
   `sentinel --json version` must run, and `sentinel --json self-check` must report `verified`.
4. **SBOM:** CycloneDX 1.5 for the wheel (scripts/m10/sbom.py), validated and bound to the wheel hash.
5. **Release manifest:** SHA256SUMS over the wheel, the sdist and the SBOM.
6. **Artifact contents:** neither the wheel nor the sdist may carry build output, caches, local agent
   tooling or private docs, and each must stay under MAX_ARTIFACT_BYTES (a SwiftPM `.build/` once
   slipped into the sdist: 95 MB of Apple SDK precompiled modules).

Release signing is NOT performed: production signing is disabled until the signing-device ceremony
(docs/roadmap/sentinel-final-release-report.md). The manifest is unsigned and says so.

Usage: python scripts/m10/release_check.py OUT_DIR
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "src"))

import sbom  # noqa: E402

from sentinel import __version__  # noqa: E402
from sentinel.release import sha256sums  # noqa: E402

EPOCH = "1767225600"  # 2026-01-01T00:00:00Z; any fixed value works, it only has to be the same twice


# Path components and suffixes that must never appear in a release artifact.
FORBIDDEN_PARTS = frozenset(
    {
        ".build",
        ".swiftpm",
        "DerivedData",
        "__pycache__",
        ".venv",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".git",
        ".ecc-src",
        ".sentinel",
        "node_modules",
        ".DS_Store",
    }
)
FORBIDDEN_SUFFIXES = (".pyc", ".pyo", ".pcm", ".swiftmodule", ".o", ".dylib", ".so")
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024


def artifact_problems(path: Path) -> list[str]:
    """Return why a built wheel or sdist must not ship (empty when it may)."""
    problems: list[str] = []
    size = path.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        problems.append(f"{path.name}: {size} bytes exceeds {MAX_ARTIFACT_BYTES}")
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        strip = 0
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path) as t:
            names = t.getnames()
        strip = 1  # the sdist's top-level <name>-<version>/ directory
    else:
        return [f"{path.name}: unknown artifact type"]
    bad = []
    for name in names:
        parts = PurePosixPath(name).parts[strip:]
        if (
            any(part in FORBIDDEN_PARTS for part in parts)
            or name.endswith(FORBIDDEN_SUFFIXES)
            or tuple(parts[:2]) == ("docs", "private")
        ):
            bad.append(name)
    if bad:
        problems.append(f"{path.name}: {len(bad)} forbidden member(s), e.g. {', '.join(bad[:3])}")
    return problems


def run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    r: subprocess.CompletedProcess[str] = subprocess.run(cmd, capture_output=True, text=True, **kw)  # type: ignore[call-overload]
    if r.returncode != 0:
        # The tool's own error is the diagnosis; a bare CalledProcessError hid it in remote CI.
        print(
            f"command failed ({r.returncode}): {' '.join(cmd)}\n{r.stderr.strip()[-4000:]}", file=sys.stderr
        )
        raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, r.stderr)
    return r


def build(out: Path) -> dict[str, str]:
    env = {**os.environ, "SOURCE_DATE_EPOCH": EPOCH}
    run(["uv", "build", "--offline", "-q", "-o", str(out), str(ROOT)], env=env)
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(out.iterdir())
        if not p.name.startswith(".")
    }


def main() -> int:
    out = Path(sys.argv[1]).resolve()
    if out.exists() and any(out.iterdir()):
        print(f"{out} is not empty; refusing", file=sys.stderr)
        return 4
    report: dict[str, object] = {
        "signed": False,
        "note": "unsigned release candidate: production signing disabled",
    }
    pyver = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    a, b = build(out / "a"), build(out / "b")
    if a != b:
        print(f"build not reproducible: {a} != {b}", file=sys.stderr)
        return 5
    report["reproducible"] = True
    dist = out / "dist"
    dist.mkdir()
    for n in a:
        shutil.copy2(out / "a" / n, dist / n)
    wheel = next(dist.glob("*.whl"))
    _, wver, _ = sbom.wheel_metadata(wheel)
    if not (pyver == __version__ == wver):
        print(f"version mismatch: pyproject {pyver}, package {__version__}, wheel {wver}", file=sys.stderr)
        return 5
    report["version"] = pyver
    problems = [msg for n in a for msg in artifact_problems(dist / n)]
    if problems:
        print("artifact contents refused: " + "; ".join(problems), file=sys.stderr)
        return 5
    report["artifact_contents"] = "clean"
    venv = out / "venv"
    vpy = str(venv / "bin" / "python")
    # The clean venv uses the interpreter running this check, not whatever uv finds first (on the GitHub
    # runners that was another Python). The runtime closure comes from uv.lock's own URLs and hashes via
    # `uv sync`; `uv pip install -r` would re-resolve through index pages that a lock-based sync never
    # caches, so it failed offline on a fresh runner (cffi "no version").
    sync_env = {**os.environ, "UV_PROJECT_ENVIRONMENT": str(venv)}
    sync = [
        "uv",
        "sync",
        "-q",
        "--frozen",
        "--offline",
        "--no-dev",
        "--no-install-project",
        "--python",
        sys.executable,
    ]
    run(sync, cwd=ROOT, env=sync_env)
    run(["uv", "pip", "install", "-q", "--offline", "--no-deps", "--python", vpy, str(wheel)])
    run(["uv", "pip", "check", "-q", "--python", vpy])  # the wheel's own requirements are met
    # A clean environment: no PYTHONPATH/PYTHONHOME, so the installed wheel (not a source tree) is what runs.
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    env["SENTINEL_HOME"] = str(out / "home")
    v = json.loads(run([str(venv / "bin" / "sentinel"), "--json", "version"], env=env).stdout)
    sc = subprocess.run(
        [str(venv / "bin" / "sentinel"), "--json", "self-check"], env=env, capture_output=True, text=True
    )
    check = json.loads(sc.stdout)
    if v.get("sentinel_version") != pyver or check.get("status") != "verified" or sc.returncode != 0:
        print(f"installed package check failed: {v} {check}", file=sys.stderr)
        return 5
    report["self_check"] = {"status": check["status"], "checked": check["checked"]}
    doc = sbom.build(wheel)
    errs = sbom.validate(doc, wheel)
    if errs:
        print("SBOM invalid: " + "; ".join(errs), file=sys.stderr)
        return 5
    (dist / "sentinel-sbom.cdx.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    report["sbom_components"] = [c["purl"] for c in doc["components"]]
    (dist / "SHA256SUMS").write_bytes(sha256sums(dist))
    report["artifacts"] = (dist / "SHA256SUMS").read_text().splitlines()
    shutil.rmtree(out / "a")
    shutil.rmtree(out / "b")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
