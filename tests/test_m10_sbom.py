"""M10: Sentinel's own SBOM and the release-candidate check (offline, unsigned)."""

from __future__ import annotations

import copy
import hashlib
import importlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from sentinel.adapters.native import ANALYZERS_DIR

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "m10"))
sys.path.insert(0, str(ANALYZERS_DIR))
sbom = importlib.import_module("sbom")
supplychain = importlib.import_module("supplychain")
release_check = importlib.import_module("release_check")

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv unavailable (not a pass)")


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:  # type: ignore[no-untyped-def]
    out = tmp_path_factory.mktemp("dist")
    r = subprocess.run(
        ["uv", "build", "--wheel", "--offline", "-q", "-o", str(out), str(ROOT)], capture_output=True
    )
    if r.returncode != 0:
        pytest.skip("offline wheel build unavailable (not a pass)")
    return next(out.glob("*.whl"))


def test_sbom_lists_the_locked_runtime_closure_with_hashes_and_licences(wheel):
    doc = sbom.build(wheel)
    assert sbom.validate(doc, wheel) == []
    names = [c["name"] for c in doc["components"]]
    assert names == sbom.runtime_closure(sbom.lock_packages()) and "cryptography" in names
    for c in doc["components"]:
        assert c["hashes"] and c["licenses"] and c["purl"].startswith("pkg:pypi/")
    meta = doc["metadata"]["component"]
    assert meta["hashes"][0]["content"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert doc == sbom.build(wheel)  # deterministic


def test_sbom_passes_sentinels_own_sbom_checks(wheel, tmp_path):
    (tmp_path / "sentinel-sbom.cdx.json").write_text(json.dumps(sbom.build(wheel)))
    assert supplychain.analyze(tmp_path) == []


@pytest.mark.parametrize(
    "mutate, problem",
    [
        (lambda d: d["metadata"]["component"]["hashes"][0].update(content="0" * 64), "hash does not match"),
        (lambda d: d["components"].pop(), "differ from the locked runtime closure"),
        (
            lambda d: d["components"].append({**d["components"][0], "name": "evil-extra"}),
            "differ from the locked",
        ),
        (lambda d: d["components"][0].update(purl="npm:bad"), "malformed purl"),
        (lambda d: d["components"][0].pop("licenses"), "missing licenses"),
        (lambda d: d["components"][0].update(hashes=[]), "missing hashes"),
        (lambda d: d.update(specVersion="1.2"), "not CycloneDX 1.5"),
        (lambda d: d["metadata"]["component"].update(version="9.9.9"), "name/version differ"),
    ],
)
def test_tampered_or_incomplete_sbom_is_rejected(wheel, mutate, problem):
    doc = copy.deepcopy(sbom.build(wheel))
    mutate(doc)
    assert any(problem in e for e in sbom.validate(doc, wheel)), sbom.validate(doc, wheel)


def test_sbom_for_a_different_wheel_is_rejected(wheel, tmp_path):
    other = tmp_path / wheel.name
    other.write_bytes(wheel.read_bytes() + b"\0")
    assert any("hash does not match" in e for e in sbom.validate(sbom.build(wheel), other))


def test_release_check_end_to_end(tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/m10/release_check.py"), str(tmp_path / "rc")],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert r.returncode == 0, r.stderr
    rep = json.loads(r.stdout)
    assert rep["reproducible"] is True and rep["signed"] is False
    assert rep["self_check"]["status"] == "verified"
    assert rep["artifact_contents"] == "clean"
    files = sorted(p.name for p in (tmp_path / "rc" / "dist").iterdir())
    assert (
        "SHA256SUMS" in files and "sentinel-sbom.cdx.json" in files and any(f.endswith(".whl") for f in files)
    )
    sums = (tmp_path / "rc" / "dist" / "SHA256SUMS").read_text()
    for line in sums.splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256((tmp_path / "rc" / "dist" / name).read_bytes()).hexdigest() == digest


def test_release_check_refuses_a_non_empty_output_dir(tmp_path):
    (tmp_path / "x").write_text("x")
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/m10/release_check.py"), str(tmp_path)], capture_output=True
    )
    assert r.returncode == 4


def test_release_check_ignores_an_inherited_pythonpath(tmp_path):
    """Regression: a PYTHONPATH pointing at the source tree must not replace the installed wheel."""
    import os

    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts/m10/release_check.py"), str(tmp_path / "rc")],
        capture_output=True,
        text=True,
        timeout=900,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["self_check"]["status"] == "verified"


def _sdist(path: Path, names: list[str]) -> Path:
    with tarfile.open(path, "w:gz") as t:
        for n in names:
            info = tarfile.TarInfo(f"sentinel_audit-1.0/{n}")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
    return path


def _wheel(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for n in names:
            z.writestr(n, "x")
    return path


CLEAN = [
    "src/sentinel/cli.py",
    "native/macos/sentinel-signer/Package.swift",
    "tests/fixtures/d10d11/agent/c-c01/.claude/settings.json",
]


@pytest.mark.parametrize(
    "bad",
    [
        "native/macos/sentinel-signer/.build/out/SDKExplicitPrecompiledModules/AppKit-X.pcm",
        "native/macos/sentinel-signer/.build/debug",
        "native/macos/sentinel-signer/.swiftpm/configuration/x",
        "src/sentinel/__pycache__/cli.cpython-312.pyc",
        "src/sentinel/stray.pyc",
        "docs/private/notes.md",
        ".ecc-src/hook.js",
        "native/macos/libx.dylib",
        "tests/.DS_Store",
    ],
)
def test_release_artifact_check_refuses_build_output_and_private_material(tmp_path, bad):
    """Regression: a SwiftPM .build/ (95 MB of SDK modules) once shipped inside the sdist unnoticed."""
    assert release_check.artifact_problems(_sdist(tmp_path / "ok.tar.gz", CLEAN)) == []
    problems = release_check.artifact_problems(_sdist(tmp_path / "bad.tar.gz", [*CLEAN, bad]))
    assert len(problems) == 1 and "1 forbidden member" in problems[0] and bad in problems[0]


def test_release_artifact_check_covers_wheels_size_and_unknown_types(tmp_path, monkeypatch):
    assert release_check.artifact_problems(_wheel(tmp_path / "a.whl", ["sentinel/cli.py"])) == []
    assert release_check.artifact_problems(_wheel(tmp_path / "b.whl", ["sentinel/__pycache__/cli.pyc"]))
    (tmp_path / "c.zip").write_bytes(b"x")
    assert release_check.artifact_problems(tmp_path / "c.zip") == ["c.zip: unknown artifact type"]
    monkeypatch.setattr(release_check, "MAX_ARTIFACT_BYTES", 10)
    assert any("exceeds" in p for p in release_check.artifact_problems(_sdist(tmp_path / "d.tar.gz", CLEAN)))


def test_release_check_reports_the_failing_tools_own_error(capsys):
    """Regression: remote CI showed only a bare CalledProcessError, hiding uv's resolution error."""
    with pytest.raises(subprocess.CalledProcessError):
        release_check.run(["sh", "-c", "echo 'No solution found' >&2; exit 3"])
    err = capsys.readouterr().err
    assert "command failed (3)" in err and "No solution found" in err


def test_release_check_clean_install_uses_the_lock_not_the_index():
    """Regression: `uv pip install -r` re-resolved through index pages a lock-based `uv sync` never caches,
    so the clean install failed offline on fresh CI runners ("no version of cffi==2.1.1"). Reproduced on
    the DM by hiding the runtime packages' index entries; the uv sync path passes with them hidden."""
    src = (ROOT / "scripts" / "m10" / "release_check.py").read_text()
    flags = ('"sync"', '"--frozen"', '"--offline"', '"--no-dev"', '"--no-install-project"', "sys.executable")
    for flag in flags:
        assert flag in src, flag
    assert '"--no-deps"' in src and '"check"' in src
    assert '"-r"' not in src and "uv export" not in src
