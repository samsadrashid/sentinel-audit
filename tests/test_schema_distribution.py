"""D-40 distribution checks: every contract ships in the wheel and the sdist, and loads once installed."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "src" / "sentinel" / "schemas"
EXPECTED = sorted(p.name for p in SCHEMA_DIR.glob("*.schema.json"))


@pytest.fixture(scope="module")
def dist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is required to build the distribution under test")
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(
        [uv, "build", "--offline", "-o", str(out)], cwd=ROOT, check=True, capture_output=True, timeout=300
    )
    return out


def _one(dist: Path, pattern: str) -> Path:
    found = sorted(dist.glob(pattern))
    assert len(found) == 1, found
    return found[0]


def test_source_tree_has_every_contract() -> None:
    assert len(EXPECTED) == 24  # common, 18 D-40 artifacts, 4 D-49 signing-protocol contracts, fix-plan
    assert "common.schema.json" in EXPECTED


def test_wheel_contains_every_schema_byte_identical(dist: Path) -> None:
    with zipfile.ZipFile(_one(dist, "*.whl")) as whl:
        names = {n for n in whl.namelist() if n.startswith("sentinel/schemas/")}
        assert sorted(Path(n).name for n in names) == EXPECTED
        for name in EXPECTED:
            assert whl.read(f"sentinel/schemas/{name}") == (SCHEMA_DIR / name).read_bytes()


def test_sdist_contains_every_schema_and_fixture(dist: Path) -> None:
    with tarfile.open(_one(dist, "*.tar.gz")) as sd:
        members = {m.name.split("/", 1)[1] for m in sd.getmembers() if "/" in m.name}
    for name in EXPECTED:
        assert f"src/sentinel/schemas/{name}" in members
    assert "tests/fixtures/schemas/historical/signed/SHA256SUMS" in members
    assert "docs/m1/schemas.md" in members


def test_installed_wheel_loads_contracts(dist: Path, tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    target = tmp_path / "site"
    subprocess.run(
        [uv, "pip", "install", "--offline", "--no-deps", "--target", str(target), str(_one(dist, "*.whl"))],
        check=True,
        capture_output=True,
        timeout=300,
    )
    code = (
        "import sys, json; sys.path.insert(0, sys.argv[1]);"
        "import sentinel, sentinel.schema as s; s.ensure_loaded();"
        "print(json.dumps({'file': sentinel.__file__, 'names': sorted(s.contract_names())}))"
    )
    run = subprocess.run(
        [sys.executable, "-I", "-c", code, str(target)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = json.loads(run.stdout)
    assert Path(out["file"]).resolve().is_relative_to(target.resolve())
    assert out["names"] == sorted(n.removesuffix(".schema.json") for n in EXPECTED)


def test_wheel_contains_the_agent_skills(dist: Path) -> None:
    with zipfile.ZipFile(_one(dist, "*.whl")) as whl:
        for agent in ("claude-code", "codex"):
            name = f"sentinel/agent_skills/{agent}/skills/sentinel/SKILL.md"
            src = ROOT / "src" / name
            assert whl.read(name) == src.read_bytes()
