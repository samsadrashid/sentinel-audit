"""M10: installed-package self-check and release SHA256SUMS. Unverifiable is never a pass."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel import cli, release


def test_development_install_is_unverifiable_not_verified(capsys):
    r = release.self_check()
    assert r["status"] in {"unverifiable", "verified"}
    if r["status"] == "unverifiable":
        code = cli.main(["--json", "self-check"], cli.Deps(env={}))
        out = json.loads(capsys.readouterr().out)
        assert code == cli.EXIT_INCOMPLETE and out["status"] == "unverifiable"
        assert out["reason"] in {"editable_install", "package_not_from_distribution"}


def test_unknown_distribution_is_unverifiable():
    r = release.self_check("sentinel-no-such-dist")
    assert r["status"] == "unverifiable" and r["reason"] == "distribution_not_installed"


def test_sha256sums_is_deterministic_and_skips_links(tmp_path):
    (tmp_path / "b.whl").write_bytes(b"b")
    (tmp_path / "a.tar.gz").write_bytes(b"a")
    (tmp_path / "link").symlink_to(tmp_path / "a.tar.gz")
    body = release.sha256sums(tmp_path).decode()
    assert body.splitlines()[0].endswith("  a.tar.gz") and "link" not in body
    assert body == release.sha256sums(tmp_path).decode()
    with pytest.raises(ValueError):
        release.sha256sums(tmp_path / "empty" if (tmp_path / "empty").mkdir() is None else tmp_path)


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv unavailable (not a pass)")
def test_wheel_install_verifies_and_detects_tampering(tmp_path):
    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    r = subprocess.run(
        ["uv", "build", "--wheel", "--offline", "-o", str(dist), str(root)], capture_output=True, timeout=300
    )
    if r.returncode != 0:
        pytest.skip("offline wheel build unavailable (not a pass)")
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", "-q", "--offline", str(venv)], check=True, timeout=120)
    py = venv / "bin" / "python"
    whl = next(dist.glob("*.whl"))
    subprocess.run(
        ["uv", "pip", "install", "-q", "--offline", "--no-deps", "--python", str(py), str(whl)],
        check=True,
        timeout=300,
    )
    probe = "import json;from sentinel import release;print(json.dumps(release.self_check()))"
    first = json.loads(subprocess.run([str(py), "-I", "-c", probe], capture_output=True, text=True).stdout)
    assert first["status"] == "verified" and first["checked"] > 50
    target = subprocess.run(
        [str(py), "-I", "-c", "import sentinel.compare as c;print(c.__file__)"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    with open(target, "a") as fh:
        fh.write("# tampered\n")
    second = json.loads(subprocess.run([str(py), "-I", "-c", probe], capture_output=True, text=True).stdout)
    assert second["status"] == "mismatch"
    assert {"file": "sentinel/compare.py", "problem": "mismatch"} in second["problems"]
    pkg = Path(target).parent
    (pkg / "compare.py").write_bytes(Path(target).read_bytes().replace(b"# tampered\n", b""))
    restored = json.loads(subprocess.run([str(py), "-I", "-c", probe], capture_output=True, text=True).stdout)
    assert restored["status"] == "verified"  # __pycache__ written by the probes is not flagged
    for planted in ("planted.py", "schemas/planted.json"):
        (pkg / planted).write_text("x = 1\n")
        third = json.loads(
            subprocess.run([str(py), "-I", "-c", probe], capture_output=True, text=True).stdout
        )
        assert third["status"] == "mismatch" and third["reason"] == "unexpected_files"
        assert {"file": planted, "problem": "unexpected_file"} in third["problems"]
        (pkg / planted).unlink()
    (pkg / "fixplan.py").unlink()
    fourth = json.loads(subprocess.run([str(py), "-I", "-c", probe], capture_output=True, text=True).stdout)
    assert fourth["status"] == "missing"
    assert sys.version_info >= (3, 12)


def test_sha256sums_excludes_dotfiles_written_by_build_tools(tmp_path):
    (tmp_path / "sentinel_audit-0.1.0-py3-none-any.whl").write_bytes(b"w")
    (tmp_path / ".gitignore").write_text("*\n")
    body = release.sha256sums(tmp_path).decode()
    assert ".gitignore" not in body and body.count("\n") == 1
