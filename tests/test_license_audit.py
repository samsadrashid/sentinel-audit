"""Third-party license inventory and notices (D-03): scripts/license_audit.py."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("license_audit", REPO / "scripts" / "license_audit.py")
assert _spec and _spec.loader
la = importlib.util.module_from_spec(_spec)
import sys  # noqa: E402

sys.modules["license_audit"] = la
_spec.loader.exec_module(la)

MIT_TEXT = "MIT License\n\nCopyright (c) 2020 Synthetic Example Authors\n\nPermission is hereby granted...\n"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_dist(
    site: Path,
    name: str,
    version: str,
    *,
    expr: str | None = "MIT",
    classifiers: tuple[str, ...] = (),
    license_text: str | None = MIT_TEXT,
    tamper: bool = False,
    suffix: str = "",
    license_field: str | None = None,
) -> None:
    d = site / f"{name.replace('-', '_')}-{version}{suffix}.dist-info"
    (d / "licenses").mkdir(parents=True)
    meta = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    if expr is not None:
        meta.append(f"License-Expression: {expr}")
    if license_field is not None:
        meta.append(f"License: {license_field}")
    meta += [f"Classifier: {c}" for c in classifiers]
    record = []
    if license_text is not None:
        meta.append("License-File: LICENSE")
        raw = license_text.encode()
        (d / "licenses" / "LICENSE").write_bytes(raw + (b"tampered" if tamper else b""))
        record.append(f"{d.name}/licenses/LICENSE,sha256={_b64(raw)},{len(raw)}")
    (d / "METADATA").write_text("\n".join(meta) + "\n\nbody\n")
    (d / "RECORD").write_text("\n".join(record) + "\n")


def lock_text(packages: list[dict[str, Any]], runtime: list[str], dev: list[str]) -> str:
    out = ["version = 1", "revision = 3", 'requires-python = ">=3.12"', ""]
    for p in packages:
        out += ["[[package]]", f'name = "{p["name"]}"', f'version = "{p["version"]}"']
        out.append('source = { registry = "https://pypi.org/simple" }')
        deps = p.get("deps", [])
        if deps:
            items = ", ".join(f'{{ name = "{n}"' + (f', marker = "{m}"' if m else "") + " }" for n, m in deps)
            out.append(f"dependencies = [{items}]")
        out.append(
            f'sdist = {{ url = "https://example.invalid/{p["name"]}.tar.gz", hash = "sha256:{"ab" * 32}" }}'
        )
        out.append("")
    rt = ", ".join(f'{{ name = "{n}" }}' for n in runtime)
    dv = ", ".join(f'{{ name = "{n}" }}' for n in dev)
    out += [
        "[[package]]",
        'name = "sentinel-audit"',
        'version = "0.1.0.dev1"',
        'source = { editable = "." }',
        f"dependencies = [{rt}]",
        "",
        "[package.dev-dependencies]",
        f"dev = [{dv}]",
        "",
    ]
    return "\n".join(out)


class World:
    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "repo"
        self.site = tmp / "site"
        self.root.mkdir()
        self.site.mkdir()
        self.packages: list[dict[str, Any]] = []
        self.runtime: list[str] = []
        self.dev: list[str] = []

    def add(
        self, name: str, version: str = "1.0", deps: tuple[tuple[str, str | None], ...] = (), **kw: Any
    ) -> None:
        self.packages.append({"name": name, "version": version, "deps": list(deps)})
        if kw.pop("install", True):
            make_dist(self.site, name, version, **kw)

    def write(self) -> None:
        (self.root / "uv.lock").write_text(lock_text(self.packages, self.runtime, self.dev))
        if not (self.root / la.REVIEW_PATH).exists():
            self.review_all()

    def review_all(self, status: str = "approved", **extra: Any) -> dict[str, Any]:
        (self.root / "uv.lock").write_text(lock_text(self.packages, self.runtime, self.dev))
        audit = la.run_audit(self.root, self.site, review_path=self._empty_review())
        reg: dict[str, Any] = {"packages": {}, "native": []}
        for p in audit.inventory["packages"]:
            reg["packages"][p["name"]] = {
                "version": p["version"],
                "scope": p["scope"],
                "license": p.get("license"),
                "license_files": {k: v["sha256"] for k, v in p.get("license_files", {}).items()},
                "status": status,
                "notes": "synthetic",
                "attribution": "synthetic attribution",
                **extra.get(p["name"], {}),
            }
        self.save_review(reg)
        return reg

    def _empty_review(self) -> Path:
        p = self.root / "empty-review.json"
        p.write_text('{"packages": {}, "native": []}')
        return p

    def save_review(self, reg: dict[str, Any]) -> None:
        (self.root / "licenses").mkdir(exist_ok=True)
        (self.root / la.REVIEW_PATH).write_text(json.dumps(reg))

    def audit(self) -> Any:
        return la.run_audit(self.root, self.site)

    def codes(self) -> set[tuple[str, str]]:
        return {(i["package"], i["code"]) for i in self.audit().issues}


@pytest.fixture
def world(tmp_path: Path) -> World:
    w = World(tmp_path)
    w.add("alpha", deps=(("beta", None),))
    w.add(
        "beta",
        deps=(("gamma", "platform_python_implementation != 'PyPy'"),),
        expr="Apache-2.0 OR BSD-3-Clause",
    )
    w.add("gamma", expr="BSD-3-Clause")
    w.add("devtool", deps=(("winonly", "sys_platform == 'win32'"),))
    w.add("winonly", install=False)
    w.runtime = ["alpha"]
    w.dev = ["devtool"]
    return w


# --- inventory completeness ---------------------------------------------------------------------


def test_runtime_and_dev_inventoried_separately_with_transitive_deps(world: World) -> None:
    world.write()
    inv = world.audit().inventory
    scopes = {p["name"]: p["scope"] for p in inv["packages"]}
    assert scopes == {
        "alpha": "runtime",
        "beta": "runtime",
        "gamma": "runtime",
        "devtool": "dev",
        "winonly": "dev",
    }
    gamma = next(p for p in inv["packages"] if p["name"] == "gamma")
    assert gamma["dependency_path"] == ["sentinel-audit", "alpha", "beta", "gamma"]
    assert gamma["markers"] == ["platform_python_implementation != 'PyPy'"]
    assert inv["counts"] == {"runtime": 3, "dev": 2, "build": 0}


def test_marker_gated_package_not_silently_dropped(world: World) -> None:
    world.write()
    assert ("winonly", "not_installed") in world.codes()


def test_shared_dependency_is_runtime_not_dev(world: World) -> None:
    world.packages[3]["deps"].append(("gamma", None))
    world.write()
    inv = world.audit().inventory
    assert next(p for p in inv["packages"] if p["name"] == "gamma")["scope"] == "runtime"


def test_orphan_and_missing_lock_entries(world: World) -> None:
    world.add("orphan")
    world.packages[0]["deps"].append(("ghost", None))
    world.write()
    codes = world.codes()
    assert ("orphan", "orphan_locked") in codes
    assert ("ghost", "missing_from_lock") in codes


def test_real_repository_inventory_covers_every_locked_package() -> None:
    import tomllib

    lock = tomllib.loads((REPO / "uv.lock").read_text())
    locked = {la.normalize(p["name"]) for p in lock["package"]} - {la.ROOT_PACKAGE}
    inv = json.loads((REPO / la.INVENTORY_PATH).read_text())
    assert {p["name"] for p in inv["packages"] if p["scope"] != "build"} == locked
    runtime = {p["name"] for p in inv["packages"] if p["scope"] == "runtime"}
    assert runtime == {"cryptography", "cffi", "pycparser"}


# --- license metadata ---------------------------------------------------------------------------


def test_missing_license_metadata(world: World) -> None:
    world.add("bare", expr=None)
    world.runtime.append("bare")
    world.write()
    assert ("bare", "missing_license_metadata") in world.codes()


def test_classifier_only_is_ambiguous_never_inferred(world: World) -> None:
    world.add("classy", expr=None, classifiers=("License :: OSI Approved :: MIT License",))
    world.dev.append("classy")
    world.write()
    audit = world.audit()
    entry = next(p for p in audit.inventory["packages"] if p["name"] == "classy")
    assert entry["license"] is None and entry["license_basis"] == "classifier only"
    assert ("classy", "ambiguous_license") in {(i["package"], i["code"]) for i in audit.issues}


def test_license_never_inferred_from_name(world: World) -> None:
    world.add("mit-license", expr=None, license_text=None)
    world.runtime.append("mit-license")
    world.write()
    entry = next(p for p in world.audit().inventory["packages"] if p["name"] == "mit-license")
    assert entry["license"] is None
    assert ("mit-license", "no_license_file") in world.codes()


def test_free_form_license_field_is_not_a_license(world: World) -> None:
    world.add("prose", expr=None, license_field="BSD, see LICENSE for details")
    world.add("single", expr=None, license_field="MIT")
    world.runtime += ["prose", "single"]
    world.write()
    inv = {p["name"]: p for p in world.audit().inventory["packages"]}
    assert inv["prose"]["license"] is None and inv["prose"]["license_field"] == "BSD, see LICENSE for details"
    assert ("prose", "missing_license_metadata") in world.codes()
    assert inv["single"]["license"] == "MIT"
    assert inv["single"]["license_basis"] == "License field (single identifier)"


def test_unknown_license(world: World) -> None:
    world.add("weird", expr="Frobnicate-1.0")
    world.runtime.append("weird")
    world.write()
    assert ("weird", "unknown_license") in world.codes()


def test_malformed_expression(world: World) -> None:
    world.add("broken", expr="MIT OR (Apache-2.0")
    world.runtime.append("broken")
    world.write()
    assert ("broken", "malformed_license") in world.codes()


def test_copyleft_incompatible_at_runtime_but_allowed_for_dev(world: World) -> None:
    world.add("gplrt", expr="GPL-3.0-only")
    world.add("gpldev", expr="GPL-3.0-only")
    world.runtime.append("gplrt")
    world.dev.append("gpldev")
    world.write()
    codes = world.codes()
    assert ("gplrt", "incompatible_license") in codes
    assert ("gpldev", "incompatible_license") not in codes


@pytest.mark.parametrize(
    ("expr", "ok"),
    [
        ("MIT", True),
        ("Apache-2.0 OR BSD-3-Clause", True),
        ("GPL-3.0-only OR MIT", True),
        ("GPL-3.0-only AND MIT", False),
        ("(MIT AND BSD-2-Clause) OR GPL-2.0-only", True),
        ("Apache-2.0 WITH LLVM-exception", False),
        ("MPL-2.0", False),
    ],
)
def test_spdx_evaluation(expr: str, ok: bool) -> None:
    assert la.spdx_allowed(expr, la.RUNTIME_ALLOWED) is ok


@pytest.mark.parametrize("expr", ["", "MIT OR", "(MIT", "MIT)", "AND MIT", "MIT; rm"])
def test_spdx_malformed(expr: str) -> None:
    with pytest.raises(ValueError):
        la.spdx_allowed(expr, la.RUNTIME_ALLOWED)


def test_spdx_ids_drop_operators_and_exceptions() -> None:
    assert la.spdx_ids("(Apache-2.0 WITH LLVM-exception) OR MIT") == ["Apache-2.0", "MIT"]


def test_tampered_license_file_not_verified_or_copied(world: World) -> None:
    world.add("tampered", tamper=True)
    world.runtime.append("tampered")
    world.write()
    audit = world.audit()
    assert ("tampered", "license_file_unverified") in {(i["package"], i["code"]) for i in audit.issues}
    notices = la.render_notices(audit)
    assert "tampered" in notices and "TEXT NOT REPRODUCED" in notices
    assert notices.count("Synthetic Example Authors") == 3  # alpha, beta, gamma only


def test_license_file_declared_but_absent(world: World) -> None:
    world.write()
    (world.site / "gamma-1.0.dist-info" / "licenses" / "LICENSE").unlink()
    assert ("gamma", "license_file_missing") in world.codes()


# --- duplicates and versions --------------------------------------------------------------------


def test_duplicate_locked_package(world: World) -> None:
    world.packages.append({"name": "gamma", "version": "2.0", "deps": []})
    world.write()
    assert ("gamma", "duplicate_locked") in world.codes()


def test_duplicate_installed_package(world: World) -> None:
    make_dist(world.site, "gamma", "1.0", suffix="-copy", expr="BSD-3-Clause")
    world.write()
    assert ("gamma", "duplicate_installed") in world.codes()


def test_name_normalisation_detects_duplicates(world: World) -> None:
    world.packages.append({"name": "Gamma_", "version": "1.0", "deps": []})
    world.packages[-1]["name"] = "GAMMA"
    world.write()
    assert ("gamma", "duplicate_locked") in world.codes()


def test_installed_version_mismatch(world: World) -> None:
    world.write()
    world.packages[2]["version"] = "1.1"
    (world.root / "uv.lock").write_text(lock_text(world.packages, world.runtime, world.dev))
    codes = world.codes()
    assert ("gamma", "version_mismatch") in codes
    assert ("gamma", "unreviewed_change") in codes


# --- review register / CI gate ------------------------------------------------------------------


def _generate(world: World) -> Any:
    audit = world.audit()
    (world.root / la.INVENTORY_PATH).write_text(la.render_inventory(audit))
    (world.root / la.NOTICES_PATH).write_text(la.render_notices(audit))
    return audit


def test_clean_world_passes_check(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["winonly"]["accepted_issues"] = ["not_installed"]
    world.save_review(reg)
    audit = _generate(world)
    assert la.check(world.root, audit, strict=True) == []
    assert la.main(["check", "--root", str(world.root), "--site-packages", str(world.site)]) == 0


def test_unreviewed_package_fails_ci(world: World) -> None:
    world.write()
    world.add("newcomer")
    world.runtime.append("newcomer")
    (world.root / "uv.lock").write_text(lock_text(world.packages, world.runtime, world.dev))
    assert ("newcomer", "unreviewed_package") in world.codes()
    assert la.main(["check", "--root", str(world.root), "--site-packages", str(world.site)]) == 1


@pytest.mark.parametrize("field", ["license", "license_file", "scope"])
def test_unreviewed_license_change_fails_ci(world: World, field: str) -> None:
    world.write()
    if field == "license":
        shutil.rmtree(world.site / "gamma-1.0.dist-info")
        make_dist(world.site, "gamma", "1.0", expr="MIT")
    elif field == "license_file":
        shutil.rmtree(world.site / "gamma-1.0.dist-info")
        make_dist(world.site, "gamma", "1.0", expr="BSD-3-Clause", license_text="Different text\n")
    else:
        world.runtime.remove("alpha")
        world.dev.append("alpha")
        (world.root / "uv.lock").write_text(lock_text(world.packages, world.runtime, world.dev))
    audit = world.audit()
    changed = [i for i in audit.issues if i["code"] == "unreviewed_change"]
    assert changed, audit.issues
    assert la.check(world.root, audit, strict=False)


def test_stale_review_entry(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["removed-long-ago"] = {"status": "approved"}
    world.save_review(reg)
    assert ("removed-long-ago", "stale_review") in world.codes()


def test_accepted_issues_cannot_hide_unreviewed_changes(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["gamma"]["accepted_issues"] = sorted(la.NEVER_ACCEPTABLE)
    reg["packages"]["gamma"]["version"] = "0.9"
    world.save_review(reg)
    assert ("gamma", "unreviewed_change") in world.codes()


def test_accepted_issue_is_acknowledged_not_dropped(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["winonly"]["accepted_issues"] = ["not_installed"]
    world.save_review(reg)
    audit = world.audit()
    assert ("winonly", "not_installed") not in {(i["package"], i["code"]) for i in audit.issues}
    assert [a["code"] for a in audit.acknowledged] == ["not_installed"]


def test_needs_review_fails_only_in_strict_mode(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["winonly"]["accepted_issues"] = ["not_installed"]
    reg["packages"]["beta"]["status"] = "needs_review"
    world.save_review(reg)
    audit = _generate(world)
    assert la.check(world.root, audit, strict=False) == []
    assert [p["code"] for p in la.check(world.root, audit, strict=True)] == ["needs_review"]


def test_invalid_review_status_is_an_error(world: World) -> None:
    world.write()
    world.save_review({"packages": {"alpha": {"status": "looks-fine"}}})
    with pytest.raises(la.AuditError):
        world.audit()
    assert la.main(["check", "--root", str(world.root), "--site-packages", str(world.site)]) == 2


def test_stale_outputs_fail_check(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["winonly"]["accepted_issues"] = ["not_installed"]
    world.save_review(reg)
    audit = _generate(world)
    (world.root / la.NOTICES_PATH).write_text(la.render_notices(audit) + "hand edit\n")
    assert [p["code"] for p in la.check(world.root, audit, strict=False)] == ["stale_output"]


def test_missing_inputs_are_environment_errors(tmp_path: Path) -> None:
    with pytest.raises(la.AuditError):
        la.run_audit(tmp_path, tmp_path)


# --- notices ------------------------------------------------------------------------------------


def test_notice_generation_is_reproducible(world: World, tmp_path: Path) -> None:
    world.write()
    first = (la.render_notices(world.audit()), la.render_inventory(world.audit()))
    shutil.copytree(world.site, tmp_path / "site2")
    second_audit = la.run_audit(world.root, tmp_path / "site2")
    assert (la.render_notices(second_audit), la.render_inventory(second_audit)) == first


def test_notices_preserve_copyright_and_separate_sentinel_license(world: World) -> None:
    world.write()
    notices = la.render_notices(world.audit())
    assert "Copyright (c) 2020 Synthetic Example Authors" in notices
    assert "Sentinel's own license is NOT part of this" in notices
    part1, rest = notices.split("PART 2.")
    assert "devtool" not in part1 and "devtool 1.0" in rest


def test_repository_outputs_are_current() -> None:
    audit = la.run_audit(REPO, la.default_site())
    assert la.check(REPO, audit, strict=False) == []
    notices = (REPO / la.NOTICES_PATH).read_text()
    for name in ("cryptography 46.0.7", "cffi 2.1.1", "pycparser 3.12"):
        assert name in notices
    assert "Copyright (c) 2008-2027, Eli Bendersky" in notices
    assert "Copyright (c) 2024, Rose Davidson" in notices  # cffi's embedded MIT notice
    assert "OpenSSL 3.5.6 (statically linked" in notices and "Apache License" in notices
    assert audit.inventory["counts"] == {"runtime": 3, "build": 6, "dev": 12}


def test_repository_passes_the_strict_release_gate() -> None:
    audit = la.run_audit(REPO, la.default_site())
    assert la.check(REPO, audit, strict=True) == []
    assert audit.open_reviews == []


# --- packaging ----------------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("uv") is None and not os.environ.get("SENTINEL_CI"), reason="uv not available"
)
def test_wheel_and_sdist_include_notices(tmp_path: Path) -> None:
    r = subprocess.run(
        ["uv", "build", "--offline", "--out-dir", str(tmp_path)], cwd=REPO, capture_output=True, text=True
    )
    if r.returncode != 0 and "offline" in (r.stderr + r.stdout).lower():
        if os.environ.get("SENTINEL_CI"):
            r = subprocess.run(
                ["uv", "build", "--out-dir", str(tmp_path)], cwd=REPO, capture_output=True, text=True
            )
        else:
            pytest.skip("build backend not cached for offline build (CI sets SENTINEL_CI and never skips)")
    assert r.returncode == 0, r.stderr
    expected = (REPO / la.NOTICES_PATH).read_bytes()
    (whl,) = tmp_path.glob("*.whl")
    with zipfile.ZipFile(whl) as z:
        names = z.namelist()
        lic = [n for n in names if n.endswith(".dist-info/licenses/THIRD_PARTY_NOTICES")]
        assert len(lic) == 1 and z.read(lic[0]) == expected
        own = [n for n in names if n.endswith(".dist-info/licenses/LICENSE")]
        assert len(own) == 1 and z.read(own[0]) == (REPO / "LICENSE").read_bytes()
        meta = z.read(next(n for n in names if n.endswith(".dist-info/METADATA"))).decode()
        assert "License-Expression: MIT" in meta and "License-File: THIRD_PARTY_NOTICES" in meta
        assert all(n.startswith(("sentinel/", "sentinel_audit-")) for n in names)
    (sdist,) = tmp_path.glob("*.tar.gz")
    with tarfile.open(sdist) as t:
        members = [m.split("/", 1)[1] for m in t.getnames() if "/" in m]
        top = {m.split("/")[0] for m in members}
        notice = t.extractfile(next(m for m in t.getmembers() if m.name.endswith("/THIRD_PARTY_NOTICES")))
        assert notice is not None and notice.read() == expected
    assert {"THIRD_PARTY_NOTICES", "LICENSE", "licenses", "scripts", "src"} <= top
    assert not top & {".ecc-src", "tools", ".claude", "integrations"}
    assert not any(m.startswith("docs/private") for m in members)


# --- build dependencies, attribution, embedded and upstream notices (session 13) ----------------

BUILD_LOCK = """# test
hatchling==1.0 \\
    --hash=sha256:{h}
tomlkit==2.0 \\
    --hash=sha256:{h}
""".format(h="ab" * 32)
PINNED = (
    '[build-system]\nrequires = ["hatchling==1.0"]\n\n[tool.uv]\n'
    'build-constraint-dependencies = ["hatchling==1.0", "tomlkit==2.0"]\n'
)


def with_build(world: World, pyproject: str = PINNED, install: bool = True) -> Path:
    bsite = world.root / "build-site"
    bsite.mkdir(exist_ok=True)
    if install:
        make_dist(bsite, "hatchling", "1.0")
        make_dist(bsite, "tomlkit", "2.0")
    (world.root / "licenses").mkdir(exist_ok=True)
    (world.root / la.BUILD_LOCK_PATH).write_text(BUILD_LOCK)
    (world.root / "pyproject.toml").write_text(pyproject)
    return bsite


def build_codes(world: World, bsite: Path) -> set[tuple[str, str]]:
    return {(i["package"], i["code"]) for i in la.run_audit(world.root, world.site, build_site=bsite).issues}


def test_build_dependencies_are_inventoried_and_must_be_reviewed(world: World) -> None:
    world.write()
    bsite = with_build(world)
    audit = la.run_audit(world.root, world.site, build_site=bsite)
    assert audit.inventory["counts"]["build"] == 2
    codes = {(i["package"], i["code"]) for i in audit.issues}
    assert ("build:hatchling", "unreviewed_package") in codes and (
        "build:tomlkit",
        "unreviewed_package",
    ) in codes


def _review_build(world: World, bsite: Path, **extra: Any) -> None:
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    audit = la.run_audit(world.root, world.site, build_site=bsite)
    for p in audit.inventory["packages"]:
        if p["scope"] == "build":
            reg["packages"][f"build:{p['name']}"] = {
                "version": p["version"],
                "scope": "build",
                "license": p["license"],
                "license_files": {k: v["sha256"] for k, v in p["license_files"].items()},
                "status": "approved",
                "attribution": "build only",
                **extra,
            }
    world.save_review(reg)


def test_reviewed_build_dependencies_pass(world: World) -> None:
    world.write()
    bsite = with_build(world)
    _review_build(world, bsite)
    assert not {c for c in build_codes(world, bsite) if c[0].startswith(("build", "build-system"))}


@pytest.mark.parametrize(
    "pyproject",
    [
        '[build-system]\nrequires = ["hatchling>=1.0"]\n\n[tool.uv]\n'
        'build-constraint-dependencies = ["hatchling==1.0", "tomlkit==2.0"]\n',
        '[build-system]\nrequires = ["hatchling==1.0"]\n',
        '[build-system]\nrequires = ["hatchling==1.0"]\n\n[tool.uv]\n'
        'build-constraint-dependencies = ["hatchling==1.0", "tomlkit==2.1"]\n',
    ],
)
def test_unpinned_or_drifting_build_dependencies_fail(world: World, pyproject: str) -> None:
    world.write()
    bsite = with_build(world, pyproject)
    _review_build(world, bsite)
    assert ("build-system", "unpinned_build_dependency") in build_codes(world, bsite)


def test_changed_build_dependency_version_fails(world: World) -> None:
    world.write()
    bsite = with_build(world)
    _review_build(world, bsite)
    (world.root / la.BUILD_LOCK_PATH).write_text(BUILD_LOCK.replace("tomlkit==2.0", "tomlkit==2.1"))
    codes = build_codes(world, bsite)
    assert ("build:tomlkit", "unreviewed_change") in codes and ("build:tomlkit", "version_mismatch") in codes


def test_missing_build_environment_cannot_be_acknowledged(world: World) -> None:
    world.write()
    bsite = with_build(world, install=False)
    _review_build(world, bsite, accepted_issues=["not_installed", "build_env_missing"])
    codes = build_codes(world, bsite)
    assert ("build-system", "build_env_missing") in codes


@pytest.mark.parametrize("bad", ["hatchling>=1.0", "hatchling==1.0"])
def test_build_lock_must_be_hash_pinned(world: World, bad: str) -> None:
    world.write()
    (world.root / "licenses").mkdir(exist_ok=True)
    (world.root / la.BUILD_LOCK_PATH).write_text(bad + "\n")
    with pytest.raises(la.AuditError):
        la.run_audit(world.root, world.site)


def test_missing_attribution_fails_for_runtime(world: World) -> None:
    world.write()
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["alpha"]["attribution"] = "   "
    reg["packages"]["alpha"]["accepted_issues"] = ["missing_attribution"]
    world.save_review(reg)
    codes = world.codes()
    assert ("alpha", "missing_attribution") in codes
    assert ("devtool", "missing_attribution") not in codes


def _embed(
    world: World, text: str = "# Copyright (c) 2024 Embedded Author\n# MIT\ncode = 1\n"
) -> dict[str, Any]:
    dist = world.site / "gamma-1.0.dist-info"
    (world.site / "gamma").mkdir(exist_ok=True)
    f = world.site / "gamma" / "vendored.py"
    f.write_text(text)
    raw = f.read_bytes()
    with (dist / "RECORD").open("a") as fh:
        fh.write(f"gamma/vendored.py,sha256={_b64(raw)},{len(raw)}\n")
    return {"path": "gamma/vendored.py", "sha256": hashlib.sha256(raw).hexdigest(), "start": 1, "end": 2}


def test_embedded_notice_is_reproduced_when_verified(world: World) -> None:
    world.write()
    note = _embed(world)
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["gamma"]["embedded_notices"] = [note]
    world.save_review(reg)
    audit = world.audit()
    notices = la.render_notices(audit)
    assert "Copyright (c) 2024 Embedded Author" in notices and "code = 1" not in notices
    assert ("gamma", "embedded_notice_unverified") not in world.codes()


@pytest.mark.parametrize("tamper", ["file", "record", "path"])
def test_embedded_notice_tampering_is_detected(world: World, tamper: str) -> None:
    world.write()
    note = _embed(world)
    if tamper == "file":
        (world.site / "gamma" / "vendored.py").write_text("# altered\n")
    elif tamper == "record":
        note["sha256"] = "0" * 64
    else:
        note["path"] = "../outside.py"
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["gamma"]["embedded_notices"] = [note]
    world.save_review(reg)
    audit = world.audit()
    assert ("gamma", "embedded_notice_unverified") in {(i["package"], i["code"]) for i in audit.issues}
    assert "Embedded Author" not in la.render_notices(audit)


@pytest.mark.parametrize("tamper", [None, "hash", "url", "path"])
def test_upstream_license_text_requires_hash_and_source(world: World, tamper: str | None) -> None:
    world.write()
    texts = world.root / "licenses" / "texts"
    texts.mkdir(parents=True, exist_ok=True)
    (texts / "up.txt").write_text("Upstream License Text\n")
    up = {
        "component": "Vendored C library",
        "file": "licenses/texts/up.txt",
        "sha256": hashlib.sha256(b"Upstream License Text\n").hexdigest(),
        "source_url": "https://example.invalid/LICENSE",
    }
    if tamper == "hash":
        up["sha256"] = "0" * 64
    elif tamper == "url":
        up["source_url"] = ""
    elif tamper == "path":
        up["file"] = "README.md"
    reg = json.loads((world.root / la.REVIEW_PATH).read_text())
    reg["packages"]["alpha"]["upstream_texts"] = [up]
    world.save_review(reg)
    audit = world.audit()
    flagged = ("alpha", "upstream_text_unverified") in {(i["package"], i["code"]) for i in audit.issues}
    assert flagged is (tamper is not None)
    assert ("Upstream License Text" in la.render_notices(audit)) is (tamper is None)


def test_repository_build_pins_match_lock() -> None:
    build = la.load_build_lock(REPO / la.BUILD_LOCK_PATH)
    assert la.check_build_pins(REPO / "pyproject.toml", build) == []
    assert {n for n, _, _ in build} == {
        "hatchling",
        "packaging",
        "pathspec",
        "pluggy",
        "tomlkit",
        "trove-classifiers",
    }


def test_sentinel_license_is_separate_from_third_party_notices() -> None:
    own = (REPO / "LICENSE").read_text()
    assert own.startswith("MIT License\n\nCopyright (c) 2026 Samsad Rashid Ony\n")
    assert "Samsad Rashid Ony" not in (REPO / la.NOTICES_PATH).read_text()


def test_residual_risks_are_disclosed_not_presented_as_verified() -> None:
    reg = json.loads((REPO / la.REVIEW_PATH).read_text())
    ids = {r["id"] for r in reg["residual_risks"]}
    assert ids == {"LR-1", "LR-2", "LR-3", "LR-4"}
    notices = (REPO / la.NOTICES_PATH).read_text()
    assert "RESIDUAL LICENSING RISKS (accepted, NOT verified)" in notices
    assert all(i in notices for i in ids)
    doc = (REPO / "docs/m1/licensing.md").read_text()
    assert all(f"| {i} |" in doc for i in ids)
