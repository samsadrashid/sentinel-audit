#!/usr/bin/env python3
"""Reproducible third-party license audit for Sentinel (D-03).

Reads three inputs and nothing else (no network):

* ``uv.lock``: the authoritative list of locked packages, versions, sources and the dependency graph;
* an installed ``site-packages`` directory: each package's own ``METADATA`` and license files, with
  every license file checked against the hash in that package's ``RECORD``;
* ``licenses/review.json``: the human-reviewed license register.

Commands:

* ``inventory``: write ``licenses/inventory.json``;
* ``notices``: write ``THIRD_PARTY_NOTICES``;
* ``check``: regenerate both in memory and fail (exit 1) when either file is stale, a package is
  unreviewed, a reviewed fact changed (version, license, license-file hash, scope), a runtime license
  is outside the allowed set, or license metadata is missing or unverifiable. ``--strict`` also fails
  on entries the register still marks ``needs_review`` (release gate).

The script never infers a license from a package name, never upgrades or installs anything, and
copies license text into the notices only when the file's hash matches the package's ``RECORD``.
Exit codes: 0 clean, 1 audit issues, 2 usage or environment error.
"""

from __future__ import annotations

import argparse
import base64
import email.parser
import hashlib
import json
import re
import sys
import sysconfig
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT_PACKAGE = "sentinel-audit"
INVENTORY_PATH = Path("licenses/inventory.json")
REVIEW_PATH = Path("licenses/review.json")
NOTICES_PATH = Path("THIRD_PARTY_NOTICES")
BUILD_LOCK_PATH = Path("licenses/build-lock.txt")
BUILD_ENV = Path("build/license-env")
#: Scopes whose reviewed entries must state an attribution requirement (what a redistributor owes).
ATTRIBUTION_SCOPES = frozenset({"runtime", "build"})

#: SPDX identifiers this audit recognises. Anything else is ``unknown_license``.
KNOWN_SPDX = frozenset(
    {
        "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "MIT-0", "MPL-2.0",
        "PSF-2.0", "Python-2.0", "Unlicense", "Zlib", "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0-only", "LGPL-3.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only",
        "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
    }
)  # fmt: skip
#: Licenses acceptable for components installed with Sentinel at runtime (MIT-compatible, permissive).
RUNTIME_ALLOWED = frozenset(
    {"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "MIT-0", "PSF-2.0", "Zlib"}
)
#: Trove classifiers are recorded but only ever treated as ambiguous evidence needing review.
CLASSIFIER_HINTS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-?",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}
#: Issue codes a reviewer may acknowledge in ``accepted_issues``; these can never be acknowledged.
NEVER_ACCEPTABLE = frozenset(
    {
        "unreviewed_package",
        "unreviewed_change",
        "stale_review",
        "license_file_unverified",
        "version_mismatch",
        "missing_attribution",
        "unpinned_build_dependency",
        "build_env_missing",
        "embedded_notice_unverified",
        "upstream_text_unverified",
    }
)
REVIEW_STATUSES = frozenset({"approved", "needs_review"})


class AuditError(Exception):
    """Environment or input error (exit 2)."""


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# --- SPDX expressions ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+-]+)")


def spdx_ids(expr: str) -> list[str]:
    """License identifiers in an SPDX expression (operators and WITH exceptions removed)."""
    tokens = _tokens(expr)
    out: list[str] = []
    skip_next = False
    for t in tokens:
        if skip_next:
            skip_next = False
            continue
        if t == "WITH":
            skip_next = True
        elif t not in {"AND", "OR", "(", ")"}:
            out.append(t)
    return out


def _tokens(expr: str) -> list[str]:
    pos, out = 0, []
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if m is None:
            raise ValueError(f"malformed SPDX expression: {expr!r}")
        out.append(m.group(1))
        pos = m.end()
    if not out:
        raise ValueError("empty SPDX expression")
    return out


def spdx_allowed(expr: str, allowed: frozenset[str]) -> bool:
    """True if the expression can be satisfied using only ``allowed`` licenses (OR: any branch;
    AND: every operand). ``WITH`` exceptions are not accepted at runtime without review."""
    tokens = _tokens(expr)
    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        value = parse_and()
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            rhs = parse_and()
            value = value or rhs
        return value

    def parse_and() -> bool:
        nonlocal pos
        value = parse_atom()
        while pos < len(tokens) and tokens[pos] == "AND":
            pos += 1
            rhs = parse_atom()
            value = value and rhs
        return value

    def parse_atom() -> bool:
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError(f"malformed SPDX expression: {expr!r}")
        tok = tokens[pos]
        pos += 1
        if tok == "(":
            value = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError(f"unbalanced SPDX expression: {expr!r}")
            pos += 1
            return value
        if tok in {")", "AND", "OR", "WITH"}:
            raise ValueError(f"malformed SPDX expression: {expr!r}")
        if pos < len(tokens) and tokens[pos] == "WITH":
            pos += 2
            return False
        return tok in allowed

    result = parse_or()
    if pos != len(tokens):
        raise ValueError(f"malformed SPDX expression: {expr!r}")
    return result


# --- lockfile -----------------------------------------------------------------------------------


@dataclass
class Locked:
    name: str
    version: str
    source: dict[str, str]
    deps: list[tuple[str, str | None]]
    sdist_sha256: str | None
    wheel_count: int


def load_lock(path: Path) -> tuple[dict[str, Locked], list[str], dict[str, list[str]], list[dict[str, Any]]]:
    """Returns (packages, runtime roots, dev-group roots, issues)."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AuditError(f"cannot read lockfile {path}: {exc}") from exc
    pkgs: dict[str, Locked] = {}
    issues: list[dict[str, Any]] = []
    root: dict[str, Any] | None = None
    for p in data.get("package", []):
        name = normalize(p["name"])
        if name in pkgs:
            issues.append(
                _issue(
                    name, "duplicate_locked", f"locked more than once ({pkgs[name].version}, {p['version']})"
                )
            )
            continue
        sdist = p.get("sdist", {}).get("hash")
        pkgs[name] = Locked(
            name=name,
            version=str(p["version"]),
            source={str(k): str(v) for k, v in p.get("source", {}).items()},
            deps=[(normalize(d["name"]), d.get("marker")) for d in p.get("dependencies", [])],
            sdist_sha256=sdist.removeprefix("sha256:") if isinstance(sdist, str) else None,
            wheel_count=len(p.get("wheels", [])),
        )
        if name == ROOT_PACKAGE:
            root = p
    if root is None:
        raise AuditError(f"lockfile has no {ROOT_PACKAGE} package")
    runtime = [normalize(d["name"]) for d in root.get("dependencies", [])]
    dev = {g: [normalize(d["name"]) for d in v] for g, v in root.get("dev-dependencies", {}).items()}
    return pkgs, runtime, dev, issues


def closure(pkgs: dict[str, Locked], roots: list[str]) -> dict[str, list[str]]:
    """Every package reachable from ``roots`` (markers included, never silently dropped), mapped to the
    shortest dependency path that pulls it in."""
    paths: dict[str, list[str]] = {}
    queue = [(r, [ROOT_PACKAGE, r]) for r in roots]
    while queue:
        name, via = queue.pop(0)
        if name in paths:
            continue
        paths[name] = via
        if name not in pkgs:
            continue
        for dep, _marker in pkgs[name].deps:
            queue.append((dep, [*via, dep]))
    return paths


# --- installed metadata -------------------------------------------------------------------------


def _record_hashes(dist: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    rec = dist / "RECORD"
    if not rec.is_file():
        return out
    for line in rec.read_text(encoding="utf-8").splitlines():
        parts = line.rsplit(",", 2)
        if len(parts) == 3 and parts[1].startswith("sha256="):
            raw = base64.urlsafe_b64decode(parts[1][7:] + "=" * (-len(parts[1][7:]) % 4))
            out[parts[0]] = raw.hex()
    return out


def find_dists(site: Path) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {}
    for d in sorted(site.glob("*.dist-info")):
        meta = d / "METADATA"
        if not meta.is_file():
            continue
        headers = email.parser.BytesHeaderParser().parsebytes(meta.read_bytes())
        found.setdefault(normalize(str(headers.get("Name", ""))), []).append(d)
    return found


@dataclass
class Observed:
    installed_version: str | None = None
    license: str | None = None
    basis: str = "none"
    license_field: str | None = None
    classifiers: list[str] = field(default_factory=list)
    license_files: dict[str, dict[str, Any]] = field(default_factory=dict)
    texts: dict[str, str] = field(default_factory=dict)
    home: str | None = None


def observe(dist: Path, site: Path) -> Observed:
    headers = email.parser.BytesHeaderParser().parsebytes((dist / "METADATA").read_bytes())
    ob = Observed(installed_version=str(headers.get("Version", "")) or None)
    expr = headers.get("License-Expression")
    lic_field = headers.get("License")
    ob.classifiers = sorted(
        str(c) for c in headers.get_all("Classifier", []) if str(c).startswith("License ::")
    )
    if lic_field is not None:
        ob.license_field = str(lic_field).strip()
    if expr is not None and str(expr).strip():
        ob.license, ob.basis = str(expr).strip(), "License-Expression"
    elif ob.license_field and re.fullmatch(r"[A-Za-z0-9.+-]+", ob.license_field):
        ob.license, ob.basis = ob.license_field, "License field (single identifier)"
    elif ob.classifiers:
        ob.basis = "classifier only"
    for url in headers.get_all("Project-URL", []) or []:
        label, _, link = str(url).partition(",")
        if label.strip().lower() in {"source", "source code", "homepage", "repository", "github"}:
            ob.home = ob.home or link.strip()
    ob.home = ob.home or (str(headers["Home-page"]) if headers.get("Home-page") else None)
    record = _record_hashes(dist)
    for lf in sorted(str(v) for v in headers.get_all("License-File", []) or []):
        candidates = [dist / "licenses" / lf, dist / lf]
        path = next((c for c in candidates if c.is_file()), None)
        entry: dict[str, Any] = {"present": path is not None, "sha256": None, "record_match": False}
        if path is not None:
            raw = path.read_bytes()
            entry["sha256"] = hashlib.sha256(raw).hexdigest()
            rel = path.relative_to(site).as_posix()
            entry["record_match"] = record.get(rel) == entry["sha256"]
            if entry["record_match"]:
                ob.texts[lf] = raw.decode("utf-8", errors="replace")
        ob.license_files[lf] = entry
    return ob


# --- build dependencies -------------------------------------------------------------------------

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)")


def load_build_lock(path: Path) -> list[tuple[str, str, list[str]]]:
    """Parse a hash-pinned requirements file: ``name==version \\`` followed by ``--hash=sha256:`` lines."""
    out: list[tuple[str, str, list[str]]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _PIN.match(line)
        if m:
            out.append((normalize(m.group(1)), m.group(2), []))
        elif line.startswith("--hash=sha256:") and out:
            out[-1][2].append(line.split(":", 1)[1].rstrip(" \\"))
        else:
            raise AuditError(f"unpinned or unparsable build requirement: {line!r}")
    for name, version, hashes in out:
        if not hashes:
            raise AuditError(f"build requirement {name}=={version} has no hashes")
    names = [n for n, _, _ in out]
    if len(set(names)) != len(names):
        raise AuditError("duplicate build requirement")
    return out


def check_build_pins(pyproject: Path, build: list[tuple[str, str, list[str]]]) -> list[dict[str, Any]]:
    """[build-system].requires and [tool.uv].build-constraint-dependencies must pin exactly the lock."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    locked = {f"{n}=={v}" for n, v, _ in build}
    issues: list[dict[str, Any]] = []
    requires = data.get("build-system", {}).get("requires", [])
    for req in requires:
        m = _PIN.match(req)
        if m is None or f"{normalize(m.group(1))}=={m.group(2)}" not in locked:
            issues.append(
                _issue("build-system", "unpinned_build_dependency", f"requires {req!r} not pinned in lock")
            )
    constraints = data.get("tool", {}).get("uv", {}).get("build-constraint-dependencies", [])
    got = set()
    for c in constraints:
        m = _PIN.match(c)
        got.add(f"{normalize(m.group(1))}=={m.group(2)}" if m else c)
    if got != locked:
        issues.append(
            _issue(
                "build-system",
                "unpinned_build_dependency",
                f"build constraints {sorted(got)} differ from {BUILD_LOCK_PATH} {sorted(locked)}",
            )
        )
    return issues


def default_build_site(root: Path) -> Path | None:
    found = sorted((root / BUILD_ENV).glob("lib/python3*/site-packages"))
    return found[0] if found else None


def embedded_notice(dist: Path, site: Path, note: dict[str, Any]) -> str | None:
    """A third-party notice embedded in one file of an installed package (e.g. a vendored module's header).
    Returned only if the file's hash matches both the review register and the package RECORD."""
    rel = str(note.get("path", ""))
    target = site / rel
    if not rel or ".." in Path(rel).parts or not target.is_file():
        return None
    raw = target.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != note.get("sha256") or _record_hashes(dist).get(rel) != digest:
        return None
    lines = raw.decode("utf-8", errors="replace").splitlines()
    start, end = int(note.get("start", 1)), int(note.get("end", len(lines)))
    return "\n".join(lines[start - 1 : end])


def upstream_text(root: Path, up: dict[str, Any]) -> str | None:
    """A license text obtained from upstream and stored in the repository with its source and hash."""
    rel = str(up.get("file", ""))
    target = root / rel
    if not rel.startswith("licenses/texts/") or ".." in Path(rel).parts or not target.is_file():
        return None
    raw = target.read_bytes()
    if hashlib.sha256(raw).hexdigest() != up.get("sha256") or not up.get("source_url"):
        return None
    return raw.decode("utf-8", errors="replace")


# --- audit --------------------------------------------------------------------------------------


def _issue(name: str, code: str, detail: str) -> dict[str, Any]:
    return {"package": name, "code": code, "detail": detail}


@dataclass
class Audit:
    inventory: dict[str, Any]
    issues: list[dict[str, Any]]
    open_reviews: list[dict[str, Any]]
    texts: dict[str, dict[str, str]]
    review: dict[str, Any]
    acknowledged: list[dict[str, Any]] = field(default_factory=list)


def load_review(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read review register {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("packages"), dict):
        raise AuditError("review register must be an object with a 'packages' object")
    for name, entry in data["packages"].items():
        if not isinstance(entry, dict) or entry.get("status") not in REVIEW_STATUSES:
            raise AuditError(f"review entry {name!r} must have status in {sorted(REVIEW_STATUSES)}")
    return data


def run_audit(
    root: Path,
    site: Path,
    lock: Path | None = None,
    review_path: Path | None = None,
    build_site: Path | None = None,
) -> Audit:
    lock = lock or root / "uv.lock"
    review = load_review(review_path or root / REVIEW_PATH)
    pkgs, runtime_roots, dev_roots, issues = load_lock(lock)
    if not site.is_dir():
        raise AuditError(f"site-packages directory not found: {site}")
    dists = find_dists(site)
    runtime = closure(pkgs, runtime_roots)
    dev = closure(pkgs, [d for g in sorted(dev_roots) for d in dev_roots[g]])
    reviewed: dict[str, Any] = review["packages"]
    entries: list[dict[str, Any]] = []
    texts: dict[str, dict[str, str]] = {}
    open_reviews: list[dict[str, Any]] = []
    in_graph = set(runtime) | set(dev)
    for name in sorted(set(pkgs) - {ROOT_PACKAGE} - in_graph):
        issues.append(_issue(name, "orphan_locked", "locked but not reachable from runtime or dev roots"))
    candidates: list[dict[str, Any]] = []
    for name in sorted(in_graph):
        scope = "runtime" if name in runtime else "dev"
        via = runtime.get(name) or dev[name]
        if name not in pkgs:
            issues.append(_issue(name, "missing_from_lock", f"required via {' -> '.join(via)}"))
            continue
        lk = pkgs[name]
        candidates.append(
            {
                "key": name,
                "name": name,
                "version": lk.version,
                "scope": scope,
                "dependency_path": via,
                "markers": sorted({m for p in pkgs.values() for d, m in p.deps if d == name and m}),
                "source": lk.source,
                "sdist_sha256": lk.sdist_sha256,
                "_site": site,
                "_dists": dists,
            }
        )
    build_lock_path = root / BUILD_LOCK_PATH
    build_names: set[str] = set()
    if build_lock_path.is_file():
        build = load_build_lock(build_lock_path)
        issues += check_build_pins(root / "pyproject.toml", build)
        bsite = build_site if build_site is not None else default_build_site(root)
        bdists = find_dists(bsite) if bsite is not None and bsite.is_dir() else {}
        if not bdists:
            issues.append(_issue("build-system", "build_env_missing", f"no build environment at {bsite}"))
        for name, version, hashes in build:
            build_names.add(f"build:{name}")
            candidates.append(
                {
                    "key": f"build:{name}",
                    "name": name,
                    "version": version,
                    "scope": "build",
                    "dependency_path": ["build-system", name],
                    "markers": [],
                    "source": {"registry": "https://pypi.org/simple", "lock": str(BUILD_LOCK_PATH)},
                    "sdist_sha256": None,
                    "artifact_sha256": sorted(hashes),
                    "_site": bsite,
                    "_dists": bdists,
                }
            )
    for c in candidates:
        name, key, scope = c["name"], c["key"], c["scope"]
        csite: Path | None = c.pop("_site")
        cdists: dict[str, list[Path]] = c.pop("_dists")
        e = {k: v for k, v in c.items() if k != "key"}
        installs = cdists.get(name, [])
        if len(installs) > 1:
            issues.append(_issue(key, "duplicate_installed", f"{len(installs)} dist-info directories"))
        if not installs or csite is None:
            e.update(installed=False, license=None, license_basis="not installed", license_files={})
            issues.append(_issue(key, "not_installed", "metadata unavailable; license unverified"))
        else:
            ob = observe(installs[0], csite)
            texts[key] = ob.texts
            e.update(
                installed=True,
                license=ob.license,
                license_basis=ob.basis,
                license_field=ob.license_field,
                classifiers=ob.classifiers,
                license_files=ob.license_files,
                project_url=ob.home,
            )
            if ob.installed_version != c["version"]:
                issues.append(
                    _issue(
                        key, "version_mismatch", f"locked {c['version']}, installed {ob.installed_version}"
                    )
                )
            if ob.license is None:
                code = "ambiguous_license" if ob.classifiers else "missing_license_metadata"
                issues.append(_issue(key, code, f"no SPDX license metadata ({ob.basis})"))
            else:
                try:
                    unknown = [i for i in spdx_ids(ob.license) if i not in KNOWN_SPDX]
                    ok_runtime = spdx_allowed(ob.license, RUNTIME_ALLOWED)
                except ValueError as exc:
                    issues.append(_issue(key, "malformed_license", str(exc)))
                    unknown, ok_runtime = [], False
                if unknown:
                    issues.append(_issue(key, "unknown_license", f"unrecognised identifiers {unknown}"))
                elif scope == "runtime" and not ok_runtime:
                    issues.append(_issue(key, "incompatible_license", f"{ob.license} not allowed at runtime"))
            if not ob.license_files:
                issues.append(_issue(key, "no_license_file", "package ships no license file"))
            for lf, info in ob.license_files.items():
                if not info["present"]:
                    issues.append(_issue(key, "license_file_missing", lf))
                elif not info["record_match"]:
                    issues.append(_issue(key, "license_file_unverified", f"{lf} does not match RECORD"))
            for note in reviewed.get(key, {}).get("embedded_notices", []):
                text = embedded_notice(installs[0], csite, note)
                if text is None:
                    issues.append(_issue(key, "embedded_notice_unverified", str(note.get("path"))))
                else:
                    texts[key][f"embedded:{note['path']}"] = text
        rev = reviewed.get(key)
        for up in (rev or {}).get("upstream_texts", []):
            text = upstream_text(root, up)
            if text is None:
                issues.append(_issue(key, "upstream_text_unverified", str(up.get("file"))))
            else:
                texts.setdefault(key, {})[f"upstream:{up['file']}"] = text
        if rev is not None and scope in ATTRIBUTION_SCOPES and not str(rev.get("attribution", "")).strip():
            issues.append(
                _issue(key, "missing_attribution", "reviewed entry records no attribution requirement")
            )
        _compare_review({**e, "name": key}, rev, issues, open_reviews)
        entries.append(e)
    acknowledged: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for i in issues:
        accepted = reviewed.get(i["package"], {}).get("accepted_issues", [])
        (acknowledged if i["code"] in accepted and i["code"] not in NEVER_ACCEPTABLE else kept).append(i)
    issues = kept
    for name in sorted(set(reviewed) - in_graph - build_names):
        issues.append(_issue(name, "stale_review", "reviewed package is no longer locked"))
    for comp in review.get("native", []):
        if comp.get("status") != "approved":
            open_reviews.append({"package": comp.get("name"), "reason": comp.get("notes", "")})
    inventory = {
        "schema": "sentinel.license-inventory/1",
        "lockfile_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "root": {"name": ROOT_PACKAGE, "version": pkgs[ROOT_PACKAGE].version, "license": "MIT"},
        "counts": {
            "runtime": sum(1 for x in entries if x["scope"] == "runtime"),
            "dev": sum(1 for x in entries if x["scope"] == "dev"),
            "build": sum(1 for x in entries if x["scope"] == "build"),
        },
        "packages": entries,
        "native": review.get("native", []),
    }
    return Audit(inventory, issues, open_reviews, texts, review, acknowledged)


def _compare_review(
    e: dict[str, Any],
    rev: dict[str, Any] | None,
    issues: list[dict[str, Any]],
    open_reviews: list[dict[str, Any]],
) -> None:
    name = e["name"]
    if rev is None:
        issues.append(_issue(name, "unreviewed_package", "not in licenses/review.json"))
        return
    observed_files = {k: v["sha256"] for k, v in e.get("license_files", {}).items()}
    checks = {
        "version": e["version"],
        "scope": e["scope"],
        "license": e.get("license"),
        "license_files": observed_files,
    }
    for key, value in checks.items():
        if rev.get(key) != value:
            issues.append(
                _issue(name, "unreviewed_change", f"{key}: reviewed {rev.get(key)!r}, observed {value!r}")
            )
    if rev["status"] == "needs_review":
        open_reviews.append({"package": name, "reason": rev.get("notes", "")})


# --- outputs ------------------------------------------------------------------------------------


def render_inventory(audit: Audit) -> str:
    return json.dumps(audit.inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_notices(audit: Audit) -> str:
    inv = audit.inventory
    rev = audit.review["packages"]
    out: list[str] = []
    w = out.append
    w("THIRD-PARTY SOFTWARE NOTICES")
    w("Sentinel (sentinel-audit) " + inv["root"]["version"])
    w("")
    w("Sentinel itself is licensed under the MIT License. Sentinel's own license is NOT part of this")
    w("file; this file covers only third-party components.")
    w("")
    w("Generated by scripts/license_audit.py from uv.lock (sha256 " + inv["lockfile_sha256"] + "),")
    w("the installed packages' own metadata, and the reviewed register licenses/review.json.")
    w("Do not edit by hand; run `python scripts/license_audit.py notices`.")
    w("")
    w("Redistribution: the Sentinel wheel and source distribution contain only Sentinel's own code.")
    w("The runtime components below are installed separately by the package installer; they are")
    w("listed here, with their license texts, because Sentinel requires them at runtime.")
    w("License texts are reproduced only when the file's SHA-256 matches the package's own RECORD.")
    w("")
    runtime = [p for p in inv["packages"] if p["scope"] == "runtime"]
    dev = [p for p in inv["packages"] if p["scope"] == "dev"]
    w("=" * 78)
    w(f"PART 1. RUNTIME DEPENDENCIES ({len(runtime)}, direct and transitive)")
    w("=" * 78)
    for p in runtime:
        r = rev.get(p["name"], {})
        w("")
        w("-" * 78)
        w(f"{p['name']} {p['version']}")
        w("-" * 78)
        w(f"License (package metadata): {p.get('license') or 'NOT DECLARED'} [{p.get('license_basis')}]")
        w(f"Review status: {r.get('status', 'UNREVIEWED')}")
        w(f"Required via: {' -> '.join(p['dependency_path'])}")
        if p["markers"]:
            w(f"Environment markers: {'; '.join(p['markers'])}")
        w(f"Source: {p['source'].get('registry', p['source'])} (project {p.get('project_url') or 'n/a'})")
        w(f"Source distribution sha256: {p.get('sdist_sha256') or 'n/a'}")
        if r.get("attribution"):
            w(f"Attribution requirement: {r['attribution']}")
        for comp in r.get("embedded", []):
            w(f"Embedded component: {comp}")
        if r.get("notes"):
            w(f"Review notes: {r['notes']}")
        texts = audit.texts.get(p["name"], {})
        for k in sorted(t for t in texts if t.startswith(("embedded:", "upstream:"))):
            kind, _, path = k.partition(":")
            w("")
            if kind == "embedded":
                w(f">>> notice embedded in {path} (hash-verified against review register and RECORD)")
            else:
                src = next(u for u in r.get("upstream_texts", []) if u["file"] == path)
                w(f">>> {src['component']}: {path} (sha256 {src['sha256']}, from {src['source_url']})")
            w(texts[k].rstrip("\n"))
            w(f"<<< end of {path}")
        for lf in sorted(p.get("license_files", {})):
            info = p["license_files"][lf]
            w("")
            if lf in texts:
                w(f">>> {lf} (sha256 {info['sha256']}, verified against RECORD)")
                w(texts[lf].rstrip("\n"))
                w(f"<<< end of {lf}")
            else:
                w(f">>> {lf}: TEXT NOT REPRODUCED (not present or not verified against RECORD)")
    w("")
    risks = audit.review.get("residual_risks", [])
    if risks:
        w("=" * 78)
        w("RESIDUAL LICENSING RISKS (accepted, NOT verified)")
        w("=" * 78)
        for rk in risks:
            w(f"{rk['id']} {rk['component']}: not verified: {rk['not_verified']} [{rk['status']}]")
        w("")
    w("=" * 78)
    w("PART 2. NATIVE macOS SECURE ENCLAVE HELPER (built locally, not distributed)")
    w("=" * 78)
    for comp in inv["native"]:
        w("")
        w(f"{comp['name']}: {comp['license']} [{comp['status']}]")
        w(f"  Use: {comp['use']}")
        w(f"  Distribution: {comp['distribution']}")
        if comp.get("notes"):
            w(f"  Notes: {comp['notes']}")
    w("")
    build = [p for p in inv["packages"] if p["scope"] == "build"]
    w("=" * 78)
    w(f"PART 3. BUILD BACKEND ({len(build)}, build time only, pinned in {BUILD_LOCK_PATH}, not distributed)")
    w("=" * 78)
    w("")
    for p in build:
        b = rev.get(f"build:{p['name']}", {})
        lic = p.get("license") or b.get("reviewed_license") or "NOT DECLARED"
        w(
            f"{p['name']} {p['version']}: {lic} "
            f"[{p.get('license_basis')}; review {b.get('status', 'UNREVIEWED')}]"
        )
    w("")
    w("=" * 78)
    w(f"PART 4. DEVELOPMENT AND TEST TOOLS ({len(dev)}, not distributed, listed for completeness)")
    w("=" * 78)
    w("")
    for p in dev:
        lic = p.get("license") or ("NOT DECLARED" if p.get("installed") else "UNVERIFIED (not installed)")
        status = rev.get(p["name"], {}).get("status", "UNREVIEWED")
        w(f"{p['name']} {p['version']}: {lic} [{p.get('license_basis')}; review {status}]")
    w("")
    return "\n".join(out)


def check(root: Path, audit: Audit, *, strict: bool) -> list[dict[str, Any]]:
    problems = list(audit.issues)
    for rel, render in ((INVENTORY_PATH, render_inventory), (NOTICES_PATH, render_notices)):
        path = root / rel
        if not path.is_file() or path.read_text(encoding="utf-8") != render(audit):
            problems.append(_issue("-", "stale_output", f"{rel} is missing or out of date"))
    if strict:
        problems += [_issue(o["package"], "needs_review", o["reason"]) for o in audit.open_reviews]
    return problems


def default_site() -> Path:
    return Path(sysconfig.get_paths()["purelib"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["inventory", "notices", "check"])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--site-packages", type=Path, default=None)
    ap.add_argument(
        "--build-site", type=Path, default=None, help=f"default: {BUILD_ENV}/lib/python3*/site-packages"
    )
    ap.add_argument("--strict", action="store_true", help="also fail on needs_review entries")
    args = ap.parse_args(argv)
    root: Path = args.root
    try:
        audit = run_audit(root, args.site_packages or default_site(), build_site=args.build_site)
    except AuditError as exc:
        print(f"license-audit: error: {exc}", file=sys.stderr)
        return 2
    if args.command == "inventory":
        (root / INVENTORY_PATH).parent.mkdir(parents=True, exist_ok=True)
        (root / INVENTORY_PATH).write_text(render_inventory(audit), encoding="utf-8")
    elif args.command == "notices":
        (root / NOTICES_PATH).write_text(render_notices(audit), encoding="utf-8")
    problems = check(root, audit, strict=args.strict) if args.command == "check" else audit.issues
    for p in problems:
        print(f"{p['code']}: {p['package']}: {p['detail']}")
    for a in audit.acknowledged:
        print(f"acknowledged: {a['code']}: {a['package']}: {a['detail']}")
    for o in audit.open_reviews:
        print(f"open-review: {o['package']}: {o['reason']}")
    n = audit.inventory["counts"]
    print(
        f"license-audit: {n['runtime']} runtime, {n['build']} build, {n['dev']} dev packages; "
        f"{len(problems)} issue(s)"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
