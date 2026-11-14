"""Supply-chain analyzer (M8). Static and offline: lockfile and manifest hygiene, dependency-confusion
vectors, typosquatting candidates, build-pipeline provenance and artifact checksum verification.
Artifacts are only hashed, never unpacked or executed (B2 stays disabled, M2-SA-12)."""

from __future__ import annotations

import hashlib
import json
import os  # noqa: E402
import re
import sys  # noqa: E402
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import MAX_FILE_BYTES, finding, main, read_text, unparseable, walk

POPULAR = {
    "pypi": [
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "django",
        "flask",
        "boto3",
        "botocore",
        "setuptools",
        "pyyaml",
        "cryptography",
        "pillow",
        "jinja2",
        "click",
        "pytest",
        "scipy",
        "sqlalchemy",
        "certifi",
        "idna",
        "six",
        "attrs",
        "colorama",
        "beautifulsoup4",
        "selenium",
        "matplotlib",
        "tensorflow",
        "torch",
        "openai",
        "fastapi",
        "pydantic",
        "httpx",
        "aiohttp",
        "paramiko",
        "psycopg2",
        "pymongo",
        "redis",
        "celery",
        "scrapy",
        "lxml",
    ],
    "npm": [
        "react",
        "lodash",
        "express",
        "axios",
        "chalk",
        "commander",
        "debug",
        "moment",
        "request",
        "vue",
        "webpack",
        "typescript",
        "eslint",
        "jquery",
        "underscore",
        "async",
        "uuid",
        "dotenv",
        "yargs",
        "minimist",
        "body-parser",
        "mongoose",
        "socket.io",
        "next",
        "colors",
        "cross-env",
        "node-fetch",
        "jsonwebtoken",
        "bcrypt",
        "electron",
    ],
}


def lev1(a: str, b: str) -> bool:
    """Edit distance exactly 1 (substitution, insertion, deletion or adjacent transposition)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    s, t = (a, b) if len(a) < len(b) else (b, a)
    return any(s == t[:i] + t[i + 1 :] for i in range(len(t)))


def typo(eco: str, name: str, rel: str, line: int, out: list[dict[str, Any]]) -> None:
    n = name.lower().replace("_", "-")
    for pop in POPULAR[eco]:
        if n != pop and lev1(n, pop):
            out.append(
                finding(
                    "typosquat-candidate",
                    rel,
                    line,
                    f"{name!r} is one edit from the popular package {pop!r}",
                    "medium",
                )
            )
            return


def requirements(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    hashed = "--hash=" in text
    for n, raw in enumerate(text.splitlines(), 1):
        ln = raw.split("#", 1)[0].strip()
        if not ln:
            continue
        if ln.startswith(("--extra-index-url", "-i ", "--index-url")):
            if "http://" in ln:
                out.append(finding("pip-insecure-index", rel, n, "Package index over plain HTTP", "high"))
            if ln.startswith("--extra-index-url"):
                out.append(
                    finding(
                        "pip-extra-index-url",
                        rel,
                        n,
                        "--extra-index-url mixes indexes (dependency confusion)",
                        "high",
                    )
                )
            continue
        if ln.startswith("-"):
            continue
        if re.match(r"^(?:git\+)?https?://|^git\+", ln):
            out.append(
                finding("pip-direct-url", rel, n, "Dependency installed from a URL, not the index", "medium")
            )
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)", ln)
        if not m:
            continue
        typo("pypi", m.group(1), rel, n, out)
        if "==" not in ln:
            out.append(
                finding("pip-unpinned", rel, n, f"{m.group(1)} is not pinned to an exact version", "low")
            )
        elif hashed and "--hash=" not in raw and not raw.rstrip().endswith("\\"):
            out.append(
                finding("pip-missing-hash", rel, n, f"{m.group(1)} has no --hash while others do", "medium")
            )


def package_json(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    try:
        d = json.loads(text)
    except ValueError:
        return
    if not isinstance(d, dict):
        return
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (d.get(sec) or {}).items():
            line = text.count("\n", 0, max(text.find(f'"{name}"'), 0)) + 1
            spec = str(spec)
            typo("npm", name, rel, line, out)
            if spec in ("*", "latest", "") or spec.startswith(("x", ">")):
                out.append(
                    finding(
                        "npm-unbounded-version", rel, line, f"{name} accepts any version ({spec!r})", "medium"
                    )
                )
            if spec.startswith(("http://", "git://", "git+http://")):
                out.append(
                    finding(
                        "npm-insecure-source", rel, line, f"{name} fetched over an insecure transport", "high"
                    )
                )
            elif spec.startswith(("https://", "git+", "github:")):
                out.append(
                    finding(
                        "npm-direct-source", rel, line, f"{name} installed from a URL or repository", "medium"
                    )
                )
    for hook in ("preinstall", "install", "postinstall"):
        if hook in (d.get("scripts") or {}):
            out.append(
                finding(
                    "npm-install-script",
                    rel,
                    text.count("\n", 0, text.find(f'"{hook}"')) + 1,
                    f"Package runs a {hook} script at install time",
                    "low",
                )
            )


def package_lock(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    try:
        d = json.loads(text)
    except ValueError:
        out.append(unparseable(rel, "package-lock.json"))
        return
    packages = d.get("packages", {}) if isinstance(d, dict) else None
    if not isinstance(packages, dict):
        out.append(unparseable(rel, "package-lock.json"))
        return
    for name, meta in packages.items():
        if not name or not isinstance(meta, dict) or meta.get("link"):
            continue
        resolved = str(meta.get("resolved") or "")
        if resolved.startswith("http://"):
            out.append(
                finding("npm-lock-insecure-resolved", rel, 0, f"{name} resolved over plain HTTP", "high")
            )
        if resolved and not meta.get("integrity"):
            out.append(
                finding("npm-lock-missing-integrity", rel, 0, f"{name} has no integrity hash", "medium")
            )


def npmrc(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*registry\s*=\s*http://", ln):
            out.append(finding("npm-insecure-registry", rel, n, "npm registry over plain HTTP", "high"))
        if re.match(r"^\s*always-auth\s*=\s*true", ln):
            out.append(
                finding("npm-always-auth", rel, n, "Credentials sent to every registry request", "low")
            )


def workflow(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in enumerate(text.splitlines(), 1):
        m = re.search(r"uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-]+)", ln)
        if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)) and not m.group(1).startswith("./"):
            out.append(
                finding(
                    "ci-action-not-pinned",
                    rel,
                    n,
                    f"{m.group(1)}@{m.group(2)} is not pinned to a commit SHA",
                    "medium",
                )
            )
    if re.search(r"\bpull_request_target\b", text) and "actions/checkout" in text:
        out.append(
            finding(
                "ci-pull-request-target-checkout",
                rel,
                0,
                "pull_request_target workflow checks out code (untrusted PR code with secrets)",
                "high",
            )
        )


CURL_PIPE = re.compile(r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")


def scripts(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for m in CURL_PIPE.finditer(text):
        out.append(
            finding(
                "curl-pipe-shell",
                rel,
                text.count("\n", 0, m.start()) + 1,
                "Remote script piped into a shell",
                "high",
            )
        )


def dockerfile(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in enumerate(text.splitlines(), 1):
        s = ln.strip()
        if s.upper().startswith("FROM ") and "@sha256:" not in s and " scratch" not in s.lower():
            out.append(finding("docker-base-not-pinned", rel, n, "Base image not pinned by digest", "low"))
        if re.match(r"^ADD\s+https?://", s, re.I):
            out.append(
                finding(
                    "docker-add-remote", rel, n, "ADD fetches a remote file without verification", "medium"
                )
            )


def checksums(root: Path, rel: str, text: str, out: list[dict[str, Any]]) -> None:
    """Verify `<sha256>  <file>` lists (SHA256SUMS, *.sha256) against files inside the target."""
    base = (root / rel).parent
    for n, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", ln.strip())
        if not m:
            continue
        target = (base / m.group(2)).resolve()
        if root not in target.parents or target.is_symlink():
            out.append(
                finding(
                    "checksum-path-outside-target",
                    rel,
                    n,
                    f"Checksum entry points outside the target: {m.group(2)}",
                    "medium",
                )
            )
            continue
        if not target.is_file():
            out.append(
                finding("checksum-file-missing", rel, n, f"Listed artifact {m.group(2)} is missing", "medium")
            )
            continue
        h = hashlib.sha256()
        with target.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != m.group(1).lower():
            out.append(
                finding(
                    "checksum-mismatch",
                    rel,
                    n,
                    f"SHA-256 of {m.group(2)} does not match the published checksum",
                    "critical",
                )
            )


LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb")
PURL = re.compile(r"^pkg:[a-z][a-z0-9.+-]*/[^@?#\s]+(?:@[^?#\s]+)?(?:\?[^#\s]*)?(?:#\S*)?$")


def lock_present(p: Path, rel: str, text: str, out: list[dict[str, Any]]) -> None:
    """A package.json with dependencies but no lockfile resolves differently on every install."""
    try:
        d = json.loads(text)
    except ValueError:
        return
    if not isinstance(d, dict) or not (d.get("dependencies") or d.get("devDependencies")):
        return
    if d.get("private") is not True and "workspaces" in d:
        return  # workspace member: the lockfile lives at the workspace root
    if not any((p.parent / lf).is_file() for lf in LOCKFILES):
        out.append(finding("npm-no-lockfile", rel, 1, "Dependencies declared without a lockfile", "medium"))


def sbom(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    """Structural SBOM validation (CycloneDX 1.4-1.6 JSON, SPDX 2.x JSON). Not a full schema validation."""
    try:
        d = json.loads(text)
    except ValueError:
        out.append(unparseable(rel, "SBOM"))
        return
    if not isinstance(d, dict):
        out.append(unparseable(rel, "SBOM"))
        return
    if d.get("bomFormat") == "CycloneDX":
        if str(d.get("specVersion")) not in ("1.4", "1.5", "1.6"):
            out.append(
                finding("sbom-unsupported-version", rel, 1, f"CycloneDX {d.get('specVersion')}", "low")
            )
        comps = d.get("components")
        if not isinstance(comps, list) or not comps:
            out.append(finding("sbom-empty", rel, 1, "SBOM lists no components", "medium"))
            return
        for c in comps:
            if not isinstance(c, dict) or not c.get("name"):
                out.append(finding("sbom-invalid-component", rel, 1, "Component without a name", "medium"))
                continue
            if not c.get("version"):
                out.append(
                    finding("sbom-component-unversioned", rel, 1, f"{c['name']}: no version", "medium")
                )
            purl = c.get("purl")
            if purl is not None and not (isinstance(purl, str) and PURL.match(purl)):
                out.append(finding("sbom-invalid-purl", rel, 1, f"{c['name']}: malformed purl", "low"))
            if not c.get("hashes"):
                out.append(
                    finding("sbom-component-no-hash", rel, 1, f"{c['name']}: no hash", "informational")
                )
    elif str(d.get("spdxVersion", "")).startswith("SPDX-2."):
        if not d.get("SPDXID") or not isinstance(d.get("packages"), list):
            out.append(finding("sbom-invalid", rel, 1, "SPDX document lacks SPDXID or packages", "medium"))
            return
        for pkg in d["packages"]:
            if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("SPDXID"):
                out.append(
                    finding("sbom-invalid-component", rel, 1, "SPDX package lacks name or SPDXID", "medium")
                )
            elif not pkg.get("versionInfo"):
                out.append(
                    finding("sbom-component-unversioned", rel, 1, f"{pkg['name']}: no versionInfo", "medium")
                )
    else:
        out.append(finding("sbom-unknown-format", rel, 1, "Neither CycloneDX nor SPDX JSON", "low"))


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in walk(root):
        rel = str(p.relative_to(root))
        try:
            _one(root, p, rel, out)
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, UnicodeError, RecursionError):
            # One malformed input is reported, never allowed to take the whole check down (V-4).
            out.append(unparseable(rel, p.name))
    return out


def _one(root: Path, p: Path, rel: str, out: list[dict[str, Any]]) -> None:
    name = p.name
    if p.stat().st_size > MAX_FILE_BYTES:
        return
    if name.startswith("requirements") and name.endswith(".txt"):
        requirements(rel, read_text(p), out)
    elif name == "package.json":
        package_json(rel, read_text(p), out)
        lock_present(p, rel, read_text(p), out)
    elif name == "package-lock.json":
        package_lock(rel, read_text(p), out)
    elif name == ".npmrc":
        npmrc(rel, read_text(p), out)
    elif ".github/workflows/" in rel.replace("\\", "/") and name.endswith((".yml", ".yaml")):
        workflow(rel, read_text(p), out)
        scripts(rel, read_text(p), out)
    elif name in ("Dockerfile", "Containerfile") or name.endswith(".dockerfile"):
        dockerfile(rel, read_text(p), out)
        scripts(rel, read_text(p), out)
    elif name.endswith((".sh", ".bash")) or name == "Makefile":
        scripts(rel, read_text(p), out)
    elif name.endswith((".cdx.json", ".spdx.json")) or name in ("bom.json", "sbom.json"):
        sbom(rel, read_text(p), out)
    elif name in ("SHA256SUMS", "sha256sums.txt", "checksums.txt") or name.endswith(".sha256"):
        checksums(root.resolve(), rel, read_text(p), out)


if __name__ == "__main__":
    raise SystemExit(main("supplychain", analyze))
