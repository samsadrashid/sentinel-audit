"""Sentinel's own SBOM (M10): CycloneDX 1.5 JSON for the actual built wheel.

* **Components** are the wheel's runtime dependency closure, resolved from `uv.lock`: name, version,
  purl, the registry source and every artifact hash recorded in the lock. Licences come from the
  reproducible licence inventory (`licenses/inventory.json`, scripts/license_audit.py).
* **metadata.component** is the wheel itself: name, version, purl and the wheel file's SHA-256, so the
  SBOM is bound to one exact artifact.
* **Deterministic:** the serial number is a UUIDv5 of the wheel hash, and the timestamp is taken only
  from SOURCE_DATE_EPOCH.

Validation (`validate`) is structural (the official CycloneDX JSON Schema is not vendored and is not
downloaded), plus correspondence checks against the artifact:

* the wheel hash matches;
* the wheel's `Requires-Dist` names are all components;
* the components are exactly the lock's runtime closure;
* every component has a version, a purl, a hash and a licence.

Usage: python scripts/m10/sbom.py WHEEL [--out FILE] [--validate FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
import uuid
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
NS = uuid.UUID("6c1e5c2a-7b1f-4d0e-9a51-5e2b1c3d4f60")
PURL = re.compile(r"^pkg:pypi/[a-z0-9._-]+@[^\s]+$")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_packages() -> dict[str, dict[str, Any]]:
    data = tomllib.loads((ROOT / "uv.lock").read_text())
    return {_norm(p["name"]): p for p in data["package"]}


def runtime_closure(pkgs: dict[str, dict[str, Any]], root: str = "sentinel-audit") -> list[str]:
    seen: set[str] = set()
    todo = [_norm(d["name"]) for d in pkgs[root].get("dependencies", [])]
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        todo += [_norm(d["name"]) for d in pkgs[n].get("dependencies", [])]
    return sorted(seen)


def licences() -> dict[str, str]:
    inv = json.loads((ROOT / "licenses" / "inventory.json").read_text())
    return {_norm(p["name"]): p.get("license") or "" for p in inv["packages"] if p.get("scope") == "runtime"}


def wheel_metadata(wheel: Path) -> tuple[str, str, list[str]]:
    with zipfile.ZipFile(wheel) as z:
        meta = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        text = z.read(meta).decode()
    name = re.search(r"^Name: (.+)$", text, re.M)
    version = re.search(r"^Version: (.+)$", text, re.M)
    reqs = [
        _norm(re.split(r"[ ;<>=!~\[(]", r, maxsplit=1)[0])
        for r in re.findall(r"^Requires-Dist: (.+)$", text, re.M)
    ]
    if not name or not version:
        raise ValueError("wheel METADATA lacks Name or Version")
    return name.group(1).strip(), version.group(1).strip(), sorted(reqs)


def build(wheel: Path) -> dict[str, Any]:
    pkgs = lock_packages()
    lic = licences()
    name, version, _ = wheel_metadata(wheel)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    comps = []
    for n in runtime_closure(pkgs, _norm(name)):
        p = pkgs[n]
        arts = [p["sdist"], *p.get("wheels", [])] if "sdist" in p else list(p.get("wheels", []))
        hashes = sorted({a["hash"].split(":", 1)[1] for a in arts if a.get("hash", "").startswith("sha256:")})
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{n}@{p['version']}",
            "name": n,
            "version": p["version"],
            "purl": f"pkg:pypi/{n}@{p['version']}",
            "hashes": [{"alg": "SHA-256", "content": h} for h in hashes],
            "externalReferences": [
                {"type": "distribution", "url": str(p.get("source", {}).get("registry", ""))}
            ],
        }
        if lic.get(n):
            comp["licenses"] = [{"expression": lic[n]}]
        comps.append(comp)
    meta: dict[str, Any] = {
        "component": {
            "type": "application",
            "bom-ref": f"pkg:pypi/{_norm(name)}@{version}",
            "name": _norm(name),
            "version": version,
            "purl": f"pkg:pypi/{_norm(name)}@{version}",
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "licenses": [{"expression": "MIT"}],
            "properties": [{"name": "sentinel:artifact", "value": wheel.name}],
        },
        "tools": {"components": [{"type": "application", "name": "sentinel-release-sbom", "version": "1"}]},
    }
    if os.environ.get("SOURCE_DATE_EPOCH"):
        import datetime as dt

        ts = dt.datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), dt.UTC)
        meta["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(NS, digest)}",
        "version": 1,
        "metadata": meta,
        "components": comps,
        "dependencies": [
            {
                "ref": f"pkg:pypi/{n}@{pkgs[n]['version']}",
                "dependsOn": sorted(
                    f"pkg:pypi/{_norm(d['name'])}@{pkgs[_norm(d['name'])]['version']}"
                    for d in pkgs[n].get("dependencies", [])
                ),
            }
            for n in [_norm(name), *runtime_closure(pkgs, _norm(name))]
        ],
    }


def validate(doc: Any, wheel: Path) -> list[str]:
    """Return a list of problems (empty means valid and bound to `wheel`)."""
    errs: list[str] = []
    if not isinstance(doc, dict):
        return ["SBOM is not a JSON object"]
    if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") != "1.5":
        errs.append("not CycloneDX 1.5")
    if not re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", str(doc.get("serialNumber", ""))):
        errs.append("serialNumber is not a urn:uuid")
    if not isinstance(doc.get("version"), int) or doc["version"] < 1:
        errs.append("version must be a positive integer")
    meta = doc.get("metadata")
    comp = meta.get("component") if isinstance(meta, dict) else None
    if not isinstance(comp, dict):
        return [*errs, "metadata.component missing"]
    name, version, reqs = wheel_metadata(wheel)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if comp.get("name") != _norm(name) or comp.get("version") != version:
        errs.append("metadata.component name/version differ from the wheel")
    if {h.get("content") for h in comp.get("hashes", [])} != {digest}:
        errs.append("metadata.component hash does not match the wheel file")
    comps = doc.get("components")
    if not isinstance(comps, list):
        return [*errs, "components missing"]
    names = []
    for c in comps:
        if not isinstance(c, dict):
            errs.append("component is not an object")
            continue
        n = str(c.get("name", ""))
        names.append(n)
        for key in ("type", "name", "version", "purl", "hashes", "licenses"):
            if not c.get(key):
                errs.append(f"{n or '?'}: missing {key}")
        if c.get("purl") and not PURL.match(str(c["purl"])):
            errs.append(f"{n}: malformed purl")
        for h in c.get("hashes", []):
            if h.get("alg") != "SHA-256" or not re.fullmatch(r"[0-9a-f]{64}", str(h.get("content", ""))):
                errs.append(f"{n}: malformed hash")
    expected = runtime_closure(lock_packages(), _norm(name))
    if sorted(names) != expected:
        errs.append(f"components {sorted(names)} differ from the locked runtime closure {expected}")
    missing = sorted(set(reqs) - set(names))
    if missing:
        errs.append(f"wheel Requires-Dist not in SBOM: {missing}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wheel", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--validate", type=Path)
    a = ap.parse_args()
    if a.validate:
        errs = validate(json.loads(a.validate.read_text()), a.wheel)
        for e in errs:
            print(f"sbom: {e}", file=sys.stderr)
        return 1 if errs else 0
    body = json.dumps(build(a.wheel), indent=2, sort_keys=True) + "\n"
    if a.out:
        a.out.write_text(body)
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
