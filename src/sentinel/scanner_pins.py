"""Approved scanner, runtime and database pins (D-22, D-53, D-54, D-56).

Everything Sentinel executes or feeds to a scanner is named here by content: native binaries by
SHA-256, container images by digest (``repository@sha256:<64hex>``), the Podman runtime binary by
SHA-256, and the OSV offline database by the SHA-256 of a snapshot manifest. Pins come only from an
approved policy file (``policy.change``); the built-in default policy pins nothing, so every
third-party scanner is ``NOT_RUN`` until the owner approves and pins it.

Verification happens immediately before each execution (`verify_binary`, `PodmanRunner`), never only
at load time.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ValidationError

SCANNER_NAMES = ("gitleaks", "semgrep", "osv-scanner", "syft", "trivy", "checkov", "grype")
#: D-29: vulnerability databases, each a verified snapshot directory with a pinned manifest.
DATABASE_KEYS = {"osv_database": "osv", "trivy_database": "trivy", "grype_database": "grype"}
IMAGE_REF = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,200}@sha256:[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ScannerPin:
    name: str
    kind: str  # "binary" | "image"
    path: Path | None = None
    sha256: str | None = None
    image: str | None = None

    @property
    def identity(self) -> str:
        return str(self.image) if self.kind == "image" else f"sha256:{self.sha256}"


@dataclass(frozen=True)
class RuntimePin:
    path: Path
    sha256: str
    probe_image: str
    #: D-71: the share-free Podman machine every container runs in. Required by the policy parser;
    #: the runner refuses the machine if it has any host-share filesystem mounted.
    machine: str | None = None


@dataclass(frozen=True)
class B2Pin:
    """D-70: the share-free Podman machine used only for B2 archive inspection, and the image (by its
    content-addressed ID) whose `python3 -I` runs Sentinel's own unpacker program."""

    machine: str
    image_id: str


@dataclass(frozen=True)
class OsvDatabasePin:
    path: Path
    manifest_sha256: str


@dataclass(frozen=True)
class Pins:
    scanners: dict[str, ScannerPin] = field(default_factory=dict)
    podman: RuntimePin | None = None
    osv_database: OsvDatabasePin | None = None
    trivy_database: OsvDatabasePin | None = None
    grype_database: OsvDatabasePin | None = None
    b2: B2Pin | None = None
    mobsf: B2Pin | None = None  # D-72: same shape; MobSF 4.6.4 image ID in the share-free machine

    def database(self, name: str) -> OsvDatabasePin | None:
        return {"osv": self.osv_database, "trivy": self.trivy_database, "grype": self.grype_database}[name]

    def describe(self) -> dict[str, Any]:
        return {
            "scanners": {n: p.identity for n, p in sorted(self.scanners.items())},
            "podman": None if self.podman is None else f"sha256:{self.podman.sha256}",
            "osv_database": None if self.osv_database is None else self.osv_database.manifest_sha256,
            "trivy_database": None if self.trivy_database is None else self.trivy_database.manifest_sha256,
            "grype_database": None if self.grype_database is None else self.grype_database.manifest_sha256,
        }


def _abs(value: Any, what: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValidationError(f"{what} must be an absolute path")
    return Path(value)


def _hex(value: Any, what: str) -> str:
    if not isinstance(value, str) or not HEX64.match(value):
        raise ValidationError(f"{what} must be 64 lowercase hex characters")
    return value


def _image(value: Any, what: str) -> str:
    if not isinstance(value, str) or not IMAGE_REF.match(value):
        raise ValidationError(f"{what} must be pinned by digest (repository@sha256:...)")
    return value


def parse(data: dict[str, Any]) -> Pins:
    """Domain checks for the policy's `scanners`, `podman` and `osv_database` keys (schema-checked first)."""
    scanners: dict[str, ScannerPin] = {}
    for name, spec in (data.get("scanners") or {}).items():
        if name not in SCANNER_NAMES:
            raise ValidationError(f"unknown scanner {name!r}")
        if spec.get("kind") == "binary":
            scanners[name] = ScannerPin(
                name, "binary", _abs(spec["path"], f"{name} path"), _hex(spec["sha256"], f"{name} sha256")
            )
        elif spec.get("kind") == "image":
            scanners[name] = ScannerPin(name, "image", image=_image(spec["image"], f"{name} image"))
        else:
            raise ValidationError(f"scanner {name}: kind must be binary or image")
    podman = None
    if data.get("podman") is not None:
        p = data["podman"]
        machine = str(p.get("machine", ""))
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", machine):
            raise ValidationError("podman machine (the share-free Podman machine, D-71) is required")
        podman = RuntimePin(
            _abs(p["path"], "podman path"),
            _hex(p["sha256"], "podman sha256"),
            _image(p["probe_image"], "probe image"),
            machine,
        )
    dbs: dict[str, OsvDatabasePin | None] = {}
    for key in DATABASE_KEYS:
        o = data.get(key)
        dbs[key] = (
            None
            if o is None
            else OsvDatabasePin(_abs(o["path"], f"{key} path"), _hex(o["manifest_sha256"], f"{key} manifest"))
        )
    share_free: dict[str, B2Pin | None] = {"b2": None, "mobsf": None}
    for key in share_free:
        if data.get(key) is None:
            continue
        spec = data[key]
        machine = str(spec.get("machine", ""))
        image_id = str(spec.get("image_id", ""))
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", machine):
            raise ValidationError(f"{key} machine must be a short lowercase Podman machine name")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValidationError(f"{key} image_id must be sha256:<64 hex>")
        share_free[key] = B2Pin(machine, image_id)
    return Pins(
        scanners,
        podman,
        dbs["osv_database"],
        dbs["trivy_database"],
        dbs["grype_database"],
        share_free["b2"],
        share_free["mobsf"],
    )


def file_sha256(path: Path, limit: int = 2 * 1024**3) -> str:
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            n += len(chunk)
            if n > limit:
                raise ValidationError(f"{path} is larger than {limit} bytes")
            h.update(chunk)
    return h.hexdigest()


def verify_binary(path: Path, expected: str) -> str | None:
    """Return a refusal reason, or None if `path` is a regular, non-link file with the expected hash."""
    try:
        if path.is_symlink() or not path.is_file():
            return "scanner_missing"
        return None if file_sha256(path) == expected else "binary_hash_mismatch"
    except (OSError, ValidationError):
        return "scanner_missing"
