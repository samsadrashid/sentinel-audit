"""Plugin ecosystem (M6): third-party analyzers with no engine privileges.

A plugin is a directory containing `sentinel-plugin.json` and one stdlib-only Python entry script that
follows the native analyzer contract (`python -I <entry> <root>`, printing
`{"tool": <name>, "findings": [...]}`). Rules:

* **Pinned or nothing.** Only plugins named in the approved policy (`plugins`, changed only through
  `policy.change`) are loaded. Each pin carries the manifest's SHA-256; the manifest carries the entry
  script's SHA-256. Both are verified immediately before every run. No directory is ever auto-discovered.
* **Out of process, inside isolation.** A plugin never runs in the engine process: there is no import,
  and it gets no engine objects, keys or state. It runs only as a separate process in the verified
  native S1 sandbox (no network, read-only target, disposable workspace). Without that, it's `NOT_RUN`.
* **Declared capabilities only.** The manifest must declare `permissions`. In M6 the only grantable
  set is `{"network": false, "filesystem_write": false, "execute_target": false}`. A plugin asking for
  anything more is refused (`plugin_permission_denied`): it is not downgraded.
* **Compatibility.** `api` must be `sentinel-plugin/1`, and Sentinel's version must fall within
  `[min_sentinel, max_sentinel]`. Activity class S1 only.
* **Failure isolation.** A crash, timeout, oversized or malformed output gives that plugin's check
  `ERROR`; nothing else in the audit is affected, and it is never `PASS`.
* **Identity.** The policy pin name must equal the verified manifest `name` (`plugin_name_mismatch`).
  The manifest and the entry are checked from the same bytes that are then used to run.
* **Provenance.** Every finding is prefixed `plugin.<name>.`; the evidence records the plugin name,
  version and manifest hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .adapters.base import AdapterManifest, PlannedCheck
from .adapters.native import NativeAnalyzerAdapter
from .domain.enums import ActivityClass
from .errors import ValidationError
from .scanner_pins import HEX64, file_sha256

API = "sentinel-plugin/1"
MANIFEST = "sentinel-plugin.json"
NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
VERSION = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,6}$")
GRANTABLE = {"network": False, "filesystem_write": False, "execute_target": False}
MANIFEST_KEYS = {
    "name",
    "version",
    "api",
    "entry",
    "entry_sha256",
    "activity_class",
    "permissions",
    "min_sentinel",
    "max_sentinel",
    "description",
    "licence",
}
MAX_MANIFEST = 16 * 1024
#: The entry is passed to the interpreter as `-c` source (argv), so it must stay well under ARG_MAX.
MAX_ENTRY = 256 * 1024


@dataclass(frozen=True)
class PluginPin:
    name: str
    path: Path
    manifest_sha256: str


def _ver(v: str) -> tuple[int, ...]:
    core = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
    return tuple(int(x) for x in core.groups()) if core else (0, 0, 0)


def parse_pins(data: dict[str, Any]) -> dict[str, PluginPin]:
    out = {}
    for name, spec in (data.get("plugins") or {}).items():
        if not NAME.match(name) or not isinstance(spec, dict):
            raise ValidationError(f"invalid plugin pin {name!r}")
        path = spec.get("path")
        digest = spec.get("manifest_sha256")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or not isinstance(digest, str)
            or not HEX64.match(digest)
        ):
            raise ValidationError(f"plugin {name}: path must be absolute and manifest_sha256 64 hex")
        out[name] = PluginPin(name, Path(path), digest)
    return out


def load_manifest(
    directory: Path, expected_sha256: str | None = None, expected_name: str | None = None
) -> tuple[dict[str, Any] | None, str]:
    """Return (manifest, "") or (None, refusal reason). Verifies everything the manifest declares."""
    m = directory / MANIFEST
    try:
        if directory.is_symlink() or not directory.is_dir() or m.is_symlink() or not m.is_file():
            return None, "plugin_missing"
        raw = m.read_bytes()
    except OSError:
        return None, "plugin_missing"
    if len(raw) > MAX_MANIFEST:
        return None, "plugin_manifest_invalid"
    digest = hashlib.sha256(raw).hexdigest()  # the bytes parsed below, not a second read
    if expected_sha256 is not None and digest != expected_sha256:
        return None, "plugin_manifest_hash_mismatch"
    try:
        d = json.loads(raw)
    except ValueError:
        return None, "plugin_manifest_invalid"
    if not isinstance(d, dict) or set(d) != MANIFEST_KEYS:
        return None, "plugin_manifest_invalid"
    if expected_name is not None and d["name"] != expected_name:
        # The policy pin names the plugin; the verified manifest must carry exactly that name.
        return None, "plugin_name_mismatch"
    if not NAME.match(str(d["name"])) or not VERSION.match(str(d["version"])) or d["api"] != API:
        return None, "plugin_incompatible_api"
    if d["activity_class"] != "S1":
        return None, "plugin_activity_class_denied"
    if d["permissions"] != GRANTABLE:
        return None, "plugin_permission_denied"
    if not (VERSION.match(str(d["min_sentinel"])) and VERSION.match(str(d["max_sentinel"]))):
        return None, "plugin_manifest_invalid"
    if not _ver(d["min_sentinel"]) <= _ver(__version__) <= _ver(d["max_sentinel"]):
        return None, "plugin_version_incompatible"
    entry = str(d["entry"])
    if "/" in entry or entry.startswith(".") or not entry.endswith(".py"):
        return None, "plugin_manifest_invalid"
    e = directory / entry
    if (
        e.is_symlink()
        or not e.is_file()
        or not HEX64.match(str(d["entry_sha256"]))
        or file_sha256(e) != d["entry_sha256"]
    ):
        return None, "plugin_entry_hash_mismatch"
    return d, ""


class PluginAdapter(NativeAnalyzerAdapter):
    """A pinned plugin run as an isolated native analyzer. Refusals are NOT_RUN with the reason."""

    def __init__(self, pin: PluginPin) -> None:
        self.pin = pin
        self._provenance: dict[str, str] | None = None
        self.name = pin.name
        self.domain = "plugin"
        self.check_id = f"plugin.{pin.name}"
        super().__init__(None)
        self.path = pin.path / "plugin.py"  # informational only; execution uses program()
        self.manifest = AdapterManifest(
            name=f"plugin-{pin.name}",
            version="1.0.0",
            scanner=f"plugin:{pin.name}",
            scanner_versions="declared in plugin manifest",
            licence="declared in plugin manifest",
            activity_class=ActivityClass.S1,
            needs_network=False,
            check_ids=(self.check_id,),
            output_schema="sentinel-analyzer/1",
            engine_owned=False,
        )

    def _verified(self) -> tuple[dict[str, Any] | None, str]:
        return load_manifest(self.pin.path, self.pin.manifest_sha256, self.pin.name)

    def plan(self, root: Path) -> list[PlannedCheck]:
        return [PlannedCheck(self.check_id, (str(root),))]

    def program(self) -> tuple[str, str, str, list[str]]:
        """Verify, then run exactly the verified bytes (V-6).

        The manifest is verified against its pin, then the entry is read **once** (no symlinks,
        size-capped), hashed, and those same bytes are handed to the interpreter as `-c` source. Nothing
        is read from the plugin directory again, so replacing the file after verification can't change
        what runs."""
        self._provenance = None
        manifest, why = self._verified()
        if manifest is None:
            return why, "", "", []
        entry = self.pin.path / str(manifest["entry"])
        try:
            fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return "plugin_entry_hash_mismatch", "", "", []
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(MAX_ENTRY + 1)
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) > MAX_ENTRY:
            return "plugin_entry_too_large", "", digest, []
        if digest != manifest["entry_sha256"]:
            return "plugin_entry_hash_mismatch", "", digest, []
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "plugin_entry_invalid", "", digest, []
        if "\x00" in source:
            return "plugin_entry_invalid", "", digest, []
        # Provenance for this execution: exactly the manifest (== pinned hash, verified over the parsed
        # bytes) and the entry bytes that are about to run.
        self._provenance = {
            "name": str(manifest["name"]),
            "version": str(manifest["version"]),
            "manifest_sha256": self.pin.manifest_sha256,
            "entry_sha256": digest,
        }
        return "", str(manifest["version"]), digest, ["-c", source]

    def execute_extra_read(self) -> list[Path]:
        return []  # the verified source travels in argv: the plugin directory is never read at run time

    def normalize(self, raw: bytes) -> list[dict[str, Any]]:
        out = super().normalize(raw)
        prov = self._provenance
        if prov is None:  # normalize is only reached after program() verified this run's bytes
            raise ValueError("plugin provenance missing")
        for f in out:
            f["rule"] = "plugin." + f["rule"]
            f["plugin"] = dict(prov)
        return out

    def health(self) -> list[str]:
        manifest, why = self._verified()
        return [] if manifest else [f"plugin {self.pin.name}: {why}"]


def plugin_adapters(pins: dict[str, PluginPin]) -> list[PluginAdapter]:
    return [PluginAdapter(p) for _, p in sorted(pins.items())]


def inspect(directory: Path) -> dict[str, Any]:
    """Read-only: validate a plugin directory and print what an operator would pin. Pins nothing."""
    m = directory / MANIFEST
    manifest, why = load_manifest(directory)
    return {
        "path": str(directory.resolve()),
        "valid": manifest is not None,
        "refusal": why or None,
        "manifest_sha256": file_sha256(m) if m.is_file() and not m.is_symlink() else None,
        "manifest": manifest,
        "note": "Pinning needs an approved policy.change: plugins.<name> = {path, manifest_sha256}.",
    }
