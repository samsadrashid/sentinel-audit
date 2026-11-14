"""B2 archive inspection, executed only inside the share-free B2 container (D-25, D-35, D-70). Stdlib only.

Input: the archive bytes on stdin. Output: one JSON document on stdout. Nothing is written outside the
container's disposable `/work` tmpfs, and the container has no host mount at all.

Rules, all fail closed. Any violation rejects the archive: it is reported, and none of it is analysed.

* **Format:** only zip-based packages (APK, AAB, IPA, JAR, ZIP) are accepted. Everything else is
  `archive-unsupported-format` (D-25: unsupported formats are rejected).
* **Entry names:** absolute paths, `..`, backslashes, drive letters, NUL, duplicates (including
  case-insensitive duplicates) and path depth over 32 are rejected.
* **Entry types:** symlinks are rejected (zip has no hard links), as are encrypted entries and unknown
  compression methods.
* **D-35 limits:** at most 10,000 entries; per-entry compression ratio at most 100:1 and whole-artifact
  ratio at most 50:1 (both checked once an entry is at least 64 KiB); largest file 256 MB; total
  1 GB. Nested archives are counted and reported, never unpacked here, so nesting stays within depth 3.
* **Declared versus actual size:** every entry is decompressed in bounded chunks and discarded. Its real
  size must equal the declared size, and the running total is capped.
* Only a few small metadata files are kept, and they are written to the disposable `/work`:
  * the decoded AndroidManifest.xml (binary AXML) and `res/xml` network-security configs;
  * the IPA Info.plist, the entitlements from `embedded.mobileprovision`, and PrivacyInfo.xcprivacy.

  The existing Android and iOS analyzers then run on that directory.
"""

from __future__ import annotations

import io
import json
import os
import plistlib
import posixpath
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

LIMITS = {
    "max_artifact_bytes": 512 * 1024 * 1024,
    "max_entries": 10_000,
    "max_path_depth": 32,
    "max_entry_ratio": 100,
    "max_total_ratio": 50,
    "ratio_min_bytes": 64 * 1024,
    "max_file_bytes": 256 * 1024 * 1024,
    "max_total_bytes": 1024 * 1024 * 1024,
    "max_metadata_bytes": 8 * 1024 * 1024,
}
NESTED = (".apk", ".aab", ".ipa", ".jar", ".zip", ".aar")
CHUNK = 1 << 20


class Rejected(Exception):
    def __init__(self, rule: str, message: str) -> None:
        super().__init__(message)
        self.rule, self.message = rule, message


def finding(rule: str, file: str, message: str, severity: str) -> dict[str, Any]:
    return {"rule": rule, "file": file, "line": 0, "message": message[:500], "severity": severity}


def _check_name(n: str, seen: set[str]) -> None:
    if not n or "\x00" in n or "\\" in n:
        raise Rejected("archive-bad-entry-name", f"unsafe entry name {n[:80]!r}")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        raise Rejected("archive-path-traversal", f"absolute entry path {n[:120]}")
    parts = [p for p in n.split("/") if p]
    if ".." in parts:
        raise Rejected("archive-path-traversal", f"entry escapes the archive: {n[:120]}")
    if len(parts) > LIMITS["max_path_depth"]:
        raise Rejected("archive-path-too-deep", f"entry path depth {len(parts)} > {LIMITS['max_path_depth']}")
    key = posixpath.normpath(n).lower()
    if key in seen:
        raise Rejected("archive-duplicate-entry", f"duplicate entry {n[:120]}")
    seen.add(key)


def validate(z: zipfile.ZipFile, size: int) -> list[zipfile.ZipInfo]:
    infos = z.infolist()
    if len(infos) > LIMITS["max_entries"]:
        raise Rejected("archive-too-many-entries", f"{len(infos)} entries > {LIMITS['max_entries']}")
    seen: set[str] = set()
    total = 0
    for i in infos:
        _check_name(i.filename, seen)
        mode = (i.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise Rejected("archive-symlink-entry", f"symlink entry {i.filename[:120]}")
        if i.flag_bits & 0x1:
            raise Rejected("archive-encrypted-entry", f"encrypted entry {i.filename[:120]}")
        if i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise Rejected("archive-unsupported-compression", f"compression {i.compress_type}")
        if i.file_size > LIMITS["max_file_bytes"]:
            raise Rejected("archive-entry-too-large", f"{i.filename[:120]} declares {i.file_size} bytes")
        if i.file_size >= LIMITS["ratio_min_bytes"] and i.file_size > LIMITS["max_entry_ratio"] * max(
            1, i.compress_size
        ):
            raise Rejected(
                "archive-compression-bomb", f"{i.filename[:120]} ratio over {LIMITS['max_entry_ratio']}:1"
            )
        total += i.file_size
        if total > LIMITS["max_total_bytes"]:
            raise Rejected(
                "archive-too-large-expanded", f"total expanded size over {LIMITS['max_total_bytes']}"
            )
    if total >= LIMITS["ratio_min_bytes"] and total > LIMITS["max_total_ratio"] * max(1, size):
        raise Rejected("archive-compression-bomb", f"whole-archive ratio over {LIMITS['max_total_ratio']}:1")
    return infos


def keep(name: str) -> bool:
    n = name.lower()
    return (
        n == "androidmanifest.xml"
        or (n.startswith("res/xml/") and n.endswith(".xml"))
        or bool(
            re.fullmatch(
                r"payload/[^/]+\.app/(info\.plist|embedded\.mobileprovision|privacyinfo\.xcprivacy)", n
            )
        )
    )


def read_all(z: zipfile.ZipFile, infos: list[zipfile.ZipInfo]) -> dict[str, bytes]:
    """Decompress every entry in bounded chunks; verify the declared sizes; keep only metadata files."""
    kept: dict[str, bytes] = {}
    total = 0
    for i in infos:
        if i.is_dir():
            continue
        got = 0
        buf = io.BytesIO() if keep(i.filename) else None
        with z.open(i) as fh:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                got += len(chunk)
                total += len(chunk)
                if got > i.file_size or total > LIMITS["max_total_bytes"]:
                    raise Rejected(
                        "archive-size-mismatch", f"{i.filename[:120]} expands beyond its declared size"
                    )
                if buf is not None and got <= LIMITS["max_metadata_bytes"]:
                    buf.write(chunk)
        if got != i.file_size:
            raise Rejected(
                "archive-size-mismatch", f"{i.filename[:120]}: {got} bytes, declared {i.file_size}"
            )
        if buf is not None and got <= LIMITS["max_metadata_bytes"]:
            kept[i.filename] = buf.getvalue()
    return kept


def materialise(
    kept: dict[str, bytes], work: Path, archive: str, out: list[dict[str, Any]]
) -> dict[str, str]:
    """Write the decoded metadata into `work`. Returns {written path: original entry path}."""
    from axml import decode

    origin: dict[str, str] = {}

    def put(rel: str, data: bytes, src: str) -> None:
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        origin[rel] = src

    for name, data in sorted(kept.items()):
        low = name.lower()
        try:
            if low == "androidmanifest.xml" or low.startswith("res/xml/"):
                text = decode(data) if data[:2] == b"\x03\x00" else data.decode("utf-8")
                if low == "androidmanifest.xml":
                    put("AndroidManifest.xml", text.encode(), name)
                elif "<network-security-config" in text:
                    put("res/xml/" + posixpath.basename(name), text.encode(), name)
            elif low.endswith("/info.plist"):
                put("Info.plist", plistlib.dumps(plistlib.loads(data)), name)
            elif low.endswith("/privacyinfo.xcprivacy"):
                put("PrivacyInfo.xcprivacy", data, name)
            elif low.endswith("/embedded.mobileprovision"):
                s, e = data.find(b"<?xml"), data.find(b"</plist>")
                if s >= 0 and e > s:
                    prof = plistlib.loads(data[s : e + len(b"</plist>")])
                    ent = prof.get("Entitlements") if isinstance(prof, dict) else None
                    if isinstance(ent, dict):
                        put("App.entitlements", plistlib.dumps(ent), name)
        except (
            ValueError,
            UnicodeDecodeError,
            plistlib.InvalidFileException,
            OverflowError,
            TypeError,
            KeyError,
        ):
            out.append(
                finding(
                    "input-unparseable",
                    f"{archive}!/{name}",
                    f"{name} could not be decoded; not analysed",
                    "informational",
                )
            )
    return origin


def inspect(data: bytes, archive: str, work: Path) -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    summary: dict[str, Any] = {"archive": archive, "bytes": len(data), "analysed": False}
    try:
        if len(data) > LIMITS["max_artifact_bytes"]:
            raise Rejected("archive-too-large", f"artifact over {LIMITS['max_artifact_bytes']} bytes")
        if not data.startswith(b"PK\x03\x04"):
            raise Rejected("archive-unsupported-format", "not a zip-based package (APK/AAB/IPA/JAR/ZIP)")
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            raise Rejected("archive-malformed", f"invalid zip structure: {str(exc)[:120]}") from exc
        with z:
            infos = validate(z, len(data))
            try:
                kept = read_all(z, infos)
            except (
                zipfile.BadZipFile,
                OSError,
                EOFError,
                ValueError,
                NotImplementedError,
                RuntimeError,
            ) as exc:
                raise Rejected(
                    "archive-malformed", f"entry could not be decompressed: {str(exc)[:120]}"
                ) from exc
        summary["entries"] = len(infos)
        summary["expanded_bytes"] = sum(i.file_size for i in infos)
        nested = [i.filename for i in infos if i.filename.lower().endswith(NESTED)]
        for n in nested[:50]:
            out.append(
                finding(
                    "archive-nested-not-unpacked",
                    f"{archive}!/{n}",
                    "Nested archive present; not unpacked (counted, depth limit kept)",
                    "informational",
                )
            )
    except Rejected as r:
        out.append(
            finding(
                r.rule, archive, r.message, "high" if r.rule != "archive-unsupported-format" else "medium"
            )
        )
        out.append(
            finding(
                "archive-not-analysed",
                archive,
                "Archive rejected by the B2 rules; nothing in it was analysed",
                "informational",
            )
        )
        return {"tool": "archive", "findings": out, "summary": summary}
    origin = materialise(kept, work, archive, out)
    if any(k.endswith(("AndroidManifest.xml",)) for k in origin) or any(
        k.startswith("res/xml/") for k in origin
    ):
        import android

        for f in android.analyze(work):
            f["file"] = f"{archive}!/{origin.get(f['file'], f['file'])}"
            out.append(f)
    if any(k in origin for k in ("Info.plist", "App.entitlements", "PrivacyInfo.xcprivacy")):
        import ios

        for f in ios.analyze(work):
            if f["rule"] == "missing-privacy-manifest":
                continue  # needs source files; an IPA has none
            f["file"] = f"{archive}!/{origin.get(f['file'], f['file'])}"
            out.append(f)
    summary["analysed"] = True
    summary["metadata_files"] = sorted(origin.values())
    return {"tool": "archive", "findings": out, "summary": summary}


def main() -> int:
    archive = sys.argv[1] if len(sys.argv) > 1 else "artifact"
    data = sys.stdin.buffer.read(LIMITS["max_artifact_bytes"] + 1)
    work = Path(os.environ.get("B2_WORK", "/work")) / "x"
    work.mkdir(parents=True, exist_ok=True)
    sys.stdout.write(json.dumps(inspect(data, archive, work), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
