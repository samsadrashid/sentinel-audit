"""Binary structural metadata (M8): PE, MSI and MSIX/APPX. Header-only and bounded.

* **PE** (`.exe`, `.dll`, `.sys`): DOS, COFF and optional headers; ASLR, DEP, CFG and high-entropy-VA
  flags; writable-and-executable sections; whether an Authenticode blob is present. The signature is
  **not verified**: that needs a trust store and revocation data, so presence is reported as presence.
* **MSI** (OLE compound file): header validation, then a bounded walk of the directory chain to see
  whether a `\\x05DigitalSignature` stream exists. No stream content is read.
* **MSIX/APPX** (zip): only the central directory is read (`zipfile.ZipFile.infolist`); no entry is
  decompressed or extracted (B2 stays disabled, M2-SA-12). Path-traversal names, absolute paths,
  compression-ratio bombs and missing signature/block-map entries are reported.

Nothing is executed, loaded, decompressed or written. Malformed files give `input-unparseable`.
"""

# ruff: noqa: E501 - finding messages are kept on one line for readability
from __future__ import annotations

import os  # noqa: E402
import struct
import sys  # noqa: E402
import zipfile
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import finding, main, unparseable, walk

PE_SUFFIXES = (".exe", ".dll", ".sys", ".scr", ".ocx")
MSIX_SUFFIXES = (".msix", ".appx", ".msixbundle", ".appxbundle")
MAX_HEADER = 64 * 1024
MAX_ZIP_ENTRIES = 50_000
MAX_RATIO = 200
CFB_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
MAX_DIR_SECTORS = 4096

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
DLL_DYNAMIC_BASE = 0x0040
DLL_NX_COMPAT = 0x0100
DLL_GUARD_CF = 0x4000


class Malformed(ValueError):
    pass


def _u(fmt: str, buf: bytes, off: int) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(buf):
        raise Malformed("truncated header")
    return struct.unpack_from(fmt, buf, off)


def pe(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    with path.open("rb") as fh:
        buf = fh.read(MAX_HEADER)
    if buf[:2] != b"MZ":
        raise Malformed("no MZ header")
    (lfanew,) = _u("<I", buf, 0x3C)
    if _u("<4s", buf, lfanew)[0] != b"PE\0\0":
        raise Malformed("no PE signature")
    _machine, nsect, _ts, _sym, _nsym, opt_size, _chars = _u("<HHIIIHH", buf, lfanew + 4)
    opt = lfanew + 24
    (magic,) = _u("<H", buf, opt)
    if magic not in (0x10B, 0x20B):
        raise Malformed("unknown optional header")
    (dllchars,) = _u("<H", buf, opt + 70)
    dd_base = opt + (96 if magic == 0x10B else 112)
    (nrva,) = _u("<I", buf, dd_base - 4)
    signed = False
    if nrva > 4:
        _sec_rva, sec_size = _u("<II", buf, dd_base + 4 * 8)
        signed = sec_size > 0
    if not dllchars & DLL_DYNAMIC_BASE:
        out.append(finding("pe-no-aslr", rel, 0, "PE built without ASLR (DYNAMIC_BASE)", "medium"))
    if not dllchars & DLL_NX_COMPAT:
        out.append(finding("pe-no-dep", rel, 0, "PE built without DEP (NX_COMPAT)", "medium"))
    if not dllchars & DLL_GUARD_CF:
        out.append(finding("pe-no-cfg", rel, 0, "PE built without Control Flow Guard", "low"))
    if not signed:
        out.append(finding("pe-unsigned", rel, 0, "No Authenticode signature blob present", "medium"))
    else:
        out.append(
            finding(
                "pe-signature-present", rel, 0, "Authenticode blob present (not verified)", "informational"
            )
        )
    sect = opt + opt_size
    for i in range(min(nsect, 96)):
        name, *_rest, chars = _u("<8s6I2HI", buf, sect + 40 * i)
        if chars & IMAGE_SCN_MEM_EXECUTE and chars & IMAGE_SCN_MEM_WRITE:
            label = name.rstrip(b"\0").decode("ascii", "replace")
            out.append(
                finding("pe-wx-section", rel, 0, f"Section {label} is writable and executable", "high")
            )


def msi(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    size = path.stat().st_size
    with path.open("rb") as fh:
        hdr = fh.read(512)
        if hdr[:8] != CFB_MAGIC:
            raise Malformed("not an OLE compound file")
        (major,) = _u("<H", hdr, 0x1A)
        (shift,) = _u("<H", hdr, 0x1E)
        if (major, shift) not in ((3, 9), (4, 12)):
            raise Malformed("invalid compound-file version or sector size")
        ssz = 1 << shift
        (nfat,) = _u("<I", hdr, 0x2C)
        (dir_start,) = _u("<I", hdr, 0x30)
        difat = list(_u("<109I", hdr, 0x4C))[: min(nfat, 109)]

        def sector(n: int) -> bytes:
            off = (n + 1) * ssz
            if n >= 0xFFFFFFFA or off + ssz > size:
                raise Malformed("sector outside file")
            fh.seek(off)
            return fh.read(ssz)

        fat: list[int] = []
        for s in difat:
            fat.extend(struct.unpack(f"<{ssz // 4}I", sector(s)))
        names: list[str] = []
        cur, seen = dir_start, 0
        while cur < 0xFFFFFFFA:
            seen += 1
            if seen > MAX_DIR_SECTORS or cur >= len(fat):
                raise Malformed("directory chain too long or broken")
            data = sector(cur)
            for e in range(ssz // 128):
                ent = data[e * 128 : (e + 1) * 128]
                (nlen,) = struct.unpack_from("<H", ent, 64)
                if 2 <= nlen <= 64:
                    names.append(ent[: nlen - 2].decode("utf-16-le", "replace"))
            cur = fat[cur]
    if "\x05DigitalSignature" in names:
        out.append(
            finding(
                "msi-signature-present",
                rel,
                0,
                "MSI DigitalSignature stream present (not verified)",
                "informational",
            )
        )
    else:
        out.append(finding("msi-unsigned", rel, 0, "MSI has no DigitalSignature stream", "medium"))


def msix(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    try:
        with zipfile.ZipFile(path) as z:  # reads only the central directory; nothing is decompressed
            infos = z.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise Malformed("not a valid zip package") from exc
    if len(infos) > MAX_ZIP_ENTRIES:
        out.append(
            finding(
                "package-entry-limit", rel, 0, f"Package has {len(infos)} entries (limit exceeded)", "medium"
            )
        )
        return
    names = {i.filename for i in infos}
    for i in infos:
        n = i.filename.replace("\\", "/")
        if n.startswith("/") or ".." in n.split("/") or (len(n) > 1 and n[1] == ":"):
            out.append(
                finding(
                    "package-path-traversal", rel, 0, f"Entry name escapes the package: {n[:200]}", "high"
                )
            )
        if i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
            out.append(
                finding(
                    "package-compression-bomb", rel, 0, f"Entry {n[:120]} expands over {MAX_RATIO}x", "high"
                )
            )
        if (i.external_attr >> 16) & 0o170000 == 0o120000:
            out.append(finding("package-symlink-entry", rel, 0, f"Symlink entry {n[:200]}", "high"))
    if path.suffix.lower() in (".msix", ".appx"):
        if "AppxSignature.p7x" not in names:
            out.append(finding("msix-unsigned", rel, 0, "No AppxSignature.p7x (unsigned package)", "medium"))
        if "AppxBlockMap.xml" not in names:
            out.append(
                finding("msix-no-blockmap", rel, 0, "No AppxBlockMap.xml (integrity map missing)", "medium")
            )


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in walk(root):
        rel = str(p.relative_to(root))
        suffix = p.suffix.lower()
        try:
            if suffix in PE_SUFFIXES:
                pe(rel, p, out)
            elif suffix == ".msi":
                msi(rel, p, out)
            elif suffix in MSIX_SUFFIXES:
                msix(rel, p, out)
        except (Malformed, struct.error, OSError, UnicodeError, IndexError, ValueError):
            out.append(unparseable(rel, f"{suffix} file"))
    return out


if __name__ == "__main__":
    raise SystemExit(main("binmeta", analyze))
