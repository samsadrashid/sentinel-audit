"""Shared helpers for Sentinel's native static analyzers (run as `python -I <analyzer>.py <root>`).

Analyzers are Sentinel's own reviewed code, but they still run only inside a verified isolation layer
(D-32, X-5). They read the target, never write to it, never execute target content, never use the
network, and print one JSON document: {"tool": name, "findings": [...]}. Limits bound every walk and
parse. XML with a DOCTYPE or entity declaration is refused rather than parsed (XXE, entity expansion).
"""

from __future__ import annotations

import json
import os
import stat
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - DOCTYPE/ENTITY input refused before parsing
from collections.abc import Iterator
from pathlib import Path
from typing import Any

MAX_FILES = 20_000
MAX_FILE_BYTES = 4 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "build", "Pods", ".gradle"}


def walk(root: Path, max_files: int = MAX_FILES) -> Iterator[Path]:
    """Regular files under root; symlinks are never followed; bounded."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                st = p.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
                continue
            n += 1
            if n > max_files:
                return
            yield p


def read_text(p: Path) -> str:
    return p.read_bytes()[:MAX_FILE_BYTES].decode("utf-8", "replace")


class UnsafeXML(ValueError):
    pass


def parse_xml(p: Path) -> ET.Element:
    raw = p.read_bytes()[:MAX_FILE_BYTES]
    head = raw[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in raw.upper():
        raise UnsafeXML(f"{p.name}: DOCTYPE/ENTITY declarations are refused")
    return ET.fromstring(raw)  # noqa: S314 - DTDs refused above


def line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


def finding(rule: str, file: str, line: int, message: str, severity: str) -> dict[str, Any]:
    return {"rule": rule, "file": file, "line": int(line), "message": message[:500], "severity": severity}


def unparseable(rel: str, what: str) -> dict[str, Any]:
    """Explicit status for input that couldn't be parsed: never a silent skip (V-5)."""
    return finding("input-unparseable", rel, 0, f"{what} could not be parsed; not analysed", "informational")


def emit(tool: str, findings: list[dict[str, Any]]) -> None:
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    sys.stdout.write(json.dumps({"tool": tool, "findings": findings}, sort_keys=True))


def main(tool: str, analyze: Any) -> int:
    if len(sys.argv) != 2:
        return 2
    root = Path(sys.argv[1]).resolve()
    if not root.is_dir():
        return 2
    emit(tool, analyze(root))
    return 0
