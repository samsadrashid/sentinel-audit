"""Cheap, read-only applicability probe (no symlink following, bounded)."""

from __future__ import annotations

import os
from pathlib import Path

MAX_ENTRIES = 20_000
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "Pods", "build"}


def any_file(root: Path, names: set[str], suffixes: tuple[str, ...]) -> bool:
    n = 0
    for _dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        if suffixes and any(d.endswith(suffixes) for d in dirnames):
            return True
        for f in filenames:
            n += 1
            if n > MAX_ENTRIES:
                return False
            if f in names or (suffixes and f.endswith(suffixes)):
                return True
    return False
