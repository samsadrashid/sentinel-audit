"""MobSF 4.6.4 in the share-free machine (D-72): the bundled in-container driver program.

The driver is Sentinel's own source (`driver.py`), passed as one `python3 -I -c` argument, so nothing
is mounted. Its SHA-256 is recorded with every result.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

DRIVER = Path(__file__).resolve().parent / "driver.py"
MAX_PROGRAM = 120 * 1024  # Linux MAX_ARG_STRLEN is 128 KiB
#: The approved MobSF release (D-72). The image ID is pinned in the approved policy.
VERSION = "4.6.4"
#: D-35: a single artifact is at most 512 MiB.
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


def program() -> tuple[str, str]:
    """(program text, sha256). Raises ValueError if it would exceed the single-argument limit."""
    text = DRIVER.read_text(encoding="utf-8")
    if len(text.encode()) > MAX_PROGRAM:
        raise ValueError("MobSF driver exceeds the argument size limit")
    return text, hashlib.sha256(text.encode()).hexdigest()
