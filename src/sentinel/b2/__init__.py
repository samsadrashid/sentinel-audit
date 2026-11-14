"""B2 archive inspection (D-25, D-35, D-70): program bundling for the share-free B2 container.

The program executed in the container is built only from Sentinel's own shipped sources: the unpacker,
the AXML decoder and the Android/iOS analyzers. It is passed as a single `python3 -I -c` argument, so
nothing is mounted. Its SHA-256 is recorded with every result.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import unpack  # noqa: F401  (limits are shared with the adapter)

HERE = Path(__file__).resolve().parent
ANALYZERS = HERE.parent / "analyzers"
SOURCES = {
    "_common": ANALYZERS / "_common.py",
    "axml": HERE / "axml.py",
    "android": ANALYZERS / "android.py",
    "ios": ANALYZERS / "ios.py",
    "unpack": HERE / "unpack.py",
}
#: Linux limits a single argv string to 128 KiB (MAX_ARG_STRLEN).
MAX_PROGRAM = 120 * 1024

BOOTSTRAP = """import json, sys, types
_S = json.loads({payload!r})
for _n in ("_common", "axml", "android", "ios", "unpack"):
    _m = types.ModuleType(_n if _n != "unpack" else "__b2__")
    _m.__file__ = "/work/" + _n + ".py"
    sys.modules[_m.__name__] = _m
    exec(compile(_S[_n], _n + ".py", "exec"), _m.__dict__)
sys.exit(sys.modules["__b2__"].main())
"""


def program() -> tuple[str, str]:
    """(program text, sha256). Raises ValueError if it would exceed the single-argument limit."""
    payload = json.dumps({k: p.read_text(encoding="utf-8") for k, p in SOURCES.items()}, sort_keys=True)
    text = BOOTSTRAP.format(payload=payload)
    if len(text.encode()) > MAX_PROGRAM:
        raise ValueError("B2 program exceeds the argument size limit")
    return text, hashlib.sha256(text.encode()).hexdigest()
