"""Filesystem locations and safe file helpers (owner-only permissions, atomic writes, root checks)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .errors import ValidationError


def state_dir() -> Path:
    """Engine state: keys metadata, trust store, nonce ledger, runs. Overridable for tests."""
    base = os.environ.get("SENTINEL_HOME")
    if base:
        return Path(base).expanduser().resolve()
    return (Path.home() / ".local" / "state" / "sentinel").resolve()


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def write_once(path: Path, data: bytes) -> None:
    """Create a file that must not already exist (write-once evidence, §6.2)."""
    ensure_private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def resolve_within(root: Path, candidate: str | Path) -> Path:
    """Resolve candidate under root; refuse anything that escapes root, including via symlinks (T6)."""
    root_r = root.resolve()
    p = (root_r / candidate).resolve()
    if p != root_r and root_r not in p.parents:
        raise ValidationError(f"path escapes scope root: {candidate}")
    return p
