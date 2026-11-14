"""Retention pruning (AC-18, D-19, §13.5, D-52 item 8).

* `prune --list` reads only: it lists runs older than the retention limit
  (`evidence_retention_days`, default 90) and deletes nothing.
* `prune --delete` deletes exactly the listed runs, and only after interactive confirmation by a human
  operator. It is refused in non-interactive sessions and from AI-agent environments.
* Before any byte is deleted, a **hash-only** `retention.deleted` entry goes into the hash-chained,
  run-key-checkpointed admin log. The entry holds the run ID's SHA-256, the signed manifest's
  SHA-256, the run's audit-log head and the evidence count: never content. After deletion, the run's
  evidence, indexes, reports, log and workspace are gone (0 files remain, re-checked), a
  `retention.delete_completed` entry records the outcome, and the log chain still verifies. Earlier
  history is never rewritten.

The age of a run comes from the timestamp of its own first audit-log entry (`audit.created`). A run
whose age can't be determined is never deleted; it is listed as `age_unknown`.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import canonical
from .errors import BlockedError, IntegrityError, SentinelError
from .paths import state_dir

RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DAY = 86400


def _created_at(run: Path) -> int | None:
    log = run / "audit-log.jsonl"
    try:
        with log.open("rb") as fh:
            first = fh.readline(65536)
        entry = canonical.decode_strict(first.strip())
    except (OSError, ValueError, SentinelError):
        return None
    if isinstance(entry, dict) and entry.get("event") == "audit.created" and isinstance(entry.get("ts"), int):
        return int(entry["ts"])
    return None


def _manifest_sha256(run: Path) -> str | None:
    m = run / "manifest.json"
    try:
        return canonical.sha256_hex(m.read_bytes()) if m.is_file() and not m.is_symlink() else None
    except OSError:
        return None


def _log_head(run: Path) -> str | None:
    try:
        lines = (run / "audit-log.jsonl").read_bytes().splitlines()
        last = canonical.decode_strict(lines[-1]) if lines else None
    except (OSError, ValueError, IndexError, SentinelError):
        return None
    return str(last["hash"]) if isinstance(last, dict) and "hash" in last else None


def candidates(runs_dir: Path, now: int, retention_days: int) -> list[dict[str, Any]]:
    """Read-only. Every run directory with its age; `expired` marks the ones `--delete` would remove."""
    out: list[dict[str, Any]] = []
    if not runs_dir.is_dir():
        return out
    for p in sorted(runs_dir.iterdir()):
        if not RUN_ID.match(p.name) or p.is_symlink() or not p.is_dir():
            continue
        created = _created_at(p)
        age = None if created is None else (now - created) // DAY
        out.append(
            {
                "run_id": p.name,
                "created_at": created,
                "age_days": age,
                "expired": created is not None and now - created >= retention_days * DAY,
                "status": "age_unknown" if created is None else "ok",
            }
        )
    return out


def _count_files(root: Path) -> int:
    return sum(len(files) for _, _, files in os.walk(root)) if root.exists() else 0


def _make_removable(root: Path) -> None:
    """Evidence is stored read-only. Restore owner write permission (never following links) so the
    tree can be removed; nothing outside `root` is touched."""
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        os.chmod(dirpath, stat.S_IRWXU)
        for n in filenames:
            p = Path(dirpath) / n
            if not p.is_symlink():
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)


def delete_expired(
    runs_dir: Path,
    now: int,
    retention_days: int,
    *,
    record: Callable[[str, dict[str, Any]], None],
    confirm: Callable[[list[str]], bool],
) -> dict[str, Any]:
    """Delete the expired runs after confirmation. `record` appends to the admin log (checkpointed)."""
    expired = [c["run_id"] for c in candidates(runs_dir, now, retention_days) if c["expired"]]
    if not expired:
        return {"deleted": [], "remaining_files": 0}
    if not confirm(expired):
        record("retention.delete_declined", {"count": len(expired)})
        raise BlockedError("deletion not confirmed by the operator", "not_confirmed")
    deleted: list[str] = []
    for rid in expired:
        run = runs_dir / rid
        if run.is_symlink() or not run.is_dir() or run.resolve().parent != runs_dir.resolve():
            raise IntegrityError(f"run {rid} is not a plain directory inside the runs directory")
        evidence_dir = run / "evidence"
        entry = {
            "run_id_sha256": canonical.sha256_hex(rid.encode()),
            "manifest_sha256": _manifest_sha256(run),
            "audit_log_head": _log_head(run),
            "evidence_files": _count_files(evidence_dir),
            "deleted_at": now,
            "retention_days": retention_days,
        }
        record("retention.deleted", entry)  # hash-only record first; nothing deleted yet
        _make_removable(run)
        shutil.rmtree(run)
        for ws in (state_dir() / "control").glob(f"{rid}.*") if (state_dir() / "control").is_dir() else []:
            ws.unlink(missing_ok=True)
        left = _count_files(run)
        if run.exists() or left:
            raise IntegrityError(f"run {rid} was not fully deleted ({left} files remain)")
        deleted.append(rid)
    stale = 0
    ws_root = state_dir() / "workspaces"
    if ws_root.is_dir() and not ws_root.is_symlink():
        for ws in ws_root.iterdir():  # leftover per-check workspaces past retention (§13.5)
            if (
                ws.name.startswith("ws-")
                and not ws.is_symlink()
                and now - int(ws.stat().st_mtime) >= retention_days * DAY
            ):
                _make_removable(ws)
                shutil.rmtree(ws)
                stale += 1
    record(
        "retention.delete_completed",
        {"count": len(deleted), "remaining_files": 0, "stale_workspaces_removed": stale},
    )
    return {"deleted": deleted, "remaining_files": 0}
