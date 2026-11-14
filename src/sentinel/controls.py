"""Kill switch, pause and resume for a running audit (AC-17, §8.2, R-04, D-52).

A running audit registers itself in ``<state>/control/<audit_id>.active`` and watches
``<state>/control/<audit_id>.cmd``. `sentinel cancel|pause|resume <audit_id>` writes a command there
atomically; the audit's watcher thread applies it within ``POLL_S`` seconds:

* **cancel:** sets the kill switch. Every running scanner process tree is killed (process group and
  container), checks that were running become ``BLOCKED`` (``cancelled``), checks not started are
  ``NOT_RUN`` (``cancelled``), the audit is ``Cancelled``, and the result is never ``PASS``.
* **pause:** no new check starts; running checks finish (or are stopped by a later cancel).
* **resume:** every remaining check is re-authorised before anything starts again. If the target's
  source revision changed while paused, the remaining checks are ``BLOCKED`` (``revision_changed``),
  the audit ends ``Cancelled`` with ``restart_required``, and the CLI starts a fresh audit.

Every transition is written to the run's audit log. Commands only ever *reduce* what runs: none can
widen scope or skip authorisation.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

from . import canonical
from .errors import ValidationError
from .paths import atomic_write, ensure_private_dir, state_dir

COMMANDS = ("cancel", "pause", "resume")
POLL_S = 0.2
AUDIT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def control_dir() -> Path:
    return ensure_private_dir(state_dir() / "control")


def _check_id(audit_id: str) -> str:
    if not AUDIT_ID.match(audit_id):
        raise ValidationError("audit id must be a UUID")
    return audit_id


def active_path(audit_id: str) -> Path:
    return control_dir() / f"{_check_id(audit_id)}.active"


def command_path(audit_id: str) -> Path:
    return control_dir() / f"{_check_id(audit_id)}.cmd"


def register(audit_id: str) -> None:
    atomic_write(active_path(audit_id), canonical.encode({"audit_id": audit_id, "pid": os.getpid()}))
    command_path(audit_id).unlink(missing_ok=True)


def unregister(audit_id: str) -> None:
    for p in (active_path(audit_id), command_path(audit_id)):
        p.unlink(missing_ok=True)


def is_active(audit_id: str) -> bool:
    p = active_path(audit_id)
    if not p.is_file():
        return False
    try:
        data = canonical.decode_strict(p.read_bytes())
        pid = int(data["pid"]) if isinstance(data, dict) else -1
        os.kill(pid, 0)
    except (ValueError, KeyError, TypeError, OSError):
        return False
    return True


def send(audit_id: str, command: str, now: int) -> dict[str, Any]:
    if command not in COMMANDS:
        raise ValidationError(f"unknown control command {command!r}")
    if not is_active(audit_id):
        raise ValidationError(f"no running audit {audit_id}")
    prev = read(audit_id)
    seq = (prev["seq"] + 1) if prev else 1
    body = {"command": command, "issued_at": now, "seq": seq}
    atomic_write(command_path(audit_id), canonical.encode(body))
    return {"audit_id": audit_id, **body}


def read(audit_id: str) -> dict[str, Any] | None:
    p = command_path(audit_id)
    if not p.is_file():
        return None
    try:
        data = canonical.decode_strict(p.read_bytes(), max_bytes=4096)
    except ValueError:
        return None
    if (
        not isinstance(data, dict)
        or set(data) != {"command", "issued_at", "seq"}
        or data["command"] not in COMMANDS
        or not isinstance(data["seq"], int)
    ):
        return None
    return data


def wait_until(predicate: Any, timeout_s: float, step: float = 0.05) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(step)
    return bool(predicate())
