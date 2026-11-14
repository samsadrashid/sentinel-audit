"""Capabilities that are configured but blocked by an external requirement: reported, never silent.

A blocked adapter plans a check wherever it would apply, and always answers `NOT_RUN` with an exact
reason. The audit then shows the gap (overall `INCOMPLETE`) instead of omitting the capability. It never
starts a process.

There is currently none. MobSF (B-7) was blocked here until D-72 (2026-11-10) accepted MobSF 4.6.4 in
the share-free machine; it is now `adapters.mobsf.MobsfAdapter`.
"""

from __future__ import annotations

from typing import Any


def blocked_adapters() -> list[Any]:
    return []
