"""Regression: a real CLI audit with the complete default adapter set completes and fails closed.

Found 2026-11-10: the run manifest calls detect() on every adapter, and the MobSF stub lacked it, so a
default `sentinel audit` would have crashed. Tests elsewhere use fixture-only adapter sets.
"""

# ruff: noqa: F811
from __future__ import annotations

import dataclasses

from sentinel import cli

from .test_b2 import MANIFEST, axml_doc, zbytes
from .test_cli import config, deps, ready, run, target  # noqa: F401


def test_default_cli_audit_with_all_adapters_completes(ready, capsys, tmp_path):
    d = dataclasses.replace(ready, adapters=lambda pol: cli.default_adapters(pol))
    t = target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    (t / "app.apk").write_bytes(zbytes([("AndroidManifest.xml", axml_doc(MANIFEST))]))
    (t / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>'
    )
    code, out = run(d, capsys, "audit", "--config", config(tmp_path, t, classes=("S1", "S2", "B2")))
    assert code in (cli.EXIT_FINDINGS, cli.EXIT_INCOMPLETE), out
    _, manifest, result = cli.verified_run(out["audit_id"])
    by = {c["adapter"]: c for c in result["checks"]}
    # Without the share-free B2 machine (test host) B2 is NOT_RUN, never PASS; MobSF is NOT_RUN.
    assert by["archive"]["status"] == "NOT_RUN"
    assert by["mobsf"]["status"] == "NOT_RUN"
    assert result["overall"] != "PASS"
    names = {a["name"] for a in manifest["adapters"]}
    assert {"archive", "mobsf", "fixture"} <= names
