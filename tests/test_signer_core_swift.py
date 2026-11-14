"""D-73: the SignerCore XCTest suite (Tests/SignerCoreTests), run from pytest so the security mutation
harness covers the Swift signer code too. Skips (never passes) off macOS or without a Swift toolchain."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1] / "native" / "macos" / "sentinel-signer"


@pytest.mark.skipif(sys.platform != "darwin", reason="sentinel-signer is macOS-only (not a pass)")
@pytest.mark.skipif(shutil.which("swift") is None, reason="Swift toolchain unavailable (not a pass)")
def test_signer_core_xctest_suite_passes():
    r = subprocess.run(["swift", "test"], cwd=PKG, capture_output=True, text=True, timeout=1800)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-3000:]
    assert " 0 failures" in out and "Executed" in out, out[-2000:]
