"""Deterministic fixture scanner used by the M1 adapter contract tests.

Reads text files under the target root (never executes them) and reports a finding for each line
containing the marker `SENTINEL-FIXTURE-FINDING`. Output is JSON on stdout. Standard library only.
Special markers let tests exercise failure paths: SENTINEL-FIXTURE-CRASH, -HANG, -GARBAGE.
"""

import json
import os
import sys
import time

MARKER = "SENTINEL-FIXTURE-FINDING"


def main() -> int:
    root = os.path.realpath(sys.argv[1])
    findings = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or os.path.getsize(path) > 1_000_000:
                continue
            rel = os.path.relpath(path, root)
            try:
                with open(path, encoding="utf-8", errors="strict") as fh:
                    lines = fh.read().splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            for i, line in enumerate(lines, 1):
                if "SENTINEL-FIXTURE-CRASH" in line:
                    raise RuntimeError("fixture crash requested")
                if "SENTINEL-FIXTURE-HANG" in line:
                    time.sleep(3600)
                if "SENTINEL-FIXTURE-GARBAGE" in line:
                    sys.stdout.write("{not json")
                    return 0
                if MARKER in line:
                    findings.append(
                        {
                            "rule": "fixture.marker",
                            "file": rel,
                            "line": i,
                            "message": "fixture marker present",
                            "severity": "medium",
                        }
                    )
    json.dump({"tool": "sentinel-fixture", "version": "1.0.0", "findings": findings}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
