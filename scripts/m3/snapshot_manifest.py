"""Write `snapshot-manifest.json` for an acquired vulnerability-database directory (D-29).

The manifest lists every file with its SHA-256 and size, plus provenance supplied by the operator. Its own
SHA-256, printed at the end, is what the approved policy pins (`trivy_database` / `grype_database`).
`scanners.verify_snapshot` re-hashes every listed file before every run.

Usage: python scripts/m3/snapshot_manifest.py DIR --source TEXT [--provenance KEY=VALUE ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

NAME = "snapshot-manifest.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", type=Path)
    ap.add_argument("--source", required=True)
    ap.add_argument("--provenance", action="append", default=[])
    a = ap.parse_args()
    root = a.dir.resolve()
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise SystemExit(f"refusing symlink in snapshot: {p}")
        if not p.is_file() or p.name == NAME:
            continue
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        files.append(
            {
                "path": str(p.relative_to(root)),
                "sha256": h.hexdigest(),
                "size": p.stat().st_size,
                "source": a.source,
            }
        )
    if not files:
        raise SystemExit("empty snapshot")
    prov = dict(kv.split("=", 1) for kv in a.provenance)
    body = (
        json.dumps(
            {"downloaded_at": int(time.time()), "files": files, "provenance": prov}, indent=1, sort_keys=True
        )
        + "\n"
    )
    (root / NAME).write_text(body)
    for p in [root, *root.rglob("*")]:  # read-only snapshot
        p.chmod(0o555 if p.is_dir() else 0o444)
    print(hashlib.sha256(body.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
