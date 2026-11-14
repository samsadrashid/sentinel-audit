"""Write dist/SHA256SUMS for built release artifacts (M10). Unsigned: release signing is not activated."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sentinel.release import sha256sums  # noqa: E402


def main() -> int:
    d = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    out = d / "SHA256SUMS"
    if out.exists():
        print(f"{out} exists; refusing to overwrite", file=sys.stderr)
        return 4
    out.write_bytes(sha256sums(d))
    print(out.read_text(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
