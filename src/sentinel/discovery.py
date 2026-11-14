"""Read-only project discovery (M2, D-52 item 1).

Walks a scoped `local_path` asset without following symbolic links, opening files, or writing anything,
and records which ecosystems, manifests, lockfiles, container and IaC files are present. The record
decides which adapters plan checks (for example OSV-Scanner only when a supported lockfile exists).
Bounded by `max_path_depth` and `max_extracted_entries` (D-19 limits); exceeding a bound marks the
record `truncated`. A truncated record never hides that fact: it is reported and contract-checked.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox"})

#: exact file name -> (ecosystem, kind)
MANIFESTS: dict[str, tuple[str, str]] = {
    "pyproject.toml": ("PyPI", "manifest"),
    "requirements.txt": ("PyPI", "lockfile"),
    "Pipfile.lock": ("PyPI", "lockfile"),
    "poetry.lock": ("PyPI", "lockfile"),
    "uv.lock": ("PyPI", "lockfile"),
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "go.mod": ("Go", "manifest"),
    "go.sum": ("Go", "lockfile"),
    "Cargo.toml": ("crates.io", "manifest"),
    "Cargo.lock": ("crates.io", "lockfile"),
    "pom.xml": ("Maven", "manifest"),
    "gradle.lockfile": ("Maven", "lockfile"),
    "Gemfile": ("RubyGems", "manifest"),
    "Gemfile.lock": ("RubyGems", "lockfile"),
}
CONTAINER_FILES = frozenset(
    {"Dockerfile", "Containerfile", "docker-compose.yml", "compose.yaml", "compose.yml"}
)
IAC_SUFFIXES = (".tf", ".tfvars")
LANGUAGE_SUFFIXES = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".sh": "shell",
}
MAX_LISTED = 500


@dataclass
class Discovery:
    root: str
    files: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    ecosystems: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    container_files: list[str] = field(default_factory=list)
    iac_files: list[str] = field(default_factory=list)
    skipped_links: int = 0
    truncated: bool = False

    @property
    def has_lockfiles(self) -> bool:
        return any(v.get("lockfile") for v in self.ecosystems.values())

    def to_json(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files": self.files,
            "languages": dict(sorted(self.languages.items())),
            "ecosystems": {
                k: {kind: sorted(v)[:MAX_LISTED] for kind, v in sorted(kinds.items())}
                for k, kinds in sorted(self.ecosystems.items())
            },
            "container_files": sorted(self.container_files)[:MAX_LISTED],
            "iac_files": sorted(self.iac_files)[:MAX_LISTED],
            "skipped_links": self.skipped_links,
            "truncated": self.truncated,
        }


def discover(root: Path, *, max_depth: int = 32, max_entries: int = 10_000) -> Discovery:
    base = root.resolve()
    d = Discovery(str(base))
    entries = 0
    stack: list[tuple[Path, int]] = [(base, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as it:
                names = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in names:
            entries += 1
            if entries > max_entries:
                d.truncated = True
                return d
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            rel = str(Path(e.path).relative_to(base))
            if stat.S_ISLNK(st.st_mode):
                d.skipped_links += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                if e.name in SKIP_DIRS:
                    continue
                if depth + 1 > max_depth:
                    d.truncated = True
                    continue
                stack.append((Path(e.path), depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            d.files += 1
            lang = LANGUAGE_SUFFIXES.get(Path(e.name).suffix.lower())
            if lang:
                d.languages[lang] = d.languages.get(lang, 0) + 1
            hit = MANIFESTS.get(e.name)
            if hit is None and e.name.startswith("requirements") and e.name.endswith(".txt"):
                hit = ("PyPI", "lockfile")
            if hit:
                d.ecosystems.setdefault(hit[0], {}).setdefault(hit[1], []).append(rel)
            if e.name in CONTAINER_FILES:
                d.container_files.append(rel)
            if e.name.endswith(IAC_SUFFIXES):
                d.iac_files.append(rel)
    return d
