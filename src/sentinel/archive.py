"""Safe archive extraction for B2 (§10 B2 rules, §10.3, D-25, D-28, D-35).

The extractor itself never runs extracted content and never deserialises code-executing formats.
It enforces every limit against *actual* bytes written, while extracting, and fails closed:
a partial extraction raises and leaves the caller with ERROR, never a successful inspection.

Where it may run: D-25/D-32 require an isolated, disposable workspace and never the host filesystem.
The engine only calls this inside an isolation environment (see isolation.py); on a host without
one, B2 checks are NOT_RUN. Unit tests call it directly on synthetic fixtures in temp directories.
"""

from __future__ import annotations

import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO

from .errors import SentinelError
from .policy import Limits

ARCHIVE_SUFFIXES = (".zip", ".jar", ".apk", ".aab", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")

#: Formats that can execute code when deserialised (D-28). Detected by magic bytes and suffix.
UNSAFE_SUFFIXES = (".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".npy", ".npz", ".ser", ".marshal")


class ExtractionError(SentinelError):
    def __init__(self, reason: str, code: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


@dataclass
class ExtractionReport:
    entries: int = 0
    bytes_written: int = 0
    max_depth_seen: int = 0
    refused: list[tuple[str, str]] = field(default_factory=list)
    unsafe_formats: list[str] = field(default_factory=list)
    skipped_oversize: list[str] = field(default_factory=list)


def is_unsafe_serialisation(name: str, head: bytes) -> bool:
    lower = name.lower()
    if lower.endswith(UNSAFE_SUFFIXES):
        return True
    # pickle protocol 2+ starts with 0x80 <proto>; torch zip checkpoints contain data.pkl
    return (len(head) >= 2 and head[0] == 0x80 and head[1] in range(2, 6)) or lower.endswith("/data.pkl")


def _safe_relpath(name: str, limits: Limits) -> PurePosixPath:
    if not name or "\x00" in name:
        raise ExtractionError(f"invalid entry name {name!r}", "bad_name")
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        raise ExtractionError(f"absolute path entry {name!r}", "absolute_path")
    if any(part == ".." for part in p.parts):
        raise ExtractionError(f"path traversal entry {name!r}", "path_traversal")
    if len(p.parts) > limits.max_path_depth:
        raise ExtractionError(
            f"path depth {len(p.parts)} exceeds {limits.max_path_depth}", "limit_path_depth"
        )
    return p


class _Budget:
    def __init__(self, limits: Limits, artifact_size: int) -> None:
        self.limits = limits
        self.artifact_size = max(artifact_size, 1)
        self.report = ExtractionReport()

    def entry(self) -> None:
        self.report.entries += 1
        if self.report.entries > self.limits.max_extracted_entries:
            raise ExtractionError("too many entries", "limit_file_count")

    def add(self, n: int) -> None:
        self.report.bytes_written += n
        if self.report.bytes_written > self.limits.max_extracted_total_bytes:
            raise ExtractionError("total extracted size exceeds limit", "limit_size")
        if self.report.bytes_written > self.limits.max_total_ratio * self.artifact_size:
            raise ExtractionError("whole-artifact compression ratio exceeds limit", "limit_ratio")


def _copy_limited(src: IO[bytes], dest: Path, compressed: int, declared: int, budget: _Budget) -> int:
    lim = budget.limits
    written = 0
    with open(dest, "xb") as out:
        while True:
            chunk = src.read(64 * 1024)
            if not chunk:
                break
            written += len(chunk)
            budget.add(len(chunk))
            if written > lim.max_extracted_file_bytes:
                raise ExtractionError("entry exceeds largest-file limit", "limit_file_size")
            if written > lim.max_entry_ratio * max(compressed, 1):
                raise ExtractionError("entry compression ratio exceeds limit", "limit_ratio")
            out.write(chunk)
    if declared >= 0 and written != declared:
        raise ExtractionError("declared and actual entry size differ", "size_mismatch")
    dest.chmod(0o400)  # never executable
    return written


def extract(
    archive: Path, workspace: Path, limits: Limits, depth: int = 1, budget: _Budget | None = None
) -> ExtractionReport:
    """Extract `archive` into empty `workspace`. Raises ExtractionError on any violation."""
    size = archive.stat().st_size
    if size > limits.max_artifact_bytes:
        raise ExtractionError("artifact exceeds size limit", "limit_artifact_size")
    budget = budget or _Budget(limits, size)
    budget.report.max_depth_seen = max(budget.report.max_depth_seen, depth)
    workspace.mkdir(parents=True, exist_ok=True)
    if any(workspace.iterdir()):
        raise ExtractionError("workspace must be empty", "workspace_not_empty")
    name = archive.name.lower()
    if zipfile.is_zipfile(archive):
        _extract_zip(archive, workspace, budget)
    elif name.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")) and tarfile.is_tarfile(archive):
        _extract_tar(archive, workspace, budget)
    else:
        raise ExtractionError("unsupported or ambiguous archive format", "unsupported_format")
    # nested archives: recurse into a separate workspace per archive
    nested = sorted(
        p for p in workspace.rglob("*") if p.is_file() and p.name.lower().endswith(ARCHIVE_SUFFIXES)
    )
    for f in nested:
        if depth + 1 > limits.max_nested_archive_depth:
            # §10.3: deeper archives are not opened; their contents are NOT_RUN (limit_nesting)
            budget.report.refused.append((str(f.relative_to(workspace)), "limit_nesting"))
            continue
        extract(f, workspace / (f.name + ".x"), limits, depth + 1, budget)
    return budget.report


def _place(workspace: Path, rel: PurePosixPath) -> Path:
    dest = workspace.joinpath(*rel.parts)
    ws = workspace.resolve()
    parent = dest.parent
    parent.mkdir(parents=True, exist_ok=True)
    if ws not in parent.resolve().parents and parent.resolve() != ws:
        raise ExtractionError("entry escapes workspace", "path_traversal")
    if dest.exists() or dest.is_symlink():
        raise ExtractionError(f"duplicate entry {rel}", "duplicate_entry")
    return dest


def _extract_zip(archive: Path, workspace: Path, budget: _Budget) -> None:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            budget.entry()
            rel = _safe_relpath(info.filename, budget.limits)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ExtractionError(f"symlink entry {info.filename!r}", "symlink")
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise ExtractionError("encrypted entry", "unsupported_format")
            dest = _place(workspace, rel)
            with zf.open(info) as src:
                head = src.read(8)
                src.seek(0)
                if is_unsafe_serialisation(info.filename, head):
                    budget.report.unsafe_formats.append(info.filename)
                    continue  # never written, never deserialised (D-28)
                _copy_limited(src, dest, info.compress_size, info.file_size, budget)


def _extract_tar(archive: Path, workspace: Path, budget: _Budget) -> None:
    with tarfile.open(archive, "r:*") as tf:
        for m in tf:
            budget.entry()
            rel = _safe_relpath(m.name, budget.limits)
            if m.issym() or m.islnk():
                raise ExtractionError(f"link entry {m.name!r}", "symlink" if m.issym() else "hardlink")
            if m.isdir():
                continue
            if not m.isfile():
                raise ExtractionError(f"special file entry {m.name!r}", "special_file")
            dest = _place(workspace, rel)
            src = tf.extractfile(m)
            if src is None:
                raise ExtractionError("unreadable entry", "bad_entry")
            head = src.read(8)
            if is_unsafe_serialisation(m.name, head):
                budget.report.unsafe_formats.append(m.name)
                continue
            src.seek(0)
            # tar has no per-entry compressed size; ratio is enforced against the whole artifact
            _copy_limited(src, dest, max(budget.artifact_size, 1), m.size, budget)
