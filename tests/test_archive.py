"""Safe archive extraction (§10 B2 rules, §10.3, D-25, D-28, D-35). Synthetic, inert archives only."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.archive import ExtractionError, extract
from sentinel.policy import Limits

LIM = Limits()


def make_zip(path: Path, entries: dict[str, bytes], deflate: bool = True) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def make_tar(path: Path, members: list[tarfile.TarInfo], data: dict[str, bytes] | None = None) -> Path:
    data = data or {}
    with tarfile.open(path, "w") as t:
        for m in members:
            body = data.get(m.name)
            if body is not None:
                m.size = len(body)
                t.addfile(m, io.BytesIO(body))
            else:
                t.addfile(m)
    return path


def ws(tmp_path: Path) -> Path:
    return tmp_path / "workspace"


def test_normal_zip_extracts_read_only_non_executable(tmp_path):
    z = make_zip(tmp_path / "a.zip", {"dir/a.txt": b"hello", "b.txt": b"world"})
    rep = extract(z, ws(tmp_path), LIM)
    assert rep.entries == 2 and rep.bytes_written == 10
    f = ws(tmp_path) / "dir" / "a.txt"
    assert f.read_bytes() == b"hello"
    assert not (f.stat().st_mode & (stat.S_IXUSR | stat.S_IWUSR))


@pytest.mark.parametrize(
    "name,code",
    [
        ("../evil.txt", "path_traversal"),
        ("a/../../evil", "path_traversal"),
        ("/abs/evil", "absolute_path"),
        ("C:\\evil", "absolute_path"),
    ],
)
def test_traversal_and_absolute_paths_refused(tmp_path, name, code):
    z = make_zip(tmp_path / "t.zip", {name: b"x"})
    with pytest.raises(ExtractionError) as e:
        extract(z, ws(tmp_path), LIM)
    assert e.value.code == code
    assert not (tmp_path / "evil.txt").exists()


def test_zip_symlink_refused(tmp_path):
    p = tmp_path / "s.zip"
    with zipfile.ZipFile(p, "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
    with pytest.raises(ExtractionError) as e:
        extract(p, ws(tmp_path), LIM)
    assert e.value.code == "symlink"


@pytest.mark.parametrize(
    "kind,code",
    [(tarfile.SYMTYPE, "symlink"), (tarfile.LNKTYPE, "hardlink"), (tarfile.CHRTYPE, "special_file")],
)
def test_tar_links_and_devices_refused(tmp_path, kind, code):
    m = tarfile.TarInfo("entry")
    m.type = kind
    m.linkname = "/etc/passwd"
    t = make_tar(tmp_path / "l.tar", [m])
    with pytest.raises(ExtractionError) as e:
        extract(t, ws(tmp_path), LIM)
    assert e.value.code == code


def test_too_many_entries(tmp_path):
    z = make_zip(tmp_path / "n.zip", {f"f{i}": b"x" for i in range(11)})
    with pytest.raises(ExtractionError) as e:
        extract(z, ws(tmp_path), replace(LIM, max_extracted_entries=10))
    assert e.value.code == "limit_file_count"


def test_compression_bomb_stopped_by_actual_bytes(tmp_path):
    z = make_zip(tmp_path / "bomb.zip", {"zeros": b"\0" * 5_000_000})
    with pytest.raises(ExtractionError) as e:
        extract(z, ws(tmp_path), LIM)
    assert e.value.code == "limit_ratio"


def test_largest_file_and_total_size_limits(tmp_path):
    big = make_zip(tmp_path / "big.zip", {"f": bytes(range(256)) * 400}, deflate=False)
    with pytest.raises(ExtractionError) as e:
        extract(big, ws(tmp_path), replace(LIM, max_extracted_file_bytes=50_000))
    assert e.value.code == "limit_file_size"
    many = make_zip(tmp_path / "many.zip", {f"f{i}": bytes(range(256)) * 40 for i in range(5)}, deflate=False)
    with pytest.raises(ExtractionError) as e:
        extract(many, tmp_path / "w2", replace(LIM, max_extracted_total_bytes=30_000))
    assert e.value.code == "limit_size"


def test_artifact_size_limit(tmp_path):
    z = make_zip(tmp_path / "a.zip", {"a": b"x" * 100}, deflate=False)
    with pytest.raises(ExtractionError) as e:
        extract(z, ws(tmp_path), replace(LIM, max_artifact_bytes=50))
    assert e.value.code == "limit_artifact_size"


def test_path_depth_limit(tmp_path):
    z = make_zip(tmp_path / "d.zip", {"/".join(["d"] * 33) + "/f": b"x"})
    with pytest.raises(ExtractionError) as e:
        extract(z, ws(tmp_path), LIM)
    assert e.value.code == "limit_path_depth"


def test_nested_archives_beyond_depth_3_not_opened(tmp_path):
    inner = make_zip(tmp_path / "l4.zip", {"deep.txt": b"deep"})
    for level in (3, 2, 1):
        inner = make_zip(tmp_path / f"l{level}.zip", {inner.name: inner.read_bytes()})
    rep = extract(inner, ws(tmp_path), LIM)
    assert rep.max_depth_seen == 3
    assert any(code == "limit_nesting" for _, code in rep.refused)
    assert not list(ws(tmp_path).rglob("deep.txt"))


def test_code_executing_formats_never_written(tmp_path):
    pickle_bytes = b"\x80\x04\x95" + b"\0" * 16  # inert bytes with a pickle protocol header; never loaded
    z = make_zip(
        tmp_path / "m.zip",
        {"model.pkl": b"x", "weights.bin": pickle_bytes, "ok.txt": b"fine", "model/data.pkl": b"x"},
    )
    rep = extract(z, ws(tmp_path), LIM)
    assert sorted(rep.unsafe_formats) == ["model.pkl", "model/data.pkl", "weights.bin"]
    assert (ws(tmp_path) / "ok.txt").exists()
    assert not (ws(tmp_path) / "model.pkl").exists() and not (ws(tmp_path) / "weights.bin").exists()


def test_unsupported_format_rejected(tmp_path):
    p = tmp_path / "x.rar"
    p.write_bytes(b"Rar!\x1a\x07\x00 not supported")
    with pytest.raises(ExtractionError) as e:
        extract(p, ws(tmp_path), LIM)
    assert e.value.code == "unsupported_format"


def test_duplicate_entries_refused(tmp_path):
    p = tmp_path / "dup.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "1")
        with pytest.warns(UserWarning):
            z.writestr("a.txt", "2")
    with pytest.raises(ExtractionError) as e:
        extract(p, ws(tmp_path), LIM)
    assert e.value.code == "duplicate_entry"


def test_workspace_must_be_empty(tmp_path):
    z = make_zip(tmp_path / "a.zip", {"a": b"x"})
    ws(tmp_path).mkdir()
    (ws(tmp_path) / "existing").write_text("x")
    with pytest.raises(ExtractionError) as e:
        extract(z, ws(tmp_path), LIM)
    assert e.value.code == "workspace_not_empty"


def test_tar_regular_files_extract(tmp_path):
    m = tarfile.TarInfo("dir/f.txt")
    t = make_tar(tmp_path / "ok.tar", [m], {"dir/f.txt": b"content"})
    rep = extract(t, ws(tmp_path), LIM)
    assert rep.entries == 1 and (ws(tmp_path) / "dir" / "f.txt").read_bytes() == b"content"


def test_partial_failure_raises_not_partial_success(tmp_path):
    z = make_zip(tmp_path / "p.zip", {"ok.txt": b"fine", "../evil": b"x"})
    with pytest.raises(ExtractionError):
        extract(z, ws(tmp_path), LIM)


def test_relpath_check_rejects_traversal_on_its_own():
    """The name check must refuse traversal by itself (the workspace placement check is a second layer)."""
    from sentinel.archive import _safe_relpath

    for name in ("../x", "a/../../x", "a/.."):
        with pytest.raises(ExtractionError) as e:
            _safe_relpath(name, LIM)
        assert e.value.code == "path_traversal"


def test_per_entry_ratio_enforced_when_whole_artifact_ratio_is_fine(tmp_path):
    import os as _os

    p = tmp_path / "mixed.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr(zipfile.ZipInfo("random.bin"), _os.urandom(1_000_000))  # stored, incompressible
        z.writestr("zeros.bin", b"\0" * 2_000_000, compress_type=zipfile.ZIP_DEFLATED)  # ~1000:1
    with pytest.raises(ExtractionError) as e:
        extract(p, ws(tmp_path), LIM)
    assert e.value.code == "limit_ratio"
    assert p.stat().st_size * LIM.max_total_ratio > 3_000_000  # whole-artifact ratio alone would allow it
