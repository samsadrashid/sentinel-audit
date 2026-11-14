"""Test helper: a minimal, internally consistent `podman save --format docker-archive` export."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path


def _member(t: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))


def layer(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for n, d in files.items():
            _member(t, n, d)
    return buf.getvalue()


def docker_archive(
    layers: list[bytes], *, diff_ids: list[str] | None = None, stored: list[bytes] | None = None
) -> tuple[bytes, str]:
    """(archive bytes, image id). `diff_ids` overrides the config; `stored` overrides the exported layers."""
    ids = diff_ids or ["sha256:" + hashlib.sha256(x).hexdigest() for x in layers]
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": ids}}).encode()
    image_id = hashlib.sha256(config).hexdigest()
    names = [f"{i:02d}/layer.tar" for i in range(len(layers))]
    manifest = json.dumps([{"Config": f"{image_id}.json", "Layers": names, "RepoTags": []}]).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for n, d in zip(names, stored or layers, strict=True):
            _member(t, n, d)
        _member(t, f"{image_id}.json", config)
        _member(t, "manifest.json", manifest)
    return buf.getvalue(), image_id


def write_archive(tmp: Path) -> tuple[Path, str]:
    data, image_id = docker_archive([layer({"bin/tool": b"#!/bin/sh\n"}), layer({"etc/x": b"y"})])
    p = tmp / "image.tar"
    p.write_bytes(data)
    return p, image_id
