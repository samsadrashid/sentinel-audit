"""Rootless Podman isolation for S1 (alternative), S2 and B1 (D-32, D-53, §10).

Podman counts as available only when all of these hold, checked on this host:

* the Podman client binary matches the approved SHA-256 in the policy (D-22, D-54);
* Podman reports **rootless** operation (Podman Machine on macOS: a rootless machine; Linux: rootless
  user namespace);
* the pinned Podman machine (``podman.machine``) is running and has no host-share filesystem mounted
  (virtiofs, 9p, sshfs, NFS, SMB): M2-SA-12, D-71;
* every stored layer of an image is intact before that image runs: `podman save` is streamed and checked
  against the image's config (ID and ``diff_ids``), once per process per image ID;
* a functional self-test inside the exact run profile, using the approved digest-pinned probe image,
  observes: no network, the target read-only, the image root read-only, the workspace writable, and an
  empty effective capability set.

There is no fallback: if any condition fails, the runner is unavailable and the checks that need it
are ``NOT_RUN`` (``host_isolation_unavailable``). Every scanner container runs with
``--network=none``, ``--read-only``, ``--cap-drop=ALL``, ``no-new-privileges``, ``--pull=never``, the
target mounted read-only, a fresh per-check workspace, and a process and memory cap. Nothing is
bind-mounted from the host (D-71): the target is streamed as a normalised tar into a per-run VM-local
volume that is removed afterwards, and a scanner database lives in a VM-local volume named after its
manifest, re-verified against that manifest before every use. Images are
referenced by digest only. A digest-addressed reference can't resolve to different content, and with
``--pull=never`` nothing is fetched. A timeout, output overflow or kill switch kills the client process
tree and force-removes the container.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from ..adapters.base import BoundedRun, run_bounded
from ..paths import ensure_private_dir, state_dir
from ..scanner_pins import RuntimePin, verify_binary

PROFILE_NAME = "podman-rootless"
#: The database-volume verifier (busybox `sha256sum -c`) runs with the same isolation as a scanner.
VERIFY_HARDENING = (
    "--pull=never",
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
)
#: Filesystems that mean a host directory is shared into the VM (M2-SA-12): refused (D-70, D-71).
SHARE_FS = ("virtiofs", "9p", "fuse.sshfs", "nfs", "nfs4", "cifs", "smb3", "fuse.virtiofs")
MAX_TARGET_BYTES = 4 * 1024**3


class VolumeError(Exception):
    pass


def write_tar(src: Path, out: Path | IO[bytes]) -> int:
    """Tar `src` with regular files and directories only (owner 0, world-readable). Symlinks and special
    files are skipped, never followed. Returns how many entries were skipped. Bounded by MAX_TARGET_BYTES."""
    skipped = total = 0
    opened = (
        tarfile.open(out, "w", format=tarfile.PAX_FORMAT)
        if isinstance(out, Path)
        else tarfile.open(fileobj=out, mode="w|", format=tarfile.PAX_FORMAT)
    )
    with opened as t:
        for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
            dirnames.sort()
            for n in [*sorted(dirnames), *sorted(filenames)]:
                p = Path(dirpath) / n
                st = p.lstat()
                import stat as _st

                if not (_st.S_ISREG(st.st_mode) or _st.S_ISDIR(st.st_mode)):
                    skipped += 1
                    if _st.S_ISLNK(st.st_mode) and n in dirnames:
                        dirnames.remove(n)
                    continue
                info = tarfile.TarInfo(str(p.relative_to(src)))
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = int(st.st_mtime)
                if _st.S_ISDIR(st.st_mode):
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    t.addfile(info)
                else:
                    total += st.st_size
                    if total > MAX_TARGET_BYTES:
                        raise VolumeError("target_too_large")
                    info.size, info.mode = st.st_size, 0o644
                    with p.open("rb") as fh:
                        t.addfile(info, fh)
    return skipped


def machine_share_problem(client: object, machine: str) -> str | None:
    """None if `machine` is the running Podman machine and has no host-share filesystem mounted."""
    run = client  # a callable like PodmanRunner._client
    try:
        ls = run(["machine", "list", "--format", "json"])  # type: ignore[operator]
        machines = json.loads(ls.stdout or "[]")
    except (OSError, subprocess.SubprocessError, ValueError):
        return "podman_machine_unavailable"
    me = next((m for m in machines if m.get("Name") == machine), None)
    if me is None:
        return "podman_machine_missing"
    if not me.get("Running"):
        return "podman_machine_not_active"
    try:
        mounts = run(["machine", "ssh", machine, "--", "cat", "/proc/mounts"], timeout=60)  # type: ignore[operator]
    except (OSError, subprocess.SubprocessError):
        return "podman_mounts_unreadable"
    if mounts.returncode != 0 or not mounts.stdout.strip():
        return "podman_mounts_unreadable"
    for line in mounts.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in SHARE_FS:
            return "podman_host_share_present"  # M2-SA-12 would apply: refuse (D-71)
    return None


#: Upper bound for an image export read during the layer-integrity check.
MAX_IMAGE_BYTES = 32 * 1024**3
MAX_IMAGE_JSON = 16 * 1024 * 1024
_verified_images: set[tuple[str, str, str]] = set()


class _Counted:
    """A read-only stream wrapper that refuses to read past `limit` bytes."""

    def __init__(self, raw: IO[bytes], limit: int) -> None:
        self.raw, self.limit, self.count = raw, limit, 0

    def read(self, n: int = -1) -> bytes:
        b = self.raw.read(n)
        self.count += len(b)
        if self.count > self.limit:
            raise VolumeError("image_too_large")
        return b


def check_docker_archive(stream: IO[bytes], image_id: str) -> str | None:
    """None if a `podman save --format docker-archive` stream is internally consistent: its config hashes
    to `image_id`, and every layer tar hashes to the config's `diff_id` for that position.

    Podman checks an image's ID, not its stored files, when a container starts. A layer damaged on disk
    (for example by a full VM disk) would otherwise run silently, and a scanner with missing files could
    under-report. Podman re-hashes layers while exporting, so damage also shows as a failed export."""
    digests: dict[str, str] = {}
    blobs: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=stream, mode="r|") as t:
            for m in t:
                if not m.isfile():
                    continue
                f = t.extractfile(m)
                if f is None:
                    continue
                h = hashlib.sha256()
                keep = m.name.endswith(".json") and m.size <= MAX_IMAGE_JSON
                data = bytearray()
                while chunk := f.read(1 << 20):
                    h.update(chunk)
                    if keep:
                        data += chunk
                digests[m.name] = h.hexdigest()
                if keep:
                    blobs[m.name] = bytes(data)
    except (tarfile.TarError, OSError, EOFError):
        return "image_export_unreadable"
    try:
        manifest = json.loads(blobs["manifest.json"])
        if not isinstance(manifest, list) or len(manifest) != 1:
            return "image_export_malformed"
        entry = manifest[0]
        config_name, layers = entry["Config"], entry["Layers"]
        diff_ids = json.loads(blobs[config_name])["rootfs"]["diff_ids"]
    except (KeyError, TypeError, ValueError):
        return "image_export_malformed"
    if digests.get(config_name) != image_id.removeprefix("sha256:"):
        return "image_config_mismatch"
    if not isinstance(layers, list) or not isinstance(diff_ids, list) or len(layers) != len(diff_ids):
        return "image_layer_count_mismatch"
    for name, want in zip(layers, diff_ids, strict=True):
        if not isinstance(want, str) or digests.get(name) != want.removeprefix("sha256:"):
            return "image_layer_corrupt"
    return None


def verify_image_layers(podman: Path, conn: list[str], image: str, timeout: float = 1800) -> str | None:
    """None if `image` is present and every stored layer is intact (cached per process and image ID)."""
    try:
        r = subprocess.run(
            [str(podman), *conn, "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True,
            text=True,
            timeout=60,
            env=client_env(podman),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "image_missing"
    image_id = r.stdout.strip().removeprefix("sha256:")
    if r.returncode != 0 or len(image_id) != 64 or any(c not in "0123456789abcdef" for c in image_id):
        return "image_missing"
    key = (str(podman), " ".join(conn), image_id)
    if key in _verified_images:
        return None
    try:
        proc = subprocess.Popen(
            [str(podman), *conn, "save", "--format", "docker-archive", image_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=client_env(podman),
        )
    except OSError:
        return "image_export_failed"
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        assert proc.stdout is not None
        try:
            bad = check_docker_archive(_Counted(proc.stdout, MAX_IMAGE_BYTES), image_id)  # type: ignore[arg-type]
        except VolumeError as exc:
            bad = str(exc)
        proc.stdout.read()  # drain, so the client can exit
        rc = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if rc != 0:
        return "image_integrity_failed"  # e.g. podman's own "file integrity checksum failed"
    if bad is not None:
        return bad
    _verified_images.add(key)
    return None


TARGET_MOUNT = "/target"
WORK_MOUNT = "/work"
EXTRA_MOUNT = "/data"
PIDS_LIMIT = 512
MEMORY = "4g"

_PROBE_SCRIPT = (
    "n=denied; wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null && n=allowed; "
    "t=denied; (echo x > /target/w) 2>/dev/null && t=allowed; "
    "r=denied; (echo x > /probe-root) 2>/dev/null && r=allowed; "
    "w=denied; (echo x > /work/w) 2>/dev/null && w=allowed; "
    "c=$(grep CapEff /proc/self/status | tr -d ' \\t' | cut -d: -f2); "
    'echo "network=$n;write_target=$t;write_root=$r;write_workspace=$w;cap_eff=$c"'
)
EXPECTED = {
    "network": "denied",
    "write_target": "denied",
    "write_root": "denied",
    "write_workspace": "allowed",
    "cap_eff": "0000000000000000",
}


def client_env(binary: Path) -> dict[str, str]:
    """Minimal environment for the Podman client: enough to find its rootless machine or socket."""
    env = {"PATH": f"{binary.parent}:/usr/bin:/bin", "LANG": "C.UTF-8"}
    for k in ("HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


@dataclass
class ContainerRun:
    run: BoundedRun
    profile: str
    workspace_removed: bool


@dataclass
class PodmanProbe:
    available: bool
    reason: str
    observations: dict[str, str] = field(default_factory=dict)


def container_args(
    name: str,
    image: str,
    args: list[str],
    *,
    target: Path | str,
    workspace: Path | None = None,
    extra_ro: Path | str | None = None,
    entrypoint: str | None = None,
    env: dict[str, str] | None = None,
    interactive: bool = False,
) -> list[str]:
    """The fixed hardened `podman run` argument list. Tests assert every flag. `workspace` is unused:
    the container workspace is a tmpfs (kept for call compatibility)."""
    out = [
        "run",
        "--rm",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={PIDS_LIMIT}",
        f"--memory={MEMORY}",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=512m",
        # D-52: the scanner's workspace is memory only. Nothing a scanner writes (logs, caches) ever
        # reaches the host disk, so no raw content or PII can persist in temporary files.
        f"--tmpfs={WORK_MOUNT}:rw,nosuid,nodev,size=1g",
        "--env=HOME=/work",
        f"--volume={target}:{TARGET_MOUNT}:ro",
        f"--workdir={WORK_MOUNT}",
    ]
    if extra_ro is not None:
        out.append(f"--volume={extra_ro}:{EXTRA_MOUNT}:ro")
    for k, v in sorted((env or {}).items()):
        if not k.isidentifier() or "\n" in v:
            raise ValueError("bad container environment entry")
        out.append(f"--env={k}={v}")
    if entrypoint is not None:
        out.append(f"--entrypoint={entrypoint}")
    if interactive:
        out.append("--interactive")  # stdin only: e.g. an SBOM produced earlier in the same run (D-61)
    return [*out, image, *args]


class PodmanRunner:
    name = PROFILE_NAME

    def __init__(self, pin: RuntimePin, workspaces: Path | None = None) -> None:
        self.pin = pin
        self.workspaces = workspaces or (state_dir() / "workspaces")

    # ── preconditions ────────────────────────────────────────────────────
    def _conn(self) -> list[str]:
        return ["--connection", self.pin.machine] if self.pin.machine else []

    def _client(self, args: list[str], timeout: float = 60) -> subprocess.CompletedProcess[str]:
        machine_cmd = bool(args) and args[0] == "machine"
        return subprocess.run(
            [str(self.pin.path), *([] if machine_cmd else self._conn()), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=client_env(self.pin.path),
            check=False,
        )

    def precondition(self) -> str | None:
        """Why this runner must not be used now, or None. Checked before every execution."""
        bad = verify_binary(self.pin.path, self.pin.sha256)
        if bad is not None:
            return f"podman_{bad}"
        try:
            r = self._client(["info", "--format", "json"])
        except (OSError, subprocess.SubprocessError):
            return "podman_unavailable"
        if r.returncode != 0:
            return "podman_unavailable"
        try:
            info = json.loads(r.stdout)
            rootless = info["host"]["security"]["rootless"]
        except (ValueError, KeyError, TypeError):
            return "podman_info_unreadable"
        if rootless is not True:
            return "podman_not_rootless"
        if not self.pin.machine:
            return "podman_machine_unpinned"  # D-71: never fall back to host bind mounts
        share = machine_share_problem(self._client, self.pin.machine)
        if share is not None:
            return share
        return None

    def image_present(self, image: str) -> bool:
        try:
            return self._client(["image", "exists", image]).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    # ── execution ────────────────────────────────────────────────────────
    def run(
        self,
        image: str,
        args: list[str],
        *,
        target_root: Path,
        timeout_s: float,
        max_output: int,
        extra_ro: Path | None = None,
        entrypoint: str | None = None,
        env: dict[str, str] | None = None,
        cancel: threading.Event | None = None,
        stdin_data: bytes | None = None,
    ) -> ContainerRun:
        cancel = cancel if cancel is not None else getattr(self, "cancel_event", None)
        damaged = verify_image_layers(self.pin.path, self._conn(), image)
        if damaged is not None:
            raise VolumeError(f"image_integrity_failed: {damaged}")  # never run a damaged image
        ensure_private_dir(self.workspaces)
        ws = Path(tempfile.mkdtemp(prefix="ws-", dir=self.workspaces)).resolve()
        os.chmod(ws, 0o700)
        name = f"sentinel-{secrets.token_hex(8)}"

        def remove() -> None:
            try:
                self._client(["rm", "--force", "--time", "0", name], timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass

        volumes: list[str] = []
        try:
            target_src: Path | str = target_root.resolve()
            extra_src: Path | str | None = extra_ro.resolve() if extra_ro is not None else None
            if not self.pin.machine:
                raise VolumeError("podman_machine_unpinned")  # D-71: no host bind mount, ever
            # D-71: nothing is bind-mounted from the host. The target becomes a fresh VM-local volume.
            target_src = self._import_volume(f"{name}-t", target_root.resolve(), ws)
            volumes.append(target_src)
            if extra_ro is not None:
                extra_src, owned = self._extra_volume(name, extra_ro.resolve(), ws)
                if owned:
                    volumes.append(extra_src)
            argv = [
                str(self.pin.path),
                *self._conn(),
                *container_args(
                    name,
                    image,
                    args,
                    target=target_src,
                    workspace=ws,
                    extra_ro=extra_src,
                    entrypoint=entrypoint,
                    env=env,
                    interactive=stdin_data is not None,
                ),
            ]
            run = run_bounded(
                argv,
                cwd=ws,
                env=client_env(self.pin.path),
                timeout_s=timeout_s,
                max_output=max_output,
                cancel=cancel,
                on_kill=remove,
                stdin_data=stdin_data,
            )
        finally:
            for v in volumes:
                try:
                    self._client(["volume", "rm", "--force", v], timeout=120)
                except (OSError, subprocess.SubprocessError):
                    pass
            shutil.rmtree(ws, ignore_errors=True)
        return ContainerRun(run, self.name, not ws.exists())

    # ── D-71 volumes ─────────────────────────────────────────────────────
    def _import_volume(self, vol: str, src: Path, ws: Path) -> str:
        """Create VM-local volume `vol` from `src` (regular files and directories only) and return it.

        The tar is streamed straight into `podman volume import` over a pipe: nothing is staged on the
        host disk, whatever the size of the target or database snapshot."""
        c = self._client(["volume", "create", vol])
        if c.returncode != 0:
            raise VolumeError(f"volume_create_failed: {c.stderr.strip()[:200]}")
        proc = subprocess.Popen(
            [str(self.pin.path), *self._conn(), "volume", "import", vol, "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=client_env(self.pin.path),
        )
        assert proc.stdin is not None
        failed: Exception | None = None
        try:
            skipped = write_tar(src, proc.stdin)
        except (VolumeError, OSError) as exc:
            failed = exc
            skipped = 0
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            _, err = proc.communicate(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            err = b"timeout"
        if failed is not None or proc.returncode != 0:
            self._client(["volume", "rm", "--force", vol])
            if isinstance(failed, VolumeError):
                raise failed
            raise VolumeError(f"volume_import_failed: {(err or b'').decode(errors='replace').strip()[:200]}")
        self.last_import_skipped = skipped
        return vol

    def _extra_volume(self, name: str, src: Path, ws: Path) -> tuple[str, bool]:
        """(volume, owned-by-this-run). A database snapshot (D-29) is cached per pinned manifest and
        re-verified inside the VM before every use; anything else is a per-run volume."""
        manifest = src / "snapshot-manifest.json"
        if not manifest.is_file():
            return self._import_volume(f"{name}-x", src, ws), True
        raw = manifest.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        vol = f"sentinel-db-{digest[:32]}"
        if self._client(["volume", "exists", vol]).returncode != 0:
            self._import_volume(vol, src, ws)
        checks = "".join(f"{e['sha256']}  /data/{e['path']}\n" for e in json.loads(raw)["files"])
        checks += f"{digest}  /data/snapshot-manifest.json\n"
        r = subprocess.run(
            [
                str(self.pin.path),
                *self._conn(),
                "run",
                "--rm",
                "-i",
                *VERIFY_HARDENING,
                f"--volume={vol}:/data:ro",
                "--entrypoint=sha256sum",
                self.pin.probe_image,
                "-c",
                "-s",
                "-",
            ],
            input=checks,
            capture_output=True,
            text=True,
            timeout=3600,
            env=client_env(self.pin.path),
            check=False,
        )
        if r.returncode != 0:
            self._client(["volume", "rm", "--force", vol])  # never reuse a volume that failed verification
            raise VolumeError("database_volume_mismatch")
        return vol, False

    def probe(self) -> PodmanProbe:
        bad = self.precondition()
        if bad is not None:
            return PodmanProbe(False, bad)
        if not self.image_present(self.pin.probe_image):
            return PodmanProbe(False, "probe_image_missing")
        target = Path(tempfile.mkdtemp(prefix="sentinel-podman-probe-")).resolve()
        try:
            res = self.run(
                self.pin.probe_image,
                ["-c", _PROBE_SCRIPT],
                target_root=target,
                timeout_s=120,
                max_output=10_000,
                entrypoint="/bin/sh",
            )
        finally:
            shutil.rmtree(target, ignore_errors=True)
        line = res.run.stdout.decode(errors="replace").strip().splitlines()[-1:] or [""]
        obs = dict(kv.split("=", 1) for kv in line[0].split(";") if "=" in kv)
        bad_obs = {k: obs.get(k) for k, v in EXPECTED.items() if obs.get(k) != v}
        if res.run.returncode != 0 or bad_obs or not res.workspace_removed:
            return PodmanProbe(False, f"self-test failed: {bad_obs or res.run.returncode}", obs)
        return PodmanProbe(True, "self-test passed", obs)


_probe_cache: dict[tuple[str, str, str], PodmanProbe] = {}


def available_runner(pin: RuntimePin | None) -> PodmanRunner | None:
    """A verified PodmanRunner for these pins, or None (no fallback). The self-test is cached per process
    and pin; the binary hash and rootless state are re-checked before every execution by the adapters."""
    if pin is None:
        return None
    key = (str(pin.path), pin.sha256, pin.probe_image)
    if key not in _probe_cache:
        _probe_cache[key] = PodmanRunner(pin).probe()
    return PodmanRunner(pin) if _probe_cache[key].available else None


def probe_status(pin: RuntimePin | None) -> dict[str, object]:
    if pin is None:
        return {"available": False, "reason": "no approved podman pin in policy (D-53, D-54)"}
    available_runner(pin)
    p = _probe_cache[(str(pin.path), pin.sha256, pin.probe_image)]
    return {"available": p.available, "reason": p.reason, "observations": p.observations}
