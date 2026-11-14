"""B2 isolation (D-25, D-32, D-70): a hardened rootless container in a share-free Podman machine.

This resolves M2-SA-12 for B2. That finding showed that Podman Machine (applehv) host shares are writable
from inside the VM even when mounted read-only. The B2 machine is created with **no host volumes**
(`podman machine init --volume ""`), and B2 containers get **no mounts at all**: the archive arrives on
stdin and the result leaves on stdout. Nothing extracted can reach the host filesystem.

Preconditions, all checked before every run. Any failure gives None from `available_runner`, so the
check is `NOT_RUN`:

* the pinned Podman binary hash;
* the B2 machine is the active, running machine (macOS runs one Podman VM at a time);
* the VM has no host-share filesystem mounted: virtiofs, 9p, sshfs, nfs or cifs, read from `/proc/mounts`
  inside the VM;
* the pinned image ID is present, and the in-container self-test passes:
  * no network;
  * read-only root filesystem;
  * no host paths visible;
  * an unprivileged uid;
  * only `/work` is writable.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..adapters.base import BoundedRun, run_bounded
from ..scanner_pins import B2Pin, RuntimePin, verify_binary
from .podman import VolumeError, client_env, verify_image_layers

PROFILE_NAME = "b2-podman-share-free"
SHARE_FS = ("virtiofs", "9p", "fuse.sshfs", "nfs", "nfs4", "cifs", "smb3", "fuse.virtiofs")
WORK_SIZE = "1100m"  # D-35 total extracted 1 GB, plus headroom for the metadata files
MEMORY = "1536m"
PIDS = 64

_SELF_TEST = r"""
import json, os, socket
r = {}
def t(name, fn):
    try:
        fn(); r[name] = "allowed"
    except OSError:
        r[name] = "denied"
t("network", lambda: socket.create_connection(("1.1.1.1", 53), timeout=2))
t("write_root", lambda: open("/probe", "w").write("x"))
t("write_work", lambda: open("/work/probe", "w").write("x"))
HOST = ("/Users", "/private", "/var/folders", "/mnt/host")
r["host_paths"] = ",".join(p for p in HOST if os.path.exists(p)) or "none"
r["uid"] = str(os.getuid())
print(json.dumps(r, sort_keys=True))
"""
EXPECTED = {
    "network": "denied",
    "write_root": "denied",
    "write_work": "allowed",
    "host_paths": "none",
    "uid": "65534",
}


@dataclass(frozen=True)
class Profile:
    """The fixed container limits of one share-free, no-mount profile."""

    name: str
    memory: str
    pids: int
    work_size: str
    user: str
    exec_tmp: bool = False  # MobSF's own tools may need an executable /tmp (D-72); B2 never does

    def __post_init__(self) -> None:
        uid, _, gid = self.user.partition(":")
        if not (uid.isdigit() and gid.isdigit()) or int(uid) == 0 or int(gid) == 0:
            raise ValueError("a share-free profile never runs as root")


B2_PROFILE = Profile(PROFILE_NAME, MEMORY, PIDS, WORK_SIZE, "65534:65534")
#: D-72: MobSF 4.6.4 runs as the image's own unprivileged user, with more memory for its JVM tools.
#: Its tmpfs is charged to the same memory cap.
MOBSF_PROFILE = Profile("mobsf-podman-share-free", "3584m", 512, "1500m", "9901:9901", exec_tmp=True)


@dataclass
class B2Probe:
    available: bool
    reason: str
    observations: dict[str, str] = field(default_factory=dict)


@dataclass
class B2Run:
    run: BoundedRun
    profile: str
    workspace_removed: bool = True


def b2_args(
    name: str, image_id: str, program: str, argv: list[str], profile: Profile = B2_PROFILE
) -> list[str]:
    """The fixed hardened `podman run` argument list. There is deliberately no --volume or --mount."""
    noexec = "" if profile.exec_tmp else ",noexec"
    return [
        "run",
        "--rm",
        "--interactive",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={profile.pids}",
        f"--memory={profile.memory}",
        f"--user={profile.user}",
        f"--tmpfs=/work:rw,nosuid,nodev{noexec},size={profile.work_size},mode=1777",
        f"--tmpfs=/tmp:rw,nosuid,nodev{noexec},size=512m,mode=1777"
        if profile.exec_tmp
        else "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--env=HOME=/work",
        "--env=B2_WORK=/work",
        "--workdir=/work",
        "--entrypoint=python3",
        image_id,
        "-I",
        "-c",
        program,
        *argv,
    ]


class B2Runner:
    name = PROFILE_NAME

    def __init__(self, podman: RuntimePin, pin: B2Pin, profile: Profile = B2_PROFILE) -> None:
        self.podman, self.pin, self.profile = podman, pin, profile
        self.name = profile.name
        self.cancel_event: threading.Event | None = None

    def _client(self, args: list[str], timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.podman.path), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=client_env(self.podman.path),
            check=False,
        )

    def precondition(self) -> str | None:
        bad = verify_binary(self.podman.path, self.podman.sha256)
        if bad is not None:
            return f"podman_{bad}"
        try:
            ls = self._client(["machine", "list", "--format", "json"])
            machines = json.loads(ls.stdout or "[]")
        except (OSError, subprocess.SubprocessError, ValueError):
            return "b2_machine_unavailable"
        me = next((m for m in machines if m.get("Name") == self.pin.machine), None)
        if me is None:
            return "b2_machine_missing"
        if not me.get("Running"):
            return "b2_machine_not_active"  # the other (shared) machine may be the active one
        try:
            mounts = self._client(
                ["machine", "ssh", self.pin.machine, "--", "cat", "/proc/mounts"], timeout=60
            )
        except (OSError, subprocess.SubprocessError):
            return "b2_mounts_unreadable"
        if mounts.returncode != 0 or not mounts.stdout.strip():
            return "b2_mounts_unreadable"
        for line in mounts.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] in SHARE_FS:
                return "b2_host_share_present"  # M2-SA-12 would apply: refuse
        try:
            info = self._client(["--connection", self.pin.machine, "info", "--format", "json"])
            rootless = json.loads(info.stdout)["host"]["security"]["rootless"]
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
            return "b2_podman_unavailable"
        if rootless is not True:
            return "b2_not_rootless"
        try:
            img = self._client(
                [
                    "--connection",
                    self.pin.machine,
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    self.pin.image_id,
                ]
            )
        except (OSError, subprocess.SubprocessError):
            return "b2_image_missing"
        if img.returncode != 0 or f"sha256:{img.stdout.strip()}" != self.pin.image_id:
            return "b2_image_missing"
        return None

    def run(
        self, program: str, argv: list[str], stdin_data: bytes, *, timeout_s: float, max_output: int
    ) -> B2Run:
        damaged = self.image_damage()
        if damaged is not None:
            raise VolumeError(f"image_integrity_failed: {damaged}")  # never run a damaged image
        name = f"sentinel-b2-{secrets.token_hex(8)}"

        def remove() -> None:
            try:
                self._client(
                    ["--connection", self.pin.machine, "rm", "--force", "--time", "0", name], timeout=30
                )
            except (OSError, subprocess.SubprocessError):
                pass

        cmd = [
            str(self.podman.path),
            "--connection",
            self.pin.machine,
            *b2_args(name, self.pin.image_id, program, argv, self.profile),
        ]
        run = run_bounded(
            cmd,
            cwd=Path("/"),
            env=client_env(self.podman.path),
            timeout_s=timeout_s,
            max_output=max_output,
            cancel=self.cancel_event,
            on_kill=remove,
            stdin_data=stdin_data,
        )
        return B2Run(run, self.name)

    def image_damage(self) -> str | None:
        """None if every stored layer of the pinned image is intact (checked once per process)."""
        return verify_image_layers(self.podman.path, ["--connection", self.pin.machine], self.pin.image_id)

    def probe(self) -> B2Probe:
        bad = self.precondition()
        if bad is not None:
            return B2Probe(False, bad)
        damaged = self.image_damage()
        if damaged is not None:
            return B2Probe(False, f"image_integrity_failed: {damaged}")
        res = self.run(_SELF_TEST, [], b"", timeout_s=120, max_output=10_000)
        try:
            obs = json.loads(res.run.stdout.decode())
        except ValueError:
            return B2Probe(False, f"self-test output unreadable (exit {res.run.returncode})")
        expected = {**EXPECTED, "uid": self.profile.user.split(":")[0]}
        wrong = {k: obs.get(k) for k, v in expected.items() if obs.get(k) != v}
        if res.run.returncode != 0 or wrong:
            return B2Probe(False, f"self-test failed: {wrong or res.run.returncode}", obs)
        return B2Probe(True, "self-test passed", obs)


_cache: dict[tuple[str, str, str, str, str], B2Probe] = {}


def available_runner(
    podman: RuntimePin | None, pin: B2Pin | None, profile: Profile = B2_PROFILE
) -> B2Runner | None:
    if podman is None or pin is None:
        return None
    key = (str(podman.path), podman.sha256, pin.machine, pin.image_id, profile.name)
    if key not in _cache or not _cache[key].available:
        _cache[key] = B2Runner(podman, pin, profile).probe()
    return B2Runner(podman, pin, profile) if _cache[key].available else None
