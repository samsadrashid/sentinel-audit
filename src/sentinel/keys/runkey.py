"""Automatic run key (§11.2, §13.7, D-34).

The run key signs manifests and audit-log checkpoints without a prompt. Its signature proves
integrity relative to the key only: any same-user process that can read the keystore can also
re-sign. It can never sign a trust-anchor action; the approval verifier rejects run keys.

Backends: macOS login keychain via /usr/bin/security, Linux Secret Service via secret-tool.
The secret is passed on stdin, never on argv. If no backend exists the run key is unavailable
and audits fail closed (D-32).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Protocol

from ..crypto.signing import Ed25519Signer, PublicKey
from ..errors import CapabilityUnavailable
from ..paths import atomic_write, state_dir

SERVICE = "dev.sentinel.run-key"


class SecretBackend(Protocol):
    name: str

    def store(self, account: str, secret_hex: str) -> None: ...
    def load(self, account: str) -> str | None: ...


class MacKeychainBackend:
    name = "macos-keychain"

    def __init__(self) -> None:
        if sys.platform != "darwin" or not os.path.exists("/usr/bin/security"):
            raise CapabilityUnavailable("run-key-keystore", "macOS security tool not available")

    def store(self, account: str, secret_hex: str) -> None:
        if not all(c in "0123456789abcdef" for c in secret_hex):
            raise ValueError("secret must be hex")
        cmd = f"add-generic-password -U -s {SERVICE} -a {account} -w {secret_hex}\n"
        r = subprocess.run(["/usr/bin/security", "-i"], input=cmd, text=True, capture_output=True, timeout=30)
        if r.returncode != 0 or "error" in r.stderr.lower():
            raise CapabilityUnavailable("run-key-keystore", "keychain store failed")

    def load(self, account: str) -> str | None:
        r = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
            text=True,
            capture_output=True,
            timeout=30,
        )
        return r.stdout.strip() if r.returncode == 0 else None


class SecretToolBackend:
    name = "linux-secret-service"

    def __init__(self) -> None:
        self._bin = shutil.which("secret-tool")
        if not sys.platform.startswith("linux") or not self._bin:
            raise CapabilityUnavailable("run-key-keystore", "secret-tool (Secret Service) not available")

    def store(self, account: str, secret_hex: str) -> None:
        assert self._bin
        r = subprocess.run(
            [self._bin, "store", "--label=sentinel run key", "service", SERVICE, "account", account],
            input=secret_hex,
            text=True,
            capture_output=True,
            timeout=30,
        )
        if r.returncode != 0:
            raise CapabilityUnavailable("run-key-keystore", "secret-tool store failed")

    def load(self, account: str) -> str | None:
        assert self._bin
        r = subprocess.run(
            [self._bin, "lookup", "service", SERVICE, "account", account],
            text=True,
            capture_output=True,
            timeout=30,
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def default_backend() -> SecretBackend:
    errors = []
    for cls in (MacKeychainBackend, SecretToolBackend):
        try:
            return cls()
        except CapabilityUnavailable as exc:
            errors.append(exc.reason)
    raise CapabilityUnavailable("run-key-keystore", "; ".join(errors))


def run_public_key() -> PublicKey | None:
    """The run key's public half, from metadata only (no keystore access; enough to verify runs)."""
    p = state_dir() / "keys" / "run-key.json"
    if not p.exists():
        return None
    from .. import canonical
    from ..schema import validate

    meta = canonical.decode_strict(p.read_bytes())

    validate(meta, "run-key-metadata")  # D-40, before the public key is used to verify runs
    return PublicKey.from_raw(bytes.fromhex(meta["public"]))


class RunKeyManager:
    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend = backend or default_backend()

    def create(self) -> PublicKey:
        signer = Ed25519Signer.generate()
        meta = {
            "key_id": signer.key_id,
            "public": signer.public.public_raw.hex(),
            "backend": self.backend.name,
            "role": "run",
        }
        from ..schema import check_output

        check_output(meta, "run-key-metadata")  # D-40: before the secret or the metadata is stored
        self.backend.store(signer.key_id.replace(":", "-"), signer.seed().hex())
        atomic_write(state_dir() / "keys" / "run-key.json", json.dumps(meta, indent=1).encode())
        return signer.public

    def public(self) -> PublicKey | None:
        return run_public_key()

    def signer(self) -> Ed25519Signer:
        pub = self.public()
        if pub is None:
            raise CapabilityUnavailable("run-key", "no run key; run `sentinel init`")
        seed_hex = self.backend.load(pub.key_id.replace(":", "-"))
        if not seed_hex:
            raise CapabilityUnavailable("run-key", "run key secret missing from keystore")
        signer = Ed25519Signer.from_seed(bytes.fromhex(seed_hex))
        if signer.key_id != pub.key_id:
            raise CapabilityUnavailable("run-key", "keystore secret does not match run key metadata")
        return signer
