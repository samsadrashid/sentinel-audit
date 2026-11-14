"""Native Secure Enclave helper: protocol, parsing and error handling WITHOUT user presence.

No test here reaches the Touch ID / passcode prompt: `sign` is only ever called with invalid requests or
a garbage handle, which the helper rejects before authentication. Real signing is covered only by the
manual hardware tests H1-H11 (docs/m1/se-hardware-tests.md).
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.errors import BlockedError, CapabilityUnavailable, ValidationError
from sentinel.keys.secure_enclave import (
    BACKEND_NAME,
    MAX_MESSAGE_BYTES,
    NativeHelperBackend,
    parse_helper_output,
    production_provider,
)

from .conftest import NOW

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "native/macos/se-helper/build.sh"


# ── output parsing ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "rc,out,ok",
    [
        (0, b'{"secure_enclave":true}', True),
        (1, b'{"error":"cancelled","message":"x"}', True),
        (2, b'{"error":"invalid_request","message":"x"}', True),
        (0, b'{"error":"cancelled","message":"x"}', False),  # error with success status
        (1, b'{"signature_der_b64":"AA=="}', False),  # success with error status
        (3, b'{"error":"cancelled","message":"x"}', False),  # unexpected status
        (-9, b'{"error":"cancelled","message":"x"}', False),  # killed by signal
        (0, b"", False),
        (0, b"not json", False),
        (0, b'{"a":1}{"b":2}', False),  # two objects
        (0, b'{"a":1,"a":2}', False),  # duplicate keys
        (0, b"[1]", False),
        (0, b"\xff\xfe", False),
        (0, b'{"a":"' + b"x" * 9000 + b'"}', False),  # over output cap
    ],
)
def test_parse_helper_output(rc, out, ok):
    resp = parse_helper_output(rc, out)
    assert (resp.get("error") != "malformed") is ok


# ── process plumbing with fake executables (never genuine hardware) ───────
def _script(tmp_path: Path, body: str) -> tuple[Path, str]:
    p = tmp_path / "fake-helper"
    p.write_text(f"#!{sys.executable} -I\n{body}")
    p.chmod(0o700)
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


ECHO = """import sys, json, os
args = sys.argv[1:]
data = sys.stdin.buffer.read()
handle = open(args[1], 'rb').read().decode() if len(args) > 1 else ''
json.dump({"error": "cancelled", "message": json.dumps({"args": args[:1] + args[2:], "n": len(data),
    "handle": handle, "env": sorted(os.environ),
    "mode": oct(os.stat(args[1]).st_mode & 0o777) if len(args) > 1 else ''})},
    sys.stdout)
sys.exit(1)
"""


def test_backend_passes_exact_bytes_handle_file_and_minimal_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "x")
    p, h = _script(tmp_path, ECHO)
    resp = NativeHelperBackend(p, h).sign(b"hello", b"payload", "caller reason ignored", 5)
    info = json.loads(resp["message"])
    assert info["args"] == ["sign", "5"] and info["n"] == 7
    assert info["handle"] == base64.b64encode(b"hello").decode() and info["mode"] == "0o600"
    assert "SECRET_TOKEN" not in info["env"] and "caller reason" not in resp["message"]


def test_backend_refuses_unpinned_or_swapped_helper(tmp_path):
    p, h = _script(tmp_path, ECHO)
    with pytest.raises(CapabilityUnavailable, match="pin"):
        NativeHelperBackend(p, "0" * 64).sign(b"h", b"m", "r", 5)
    p.write_text(p.read_text() + "\n# changed\n")
    with pytest.raises(CapabilityUnavailable, match="pin"):
        NativeHelperBackend(p, h).sign(b"h", b"m", "r", 5)
    with pytest.raises(ValidationError):
        NativeHelperBackend(p, "ABC")


def test_backend_size_limits_and_timeout(tmp_path):
    p, h = _script(tmp_path, "import time; time.sleep(30)\n")
    b = NativeHelperBackend(p, h)
    for msg in (b"", b"x" * (MAX_MESSAGE_BYTES + 1)):
        with pytest.raises(BlockedError):
            b.sign(b"h", msg, "r", 1)
    with pytest.raises(BlockedError):
        b.status()  # helper never answers: timeout result is not a valid status


def test_backend_create_recomputes_key_id_and_rejects_bad_keys(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    )
    good = json.dumps({"public_x963_hex": pub.hex(), "handle_b64": "aGFuZGxl"})
    p, h = _script(tmp_path, f"print({good!r}, end='')\n")
    meta = NativeHelperBackend(p, h).create(NOW)
    assert meta.backend == BACKEND_NAME and meta.key_id.startswith("p256:")
    for bad in (
        {"public_x963_hex": "04" + "00" * 64, "handle_b64": "aA=="},
        {"public_x963_hex": pub.hex()},
        {"public_x963_hex": pub.hex(), "handle_b64": "aA==", "key_id": "p256:x"},
    ):
        p, h = _script(tmp_path, f"print({json.dumps(bad)!r}, end='')\n")
        with pytest.raises((BlockedError, ValidationError)):
            NativeHelperBackend(p, h).create(NOW)


def test_production_still_fails_closed():
    with pytest.raises(CapabilityUnavailable):
        production_provider()


# ── the real native helper, prompt-free paths only ─────────────────────────
needs_mac = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("swiftc") is None, reason="needs macOS with swiftc"
)


@pytest.fixture(scope="module")
def helper(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("se") / "sentinel-se-helper"
    subprocess.run(["/bin/sh", str(BUILD), str(out)], check=True, capture_output=True, timeout=600)
    return out


def run(helper: Path, *args: str, stdin: bytes = b"") -> tuple[int, dict]:
    r = subprocess.run([str(helper), *args], input=stdin, capture_output=True, timeout=30)
    assert r.stderr == b""  # nothing logged
    return r.returncode, json.loads(r.stdout)


@needs_mac
def test_real_helper_status(helper):
    rc, out = run(helper, "status")
    assert rc == 0 and set(out) == {"secure_enclave"} and isinstance(out["secure_enclave"], bool)


@needs_mac
@pytest.mark.parametrize(
    "args",
    [
        (),
        ("bogus",),
        ("status", "x"),
        ("create", "x"),
        ("sign",),
        ("sign", "/tmp/h"),
        ("sign", "/tmp/h", "10", "extra"),
        ("--help",),
        ("SIGN", "/tmp/h", "10"),
    ],
)
def test_real_helper_rejects_bad_commands(helper, args):
    rc, out = run(helper, *args)
    assert rc == 2 and out == {"error": "invalid_request", "message": "invalid request"}


@needs_mac
@pytest.mark.parametrize("timeout", ["0", "010", "-1", "301", "1.5", "", "abc", "99999"])
def test_real_helper_rejects_bad_timeout(helper, tmp_path, timeout):
    hf = tmp_path / "h"
    hf.write_bytes(base64.b64encode(b"x" * 32))
    assert run(helper, "sign", str(hf), timeout, stdin=b"m")[1]["error"] == "invalid_request"


@needs_mac
@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not base64!",
        base64.b64encode(b"x" * 32) + b"\n",
        b" " + base64.b64encode(b"x"),
        base64.b64encode(b"x" * 4097),
        b"x" * 9000,
    ],
)
def test_real_helper_rejects_bad_handle_files(helper, tmp_path, content):
    hf = tmp_path / "h"
    hf.write_bytes(content)
    assert run(helper, "sign", str(hf), "10", stdin=b"m")[1]["error"] == "invalid_request"


@needs_mac
def test_real_helper_rejects_relative_missing_handle_and_bad_stdin(helper, tmp_path):
    hf = tmp_path / "h"
    hf.write_bytes(base64.b64encode(b"x" * 32))
    assert run(helper, "sign", "h", "10", stdin=b"m")[1]["error"] == "invalid_request"
    assert run(helper, "sign", str(tmp_path / "nope"), "10", stdin=b"m")[1]["error"] == "invalid_request"
    assert run(helper, "sign", str(hf), "10", stdin=b"")[1]["error"] == "invalid_request"
    big = b"x" * (MAX_MESSAGE_BYTES + 1)
    assert run(helper, "sign", str(hf), "10", stdin=big)[1]["error"] == "invalid_request"


@needs_mac
def test_real_helper_garbage_handle_unusable_before_prompt(helper, tmp_path):
    hf = tmp_path / "h"
    hf.write_bytes(base64.b64encode(b"definitely not a Secure Enclave key blob"))
    rc, out = run(helper, "sign", str(hf), "10", stdin=b"payload")
    assert rc == 1 and out["error"] in ("key_unusable", "not_interactive", "no_secure_enclave")


@needs_mac
def test_real_helper_create_returns_documented_format(helper):
    """Key creation needs no user presence. Asserts format only; it does NOT prove hardware backing."""
    h = hashlib.sha256(helper.read_bytes()).hexdigest()
    b = NativeHelperBackend(helper, h)
    if not b.status():
        pytest.skip("no Secure Enclave on this host")
    meta = b.create(NOW)
    assert len(meta.public_x963) == 65 and meta.public_x963[0] == 4 and 0 < len(meta.handle) <= 4096
