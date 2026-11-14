"""The legacy Secure Enclave key-file form (`handle_b64` metadata, rejected handle-on-disk design,
SE-H1 FAIL, superseded by D-47) is refused everywhere. Only the public-only form is accepted, and a
legacy private handle is never decoded, imported, stored or used.
"""

# ruff: noqa: F811  (pytest fixtures imported from sibling test modules)
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import pytest

import sentinel
from sentinel import admin, cli, schema
from sentinel.crypto.signing import P256
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import CapabilityUnavailable
from sentinel.keys import operator as operator_mod
from sentinel.keys import secure_enclave as se
from sentinel.keys.operator import TrustStore
from sentinel.paths import state_dir

from .conftest import NOW, FakeOperator
from .test_trust_admin import EMPTY, deps, f, home, key_subj, run  # noqa: F401

SRC = Path(sentinel.__file__).parent
SIGNED = Path(__file__).parent / "fixtures/schemas/historical/signed"


def legacy_keyfile(op: FakeOperator, **over: Any) -> dict[str, Any]:
    return {
        "key_id": op.public.key_id,
        "algorithm": P256,
        "public_x963_hex": op.public.public_raw.hex(),
        "handle_b64": base64.b64encode(b"opaque-legacy-handle").decode(),
        "backend": se.BACKEND_NAME,
        "created_at": NOW,
        **over,
    }


def converted(legacy: dict[str, Any]) -> dict[str, str]:
    """The documented conversion: drop the handle, keep the public key."""
    return {
        "key_id": legacy["key_id"],
        "algorithm": legacy["algorithm"],
        "public_hex": legacy["public_x963_hex"],
    }


def _cli(home, capsys, tmp_path, verb, keyfile, approval, *extra: str) -> tuple[int, Any]:
    return run(
        home, capsys, "key", verb, "--key", f(tmp_path, keyfile), "--approval", f(tmp_path, approval),
        "--operator", "owner", "--expires-at", str(NOW + 365 * 86400), *extra,
    )  # fmt: skip


@pytest.mark.parametrize(
    "variant",
    [
        {},
        {"handle_b64": ""},
        {"backend": "something-else"},
        {"extra": 1},
    ],
)
def test_parse_refuses_every_legacy_shape(variant, monkeypatch):
    op = FakeOperator.make(P256)
    decoded: list[Any] = []
    monkeypatch.setattr(base64, "b64decode", lambda *a, **k: decoded.append(a) or b"")
    monkeypatch.setattr(se.SecureEnclaveKeyMetadata, "from_json", classmethod(lambda c, d: decoded.append(d)))
    with pytest.raises(schema.SchemaError) as exc:
        admin.parse_key_file(legacy_keyfile(op, **variant))
    assert exc.value.code == "legacy_key_format" and "public_hex" in str(exc.value)
    assert decoded == []  # the private handle is never decoded or turned into metadata


def test_public_fields_with_a_handle_are_still_refused():
    op = FakeOperator.make(P256)
    data = {**converted(legacy_keyfile(op)), "handle_b64": "aA=="}
    with pytest.raises(schema.SchemaError, match="legacy"):
        admin.parse_key_file(data)


def test_schema_alone_refuses_the_legacy_shape():
    with pytest.raises(schema.SchemaError):
        schema.validate(legacy_keyfile(FakeOperator.make(P256)), "operator-public-key")


def test_cli_enrol_refuses_legacy_file_without_burning_the_approval(home, capsys, tmp_path):
    op = FakeOperator.make(P256)
    ap = op.approve(A.KEY_ROTATE, key_subj(op), f"trust:{EMPTY}")
    code, out = _cli(home, capsys, tmp_path, "enrol", legacy_keyfile(op), ap)
    assert code == cli.EXIT_INVALID and out["code"] == "legacy_key_format"
    assert TrustStore().get(op.public.key_id) is None
    assert not (state_dir() / "keys" / "secure-enclave").exists()  # nothing of the handle is stored
    # The same approval still works with the converted public-only file: nothing was consumed.
    code, _ = _cli(home, capsys, tmp_path, "enrol", converted(legacy_keyfile(op)), ap)
    assert code == cli.EXIT_OK and TrustStore().get(op.public.key_id) is not None


def test_cli_rotate_refuses_legacy_file(home, capsys, tmp_path):
    first = FakeOperator.make(P256)
    ap = first.approve(A.KEY_ROTATE, key_subj(first), f"trust:{EMPTY}")
    assert _cli(home, capsys, tmp_path, "enrol", converted(legacy_keyfile(first)), ap)[0] == cli.EXIT_OK
    new = FakeOperator.make(P256)
    rot = first.approve(A.KEY_ROTATE, key_subj(new), f"trust:{TrustStore().fingerprint()}")
    code, out = _cli(
        home, capsys, tmp_path, "rotate", legacy_keyfile(new), rot,
        "--trust-fingerprint", TrustStore().fingerprint(),
    )  # fmt: skip
    assert code == cli.EXIT_INVALID and out["code"] == "legacy_key_format"
    assert TrustStore().get(new.public.key_id) is None


def test_production_code_has_no_legacy_handle_import_path():
    """No production module outside the dormant keys/secure_enclave.py references the handle format,
    its metadata store, or builds a signer; production signing has no success path."""
    forbidden = re.compile(
        r"KeyMetadataStore|SecureEnclaveKeyMetadata|SecureEnclaveProvider\(|NativeHelperBackend\("
        r"|helper_backend\(|sign_payload\(|\.sign_with_presence\("
    )
    hits = {
        str(p.relative_to(SRC)): m.group(0)
        for p in SRC.rglob("*.py")
        if not (p.name == "secure_enclave.py" and p.parent.name == "keys")
        for m in [forbidden.search(p.read_text())]
        if m
    }
    assert hits == {}
    body = (SRC / "keys" / "secure_enclave.py").read_text().split("def production_provider", 1)[1]
    body = body.split("\ndef ", 1)[0]
    assert "return" not in body and "raise CapabilityUnavailable" in body


def test_signing_stays_disabled(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
    with pytest.raises(CapabilityUnavailable, match="not activated"):
        operator_mod.available_provider()


def test_existing_trust_store_public_keys_and_approvals_are_unaffected(tmp_path):
    from .test_d49_signing import _legacy_p256_store

    p = tmp_path / "trust.json"
    _legacy_p256_store(p)
    assert TrustStore(p).fingerprint()
    assert "handle" not in (SIGNED / "trust.json").read_text()
    keys = json.loads((SIGNED / "keys.json").read_text())
    for blob in json.dumps(keys), *(q.read_text() for q in SIGNED.rglob("*.json")):
        assert "handle_b64" not in blob
