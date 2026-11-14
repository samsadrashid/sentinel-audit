"""D-47: operator keys are ECDSA P-256 only. Ed25519 can't enter the trust store, be enrolled or rotated
in, or authorise anything, on any path. The run key stays Ed25519 and never approves (D-16)."""

# ruff: noqa: F811
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from sentinel import admin, approvals, canonical, cli, schema, signing_protocol
from sentinel.crypto.signing import ED25519, OPERATOR_ALGORITHMS, P256, RUN_KEY_ALGORITHM
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import BlockedError, ValidationError
from sentinel.keys.operator import OperatorKey, TrustStore, key_to_json

from .conftest import NOW, FakeOperator
from .test_trust_admin import EMPTY, deps, f, home, key_subj, run  # noqa: F401

SIGNED = Path(__file__).parent / "fixtures/schemas/historical/signed"
YEAR = 365 * 86400


def ed_key() -> OperatorKey:
    o = FakeOperator.make(ED25519)
    return OperatorKey(o.public.key_id, "x", o.public, "active", NOW + YEAR)


def test_algorithm_sets():
    assert OPERATOR_ALGORITHMS == frozenset({P256}) and RUN_KEY_ALGORITHM == ED25519


def test_ed25519_key_files_are_refused():
    o = FakeOperator.make(ED25519)
    data = {"key_id": o.public.key_id, "algorithm": ED25519, "public_hex": o.public.public_raw.hex()}
    with pytest.raises(ValidationError):
        admin.parse_key_file(data)
    with pytest.raises(schema.SchemaError):
        schema.validate(data, "operator-public-key")


def test_explicit_ed25519_trust_entries_are_refused(tmp_path):
    e = key_to_json(ed_key())
    p = tmp_path / "t.json"
    p.write_bytes(canonical.encode({"keys": [e]}))
    with pytest.raises(ValidationError):
        TrustStore(p)


def test_historical_ed25519_trust_store_is_refused_as_production_trust(tmp_path):
    """The pre-D-47 signed fixture stays byte-identical evidence, but it can't be used as trust."""
    p = tmp_path / "t.json"
    p.write_bytes((SIGNED / "trust.json").read_bytes())
    schema.validate(canonical.decode_strict(p.read_bytes()), "trust-store")  # still valid historical shape
    with pytest.raises(ValidationError, match="not allowed for operator keys"):
        TrustStore(p)


def test_enrol_and_rotation_refuse_ed25519(tmp_path):
    ts = TrustStore(tmp_path / "t.json")
    with pytest.raises(BlockedError) as e:
        ts.enrol(ed_key())
    assert e.value.code == "bad_algorithm"
    with pytest.raises(BlockedError) as e:
        ts.apply_rotation(ed_key())
    assert e.value.code == "bad_algorithm"
    assert ts._keys == {}


def test_an_injected_ed25519_key_can_authorise_nothing(tmp_path):
    """Defence in depth: even if an Ed25519 key reached memory, no verification path accepts it."""
    o = FakeOperator.make(ED25519)
    ts = TrustStore(tmp_path / "t.json")
    ts._keys[o.public.key_id] = OperatorKey(o.public.key_id, "x", o.public, "active", NOW + YEAR)
    ap = o.approve(A.SUPPRESS, {"type": "suppression_entry", "sha256": "a" * 64}, "r")
    with pytest.raises(BlockedError) as e:
        approvals.verify(
            ap,
            approvals.Expectation(A.SUPPRESS, {"type": "suppression_entry", "sha256": "a" * 64}, "r"),
            ts,
            approvals.NonceLedger(tmp_path / "n.json"),
            NOW + 1,
            consume=True,
        )
    assert e.value.code == "bad_algorithm"
    assert not (tmp_path / "n.json").exists()  # no nonce consumed
    k = ts._keys[o.public.key_id]
    ts._keys[o.public.key_id] = dataclasses.replace(k, role="recovery", permitted_actions=("key.revoke",))
    with pytest.raises(BlockedError) as e:
        ts.authorise(o.public.key_id, "key.revoke", NOW + 1, role="recovery")
    assert e.value.code == "bad_algorithm"


def test_cli_enrol_refuses_an_ed25519_key(home, capsys, tmp_path):
    o = FakeOperator.make(ED25519)
    kf = {"key_id": o.public.key_id, "algorithm": ED25519, "public_hex": o.public.public_raw.hex()}
    ap = o.approve(A.KEY_ROTATE, key_subj(o), f"trust:{EMPTY}")
    code, _ = run(
        home,
        capsys,
        "key",
        "enrol",
        "--key",
        f(tmp_path, kf),
        "--approval",
        f(tmp_path, ap),
        "--operator",
        "o",
        "--expires-at",
        str(NOW + YEAR),
    )
    assert code == cli.EXIT_INVALID
    assert run(home, capsys, "key", "list")[1]["keys"] == []


def test_no_sign_request_for_an_ed25519_key(tmp_path):
    o = FakeOperator.make(ED25519)
    ts = TrustStore(tmp_path / "t.json")
    payload = approvals.build_payload(
        action=A.SUPPRESS,
        subject={"type": "suppression_entry", "sha256": "a" * 64},
        revision="r",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=o.public.key_id,
        rationale="x",
    )
    vol = tmp_path / "v"
    vol.mkdir()
    with pytest.raises(BlockedError):
        signing_protocol.emit_request(payload, vol, ts, NOW + 1)
    assert not (vol / "sentinel-v1").exists()
