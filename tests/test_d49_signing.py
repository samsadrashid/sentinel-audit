# ruff: noqa: F811
"""D-49 engine-side operator-signing infrastructure.

(1) D-45 roles and permitted actions; (2) trust-store fingerprint covers them; (3) the separate D-47
recovery WebAuthn assertion verifier; (4) protocol-v1 request emission and response reception;
(5) test-key fixtures. All keys here are software test keys (tests/signing_fixtures.py): this is
engine-side enforcement evidence, **not** hardware validation of operator presence.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest

from sentinel import admin, approvals, canonical, recovery, signing_protocol
from sentinel.crypto.signing import P256, Ed25519Signer
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import BlockedError, IntegrityError, ValidationError
from sentinel.keys.operator import (
    OPERATOR_ACTIONS,
    RECOVERY_ACTIONS,
    OperatorKey,
    RecoveryCredential,
    TrustStore,
)

from .conftest import NOW, FakeOperator
from .signing_fixtures import FakeRecoveryAuthenticator, FakeSigningDevice
from .test_trust_admin import deps, home  # noqa: F401

SIGNED = Path(__file__).parent / "fixtures/schemas/historical/signed"
YEAR = 365 * 86400


# ── fixtures ───────────────────────────────────────────────────────────────
@pytest.fixture
def op() -> FakeOperator:
    return FakeOperator.make(P256)


@pytest.fixture
def auth() -> FakeRecoveryAuthenticator:
    return FakeRecoveryAuthenticator()


@pytest.fixture
def store(tmp_path: Path, op: FakeOperator, auth: FakeRecoveryAuthenticator) -> TrustStore:
    """An operator key plus an enrolled recovery credential."""
    ts = TrustStore(tmp_path / "trust.json")
    ts.enrol(OperatorKey(op.public.key_id, "owner", op.public, "active", NOW + YEAR))
    rec = admin.parse_key_file(auth.key_file()).as_trusted("owner-recovery", NOW + YEAR)
    ts.apply_rotation(rec)
    ts.save()
    return TrustStore(tmp_path / "trust.json")


@pytest.fixture
def ctx(store: TrustStore, tmp_path: Path) -> admin.AdminContext:
    return admin.AdminContext(
        store, approvals.NonceLedger(tmp_path / "n.json"), Ed25519Signer.generate(), NOW + 1, tmp_path / "log"
    )


def fp(ts: TrustStore) -> str:
    return ts.fingerprint()


# ── D-45: roles, permissions, fingerprint ─────────────────────────────────
def test_role_and_permissions_are_persisted_and_part_of_the_fingerprint(store, op, tmp_path):
    entries = {k["key_id"]: k for k in store._as_json()["keys"]}
    assert entries[op.public.key_id]["role"] == "operator"
    assert entries[op.public.key_id]["permitted_actions"] == list(OPERATOR_ACTIONS)
    rec = next(k for k in entries.values() if k["role"] == "recovery")
    assert rec["permitted_actions"] == list(RECOVERY_ACTIONS) and rec["rp_id"] == "sentinel-recovery.invalid"
    before = fp(store)
    k = store.get(op.public.key_id)
    assert k is not None
    store._keys[k.key_id] = OperatorKey(
        k.key_id, k.operator, k.public, k.status, k.expires_at, "operator", ("suppress",)
    )
    assert fp(store) != before  # narrowing permissions changes the fingerprint


def _legacy_p256_store(path):  # type: ignore[no-untyped-def]
    """A pre-D-45 (no role) trust store holding a P-256 key, in the historical entry shape."""
    from sentinel import canonical as _c

    op = FakeOperator.make(P256)
    entry = {
        "algorithm": P256,
        "expires_at": NOW + 10**7,
        "key_id": op.public.key_id,
        "operator": "owner",
        "public": op.public.public_raw.hex(),
        "status": "active",
    }
    path.write_bytes(_c.encode({"keys": [entry]}))
    return op


def test_pre_d45_trust_store_loads_as_operator_keys(tmp_path):
    p = tmp_path / "t.json"
    _legacy_p256_store(p)
    ts = TrustStore(p)
    (k,) = ts._keys.values()
    assert k.role == "operator" and k.permitted_actions == OPERATOR_ACTIONS
    assert "role" in json.dumps(ts._as_json())  # written back only in the explicit form


@pytest.mark.parametrize(
    "change",
    [
        {"permitted_actions": ["suppress", "authorize_record"]},  # not sorted
        {"permitted_actions": []},
        {"permitted_actions": ["signer.release"]},  # device-only action
        {"role": "auditor"},
        {"status": "suspect"},  # only recovery keys can be suspect
        {"rp_id": "sentinel-recovery.invalid"},  # credential fields on an operator key
    ],
)
def test_bad_operator_entries_are_refused(store, op, tmp_path, change):
    data = store._as_json()
    entry = next(k for k in data["keys"] if k["key_id"] == op.public.key_id)
    entry.update(change)
    p = tmp_path / "bad.json"
    p.write_bytes(canonical.encode(data))
    with pytest.raises(ValidationError):
        TrustStore(p)


@pytest.mark.parametrize(
    "change",
    [
        {"permitted_actions": ["key.revoke", "suppress"]},
        {"rp_id": "example.com"},
        {"cose_alg": -8},
        {"counter_mode": "sometimes"},
        {"last_count": -1},
        {"credential_id_b64": "!!"},
    ],
)
def test_bad_recovery_entries_are_refused(store, tmp_path, change):
    data = store._as_json()
    entry = next(k for k in data["keys"] if k["role"] == "recovery")
    entry.update(change)
    p = tmp_path / "bad.json"
    p.write_bytes(canonical.encode(data))
    with pytest.raises(ValidationError):
        TrustStore(p)


def test_action_outside_permitted_actions_is_blocked(tmp_path, op):
    ts = TrustStore(tmp_path / "t.json")
    ts.enrol(OperatorKey(op.public.key_id, "o", op.public, "active", NOW + YEAR, "operator", ("suppress",)))
    ap = op.approve(A.POLICY_CHANGE, {"type": "policy_file", "sha256": "a" * 64}, "policy-prev:none")
    with pytest.raises(BlockedError) as e:
        approvals.verify(
            ap,
            approvals.Expectation(
                A.POLICY_CHANGE, {"type": "policy_file", "sha256": "a" * 64}, "policy-prev:none"
            ),
            ts,
            approvals.NonceLedger(tmp_path / "n.json"),
            NOW + 1,
            consume=False,
        )
    assert e.value.code == "action_not_permitted"


def test_recovery_key_signature_is_never_an_operator_signature(store, auth, tmp_path):
    """Even a valid raw ECDSA signature by the recovery key is refused on the ordinary path (D-47)."""
    payload = approvals.build_payload(
        action=A.KEY_REVOKE,
        subject={"type": "operator_key", "key_id": "p256:" + "0" * 32},
        revision=f"trust:{fp(store)}",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="x",
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    sig = auth._key.sign(canonical.encode(payload), ec.ECDSA(hashes.SHA256()))
    with pytest.raises(BlockedError) as e:
        approvals.verify(
            approvals.Approval(payload, sig),
            approvals.Expectation(A.KEY_REVOKE, payload["subject"], payload["revision"]),
            store,
            approvals.NonceLedger(tmp_path / "n.json"),
            NOW + 1,
            consume=False,
        )
    assert e.value.code == "wrong_key_role"


# ── D-47: recovery assertions ─────────────────────────────────────────────
def _rotate_payload(auth: FakeRecoveryAuthenticator, ts: TrustStore, new: FakeOperator) -> dict[str, Any]:
    cand = admin.CandidateKey(new.public)
    return approvals.build_payload(
        action=A.KEY_ROTATE,
        subject=admin.key_subject(cand),
        revision=f"trust:{fp(ts)}",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="recovery test",
    )


def _rotate(ctx: admin.AdminContext, rap: recovery.RecoveryApproval, new: FakeOperator) -> OperatorKey:
    return admin.rotate(
        ctx,
        admin.CandidateKey(new.public),
        rap,
        operator="replacement",
        expires_at=NOW + YEAR,
        expected_trust_fingerprint=fp(ctx.trust),
    )


def test_recovery_enrols_a_replacement_operator_key_and_records_the_counter(ctx, auth):
    new = FakeOperator.make(P256)
    rap = auth.assertion(_rotate_payload(auth, ctx.trust, new))
    k = _rotate(ctx, rap, new)
    assert k.role == "operator" and k.permitted_actions == OPERATOR_ACTIONS
    saved = TrustStore(ctx.trust.path).get(auth.public.key_id)
    assert saved is not None and saved.recovery is not None
    assert saved.recovery.counter_mode == "increasing" and saved.recovery.last_count == 1
    with pytest.raises(BlockedError):  # one-time nonce: the same assertion can't be replayed
        _rotate(ctx, rap, new)


def _bad(ctx, auth, new, code, payload=None, **kw):  # type: ignore[no-untyped-def]
    rap = auth.assertion(payload or _rotate_payload(auth, ctx.trust, new), **kw)
    with pytest.raises(BlockedError) as e:
        _rotate(ctx, rap, new)
    assert e.value.code == code, e.value.reason
    assert ctx.trust.get(new.public.key_id) is None


def _cd(auth, payload, **over):  # type: ignore[no-untyped-def]
    base = {
        "type": "webauthn.get",
        "challenge": recovery.b64url(recovery.challenge_for(payload)),
        "origin": "https://sentinel-recovery.invalid",
        "crossOrigin": False,
    }
    return {**base, **over}


@pytest.mark.parametrize(
    "over, code",
    [
        ({"type": "webauthn.create"}, "bad_client_data"),
        ({"tokenBinding": {"status": "present"}}, "bad_client_data"),
        ({"topOrigin": "https://sentinel-recovery.invalid"}, "bad_client_data"),
        ({"origin": "https://sentinel-recovery.invalid:443"}, "bad_origin"),
        ({"origin": "https://sentinel-recovery.invalid/"}, "bad_origin"),
        ({"origin": "https://SENTINEL-recovery.invalid"}, "bad_origin"),
        ({"origin": "http://sentinel-recovery.invalid"}, "bad_origin"),
        ({"crossOrigin": True}, "bad_origin"),
        ({"challenge": recovery.b64url(b"\0" * 32)}, "bad_challenge"),
    ],
)
def test_client_data_is_validated_exactly(ctx, auth, over, code):
    new = FakeOperator.make(P256)
    payload = _rotate_payload(auth, ctx.trust, new)
    _bad(ctx, auth, new, code, payload, client_data=_cd(auth, payload, **over))


def test_client_data_without_cross_origin_is_accepted(ctx, auth):
    new = FakeOperator.make(P256)
    payload = _rotate_payload(auth, ctx.trust, new)
    cd = _cd(auth, payload)
    del cd["crossOrigin"]
    _rotate(ctx, auth.assertion(payload, client_data=cd), new)


def test_duplicate_keys_in_client_data_are_refused(ctx, auth):
    new = FakeOperator.make(P256)
    payload = _rotate_payload(auth, ctx.trust, new)
    cd = json.dumps(_cd(auth, payload), separators=(",", ":"))
    raw = (cd[:-1] + ',"type":"webauthn.get"}').encode()
    _bad(ctx, auth, new, "bad_client_data", payload, client_data_raw=raw)


@pytest.mark.parametrize(
    "kw, code",
    [
        ({"flags": recovery.FLAG_UV}, "presence_missing"),
        ({"flags": recovery.FLAG_UP}, "presence_missing"),
        ({"flags": recovery.FLAG_UP | recovery.FLAG_UV | recovery.FLAG_AT}, "bad_flags"),
        ({"flags": recovery.FLAG_UP | recovery.FLAG_UV | recovery.FLAG_ED}, "bad_flags"),
        ({"rp_id_for_hash": "example.com"}, "bad_rp_id"),
        ({"extra_auth": b"\0"}, "bad_authenticator_data"),
        ({"credential_id": b"other-credential"}, "wrong_credential"),
    ],
)
def test_authenticator_data_and_credential_are_validated(ctx, auth, kw, code):
    _bad(ctx, auth, FakeOperator.make(P256), code, **kw)


def test_signature_over_other_bytes_is_refused(ctx, auth):
    new = FakeOperator.make(P256)
    rap = auth.assertion(_rotate_payload(auth, ctx.trust, new))
    forged = recovery.RecoveryApproval(
        rap.payload,
        rap.authenticator_data,
        rap.client_data_json,
        rap.credential_id,
        rap.signature[:-1] + b"\0",
    )
    with pytest.raises(BlockedError) as e:
        _rotate(ctx, forged, new)
    assert e.value.code == "bad_signature"


def test_challenge_binds_the_exact_payload(ctx, auth):
    """An assertion made for one replacement key can't enrol another."""
    a, b = FakeOperator.make(P256), FakeOperator.make(P256)
    rap = auth.assertion(_rotate_payload(auth, ctx.trust, a))
    moved = recovery.RecoveryApproval(
        _rotate_payload(auth, ctx.trust, b) | {"nonce": rap.payload["nonce"]},
        rap.authenticator_data,
        rap.client_data_json,
        rap.credential_id,
        rap.signature,
    )
    with pytest.raises(BlockedError) as e:
        _rotate(ctx, moved, b)
    assert e.value.code == "bad_challenge"


# OD-3 counter policy
def _set_counter(ctx: admin.AdminContext, auth: FakeRecoveryAuthenticator, mode: str, n: int) -> None:
    k = ctx.trust.get(auth.public.key_id)
    assert k is not None and k.recovery is not None
    ctx.trust.update_recovery(
        k.key_id, RecoveryCredential(k.recovery.credential_id, counter_mode=mode, last_count=n)
    )


@pytest.mark.parametrize(
    "mode, stored, new, outcome, suspect",
    [
        ("unset", 0, 0, "zero", False),
        ("unset", 0, 7, "increasing", False),
        ("increasing", 5, 6, "increasing", False),
        ("increasing", 5, 5, "counter_not_increasing", False),
        ("increasing", 5, 4, "counter_rollback", True),
        ("increasing", 5, 0, "counter_rollback", True),
        ("zero", 0, 0, "zero", False),
        ("zero", 0, 3, "counter_mode_changed", True),
    ],
)
def test_counter_policy(ctx, auth, mode, stored, new, outcome, suspect):
    _set_counter(ctx, auth, mode, stored)
    target = FakeOperator.make(P256)
    rap = auth.assertion(_rotate_payload(auth, ctx.trust, target), count=new)
    if outcome in ("zero", "increasing"):
        _rotate(ctx, rap, target)
        k = TrustStore(ctx.trust.path).get(auth.public.key_id)
        assert k is not None and k.recovery is not None and k.recovery.counter_mode == outcome
        return
    with pytest.raises(BlockedError) as e:
        _rotate(ctx, rap, target)
    assert e.value.code == outcome
    k = TrustStore(ctx.trust.path).get(auth.public.key_id) if suspect else ctx.trust.get(auth.public.key_id)
    assert k is not None and (k.status == "suspect") is suspect


def test_suspect_recovery_key_is_refused_for_everything(ctx, auth):
    _set_counter(ctx, auth, "increasing", 5)
    t = FakeOperator.make(P256)
    with pytest.raises(BlockedError):
        _rotate(ctx, auth.assertion(_rotate_payload(auth, ctx.trust, t), count=1), t)
    ctx.trust = TrustStore(ctx.trust.path)
    t2 = FakeOperator.make(P256)
    with pytest.raises(BlockedError) as e:
        _rotate(ctx, auth.assertion(_rotate_payload(auth, ctx.trust, t2), count=99), t2)
    assert e.value.code == "suspect_key"


# D-45 recovery limits
def test_recovery_cannot_enrol_another_recovery_key(ctx, auth):
    other = FakeRecoveryAuthenticator(credential_id=b"second")
    cand = admin.parse_key_file(other.key_file())
    payload = approvals.build_payload(
        action=A.KEY_ROTATE,
        subject=admin.key_subject(cand),
        revision=f"trust:{fp(ctx.trust)}",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="x",
    )
    with pytest.raises(BlockedError) as e:
        admin.rotate(
            ctx,
            cand,
            auth.assertion(payload),
            operator="x",
            expires_at=NOW + YEAR,
            expected_trust_fingerprint=fp(ctx.trust),
        )
    assert e.value.code == "action_not_permitted"


def test_operator_key_may_enrol_a_recovery_key(ctx, op):
    other = FakeRecoveryAuthenticator(credential_id=b"second")
    cand = admin.parse_key_file(other.key_file())
    ap = op.approve(A.KEY_ROTATE, admin.key_subject(cand), f"trust:{fp(ctx.trust)}")
    k = admin.rotate(
        ctx, cand, ap, operator="r2", expires_at=NOW + YEAR, expected_trust_fingerprint=fp(ctx.trust)
    )
    assert k.role == "recovery" and k.permitted_actions == RECOVERY_ACTIONS


def _revoke_payload(signer_id: str, ts: TrustStore, target: str) -> dict[str, Any]:
    return approvals.build_payload(
        action=A.KEY_REVOKE,
        subject={"type": "operator_key", "key_id": target},
        revision=f"trust:{fp(ts)}",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=signer_id,
        rationale="x",
    )


def test_recovery_cannot_revoke_itself(ctx, auth, op):
    second = FakeOperator.make(P256)
    ctx.trust.apply_rotation(OperatorKey(second.public.key_id, "b", second.public, "active", NOW + YEAR))
    rap = auth.assertion(_revoke_payload(auth.public.key_id, ctx.trust, auth.public.key_id))
    with pytest.raises(BlockedError) as e:
        admin.revoke(ctx, auth.public.key_id, rap, expected_trust_fingerprint=fp(ctx.trust))
    assert e.value.code == "self_revocation"


def test_recovery_can_revoke_an_operator_key_only_if_another_remains(ctx, auth, op):
    rap = auth.assertion(_revoke_payload(auth.public.key_id, ctx.trust, op.public.key_id))
    with pytest.raises(BlockedError) as e:
        admin.revoke(ctx, op.public.key_id, rap, expected_trust_fingerprint=fp(ctx.trust))
    assert e.value.code == "last_active_key"  # the recovery key does not count as an operator key
    new = FakeOperator.make(P256)
    _rotate(ctx, auth.assertion(_rotate_payload(auth, ctx.trust, new)), new)
    rap = auth.assertion(_revoke_payload(auth.public.key_id, ctx.trust, op.public.key_id))
    admin.revoke(ctx, op.public.key_id, rap, expected_trust_fingerprint=fp(ctx.trust))
    k = ctx.trust.get(op.public.key_id)
    assert k is not None and k.status == "revoked"


@pytest.mark.parametrize(
    "action",
    [a for a in A if a not in (A.KEY_ROTATE, A.KEY_REVOKE)],
)
def test_recovery_never_authorises_ordinary_actions(ctx, auth, action):
    payload = approvals.build_payload(
        action=action,
        subject={"type": "x"},
        revision="r",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="x",
    )
    with pytest.raises(BlockedError) as e:
        recovery.verify(
            auth.assertion(payload),
            approvals.Expectation(action, {"type": "x"}, "r"),
            ctx.trust,
            ctx.ledger,
            NOW + 1,
            consume=False,
        )
    assert e.value.code == "action_not_permitted"


def test_operator_key_assertion_is_not_a_recovery_assertion(ctx, op, auth):
    """A WebAuthn-shaped approval naming an operator-role key is refused by the recovery path."""
    fake = FakeRecoveryAuthenticator(_key=op._p256)  # same private key as the operator key
    payload = _revoke_payload(op.public.key_id, ctx.trust, auth.public.key_id)
    with pytest.raises(BlockedError) as e:
        recovery.verify(
            fake.assertion(payload),
            approvals.Expectation(A.KEY_REVOKE, payload["subject"], payload["revision"]),
            ctx.trust,
            ctx.ledger,
            NOW + 1,
            consume=False,
        )
    assert e.value.code == "wrong_key_role"


def test_recovery_approval_file_round_trips_and_is_schema_checked(ctx, auth):
    new = FakeOperator.make(P256)
    rap = auth.assertion(_rotate_payload(auth, ctx.trust, new))
    again = recovery.load_any(json.loads(json.dumps(rap.to_json())))
    assert isinstance(again, recovery.RecoveryApproval) and again == rap
    bad = rap.to_json()
    bad["webauthn"]["extra"] = "x"
    with pytest.raises(ValidationError):
        recovery.load_any(bad)
    both = {**rap.to_json(), "signature": "AA=="}
    with pytest.raises(ValidationError):
        recovery.load_any(both)


# ── protocol v1: request emission and response reception ─────────────────
@pytest.fixture
def volume(tmp_path: Path) -> Path:
    v = tmp_path / "XFER"
    v.mkdir()
    return v


@pytest.fixture
def state(tmp_path: Path, monkeypatch) -> Path:
    s = tmp_path / "state"
    monkeypatch.setenv("SENTINEL_HOME", str(s))
    return s


def _revoke_request(store: TrustStore, signer_id: str, target: str) -> dict[str, Any]:
    return _revoke_payload(signer_id, store, target)


def test_emit_writes_one_canonical_request_and_a_pending_record(state, volume, store, op, auth):
    out = signing_protocol.emit_request(
        _revoke_request(store, op.public.key_id, auth.public.key_id), volume, store, NOW + 1
    )
    f = Path(out["file"])
    assert f.parent == volume / "sentinel-v1" / "to-signer" and f.name == f"req-{out['request_id']}.json"
    body = f.read_bytes()
    req = canonical.decode_strict(body)
    assert canonical.encode(req) == body and set(req) == {
        "envelope",
        "payload",
        "payload_sha256",
        "request_id",
    }
    assert req["payload_sha256"] == canonical.sha256_hex(canonical.encode(req["payload"]))
    pend = signing_protocol.load_pending(out["request_id"])
    assert pend is not None and pend.state == "pending"


@pytest.mark.parametrize(
    "change, exc",
    [
        ({"rationale": "café"}, ValidationError),  # not printable ASCII
        ({"rationale": "tab\there"}, ValidationError),
        ({"action": "allowlist.change"}, ValidationError),
        ({"extra": 1}, ValidationError),
    ],
)
def test_emit_refuses_payloads_the_device_must_refuse(state, volume, store, op, auth, change, exc):
    p = {**_revoke_request(store, op.public.key_id, auth.public.key_id), **change}
    with pytest.raises(exc):
        signing_protocol.emit_request(p, volume, store, NOW + 1)
    assert not (volume / "sentinel-v1" / "to-signer").exists() or not any(
        (volume / "sentinel-v1" / "to-signer").iterdir()
    )


def test_emit_refuses_actions_outside_the_key_role(state, volume, store, auth):
    p = approvals.build_payload(
        action=A.SUPPRESS,
        subject={"type": "finding", "fingerprint": "f" * 64},
        revision="r",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="x",
    )
    with pytest.raises(BlockedError) as e:
        signing_protocol.emit_request(p, volume, store, NOW + 1)
    assert e.value.code == "action_not_permitted"


def test_operator_round_trip_produces_a_usable_approval(state, volume, store, op, auth):
    second = FakeOperator.make(P256)
    store.apply_rotation(OperatorKey(second.public.key_id, "b", second.public, "active", NOW + YEAR))
    store.save()
    payload = _revoke_request(store, op.public.key_id, second.public.key_id)
    out = signing_protocol.emit_request(payload, volume, store, NOW + 1)
    dev = FakeSigningDevice(volume)
    (req,) = dev.requests()
    dev.sign_operator(req, op)
    (r,) = signing_protocol.receive_responses(volume, store, NOW + 2)
    assert r["status"] == "received" and r["request_id"] == out["request_id"]
    assert not list((volume / "sentinel-v1").rglob("*.json"))  # request and response removed
    ap = approvals.load_approval_file(Path(r["approval"]))
    ctx = admin.AdminContext(
        store, approvals.NonceLedger(), Ed25519Signer.generate(), NOW + 3, volume.parent / "admin-log.jsonl"
    )
    admin.revoke(ctx, second.public.key_id, ap, expected_trust_fingerprint=fp(store))
    # replaying the same response is refused: the request is no longer pending
    dev.sign_operator(req, op)
    (again,) = signing_protocol.receive_responses(volume, store, NOW + 4)
    assert again["status"] == "refused" and again["code"] == "unknown_request"


def test_recovery_round_trip(state, volume, store, auth, op):
    new = FakeOperator.make(P256)
    payload = _rotate_payload(auth, store, new)
    signing_protocol.emit_request(payload, volume, store, NOW + 1)
    dev = FakeSigningDevice(volume)
    (req,) = dev.requests()
    dev.sign_recovery(req, auth)
    (r,) = signing_protocol.receive_responses(volume, store, NOW + 2)
    assert r["status"] == "received"
    rap = recovery.load_any(json.loads(Path(r["approval"]).read_text()))
    assert isinstance(rap, recovery.RecoveryApproval)


def _one_response(state, volume, store, op, auth, mutate):  # type: ignore[no-untyped-def]
    payload = _revoke_request(store, op.public.key_id, auth.public.key_id)
    signing_protocol.emit_request(payload, volume, store, NOW + 1)
    dev = FakeSigningDevice(volume)
    (req,) = dev.requests()
    path = dev.sign_operator(req, op)
    mutate(path, req, dev)
    (r,) = signing_protocol.receive_responses(volume, store, NOW + 2)
    assert r["status"] == "refused"
    assert any(volume.rglob("req-*.json"))  # nothing removed on refusal
    return r


def _rewrite(path: Path, **change: Any) -> None:
    body = canonical.decode_strict(path.read_bytes())
    body.update(change)
    path.write_bytes(canonical.encode(body))


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda p, r, d: _rewrite(p, payload_sha256="0" * 64), "payload_mismatch"),
        (
            lambda p, r, d: _rewrite(p, signature_der_b64=base64.b64encode(b"\x30\x00").decode()),
            "bad_signature",
        ),
        (lambda p, r, d: _rewrite(p, key_id="p256:" + "1" * 32), "key_mismatch"),
        (lambda p, r, d: _rewrite(p, envelope="sentinel/v2/sign-response"), "schema_invalid"),
        (lambda p, r, d: _rewrite(p, note="please approve"), "schema_invalid"),
        (lambda p, r, d: _rewrite(p, request_id="f" * 32), "IntegrityError"),
        (lambda p, r, d: p.write_bytes(p.read_bytes() + b"\n"), "IntegrityError"),  # not canonical
        (lambda p, r, d: p.write_bytes(b" " * 4096), "IntegrityError"),  # oversized
        (lambda p, r, d: p.write_bytes(b""), "IntegrityError"),  # empty
    ],
)
def test_bad_responses_are_refused(state, volume, store, op, auth, mutate, code):
    r = _one_response(state, volume, store, op, auth, mutate)
    assert r["code"] == code, r


def test_symlinked_or_hard_linked_responses_are_refused(state, volume, store, op, auth, tmp_path):
    def link(p: Path, r: dict, d: FakeSigningDevice) -> None:  # type: ignore[type-arg]
        target = tmp_path / "elsewhere.json"
        target.write_bytes(p.read_bytes())
        p.unlink()
        p.symlink_to(target)

    assert _one_response(state, volume, store, op, auth, link)["code"] == "IntegrityError"

    def hard(p: Path, r: dict, d: FakeSigningDevice) -> None:  # type: ignore[type-arg]
        os.link(p, tmp_path / "second-link.json")

    for f in volume.rglob("*.json"):
        f.unlink()
    assert _one_response(state, volume, store, op, auth, hard)["code"] == "IntegrityError"


def test_symlinked_volume_directories_are_refused(state, volume, store, tmp_path):
    real = tmp_path / "real"
    (real / "from-signer").mkdir(parents=True)
    (volume / "sentinel-v1").symlink_to(real)
    with pytest.raises(IntegrityError):
        signing_protocol.receive_responses(volume, store, NOW)


def test_wrong_signature_form_for_the_key_role_is_refused(state, volume, store, op, auth):
    """An ECDSA response from a recovery key, or a WebAuthn response from an operator key."""
    new = FakeOperator.make(P256)
    signing_protocol.emit_request(_rotate_payload(auth, store, new), volume, store, NOW + 1)
    dev = FakeSigningDevice(volume)
    (req,) = dev.requests()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    sig = auth._key.sign(canonical.encode(req["payload"]), ec.ECDSA(hashes.SHA256()))
    dev.respond(
        req,
        {
            "envelope": "sentinel/v1/sign-response",
            "key_id": auth.public.key_id,
            "payload_sha256": req["payload_sha256"],
            "request_id": req["request_id"],
            "signature_der_b64": base64.b64encode(sig).decode(),
        },
    )
    (r,) = signing_protocol.receive_responses(volume, store, NOW + 2)
    assert r["status"] == "refused" and r["code"] == "wrong_key_role"


def test_too_many_responses_refuse_the_whole_receive(state, volume, store):
    d = volume / "sentinel-v1" / "from-signer"
    d.mkdir(parents=True)
    for i in range(17):
        (d / f"resp-{i:032x}.json").write_bytes(b"{}")
    with pytest.raises(BlockedError) as e:
        signing_protocol.receive_responses(volume, store, NOW)
    assert e.value.code == "too_many_responses"


# ── CLI ────────────────────────────────────────────────────────────────────
def test_cli_request_receive_and_use(home, capsys, tmp_path):  # noqa: F811
    from sentinel import cli

    from .test_trust_admin import enrol, f, run

    a, b = FakeOperator.make(P256), FakeOperator.make(P256)
    assert enrol(home, capsys, tmp_path, a)[0] == 0
    trust_fp = run(home, capsys, "key", "list")[1]["trust_fingerprint"]
    ap = a.approve(A.KEY_ROTATE, admin.key_subject(admin.CandidateKey(b.public)), f"trust:{trust_fp}")
    kf = {"key_id": b.public.key_id, "algorithm": P256, "public_hex": b.public.public_raw.hex()}
    code, _ = run(
        home,
        capsys,
        "key",
        "rotate",
        "--key",
        f(tmp_path, kf),
        "--approval",
        f(tmp_path, ap),
        "--operator",
        "b",
        "--expires-at",
        str(NOW + YEAR),
        "--trust-fingerprint",
        trust_fp,
    )
    assert code == 0
    trust_fp = run(home, capsys, "key", "list")[1]["trust_fingerprint"]
    vol = tmp_path / "XFER"
    vol.mkdir()
    payload = _revoke_payload(a.public.key_id, TrustStore(), b.public.key_id)
    code, out = run(
        home, capsys, "approval", "request", "--payload", f(tmp_path, payload), "--volume", str(vol)
    )
    assert code == 0 and out["role"] == "operator"
    dev = FakeSigningDevice(vol)
    (req,) = dev.requests()
    dev.sign_operator(req, a)
    code, out = run(home, capsys, "approval", "receive", "--volume", str(vol))
    assert code == 0 and out["responses"][0]["status"] == "received"
    code, out = run(
        home,
        capsys,
        "key",
        "revoke",
        "--key-id",
        b.public.key_id,
        "--approval",
        out["responses"][0]["approval"],
        "--trust-fingerprint",
        trust_fp,
    )
    assert code == 0, out
    hist = run(home, capsys, "history", "verify")[1]
    assert cli.EXIT_OK == 0 and hist


def test_cli_refuses_recovery_approvals_for_ordinary_actions(home, capsys, tmp_path):  # noqa: F811
    from sentinel import cli

    from .test_trust_admin import f, run

    auth = FakeRecoveryAuthenticator()
    rap = auth.approve(A.SUPPRESS, {"type": "finding", "fingerprint": "f" * 64}, "r")
    entry = {"x": 1}
    code, out = run(
        home,
        capsys,
        "suppress",
        "add",
        "--entry",
        f(tmp_path, entry),
        "--approval",
        f(tmp_path, rap.to_json()),
    )
    assert code == cli.EXIT_BLOCKED and out["code"] == "wrong_key_role"


def test_tampered_pending_record_is_an_integrity_error(state, volume, store, op, auth):
    out = signing_protocol.emit_request(
        _revoke_request(store, op.public.key_id, auth.public.key_id), volume, store, NOW + 1
    )
    p = signing_protocol.pending_dir() / f"{out['request_id']}.json"
    rec = canonical.decode_strict(p.read_bytes())
    rec["payload"]["rationale"] = "changed after emission"
    p.write_bytes(canonical.encode(rec))
    with pytest.raises(IntegrityError):
        signing_protocol.load_pending(out["request_id"])


def test_listing_never_shows_a_recovery_key_raw_signature_as_valid(store, auth):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from sentinel import cli

    payload = approvals.build_payload(
        action=A.SUPPRESS,
        subject={"type": "suppression_entry", "sha256": "a" * 64},
        revision="r",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="x",
    )
    sig = auth._key.sign(canonical.encode(payload), ec.ECDSA(hashes.SHA256()))
    assert cli._operator_signature_valid(store, approvals.Approval(payload, sig)) is False


# ── targeted kills: domain layers behind the schema, and receive-time checks ──
def test_domain_loader_refuses_permissions_outside_the_role_even_without_the_schema(store, op):
    from sentinel.keys.operator import _key_from_json

    entry = next(k for k in store._as_json()["keys"] if k["key_id"] == op.public.key_id)
    with pytest.raises(ValidationError, match="subset"):
        _key_from_json({**entry, "permitted_actions": ["authorize_record", "signer.release"]})


@pytest.mark.parametrize("change", [{"rp_id": "example.com"}, {"cose_alg": -8}])
def test_domain_loader_refuses_non_es256_recovery_entries_even_without_the_schema(store, change):
    from sentinel.keys.operator import _key_from_json

    entry = next(k for k in store._as_json()["keys"] if k["role"] == "recovery")
    with pytest.raises(ValidationError, match="ES256"):
        _key_from_json({**entry, **change})


def test_recovery_path_refuses_ordinary_actions_even_if_a_key_lists_them(ctx, auth):
    import dataclasses

    k = ctx.trust.get(auth.public.key_id)
    assert k is not None
    ctx.trust._keys[k.key_id] = dataclasses.replace(
        k, permitted_actions=("key.revoke", "key.rotate", "suppress")
    )
    payload = approvals.build_payload(
        action=A.SUPPRESS,
        subject={"type": "x"},
        revision="r",
        scope={},
        issued_at=NOW,
        lifetime=600,
        key_id=auth.public.key_id,
        rationale="x",
    )
    with pytest.raises(BlockedError) as e:
        recovery.verify(
            auth.assertion(payload),
            approvals.Expectation(A.SUPPRESS, {"type": "x"}, "r"),
            ctx.trust,
            ctx.ledger,
            NOW + 1,
            consume=False,
        )
    assert e.value.code == "action_not_permitted"


def test_recovery_path_enforces_the_key_permitted_actions(ctx, auth):
    import dataclasses

    k = ctx.trust.get(auth.public.key_id)
    assert k is not None
    ctx.trust._keys[k.key_id] = dataclasses.replace(k, permitted_actions=("key.revoke",))
    new = FakeOperator.make(P256)
    with pytest.raises(BlockedError) as e:
        _rotate(ctx, auth.assertion(_rotate_payload(auth, ctx.trust, new)), new)
    assert e.value.code == "action_not_permitted"


def test_first_key_must_be_an_operator_key(tmp_path, auth):
    ts = TrustStore(tmp_path / "empty.json")
    c = admin.AdminContext(
        ts, approvals.NonceLedger(tmp_path / "n.json"), Ed25519Signer.generate(), NOW + 1, tmp_path / "l"
    )
    cand = admin.parse_key_file(auth.key_file())
    ap = approvals.Approval(
        approvals.build_payload(
            action=A.KEY_ROTATE,
            subject=admin.key_subject(cand),
            revision=f"trust:{admin.EMPTY_TRUST_FINGERPRINT}",
            scope={},
            issued_at=NOW,
            lifetime=600,
            key_id=auth.public.key_id,
            rationale="x",
        ),
        b"\x30\x00",
    )
    with pytest.raises(BlockedError) as e:
        admin.enrol(c, cand, ap, operator="o", expires_at=NOW + YEAR)
    assert e.value.code == "action_not_permitted"


def test_enrolment_refuses_a_recovery_assertion(tmp_path, auth, op):
    ts = TrustStore(tmp_path / "empty.json")
    c = admin.AdminContext(
        ts, approvals.NonceLedger(tmp_path / "n.json"), Ed25519Signer.generate(), NOW + 1, tmp_path / "l"
    )
    cand = admin.CandidateKey(op.public)
    rap = auth.approve(A.KEY_ROTATE, admin.key_subject(cand), f"trust:{admin.EMPTY_TRUST_FINGERPRINT}")
    with pytest.raises(BlockedError) as e:
        admin.enrol(c, cand, rap, operator="o", expires_at=NOW + YEAR)
    assert e.value.code == "wrong_key_role"


def test_read_untrusted_refuses_by_size_before_reading(tmp_path):
    p = tmp_path / "r.json"
    p.write_bytes(b"x" * 3000)
    with pytest.raises(IntegrityError, match="size 3000"):
        signing_protocol.read_untrusted(p, 2048)
    p.write_bytes(b"")
    with pytest.raises(IntegrityError, match="size 0"):
        signing_protocol.read_untrusted(p, 2048)


def test_recovery_response_with_a_bad_assertion_is_refused_at_receive(state, volume, store, auth):
    new = FakeOperator.make(P256)
    signing_protocol.emit_request(_rotate_payload(auth, store, new), volume, store, NOW + 1)
    dev = FakeSigningDevice(volume)
    (req,) = dev.requests()
    good = auth.assertion(req["payload"]).webauthn_json()
    good["credential_id_b64"] = base64.b64encode(b"someone-else").decode()
    dev.respond(
        req,
        {
            "envelope": "sentinel/v1/sign-response",
            "key_id": auth.public.key_id,
            "payload_sha256": req["payload_sha256"],
            "request_id": req["request_id"],
            "webauthn": good,
        },
    )
    (r,) = signing_protocol.receive_responses(volume, store, NOW + 2)
    assert r["status"] == "refused" and r["code"] == "wrong_credential"


def test_cleanup_never_follows_a_symlinked_to_signer_directory(state, volume, store, op, auth, tmp_path):
    payload = _revoke_request(store, op.public.key_id, auth.public.key_id)
    out = signing_protocol.emit_request(payload, volume, store, NOW + 1)
    dev = FakeSigningDevice(volume)
    (req,) = dev.requests()
    to_signer = volume / "sentinel-v1" / "to-signer"
    elsewhere = tmp_path / "victim"
    elsewhere.mkdir()
    victim = elsewhere / f"req-{out['request_id']}.json"
    victim.write_text("keep me")
    (to_signer / f"req-{out['request_id']}.json").unlink()
    to_signer.rmdir()
    to_signer.symlink_to(elsewhere)
    dev.sign_operator(req, op)
    (r,) = signing_protocol.receive_responses(volume, store, NOW + 2)
    assert r["status"] == "received"
    assert victim.read_text() == "keep me"
