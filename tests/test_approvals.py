"""Canonical approval payloads (D-33), nonce semantics (D-36), expiry (D-37), algorithm agility (D-38)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel import approvals
from sentinel.crypto.signing import P256, Ed25519Signer
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import BlockedError, ValidationError
from sentinel.keys.operator import OperatorKey, TrustStore

from .conftest import NOW, FakeOperator, resign

SUBJ = {"type": "finding", "fingerprint": "f" * 64}
REV = "commit:abc123"


def exp(action=A.SUPPRESS, subject=SUBJ, revision=REV, scope=None):
    return approvals.Expectation(action=action, subject=subject, revision=revision, required_scope=scope)


def test_valid_standing_approval(operator, trust, ledger):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV)
    approvals.verify(ap, exp(), trust, ledger, NOW + 10, consume=True)


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("context", "sentinel/v1/approval/policy.change", "wrong_context"),
        ("action", "policy.change", "wrong_context"),
        ("subject", {"type": "finding", "fingerprint": "0" * 64}, "wrong_subject"),
        ("revision", "commit:other", "wrong_revision"),
    ],
)
def test_semantic_mismatches_blocked(operator, trust, ledger, field, value, code):
    ap = resign(operator.approve(A.SUPPRESS, SUBJ, REV), operator, **{field: value})
    with pytest.raises(BlockedError) as e:
        approvals.verify(ap, exp(), trust, ledger, NOW + 10, consume=True)
    assert e.value.code == code


def test_altered_payload_fails_signature(operator, trust, ledger):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV)
    altered = approvals.Approval({**ap.payload, "rationale": "changed"}, ap.signature)
    with pytest.raises(BlockedError) as e:
        approvals.verify(altered, exp(), trust, ledger, NOW + 10, consume=True)
    assert e.value.code == "bad_signature"


def test_cross_action_reuse_rejected(operator, trust, ledger):
    """An approval for one action never authorises another."""
    ap = operator.approve(A.SUPPRESS, SUBJ, REV)
    with pytest.raises(BlockedError):
        approvals.verify(ap, exp(action=A.REVIEW_ACCEPT_RISK), trust, ledger, NOW + 10, consume=True)


def test_expiry_boundary_and_future_issue(operator, trust, ledger):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV, lifetime=100)
    approvals.verify(ap, exp(), trust, ledger, NOW + 99, consume=False)
    with pytest.raises(BlockedError, match="expired"):
        approvals.verify(ap, exp(), trust, ledger, NOW + 100, consume=False)
    fut = operator.approve(A.SUPPRESS, SUBJ, REV, issued_at=NOW + 10_000)
    with pytest.raises(BlockedError) as e:
        approvals.verify(fut, exp(), trust, ledger, NOW, consume=False)
    assert e.value.code == "future_issue"


@pytest.mark.parametrize(
    "action,limit",
    [
        (A.REVOKE_RECORD, 3600),
        (A.KEY_ROTATE, 3600),
        (A.KEY_REVOKE, 3600),
        (A.REVIEW_VERIFY_NO_EVIDENCE, 90 * 86400),
        (A.REVIEW_ACCEPT_RISK, 90 * 86400),
        (A.SUPPRESS, 90 * 86400),
        (A.POLICY_CHANGE, 90 * 86400),
    ],
)
def test_d37_maximum_expiry(operator, action, limit):
    operator.approve(action, SUBJ, REV, lifetime=limit)
    with pytest.raises(BlockedError) as e:
        operator.approve(action, SUBJ, REV, lifetime=limit + 1)
    assert e.value.code == "expiry_too_long"


def test_authorization_expiry_by_environment(operator):
    local = {"assets": [{"environment": "local"}]}
    prod = {"assets": [{"environment": "production"}]}
    operator.approve(A.AUTHORIZE_RECORD, SUBJ, REV, scope=local, lifetime=30 * 86400)
    operator.approve(A.AUTHORIZE_RECORD, SUBJ, REV, scope=prod, lifetime=24 * 3600)
    with pytest.raises(BlockedError):
        operator.approve(A.AUTHORIZE_RECORD, SUBJ, REV, scope=prod, lifetime=24 * 3600 + 1)
    mixed = {"assets": [{"environment": "local"}, {"environment": "production"}]}
    with pytest.raises(BlockedError):  # mixed scope takes the strictest (production) limit
        operator.approve(A.AUTHORIZE_RECORD, SUBJ, REV, scope=mixed, lifetime=2 * 86400)


def test_over_maximum_lifetime_rejected_at_verify_even_if_signed(operator, trust, ledger):
    ap = resign(operator.approve(A.SUPPRESS, SUBJ, REV), operator, expires_at=NOW + 91 * 86400)
    with pytest.raises(BlockedError) as e:
        approvals.verify(ap, exp(), trust, ledger, NOW + 1, consume=False)
    assert e.value.code == "expiry_too_long"


def test_one_time_nonce_consumed(operator, trust, ledger):
    subj = {"type": "approval", "sha256": "a" * 64}
    ap = operator.approve(A.KEY_REVOKE, subj, REV)
    approvals.verify(ap, exp(A.KEY_REVOKE, subj), trust, ledger, NOW + 1, consume=True)
    with pytest.raises(BlockedError) as e:
        approvals.verify(ap, exp(A.KEY_REVOKE, subj), trust, ledger, NOW + 2, consume=True)
    assert e.value.code == "nonce_reused"


def test_standing_reverification_does_not_consume_extend_or_widen(operator, trust, ledger):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV, lifetime=500)
    for t in (1, 2, 3):
        approvals.verify(ap, exp(), trust, ledger, NOW + t, consume=True)
    entry = ledger.entries[ap.payload["nonce"]]
    assert entry["expires_at"] == NOW + 500 and entry["payload_hash"] == ap.payload_hash
    assert ap.payload["scope"] == {}
    with pytest.raises(BlockedError):  # repeated verification never extends expiry
        approvals.verify(ap, exp(), trust, ledger, NOW + 500, consume=True)


def test_changed_payload_with_registered_nonce_rejected(operator, trust, ledger):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV)
    approvals.verify(ap, exp(), trust, ledger, NOW + 1, consume=True)
    other = resign(ap, operator, rationale="different payload, same nonce")
    with pytest.raises(BlockedError) as e:
        approvals.verify(other, exp(), trust, ledger, NOW + 2, consume=True)
    assert e.value.code == "nonce_rebound"


def test_scope_coverage(operator, trust, ledger):
    scope = {"assets": [{"id": "a"}], "operations": ["read"]}
    ap = operator.approve(A.POLICY_CHANGE, SUBJ, REV, scope=scope)
    e = exp(A.POLICY_CHANGE, scope={"operations": ["read"]})
    approvals.verify(ap, e, trust, ledger, NOW + 1, consume=False)
    with pytest.raises(BlockedError) as err:
        approvals.verify(
            ap,
            exp(A.POLICY_CHANGE, scope={"operations": ["write"]}),
            trust,
            ledger,
            NOW + 1,
            consume=False,
        )
    assert err.value.code == "out_of_scope"


def test_revocation_of_standing_approval(operator, trust, ledger):
    target = operator.approve(A.SUPPRESS, SUBJ, REV)
    approvals.verify(target, exp(), trust, ledger, NOW + 1, consume=True)
    rev = operator.approve(
        A.REVOKE_RECORD, {"type": "approval", "sha256": target.payload_hash}, target.payload["revision"]
    )
    approvals.apply_revocation(rev, target, trust, ledger, NOW + 2)
    with pytest.raises(BlockedError) as e:
        approvals.verify(target, exp(), trust, ledger, NOW + 3, consume=False)
    assert e.value.code == "revoked"
    reloaded = approvals.NonceLedger(ledger.path)  # persisted
    assert target.payload_hash in reloaded.revoked
    with pytest.raises(BlockedError):  # the revocation is itself one-time
        approvals.apply_revocation(rev, target, trust, ledger, NOW + 4)


def test_one_time_actions_cannot_be_revoked(operator, trust, ledger):
    target = operator.approve(A.KEY_ROTATE, SUBJ, REV)
    rev = operator.approve(
        A.REVOKE_RECORD, {"type": "approval", "sha256": target.payload_hash}, target.payload["revision"]
    )
    with pytest.raises(BlockedError):
        approvals.apply_revocation(rev, target, trust, ledger, NOW + 1)


def test_unknown_revoked_and_run_keys_authorise_nothing(operator, trust, ledger):
    run_key = Ed25519Signer.generate()  # not in the operator trust store
    payload = approvals.build_payload(
        action=A.SUPPRESS,
        subject=SUBJ,
        revision=REV,
        scope={},
        issued_at=NOW,
        lifetime=60,
        key_id=run_key.key_id,
        rationale="r",
    )
    forged = approvals.Approval(payload, run_key.sign(approvals.canonical.encode(payload)))
    with pytest.raises(BlockedError) as e:
        approvals.verify(forged, exp(), trust, ledger, NOW + 1, consume=False)
    assert e.value.code == "unknown_key"
    trust.apply_revocation(operator.public.key_id)
    with pytest.raises(BlockedError) as e:
        approvals.verify(
            operator.approve(A.SUPPRESS, SUBJ, REV), exp(), trust, ledger, NOW + 1, consume=False
        )
    assert e.value.code == "revoked_key"


def test_p256_operator_key_is_accepted(tmp_path: Path, ledger):
    """D-38: Secure Enclave-style P-256 operator keys verify through the same path."""
    o = FakeOperator.make(P256)
    ts = TrustStore(tmp_path / "p.json")
    ts.enrol(OperatorKey(o.public.key_id, "owner", o.public, "active", NOW + 10_000))
    ap = o.approve(A.SUPPRESS, SUBJ, REV)
    approvals.verify(ap, exp(), ts, ledger, NOW + 1, consume=True)
    bad = approvals.Approval({**ap.payload, "rationale": "x"}, ap.signature)
    with pytest.raises(BlockedError):
        approvals.verify(bad, exp(), ts, ledger, NOW + 1, consume=False)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["payload"].pop("nonce"),
        lambda d: d["payload"].update(extra=1),
        lambda d: d["payload"].update(issued_at="now"),
        lambda d: d["payload"].update(issued_at=True),
        lambda d: d["payload"].update(nonce="zz"),
        lambda d: d["payload"].update(scope={"x": 1.5}),
        lambda d: d.update(signature="***"),
        lambda d: d.update(signature=5),
        lambda d: d.update(extra=1),
    ],
)
def test_malformed_approval_files_rejected(operator, mutate):
    data = operator.approve(A.SUPPRESS, SUBJ, REV).to_json()
    mutate(data)
    with pytest.raises(ValidationError):
        approvals.Approval.from_json(data)


def test_approval_file_roundtrip(operator, tmp_path: Path):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV)
    approvals.save_approval_file(tmp_path / "a.json", ap)
    assert approvals.load_approval_file(tmp_path / "a.json") == ap


def test_display_text_shows_exact_payload_and_hash(operator):
    ap = operator.approve(A.SUPPRESS, SUBJ, REV)
    text = approvals.display_text(ap.payload)
    assert ap.payload["nonce"] in text and ap.payload_hash in text


def test_known_limitation_ledger_rollback_replays_until_expiry(operator, trust, ledger):
    """D-34/D-36 residual risk, demonstrated: deleting the ledger re-enables a one-time approval,
    but only until its expiry. Sentinel claims no protection beyond that boundary."""
    subj = {"type": "approval", "sha256": "b" * 64}
    ap = operator.approve(A.KEY_REVOKE, subj, REV, lifetime=600)
    approvals.verify(ap, exp(A.KEY_REVOKE, subj), trust, ledger, NOW + 1, consume=True)
    ledger.path.unlink()  # same-user rollback
    rolled_back = approvals.NonceLedger(ledger.path)
    approvals.verify(
        ap, exp(A.KEY_REVOKE, subj), trust, rolled_back, NOW + 2, consume=True
    )  # replay accepted
    with pytest.raises(BlockedError):
        approvals.verify(
            ap,
            exp(A.KEY_REVOKE, subj),
            trust,
            approvals.NonceLedger(Path(str(ledger.path) + ".x")),
            NOW + 600,
            consume=True,
        )  # expiry still bounds it


# ── D-42: `allowlist.change` is removed and rejected everywhere ───────────
#: D-74: `release.publish` has a strict payload shape (subject, revision and scope), so the generic
#: placeholders above don't apply to it.
_RELEASE_FIELDS = {
    "subject": {"type": "release", "name": "sentinel-audit", "version": "1.0", "commit": "0" * 40},
    "revision": "sums:" + "0" * 64,
    "scope": {"artifacts": [{"name": "sentinel_audit-1.0-py3-none-any.whl", "sha256": "0" * 64}]},
}


def _raw_signed(operator, action: str, context: str | None = None) -> dict:
    """A correctly signed payload with an arbitrary action string (bypasses build_payload)."""
    payload = {
        "context": context or f"sentinel/v1/approval/{action}",
        "action": action,
        "subject": SUBJ,
        "revision": REV,
        "scope": {},
        **(_RELEASE_FIELDS if action == "release.publish" else {}),
        "issued_at": NOW,
        "expires_at": NOW + 3600,
        "nonce": "ab" * 16,
        "key_id": operator.public.key_id,
        "rationale": "allowlist change attempt",
    }
    sig = operator.sign(approvals.canonical.encode(payload))
    import base64

    return {"payload": payload, "signature": base64.b64encode(sig).decode()}


def test_allowlist_change_is_not_an_action():
    assert "allowlist.change" not in {a.value for a in A}
    assert set(approvals.MAX_EXPIRY) == {
        "authorize_record:local",
        "authorize_record:staging",
        "authorize_record:production",
        A.REVOKE_RECORD,
        A.KEY_ROTATE,
        A.KEY_REVOKE,
        A.REVIEW_VERIFY_NO_EVIDENCE,
        A.REVIEW_ACCEPT_RISK,
        A.SUPPRESS,
        A.POLICY_CHANGE,
        A.RELEASE_PUBLISH,  # D-74
    }


def test_signed_allowlist_change_rejected_when_loading(operator, tmp_path):
    data = _raw_signed(operator, "allowlist.change")
    with pytest.raises(ValidationError, match="unknown approval action"):
        approvals.Approval.from_json(data)
    p = tmp_path / "ap.json"
    import json

    p.write_text(json.dumps(data))
    with pytest.raises(ValidationError, match="unknown approval action"):
        approvals.load_approval_file(p)


@pytest.mark.parametrize("expected", list(A))
def test_signed_allowlist_change_never_verifies_as_any_action(operator, trust, ledger, expected):
    data = _raw_signed(operator, "allowlist.change")
    ap = approvals.Approval(data["payload"], __import__("base64").b64decode(data["signature"]))
    with pytest.raises(BlockedError) as e:
        approvals.verify(ap, exp(expected), trust, ledger, NOW + 1, consume=False)
    assert e.value.code == "wrong_context"


def test_known_action_with_foreign_context_rejected_when_loading(operator):
    data = _raw_signed(operator, "policy.change", context="sentinel/v1/approval/allowlist.change")
    with pytest.raises(ValidationError, match="context does not match"):
        approvals.Approval.from_json(data)


@pytest.mark.parametrize("action", [a.value for a in A])
def test_every_defined_action_still_loads(operator, action):
    approvals.Approval.from_json(_raw_signed(operator, action))
