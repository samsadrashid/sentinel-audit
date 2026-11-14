"""Secure Enclave integration boundary, tested with FAKE backends only.

These tests prove the Python trust logic. They do NOT prove hardware-backed user presence: the fake
backend holds a software key and declares genuine_hardware=False. Hardware tests H1-H11 in
docs/m1/se-helper-contract.md are still outstanding.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sentinel import approvals, canonical
from sentinel.crypto.signing import ED25519, P256, PublicKey, key_id_for
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import BlockedError, CapabilityUnavailable, ValidationError
from sentinel.keys import operator as op_mod
from sentinel.keys.operator import TrustStore
from sentinel.keys.secure_enclave import (
    BACKEND_NAME,
    KeyMetadataStore,
    SecureEnclaveKeyMetadata,
    SecureEnclaveProvider,
    production_provider,
    register_key,
    revoke_key,
    rotate_key,
    sign_payload,
)

from .conftest import NOW

SUBJ = {"type": "finding", "fingerprint": "f" * 64}


class FakeBackend:
    """TEST ONLY. Software key standing in for the Secure Enclave. Never genuine hardware."""

    genuine_hardware = False

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public = self.key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.key_id = key_id_for(P256, self.public)
        self.calls = 0
        self.mode = "ok"
        self.last_message: bytes | None = None

    def meta(self) -> SecureEnclaveKeyMetadata:
        return SecureEnclaveKeyMetadata.from_json(
            {
                "key_id": self.key_id,
                "algorithm": P256,
                "public_x963_hex": self.public.hex(),
                "handle_b64": base64.b64encode(b"opaque-handle").decode(),
                "backend": BACKEND_NAME,
                "created_at": NOW,
            }
        )

    def sign(self, handle: bytes, message: bytes, reason: str, timeout_s: int) -> dict[str, Any]:
        self.calls += 1
        self.last_message = message
        digest = canonical.sha256_hex(message)
        assert digest[:16] in reason  # the prompt reason carries the helper-side digest
        sig = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        ok = {
            "signature_der_b64": base64.b64encode(sig).decode(),
            "message_sha256": digest,
            "key_id": self.key_id,
        }
        m = self.mode
        if m == "ok":
            return ok
        if m in ("cancelled", "timeout", "auth_failed", "no_secure_enclave", "not_interactive"):
            return {"error": m, "message": "x"}
        if m == "unknown_error":
            return {"error": "weird", "message": "x"}
        if m == "error_extra":
            return {"error": "cancelled", "message": "x", "signature_der_b64": ok["signature_der_b64"]}
        if m == "extra_key":
            return {**ok, "debug": 1}
        if m == "missing_key":
            return {k: v for k, v in ok.items() if k != "message_sha256"}
        if m == "not_dict":
            return ["nope"]  # type: ignore[return-value]
        if m == "wrong_digest":
            return {**ok, "message_sha256": "0" * 64}
        if m == "wrong_key_id":
            return {**ok, "key_id": "p256:" + "1" * 32}
        if m == "bad_b64":
            return {**ok, "signature_der_b64": "***"}
        if m == "other_message":  # signs different bytes but reports the right digest
            other = self.key.sign(message + b"x", ec.ECDSA(hashes.SHA256()))
            return {**ok, "signature_der_b64": base64.b64encode(other).decode()}
        if m == "other_key":
            k2 = ec.generate_private_key(ec.SECP256R1())
            return {
                **ok,
                "signature_der_b64": base64.b64encode(k2.sign(message, ec.ECDSA(hashes.SHA256()))).decode(),
            }
        if m == "oversized_sig":
            return {**ok, "signature_der_b64": base64.b64encode(b"\x30" * 200).decode()}
        raise AssertionError(m)


@pytest.fixture
def be() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def se_trust(tmp_path: Path, be: FakeBackend) -> TrustStore:
    ts = TrustStore(tmp_path / "trust.json")
    register_key(be.meta(), ts, KeyMetadataStore(tmp_path / "meta"), operator="owner", expires_at=NOW + 10**6)
    return ts


def provider(be, trust, interactive=True) -> SecureEnclaveProvider:
    return SecureEnclaveProvider(
        be.meta(), trust, be, now=lambda: NOW, interactive=lambda: interactive, allow_test_backend=True
    )


def payload(key_id: str, action=A.SUPPRESS, subject=SUBJ, revision="commit:a", lifetime=3600):
    return approvals.build_payload(
        action=action,
        subject=subject,
        revision=revision,
        scope={},
        issued_at=NOW,
        lifetime=lifetime,
        key_id=key_id,
        rationale="test",
    )


def expect(action=A.SUPPRESS, subject=SUBJ, revision="commit:a"):
    return approvals.Expectation(action=action, subject=subject, revision=revision)


# ── success and exact payload binding ──────────────────────────────────────
def test_valid_signature_verifies_through_approval_checks(be, se_trust, ledger):
    shown: list[str] = []
    ap = sign_payload(provider(be, se_trust), payload(be.key_id), shown.append)
    assert be.last_message == canonical.encode(ap.payload)  # exactly the bytes shown were signed
    assert ap.payload_hash in shown[0] and ap.payload["nonce"] in shown[0]
    approvals.verify(ap, expect(), se_trust, ledger, NOW + 1, consume=True)


def test_altered_payload_after_signing_rejected(be, se_trust, ledger):
    ap = sign_payload(provider(be, se_trust), payload(be.key_id), lambda _t: None)
    altered = approvals.Approval({**ap.payload, "scope": {"assets": ["everything"]}}, ap.signature)
    with pytest.raises(BlockedError) as e:
        approvals.verify(altered, expect(), se_trust, ledger, NOW + 1, consume=False)
    assert e.value.code == "bad_signature"


def test_expired_and_wrongly_scoped_approvals_rejected(be, se_trust, ledger):
    ap = sign_payload(provider(be, se_trust), payload(be.key_id, lifetime=60), lambda _t: None)
    with pytest.raises(BlockedError, match="expired"):
        approvals.verify(ap, expect(), se_trust, ledger, NOW + 60, consume=False)
    with pytest.raises(BlockedError):
        approvals.verify(ap, expect(action=A.REVIEW_ACCEPT_RISK), se_trust, ledger, NOW + 1, consume=False)
    with pytest.raises(BlockedError):
        approvals.verify(ap, expect(revision="commit:b"), se_trust, ledger, NOW + 1, consume=False)


def test_each_approval_needs_a_fresh_signing_operation(be, se_trust):
    p = provider(be, se_trust)
    a1 = sign_payload(p, payload(be.key_id), lambda _t: None)
    a2 = sign_payload(p, payload(be.key_id), lambda _t: None)
    assert be.calls == 2 and a1.payload["nonce"] != a2.payload["nonce"]


def test_payload_for_another_key_refused_before_prompt(be, se_trust):
    with pytest.raises(BlockedError) as e:
        sign_payload(provider(be, se_trust), payload("p256:" + "2" * 32), lambda _t: None)
    assert e.value.code == "key_mismatch" and be.calls == 0


# ── provider response is never trusted on its own ─────────────────────────
@pytest.mark.parametrize(
    "mode,code",
    [
        ("wrong_digest", "payload_mismatch"),
        ("wrong_key_id", "key_mismatch"),
        ("other_message", "bad_signature"),
        ("other_key", "bad_signature"),
        ("oversized_sig", "bad_signature"),
        ("bad_b64", "backend_malformed"),
        ("extra_key", "backend_malformed"),
        ("missing_key", "backend_malformed"),
        ("not_dict", "backend_malformed"),
        ("unknown_error", "backend_malformed"),
        ("error_extra", "backend_malformed"),
    ],
)
def test_malformed_or_lying_backend_blocked(be, se_trust, mode, code):
    be.mode = mode
    with pytest.raises(BlockedError) as e:
        provider(be, se_trust).sign_with_presence(b"m", "m")
    assert e.value.code == code


@pytest.mark.parametrize(
    "mode", ["cancelled", "timeout", "auth_failed", "no_secure_enclave", "not_interactive"]
)
def test_cancellation_timeout_and_unavailability_fail_closed(be, se_trust, mode):
    be.mode = mode
    with pytest.raises(BlockedError) as e:
        provider(be, se_trust).sign_with_presence(b"m", "m")
    assert e.value.code == f"presence_{mode}"


def test_non_interactive_caller_refused_before_backend(be, se_trust):
    with pytest.raises(CapabilityUnavailable):
        provider(be, se_trust, interactive=False).sign_with_presence(b"m", "m")
    assert be.calls == 0


# ── key identity and status ────────────────────────────────────────────────
def test_unknown_revoked_and_expired_keys_rejected(tmp_path, be):
    ts = TrustStore(tmp_path / "t.json")
    with pytest.raises(BlockedError, match="unknown"):
        provider(be, ts).sign_with_presence(b"m", "m")
    register_key(be.meta(), ts, KeyMetadataStore(tmp_path / "m"), operator="o", expires_at=NOW + 1)
    ts.apply_revocation(be.key_id)
    with pytest.raises(BlockedError, match="revoked"):
        provider(be, ts).sign_with_presence(b"m", "m")
    assert be.calls == 0


def test_trust_store_public_key_must_match_metadata(tmp_path, be):
    other = FakeBackend()
    ts = TrustStore(tmp_path / "t.json")
    # same key id is impossible for a different public key; simulate a swapped trust entry
    register_key(other.meta(), ts, KeyMetadataStore(tmp_path / "m"), operator="o", expires_at=NOW + 100)
    meta = SecureEnclaveKeyMetadata(other.key_id, P256, be.public, b"h", BACKEND_NAME, NOW)
    be.key_id = other.key_id  # backend claims the registered id; only the pre-check can catch this
    p = SecureEnclaveProvider(
        meta, ts, be, now=lambda: NOW, interactive=lambda: True, allow_test_backend=True
    )
    with pytest.raises(BlockedError) as e:
        p.sign_with_presence(b"m", "m")
    assert e.value.code == "key_mismatch"
    assert be.calls == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(algorithm=ED25519),
        lambda d: d.update(key_id="p256:" + "3" * 32),
        lambda d: d.update(public_x963_hex="04" + "00" * 64),
        lambda d: d.update(handle_b64=""),
        lambda d: d.update(handle_b64="***"),
        lambda d: d.update(backend="software"),
        lambda d: d.update(created_at="now"),
        lambda d: d.update(extra=1),
        lambda d: d.update(handle_b64=base64.b64encode(b"x" * 5000).decode()),
    ],
)
def test_malformed_or_mismatched_metadata_rejected(be, mutate):
    d = be.meta().to_json()
    mutate(d)
    with pytest.raises(ValidationError):
        SecureEnclaveKeyMetadata.from_json(d)


def test_metadata_store_roundtrip_and_bad_ids(tmp_path, be):
    store = KeyMetadataStore(tmp_path)
    store.save(be.meta())
    assert store.load(be.key_id) == be.meta()
    with pytest.raises(BlockedError):
        store.load("p256:" + "4" * 32)
    for bad in ("../x", "ed25519:" + "0" * 32, "p256:ZZ"):
        with pytest.raises(ValidationError):
            store.load(bad)


# ── no software fallback ───────────────────────────────────────────────────
def test_fake_backend_refused_without_explicit_test_flag(be, se_trust):
    with pytest.raises(CapabilityUnavailable, match="non-hardware"):
        SecureEnclaveProvider(be.meta(), se_trust, be, now=lambda: NOW)
    assert provider(be, se_trust).hardware_backed is False


def test_production_paths_fail_closed():
    with pytest.raises(CapabilityUnavailable, match="not activated"):
        production_provider()
    with pytest.raises(CapabilityUnavailable):
        op_mod.available_provider()


# ── rotation and revocation through approvals ─────────────────────────────
def test_rotation_requires_approval_from_active_key(tmp_path, be, se_trust, ledger):
    store = KeyMetadataStore(tmp_path / "meta2")
    new = FakeBackend()
    subj = {"type": "operator_key", "key_id": new.key_id, "public_sha256": canonical.sha256_hex(new.public)}
    rev = f"trust:{se_trust.fingerprint()}"
    ap = sign_payload(provider(be, se_trust), payload(be.key_id, A.KEY_ROTATE, subj, rev), lambda _t: None)
    rotate_key(ap, new.meta(), se_trust, store, ledger, NOW + 1, operator="owner", expires_at=NOW + 10**6)
    assert se_trust.usable(new.key_id, NOW + 2).public.algorithm == P256
    sign_payload(provider(new, se_trust), payload(new.key_id), lambda _t: None)  # new key works
    with pytest.raises(BlockedError):  # one-time approval can't be replayed
        rotate_key(ap, new.meta(), se_trust, store, ledger, NOW + 3, operator="owner", expires_at=NOW + 10**6)


def test_rotation_approval_bound_to_new_key_and_trust_state(tmp_path, be, se_trust, ledger):
    store = KeyMetadataStore(tmp_path / "meta2")
    new, attacker = FakeBackend(), FakeBackend()
    subj = {"type": "operator_key", "key_id": new.key_id, "public_sha256": canonical.sha256_hex(new.public)}
    ap = sign_payload(
        provider(be, se_trust),
        payload(be.key_id, A.KEY_ROTATE, subj, f"trust:{se_trust.fingerprint()}"),
        lambda _t: None,
    )
    with pytest.raises(BlockedError):  # approval for one key can't enrol another
        rotate_key(ap, attacker.meta(), se_trust, store, ledger, NOW + 1, operator="x", expires_at=NOW + 10)
    stale = sign_payload(
        provider(be, se_trust), payload(be.key_id, A.KEY_ROTATE, subj, "trust:" + "0" * 64), lambda _t: None
    )
    with pytest.raises(BlockedError):  # approval made against a different trust state
        rotate_key(stale, new.meta(), se_trust, store, ledger, NOW + 1, operator="x", expires_at=NOW + 10)


def test_revocation_blocks_future_signing_and_verification(tmp_path, be, se_trust, ledger):
    good = sign_payload(provider(be, se_trust), payload(be.key_id), lambda _t: None)
    rv = sign_payload(
        provider(be, se_trust),
        payload(
            be.key_id,
            A.KEY_REVOKE,
            {"type": "operator_key", "key_id": be.key_id},
            f"trust:{se_trust.fingerprint()}",
        ),
        lambda _t: None,
    )
    revoke_key(rv, be.key_id, se_trust, ledger, NOW + 1)
    with pytest.raises(BlockedError, match="revoked"):
        provider(be, se_trust).sign_with_presence(b"m", "m")
    with pytest.raises(BlockedError):
        approvals.verify(good, expect(), se_trust, ledger, NOW + 2, consume=False)
    with pytest.raises(BlockedError, match="unknown"):
        revoke_key(rv, "p256:" + "5" * 32, se_trust, ledger, NOW + 3)


def test_run_key_cannot_act_as_operator_key(tmp_path, se_trust, ledger):
    from sentinel.crypto.signing import Ed25519Signer

    run = Ed25519Signer.generate()
    p = payload(run.key_id)
    forged = approvals.Approval(p, run.sign(canonical.encode(p)))
    with pytest.raises(BlockedError) as e:
        approvals.verify(forged, expect(), se_trust, ledger, NOW + 1, consume=False)
    assert e.value.code == "unknown_key"
    assert PublicKey.from_raw(run.public.public_raw, ED25519).algorithm == ED25519
