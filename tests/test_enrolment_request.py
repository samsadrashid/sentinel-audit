"""First enrolment over protocol v1 (ceremony steps 6-8): the engine emits and receives the self-signed
enrolment for a key it doesn't trust yet, checking the response against the candidate key recorded at
emission. `key enrol` still verifies the approval again, in full, before anything is trusted."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sentinel import admin, approvals, canonical, signing_protocol
from sentinel.crypto.signing import Ed25519Signer
from sentinel.domain.enums import ApprovalAction
from sentinel.errors import BlockedError
from sentinel.keys.operator import TrustStore


def new_key() -> tuple[ec.EllipticCurvePrivateKey, admin.CandidateKey]:
    k = ec.generate_private_key(ec.SECP256R1())
    x963 = k.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    from sentinel.crypto.signing import P256, PublicKey

    pub = PublicKey.from_raw(x963, P256)
    return k, admin.parse_key_file({"key_id": pub.key_id, "algorithm": P256, "public_hex": x963.hex()})


def enrol_payload(cand: admin.CandidateKey, signer: str | None = None) -> dict:  # type: ignore[type-arg]
    return approvals.build_payload(
        action=ApprovalAction.KEY_ROTATE,
        subject=admin.key_subject(cand),
        revision=f"trust:{admin.EMPTY_TRUST_FINGERPRINT}",
        scope={},
        issued_at=int(time.time()),
        lifetime=600,
        key_id=signer or cand.public.key_id,
        rationale="first enrolment",
    )


def respond(vol, emitted, payload, priv) -> None:  # type: ignore[no-untyped-def]
    sig = priv.sign(canonical.encode(payload), ec.ECDSA(hashes.SHA256()))
    body = {
        "envelope": "sentinel/v1/sign-response",
        "key_id": payload["key_id"],
        "payload_sha256": emitted["payload_sha256"],
        "request_id": emitted["request_id"],
        "signature_der_b64": base64.b64encode(sig).decode(),
    }
    out = vol / "sentinel-v1" / "from-signer"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"resp-{emitted['request_id']}.json").write_bytes(canonical.encode(body))


def test_enrolment_round_trip_then_key_enrol(tmp_path):
    priv, cand = new_key()
    trust = TrustStore(tmp_path / "trust.json")
    vol = tmp_path / "vol"
    vol.mkdir()
    p = enrol_payload(cand)
    with pytest.raises(BlockedError):
        signing_protocol.emit_request(p, vol, trust, int(time.time()))  # not trusted, no enrolment key
    emitted = signing_protocol.emit_request(p, vol, trust, int(time.time()), enrol_key=cand)
    respond(vol, emitted, p, priv)
    res = signing_protocol.receive_responses(vol, trust, int(time.time()))
    assert [r["status"] for r in res] == ["received"], res
    ap = approvals.Approval.from_json(json.loads(open(res[0]["approval"], "rb").read()))
    ctx = admin.AdminContext(
        trust, approvals.NonceLedger(tmp_path / "n.json"), Ed25519Signer.generate(), int(time.time())
    )
    admin.enrol(ctx, cand, ap, operator="owner", expires_at=int(time.time()) + 86400)
    assert trust.get(cand.public.key_id) is not None


def test_enrolment_response_by_another_key_is_refused(tmp_path):
    _, cand = new_key()
    other, _ = new_key()
    trust = TrustStore(tmp_path / "trust.json")
    vol = tmp_path / "vol"
    vol.mkdir()
    p = enrol_payload(cand)
    emitted = signing_protocol.emit_request(p, vol, trust, int(time.time()), enrol_key=cand)
    respond(vol, emitted, p, other)
    res = signing_protocol.receive_responses(vol, trust, int(time.time()))
    assert res[0]["status"] == "refused" and res[0]["code"] == "bad_signature"


@pytest.mark.parametrize(
    "case", ["wrong_signer", "wrong_revision", "wrong_subject", "recovery_role", "trust_initialised"]
)
def test_only_the_keys_own_first_enrolment_may_be_emitted(tmp_path, case):
    _, cand = new_key()
    _, other = new_key()
    trust = TrustStore(tmp_path / "trust.json")
    vol = tmp_path / "vol"
    vol.mkdir()
    p = enrol_payload(cand)
    key = cand
    if case == "wrong_signer":
        p = enrol_payload(cand, signer=other.public.key_id)
    elif case == "wrong_revision":
        p = {**p, "revision": "trust:" + "0" * 64}
    elif case == "wrong_subject":
        p = {**p, "subject": admin.key_subject(other)}
    elif case == "recovery_role":
        key = admin.CandidateKey(cand.public, "recovery")
    else:
        from sentinel.keys.operator import OperatorKey

        trust.enrol(OperatorKey(other.public.key_id, "x", other.public, "active", int(time.time()) + 86400))
    with pytest.raises(BlockedError):
        signing_protocol.emit_request(p, vol, trust, int(time.time()), enrol_key=key)
    assert not (vol / "sentinel-v1" / "to-signer").exists() or not list(
        (vol / "sentinel-v1" / "to-signer").iterdir()
    )


def test_receive_rechecks_the_trust_store_is_still_empty(tmp_path):
    priv, cand = new_key()
    _, other = new_key()
    trust = TrustStore(tmp_path / "trust.json")
    vol = tmp_path / "vol"
    vol.mkdir()
    p = enrol_payload(cand)
    emitted = signing_protocol.emit_request(p, vol, trust, int(time.time()), enrol_key=cand)
    from sentinel.keys.operator import OperatorKey

    trust.enrol(OperatorKey(other.public.key_id, "x", other.public, "active", int(time.time()) + 86400))
    respond(vol, emitted, p, priv)
    res = signing_protocol.receive_responses(vol, trust, int(time.time()))
    assert res[0]["status"] == "refused" and res[0]["code"] == "enrol_after_init"
