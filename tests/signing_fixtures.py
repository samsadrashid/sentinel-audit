"""TEST-ONLY signing fixtures (D-49 item 5).

Software stand-ins for the dedicated signing device and the FIDO2 recovery authenticator, so the
engine-side enforcement (D-45 permissions, the D-47 recovery verifier, the protocol-v1 envelopes) can be
tested automatically. They hold software private keys and **prove nothing about hardware, Secure
Enclave access control, biometry or user presence**. AC-11 evidence produced with them is engine-side
enforcement evidence only (D-49). They live under tests/ and are never imported by the engine.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sentinel import approvals, canonical, recovery
from sentinel.crypto.signing import P256, PublicKey
from sentinel.domain.enums import ApprovalAction
from sentinel.keys.operator import RECOVERY_RP_ID

from .conftest import NOW


@dataclass
class FakeRecoveryAuthenticator:
    """Software FIDO2 ES256 authenticator producing WebAuthn assertions (TEST ONLY)."""

    rp_id: str = RECOVERY_RP_ID
    counter: int | None = 0  # None: zero-counter authenticator; else incremented before each assertion
    credential_id: bytes = field(default_factory=lambda: hashlib.sha256(b"test-credential").digest())
    _key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))

    @property
    def public(self) -> PublicKey:
        raw = self._key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return PublicKey.from_raw(raw, P256)

    def key_file(self) -> dict[str, Any]:
        return {
            "key_id": self.public.key_id,
            "algorithm": P256,
            "public_hex": self.public.public_raw.hex(),
            "role": "recovery",
            "credential_id_b64": base64.b64encode(self.credential_id).decode(),
            "rp_id": RECOVERY_RP_ID,
            "cose_alg": -7,
        }

    def assertion(
        self,
        payload: dict[str, Any],
        *,
        flags: int = recovery.FLAG_UP | recovery.FLAG_UV,
        client_data: dict[str, Any] | None = None,
        client_data_raw: bytes | None = None,
        rp_id_for_hash: str | None = None,
        count: int | None = None,
        extra_auth: bytes = b"",
        credential_id: bytes | None = None,
    ) -> recovery.RecoveryApproval:
        if count is None:
            if self.counter is None:
                count = 0
            else:
                self.counter += 1
                count = self.counter
        auth = (
            hashlib.sha256((rp_id_for_hash or self.rp_id).encode()).digest()
            + bytes([flags])
            + struct.pack(">I", count)
            + extra_auth
        )
        cd = client_data or {
            "type": "webauthn.get",
            "challenge": recovery.b64url(recovery.challenge_for(payload)),
            "origin": "https://" + self.rp_id,
            "crossOrigin": False,
        }
        cdj = (
            client_data_raw if client_data_raw is not None else json.dumps(cd, separators=(",", ":")).encode()
        )
        sig = self._key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return recovery.RecoveryApproval(payload, auth, cdj, credential_id or self.credential_id, sig)

    def approve(
        self,
        action: ApprovalAction,
        subject: dict[str, str],
        revision: str,
        *,
        lifetime: int = 3600,
        issued_at: int = NOW,
        **kw: Any,
    ) -> recovery.RecoveryApproval:
        payload = approvals.build_payload(
            action=action,
            subject=subject,
            revision=revision,
            scope={},
            issued_at=issued_at,
            lifetime=lifetime,
            key_id=self.public.key_id,
            rationale="recovery test",
        )
        return self.assertion(payload, **kw)


class FakeSigningDevice:
    """Plays the signing device's half of protocol v1 over a directory (TEST ONLY): it reads a request
    and writes a response. It performs none of the device's own validation, display or presence checks;
    the engine must not rely on any of them."""

    def __init__(self, volume: Path) -> None:
        self.volume = volume

    def requests(self) -> list[dict[str, Any]]:
        d = self.volume / "sentinel-v1" / "to-signer"
        return [json.loads(p.read_text()) for p in sorted(d.glob("req-*.json"))]

    def respond(self, request: dict[str, Any], body: dict[str, Any]) -> Path:
        out = self.volume / "sentinel-v1" / "from-signer"
        out.mkdir(parents=True, exist_ok=True)
        p = out / f"resp-{request['request_id']}.json"
        p.write_bytes(canonical.encode(body))
        return p

    def sign_operator(self, request: dict[str, Any], signer: Any, **over: Any) -> Path:
        payload = request["payload"]
        sig = signer.sign(canonical.encode(payload))
        body = {
            "envelope": "sentinel/v1/sign-response",
            "key_id": signer.public.key_id,
            "payload_sha256": request["payload_sha256"],
            "request_id": request["request_id"],
            "signature_der_b64": base64.b64encode(sig).decode(),
            **over,
        }
        return self.respond(request, body)

    def sign_recovery(self, request: dict[str, Any], auth: FakeRecoveryAuthenticator, **over: Any) -> Path:
        rap = auth.assertion(request["payload"])
        body = {
            "envelope": "sentinel/v1/sign-response",
            "key_id": auth.public.key_id,
            "payload_sha256": request["payload_sha256"],
            "request_id": request["request_id"],
            "webauthn": rap.webauthn_json(),
            **over,
        }
        return self.respond(request, body)
