"""Signing primitives (D-16, D-38).

- Run key: Ed25519 only.
- Operator keys: ECDSA P-256 with SHA-256 only (D-47). Ed25519 is the run key's algorithm only.
  Verification uses only the algorithm recorded for the key; there is no algorithm negotiation
  from signature bytes.

Key IDs are derived from the algorithm and public key, never chosen by the caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ED25519 = "ed25519"
P256 = "ecdsa-p256-sha256"
ALGORITHMS = frozenset({ED25519, P256})
#: D-47 (amends D-38): operator keys are ECDSA P-256 only (Secure Enclave on the signing device;
#: FIDO2 ES256 for recovery). Ed25519 operator keys are not used in V1 and are refused everywhere an
#: operator key is parsed, enrolled, rotated in or used. The run key stays Ed25519 (D-16, D-34).
OPERATOR_ALGORITHMS = frozenset({P256})
RUN_KEY_ALGORITHM = ED25519


def key_id_for(algorithm: str, public_raw: bytes) -> str:
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {algorithm!r}")
    prefix = "ed25519" if algorithm == ED25519 else "p256"
    return f"{prefix}:" + hashlib.sha256(algorithm.encode() + b"\0" + public_raw).hexdigest()[:32]


@dataclass(frozen=True)
class PublicKey:
    key_id: str
    algorithm: str
    public_raw: bytes

    @classmethod
    def from_raw(cls, raw: bytes, algorithm: str = ED25519) -> PublicKey:
        if algorithm == ED25519:
            if len(raw) != 32:
                raise ValueError("ed25519 public key must be 32 bytes")
            Ed25519PublicKey.from_public_bytes(raw)
        elif algorithm == P256:
            if len(raw) != 65 or raw[0] != 0x04:
                raise ValueError("p256 public key must be a 65-byte uncompressed point")
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)  # validates the point
        else:
            raise ValueError(f"unsupported algorithm {algorithm!r}")
        return cls(key_id_for(algorithm, raw), algorithm, raw)

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            if self.algorithm == ED25519:
                Ed25519PublicKey.from_public_bytes(self.public_raw).verify(signature, message)
            elif self.algorithm == P256:
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.public_raw)
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))  # DER-encoded signature
            else:
                return False
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


class Ed25519Signer:
    """In-memory Ed25519 signer. Inside the engine, only the run key uses this (§11.2)."""

    def __init__(self, private: Ed25519PrivateKey) -> None:
        self._private = private
        raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public = PublicKey.from_raw(raw, ED25519)

    @property
    def key_id(self) -> str:
        return self.public.key_id

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed(self) -> bytes:
        return self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def __repr__(self) -> str:  # never expose key material
        return f"Ed25519Signer(key_id={self.key_id!r})"
