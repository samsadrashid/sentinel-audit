"""Shared test fixtures.

Operator signatures in tests are produced by keys generated *inside the test process*. That stands
in for a user-presence provider and exists only in tests; production code has no path that signs
operator approvals (keys/operator.available_provider always fails closed in M1).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sentinel import approvals
from sentinel.crypto.signing import ED25519, P256, Ed25519Signer, PublicKey
from sentinel.domain.enums import ApprovalAction
from sentinel.keys.operator import OperatorKey, TrustStore

NOW = 1_800_000_000


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "sentinel-home"
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    return home


@dataclass
class FakeOperator:
    """Test-only stand-in for a hardware/presence-backed operator key."""

    algorithm: str
    _ed: Ed25519Signer | None = None
    _p256: ec.EllipticCurvePrivateKey | None = None

    @classmethod
    def make(cls, algorithm: str = P256) -> FakeOperator:
        if algorithm == ED25519:
            return cls(ED25519, _ed=Ed25519Signer.generate())
        return cls(P256, _p256=ec.generate_private_key(ec.SECP256R1()))

    @property
    def public(self) -> PublicKey:
        if self._ed:
            return self._ed.public
        assert self._p256
        raw = self._p256.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return PublicKey.from_raw(raw, P256)

    def sign(self, message: bytes) -> bytes:
        if self._ed:
            return self._ed.sign(message)
        assert self._p256
        return self._p256.sign(message, ec.ECDSA(hashes.SHA256()))

    def approve(
        self,
        action: ApprovalAction,
        subject: dict[str, str],
        revision: str,
        scope: dict[str, Any] | None = None,
        lifetime: int = 3600,
        issued_at: int = NOW,
        rationale: str = "test",
    ) -> approvals.Approval:
        payload = approvals.build_payload(
            action=action,
            subject=subject,
            revision=revision,
            scope=scope or {},
            issued_at=issued_at,
            lifetime=lifetime,
            key_id=self.public.key_id,
            rationale=rationale,
        )
        return approvals.Approval(payload, self.sign(approvals.canonical.encode(payload)))


@pytest.fixture
def operator() -> FakeOperator:
    return FakeOperator.make(P256)


@pytest.fixture
def trust(operator: FakeOperator, tmp_path: Path) -> TrustStore:
    ts = TrustStore(tmp_path / "trust.json")
    ts.enrol(OperatorKey(operator.public.key_id, "owner", operator.public, "active", NOW + 365 * 86400))
    ts.save()
    return ts


@pytest.fixture
def ledger(tmp_path: Path) -> approvals.NonceLedger:
    return approvals.NonceLedger(tmp_path / "ledger.json")


def resign(approval: approvals.Approval, op: FakeOperator, **changes: Any) -> approvals.Approval:
    """Build a correctly signed approval with altered fields (to test semantic checks, not signatures)."""
    payload = {**approval.payload, **changes}
    return approvals.Approval(payload, op.sign(approvals.canonical.encode(payload)))


def now() -> int:
    return int(time.time())


def FIXTURE_ONLY(pol: Any) -> list[Any]:  # noqa: N802 - M1-era tests audit with the fixture adapter only
    from sentinel import cli

    return [cli.FixtureAdapter(allowlisted_sha256=pol.adapter_allowlist.get("fixture"))]
