"""Signing primitives (D-16, D-38), run key manager and operator trust store."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel import canonical
from sentinel.crypto.signing import ED25519, P256, Ed25519Signer, PublicKey, key_id_for
from sentinel.errors import BlockedError, CapabilityUnavailable, ValidationError
from sentinel.keys import operator as op_mod
from sentinel.keys.operator import OperatorKey, TrustStore
from sentinel.keys.runkey import RunKeyManager

from .conftest import NOW, FakeOperator


# ── signing primitives ─────────────────────────────────────────────────────
@pytest.mark.parametrize("alg", [ED25519, P256])
def test_sign_verify_and_tamper(alg):
    o = FakeOperator.make(alg)
    sig = o.sign(b"message")
    assert o.public.verify(sig, b"message")
    assert not o.public.verify(sig, b"messagE")
    assert not o.public.verify(b"\x00" * len(sig), b"message")
    assert not o.public.verify(b"", b"message")


def test_verification_uses_only_declared_algorithm():
    o = FakeOperator.make(P256)
    sig = o.sign(b"m")
    wrong = PublicKey(o.public.key_id, ED25519, o.public.public_raw)
    assert not wrong.verify(sig, b"m")  # no algorithm guessing from signature bytes


def test_key_id_is_bound_to_algorithm_and_key():
    raw = Ed25519Signer.generate().public.public_raw
    assert key_id_for(ED25519, raw).startswith("ed25519:")
    with pytest.raises(ValueError):
        key_id_for("rsa", raw)


@pytest.mark.parametrize(
    "raw,alg",
    [(b"x" * 31, ED25519), (b"\x04" + b"\x01" * 64, P256), (b"\x02" * 33, P256), (b"x" * 32, "rsa")],
)
def test_malformed_public_keys_rejected(raw, alg):
    with pytest.raises(ValueError):
        PublicKey.from_raw(raw, alg)


def test_signer_repr_has_no_secret():
    s = Ed25519Signer.generate()
    assert s.seed().hex() not in repr(s) and s.key_id in repr(s)


# ── run key manager (fake backend; the real keychain is not touched by tests) ──
class FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def store(self, account: str, secret_hex: str) -> None:
        self.data[account] = secret_hex

    def load(self, account: str) -> str | None:
        return self.data.get(account)


def test_run_key_create_and_sign_roundtrip():
    mgr = RunKeyManager(FakeBackend())
    pub = mgr.create()
    assert pub.algorithm == ED25519
    s = mgr.signer()
    assert s.key_id == pub.key_id and pub.verify(s.sign(b"x"), b"x")


def test_run_key_missing_or_mismatched_secret_fails_closed():
    b = FakeBackend()
    mgr = RunKeyManager(b)
    with pytest.raises(CapabilityUnavailable):
        mgr.signer()  # no key yet
    pub = mgr.create()
    b.data[pub.key_id.replace(":", "-")] = Ed25519Signer.generate().seed().hex()
    with pytest.raises(CapabilityUnavailable):
        mgr.signer()  # keystore secret doesn't match metadata
    b.data.clear()
    with pytest.raises(CapabilityUnavailable):
        mgr.signer()


# ── operator trust store ───────────────────────────────────────────────────
def _key(o: FakeOperator, status: str = "active", exp: int = NOW + 1000) -> OperatorKey:
    return OperatorKey(o.public.key_id, "owner", o.public, status, exp)


@pytest.mark.parametrize("alg", [P256])
def test_trust_store_roundtrip_p256(tmp_path: Path, alg):
    o = FakeOperator.make(alg)
    ts = TrustStore(tmp_path / "t.json")
    ts.enrol(_key(o))
    ts.save()
    again = TrustStore(tmp_path / "t.json")
    assert again.usable(o.public.key_id, NOW).public.algorithm == alg
    assert again.fingerprint() == ts.fingerprint()


def test_trust_store_second_enrolment_blocked(tmp_path: Path):
    ts = TrustStore(tmp_path / "t.json")
    ts.enrol(_key(FakeOperator.make()))
    with pytest.raises(BlockedError):
        ts.enrol(_key(FakeOperator.make()))


def test_unknown_revoked_expired_keys_authorise_nothing(tmp_path: Path):
    o = FakeOperator.make()
    ts = TrustStore(tmp_path / "t.json")
    ts.enrol(_key(o, exp=NOW + 10))
    with pytest.raises(BlockedError, match="unknown"):
        ts.usable("ed25519:" + "0" * 32, NOW)
    with pytest.raises(BlockedError, match="expired"):
        ts.usable(o.public.key_id, NOW + 10)
    ts.apply_revocation(o.public.key_id)
    with pytest.raises(BlockedError, match="revoked"):
        ts.usable(o.public.key_id, NOW)


def test_tampered_trust_store_rejected(tmp_path: Path):
    o = FakeOperator.make()
    ts = TrustStore(tmp_path / "t.json")
    ts.enrol(_key(o))
    ts.save()
    data = canonical.decode_strict((tmp_path / "t.json").read_bytes())
    for mutate in (
        lambda d: d["keys"][0].update(key_id="ed25519:" + "1" * 32),
        lambda d: d["keys"][0].update(algorithm="rsa"),
        lambda d: d["keys"][0].update(status="maybe"),
        lambda d: d.update(extra=1),
    ):
        bad = canonical.decode_strict(canonical.encode(data))
        mutate(bad)
        (tmp_path / "bad.json").write_bytes(canonical.encode(bad))
        with pytest.raises(ValidationError):
            TrustStore(tmp_path / "bad.json")


def test_operator_signing_fails_closed_without_provider():
    with pytest.raises(CapabilityUnavailable) as exc:
        op_mod.available_provider()
    assert "operator" in exc.value.capability
