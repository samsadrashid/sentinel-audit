# ruff: noqa: F811  (pytest fixtures re-used from test_trust_admin by import)
"""Governance completion: unsigned payload preparation, standing-decision revocation, helper hash pinning.

Signatures come from test-only keys (conftest.FakeOperator) signing the prepared canonical bytes, which
is exactly what an operator's presence-backed signer would do. Sentinel itself never signs.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from sentinel import approvals, canonical, cli, policy, prepare
from sentinel.approvals import Approval
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import CapabilityUnavailable, ValidationError
from sentinel.keys import secure_enclave as se
from sentinel.keys.operator import TrustStore
from sentinel.paths import state_dir

from .conftest import NOW, FakeOperator, resign
from .test_trust_admin import (  # noqa: F401  (fixtures)
    RISK,
    SUPPRESS,
    add,
    audit,
    deps,
    entry,
    f,
    finding_target,
    home,
    keyfile,
    op1,
    rotate,
    run,
    sign_entry,
)


def sign_prepared(op: FakeOperator, out: dict[str, Any]) -> Approval:
    """What an external presence-backed signer does: sign the canonical bytes shown to the operator."""
    payload = json.loads(out["canonical"])
    assert canonical.digest(payload) == out["payload_sha256"]
    return Approval(payload, op.sign(out["canonical"].encode()))


def state_snapshot() -> dict[str, bytes]:
    root = state_dir()
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def prep(deps, capsys, kind: str, op: FakeOperator, *extra: str, lifetime="3600") -> tuple[int, Any]:
    return run(
        deps,
        capsys,
        "approval",
        "prepare",
        kind,
        "--key-id",
        op.public.key_id,
        "--lifetime",
        lifetime,
        *extra,
    )


# ── 1. payload preparation ─────────────────────────────────────────────────
def test_prepare_has_no_side_effects(op1, home, capsys, tmp_path):
    new = FakeOperator.make()
    before = state_snapshot()
    code, out = prep(
        home,
        capsys,
        "key-rotate",
        op1,
        "--key",
        f(tmp_path, keyfile(new)),
        "--rationale",
        "adding the second operator key",
    )
    assert code == 0 and "UNSIGNED" in out["note"]
    assert state_snapshot() == before  # no ledger, trust, log or decision write
    assert "signature" not in out
    with pytest.raises(ValidationError):  # a prepared payload is never loadable as an approval
        Approval.from_json(out["payload"])


def test_prepare_shows_every_field_and_full_hash(op1, home, capsys, tmp_path):
    code, out = prep(
        home,
        capsys,
        "key-revoke",
        op1,
        "--target-key-id",
        op1.public.key_id,
        "--rationale",
        "rotating out the old key",
    )
    assert code == 0
    for field in approvals.REQUIRED_FIELDS:
        assert f'"{field}"' in out["display"]
    assert out["payload_sha256"] in out["display"] and len(out["payload_sha256"]) == 64
    assert out["payload"]["revision"] == f"trust:{TrustStore().fingerprint()}"


def test_prepared_payload_is_reproducible(op1, home, capsys, tmp_path):
    _, out = prep(
        home,
        capsys,
        "key-revoke",
        op1,
        "--target-key-id",
        op1.public.key_id,
        "--rationale",
        "rotating out the old key",
    )
    reordered = dict(reversed(list(out["payload"].items())))
    again = prepare.describe(reordered)
    assert again["canonical"] == out["canonical"] and again["payload_sha256"] == out["payload_sha256"]
    p = Path(f(tmp_path, out["payload"]))
    assert run(home, capsys, "approval", "inspect", str(p))[1]["payload_sha256"] == out["payload_sha256"]


def test_prepared_payload_signed_externally_is_accepted_once(op1, home, capsys, tmp_path):
    new = FakeOperator.make()
    _, out = prep(
        home,
        capsys,
        "key-rotate",
        op1,
        "--key",
        f(tmp_path, keyfile(new)),
        "--rationale",
        "adding the second operator key",
    )
    ap = sign_prepared(op1, out)
    assert rotate(home, capsys, tmp_path, new, op1, approval=ap)[0] == 0
    assert rotate(home, capsys, tmp_path, new, op1, approval=ap)[0] == cli.EXIT_BLOCKED  # one-time


def test_tampered_wrong_key_and_expired_prepared_approvals(op1, home, capsys, tmp_path):
    new = FakeOperator.make()
    _, out = prep(
        home,
        capsys,
        "key-rotate",
        op1,
        "--key",
        f(tmp_path, keyfile(new)),
        "--rationale",
        "adding the second operator key",
    )
    good = sign_prepared(op1, out)
    tampered = Approval({**good.payload, "rationale": "something else entirely"}, good.signature)
    assert rotate(home, capsys, tmp_path, new, op1, approval=tampered)[1]["code"] == "bad_signature"
    wrong_key = Approval(good.payload, FakeOperator.make().sign(out["canonical"].encode()))
    assert rotate(home, capsys, tmp_path, new, op1, approval=wrong_key)[1]["code"] == "bad_signature"
    home.clock = lambda: NOW + 3600
    assert rotate(home, capsys, tmp_path, new, op1, approval=good)[1]["code"] == "expired"


@pytest.mark.parametrize(
    "argv,code",
    [
        (["key-rotate"], cli.EXIT_INVALID),  # missing --key
        (["key-revoke", "--target-key-id", "x", "--finding", "a" * 64], cli.EXIT_INVALID),  # ambiguous
        (["review", "--finding", "nothex", "--revision", "r"], cli.EXIT_INVALID),
        (["review", "--finding", "a" * 64, "--revision", "r", "--rationale", "short"], cli.EXIT_INVALID),
        (["allowlist-change"], cli.EXIT_INVALID),  # unsupported
        (["key-revoke", "--target-key-id", "ed25519:" + "0" * 32, "--rationale", "long enough reason"], 3),
    ],
)
def test_prepare_rejects_bad_requests(op1, home, capsys, argv, code):
    assert prep(home, capsys, argv[0], op1, *argv[1:])[0] == code


def test_prepare_rejects_over_max_lifetime_and_unknown_signer(op1, home, capsys):
    args = ["--target-key-id", op1.public.key_id, "--rationale", "long enough reason"]
    assert (
        prep(home, capsys, "key-revoke", op1, *args, lifetime="3601")[1]["code"] == "expiry_too_long"
    )  # D-37
    assert prep(home, capsys, "key-revoke", op1, *args, lifetime="1h")[0] == cli.EXIT_INVALID
    assert prep(home, capsys, "key-revoke", op1, *args)[0] == 0
    assert prep(home, capsys, "key-revoke", FakeOperator.make(), *args)[1]["code"] == "unknown_key"


def test_prepare_enrol_and_entry_kinds(home, capsys, tmp_path):
    op = FakeOperator.make()
    code, out = prep(
        home,
        capsys,
        "key-enrol",
        op,
        "--key",
        f(tmp_path, keyfile(op)),
        "--rationale",
        "first operator key for this host",
    )
    assert code == 0
    ap = sign_prepared(op, out)
    code, _ = run(
        home,
        capsys,
        "key",
        "enrol",
        "--key",
        f(tmp_path, keyfile(op)),
        "--approval",
        f(tmp_path, ap),
        "--operator",
        "owner",
        "--expires-at",
        str(NOW + 86400),
    )
    assert code == 0
    e = entry("a" * 64, "rev")
    code, out = prep(home, capsys, "suppress", op, "--entry", f(tmp_path, e), lifetime=str(2 * 86400))
    assert code == 0 and out["payload"]["rationale"] == e["reason"]
    assert add(home, capsys, tmp_path, SUPPRESS, e, sign_prepared(op, out))[0] == 0
    assert (
        prep(home, capsys, "suppress", op, "--entry", f(tmp_path, e), "--rationale", "a different reason")[0]
        == 4
    )
    assert prep(home, capsys, "accept-risk", op, "--entry", f(tmp_path, e), lifetime=str(2 * 86400))[0] == 4
    short = prep(home, capsys, "suppress", op, "--entry", f(tmp_path, e), lifetime="60")
    assert short[0] == cli.EXIT_INVALID  # entry would outlive its approval


def test_prepare_policy_change_and_record(op1, home, capsys, tmp_path):
    p = tmp_path / "policy.json"
    p.write_bytes(canonical.encode({"owned_assets": ["app"]}))
    code, out = prep(
        home, capsys, "policy-change", op1, "--policy", str(p), "--rationale", "own the app asset now"
    )
    assert code == 0 and out["payload"]["subject"]["sha256"] == canonical.sha256_hex(p.read_bytes())
    ap = Path(f(tmp_path, sign_prepared(op1, out)))
    assert run(home, capsys, "policy", "validate", "--policy", str(p), "--policy-approval", str(ap))[0] == 0
    bad = tmp_path / "bad-policy.json"
    bad.write_text('{"unknown": 1}')
    assert prep(home, capsys, "policy-change", op1, "--policy", str(bad), "--rationale", "x" * 20)[0] == 4


def test_cli_never_signs_or_prompts_in_prepare():
    src = Path(prepare.__file__).read_text()
    assert ".sign(" not in src and "register(" not in src and "consume=True" not in src


# ── 2. decision revocation ─────────────────────────────────────────────────
def _record(home, capsys, tmp_path, op, kind="suppress"):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    if kind == "review":
        ap = op.approve(
            A.REVIEW_VERIFY_NO_EVIDENCE,
            {"type": "finding", "fingerprint": fp},
            rev,
            rationale="reproduced manually on staging",
        )
        run(
            home,
            capsys,
            "review",
            "verify",
            "--finding",
            fp,
            "--revision",
            rev,
            "--approval",
            f(tmp_path, ap),
        )
    else:
        e = entry(fp, rev, kind)
        ap = sign_entry(op, e)
        assert add(home, capsys, tmp_path, SUPPRESS if kind == "suppress" else RISK, e, ap)[0] == 0
    return t, ap.payload_hash


def _revoke(home, capsys, tmp_path, op, decision_id, *, approval=None, lifetime="3600"):
    if approval is None:
        _, out = prep(
            home,
            capsys,
            "decision-revoke",
            op,
            "--decision-id",
            decision_id,
            "--rationale",
            "no longer accepted after review",
            lifetime=lifetime,
        )
        approval = sign_prepared(op, out)
    return run(
        home, capsys, "decisions", "revoke", "--decision-id", decision_id, "--approval", f(tmp_path, approval)
    )


@pytest.mark.parametrize("kind", ["suppress", "accept_risk", "review"])
def test_revoked_decisions_stop_applying(op1, home, capsys, tmp_path, kind):
    t, did = _record(home, capsys, tmp_path, op1, kind)
    applied = audit(home, capsys, tmp_path, t)
    assert applied["decisions"]["applied"][0]["decision_id"] == did
    original = (state_dir() / "decisions" / f"{kind}-{did}.json").read_bytes()
    assert _revoke(home, capsys, tmp_path, op1, did)[0] == 0
    a = audit(home, capsys, tmp_path, t)
    fin = a["result"]["findings"][0]
    assert fin["state"] == "suspected" and fin["suppression"] is None
    assert a["decisions"]["rejected"][0]["code"] == "decision_revoked"
    assert "not applied" in cli.reports.to_markdown(a["result"]).decode()
    # original decision is preserved byte for byte and still shows a valid historical signature
    assert (state_dir() / "decisions" / f"{kind}-{did}.json").read_bytes() == original
    (listed,) = run(home, capsys, "decisions", "list")[1]["decisions"]
    assert listed["revocation"] == "revoked" and listed["signature_valid"] is True
    log = (state_dir() / "history" / "admin-log.jsonl").read_text()
    assert '"event":"decision.revoke"' in log


def test_revocation_replay_and_binding(op1, home, capsys, tmp_path):
    _, did = _record(home, capsys, tmp_path, op1)
    _, out = prep(
        home,
        capsys,
        "decision-revoke",
        op1,
        "--decision-id",
        did,
        "--rationale",
        "no longer accepted after review",
    )
    ap = sign_prepared(op1, out)
    other = {**ap.payload, "subject": {**ap.payload["subject"], "entry_sha256": "0" * 64}}
    assert (
        _revoke(home, capsys, tmp_path, op1, did, approval=resign(ap, op1, **other))[1]["code"]
        == "wrong_subject"
    )
    wrong_rev = resign(ap, op1, revision="tree-sha256:" + "0" * 64)
    assert _revoke(home, capsys, tmp_path, op1, did, approval=wrong_rev)[1]["code"] == "wrong_revision"
    assert _revoke(home, capsys, tmp_path, op1, did, approval=ap)[0] == 0
    assert _revoke(home, capsys, tmp_path, op1, did, approval=ap)[1]["code"] == "already_revoked"
    assert _revoke(home, capsys, tmp_path, op1, "f" * 64, approval=ap)[1]["code"] == "unknown_decision"


def test_revocation_expiry_and_lifetime(op1, home, capsys, tmp_path):
    _, did = _record(home, capsys, tmp_path, op1)
    assert (
        prep(
            home,
            capsys,
            "decision-revoke",
            op1,
            "--decision-id",
            did,
            "--rationale",
            "no longer accepted after review",
            lifetime="3601",
        )[1]["code"]
        == "expiry_too_long"
    )
    _, out = prep(
        home,
        capsys,
        "decision-revoke",
        op1,
        "--decision-id",
        did,
        "--rationale",
        "no longer accepted after review",
    )
    ap = sign_prepared(op1, out)
    home.clock = lambda: NOW + 3600
    assert _revoke(home, capsys, tmp_path, op1, did, approval=ap)[1]["code"] == "expired"


def test_forged_or_broken_revocation_blocks_rather_than_applies(op1, home, capsys, tmp_path):
    t, did = _record(home, capsys, tmp_path, op1)
    rv = state_dir() / "decisions-revocations"
    rv.mkdir(mode=0o700)
    forger = FakeOperator.make()
    _, out = prep(
        home,
        capsys,
        "decision-revoke",
        op1,
        "--decision-id",
        did,
        "--rationale",
        "no longer accepted after review",
    )
    forged = Approval(json.loads(out["canonical"]), forger.sign(out["canonical"].encode()))
    (rv / f"{did}.json").write_bytes(canonical.encode(forged.to_json()))
    a = audit(home, capsys, tmp_path, t)
    assert a["result"]["findings"][0]["suppression"] is None
    assert a["decisions"]["rejected"][0]["code"] == "revocation_unverifiable"


def test_revocation_survives_later_key_revocation(op1, home, capsys, tmp_path):
    t, did = _record(home, capsys, tmp_path, op1)
    _revoke(home, capsys, tmp_path, op1, did)
    new = FakeOperator.make()
    rotate(home, capsys, tmp_path, new, op1)
    ap = op1.approve(
        A.KEY_REVOKE,
        {"type": "operator_key", "key_id": op1.public.key_id},
        f"trust:{TrustStore().fingerprint()}",
    )
    run(
        home,
        capsys,
        "key",
        "revoke",
        "--key-id",
        op1.public.key_id,
        "--approval",
        f(tmp_path, ap),
        "--trust-fingerprint",
        TrustStore().fingerprint(),
    )
    (listed,) = run(home, capsys, "decisions", "list")[1]["decisions"]
    assert listed["revocation"] == "revoked"


@pytest.mark.parametrize("variant", ["non_interactive", "agent_caller"])
def test_revocation_refused_from_agents_and_non_interactive(op1, home, capsys, tmp_path, variant):
    _, did = _record(home, capsys, tmp_path, op1)
    if variant == "non_interactive":
        home.interactive = lambda: False
    else:
        home.env = {"CODEX_SANDBOX": "1"}
    code, out = _revoke(home, capsys, tmp_path, op1, did)
    assert code == cli.EXIT_BLOCKED and out["code"] == variant
    assert not (state_dir() / "decisions-revocations").exists()


# ── 3. helper hash pinning ─────────────────────────────────────────────────
def _fake_helper(content: str = "#!/bin/sh\necho '{\"secure_enclave\":true}'\n") -> str:
    p = se.helper_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    p.chmod(0o700)
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_no_pin_or_no_binary_means_no_helper():
    with pytest.raises(CapabilityUnavailable, match="no Secure Enclave helper pin"):
        se.helper_backend(None)
    with pytest.raises(CapabilityUnavailable, match="not found"):
        se.helper_backend("a" * 64)


def test_replaced_binary_is_refused_before_execution(tmp_path):
    pin = _fake_helper()
    marker = tmp_path / "executed"
    b = se.helper_backend(pin)
    assert b.status() is True
    _fake_helper(f"#!/bin/sh\ntouch {marker}\necho '{{\"secure_enclave\":true}}'\n")  # rebuilt / swapped
    with pytest.raises(CapabilityUnavailable, match="pin"):
        se.helper_backend(pin).status()
    assert not marker.exists()  # never executed


def test_symlinked_helper_refused():
    pin = _fake_helper()
    real = se.helper_path().with_name("real")
    os.replace(se.helper_path(), real)
    se.helper_path().symlink_to(real)
    with pytest.raises(CapabilityUnavailable):
        se.helper_backend(pin)


@pytest.mark.parametrize("bad", ["", "A" * 64, "a" * 63, 123, None.__class__.__name__])
def test_invalid_pin_in_policy_rejected(bad):
    with pytest.raises(ValidationError):
        policy._parse_policy(canonical.encode({"se_helper_sha256": bad}), "t")


def test_pin_comes_only_from_approved_policy(op1, home, capsys, tmp_path):
    pin = _fake_helper()
    p = tmp_path / "policy.json"
    p.write_bytes(canonical.encode({"se_helper_sha256": pin}))
    _, out = prep(
        home, capsys, "policy-change", op1, "--policy", str(p), "--rationale", "approve helper build 1"
    )
    ap = Path(f(tmp_path, sign_prepared(op1, out)))
    code, st = run(home, capsys, "status", "--policy", str(p), "--policy-approval", str(ap))
    assert code == 0 and st["se_helper"]["pinned"] and st["se_helper"]["hash_matches_pin"]
    # unauthorised pin change: edit the pin without a new approval
    p.write_bytes(canonical.encode({"se_helper_sha256": "b" * 64}))
    assert (
        run(home, capsys, "status", "--policy", str(p), "--policy-approval", str(ap))[0] == cli.EXIT_BLOCKED
    )
    # an unapproved policy file is refused outright
    assert run(home, capsys, "status", "--policy", str(p))[0] == cli.EXIT_BLOCKED


def test_rebuild_is_not_silently_trusted(op1, home, capsys, tmp_path):
    pin = _fake_helper()
    p = tmp_path / "policy.json"
    p.write_bytes(canonical.encode({"se_helper_sha256": pin}))
    _, out = prep(
        home, capsys, "policy-change", op1, "--policy", str(p), "--rationale", "approve helper build 1"
    )
    ap = Path(f(tmp_path, sign_prepared(op1, out)))
    _fake_helper("#!/bin/sh\necho rebuilt\n")
    st = run(home, capsys, "status", "--policy", str(p), "--policy-approval", str(ap))[1]["se_helper"]
    assert st["pinned"] and not st["hash_matches_pin"]


def test_production_still_not_activated_even_with_valid_pin():
    pin = _fake_helper()
    with pytest.raises(CapabilityUnavailable, match="not activated"):
        se.production_provider(pin)
    with pytest.raises(CapabilityUnavailable, match="not activated"):
        se.production_provider()
