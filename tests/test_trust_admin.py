"""Trust administration and review decisions through the CLI and engine.

Approvals are signed by test-only operator keys (conftest.FakeOperator), standing in for presence-backed
signatures. No CLI path creates an operator signature; these tests only feed pre-signed files in.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sentinel import canonical, cli
from sentinel.approvals import Approval, save_approval_file
from sentinel.domain.enums import ApprovalAction as A
from sentinel.keys.operator import TrustStore
from sentinel.keys.runkey import RunKeyManager
from sentinel.orchestrator import target_revision
from sentinel.paths import state_dir

from .conftest import NOW, FakeOperator, resign
from .test_cli import FIXTURE_ONLY, HOST, MemBackend, config, target

EMPTY = canonical.digest({"keys": []})


@pytest.fixture
def deps() -> cli.Deps:
    backend = MemBackend()
    return cli.Deps(
        run_keys=lambda: RunKeyManager(backend),
        host=lambda: HOST,
        clock=lambda: NOW,
        env={},
        interactive=lambda: True,
        adapters=FIXTURE_ONLY,
    )


def run(deps, capsys, *argv: str) -> tuple[int, Any]:
    code = cli.main(["--json", *argv], deps)
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip().startswith("{") else out


@pytest.fixture
def home(deps, capsys) -> cli.Deps:
    assert run(deps, capsys, "init")[0] == 0
    return deps


_n = [0]


def f(tmp_path: Path, obj: Any) -> str:
    _n[0] += 1
    p = tmp_path / f"in-{_n[0]}.json"
    if isinstance(obj, Approval):
        save_approval_file(p, obj)
    else:
        p.write_text(json.dumps(obj))
    return str(p)


def keyfile(op: FakeOperator) -> dict[str, str]:
    return {
        "key_id": op.public.key_id,
        "algorithm": op.public.algorithm,
        "public_hex": op.public.public_raw.hex(),
    }


def key_subj(op: FakeOperator) -> dict[str, str]:
    return {
        "type": "operator_key",
        "key_id": op.public.key_id,
        "public_sha256": canonical.sha256_hex(op.public.public_raw),
    }


def trust_fp() -> str:
    return TrustStore().fingerprint()


def enrol(deps, capsys, tmp_path, op, signer=None, **kw) -> tuple[int, Any]:
    ap = (signer or op).approve(
        A.KEY_ROTATE, kw.pop("subject", key_subj(op)), kw.pop("revision", f"trust:{EMPTY}"), **kw
    )
    return run(
        deps,
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
        str(NOW + 365 * 86400),
    )


def rotate(deps, capsys, tmp_path, new, by, *, fp=None, approval=None) -> tuple[int, Any]:
    ap = approval or by.approve(A.KEY_ROTATE, key_subj(new), f"trust:{trust_fp()}")
    return run(
        deps,
        capsys,
        "key",
        "rotate",
        "--key",
        f(tmp_path, keyfile(new)),
        "--approval",
        f(tmp_path, ap),
        "--operator",
        "second",
        "--expires-at",
        str(NOW + 365 * 86400),
        "--trust-fingerprint",
        fp or trust_fp(),
    )


def revoke(deps, capsys, tmp_path, key_id, by, *, approval=None) -> tuple[int, Any]:
    ap = approval or by.approve(
        A.KEY_REVOKE, {"type": "operator_key", "key_id": key_id}, f"trust:{trust_fp()}"
    )
    return run(
        deps,
        capsys,
        "key",
        "revoke",
        "--key-id",
        key_id,
        "--approval",
        f(tmp_path, ap),
        "--trust-fingerprint",
        trust_fp(),
    )


@pytest.fixture
def op1(home, capsys, tmp_path) -> FakeOperator:
    op = FakeOperator.make()
    assert enrol(home, capsys, tmp_path, op)[0] == 0
    return op


# ── enrolment ──────────────────────────────────────────────────────────────
def test_enrol_self_signed_bootstrap(home, capsys, tmp_path):
    op = FakeOperator.make("ecdsa-p256-sha256")
    code, out = enrol(home, capsys, tmp_path, op)
    assert code == 0 and out["public_sha256"] == canonical.sha256_hex(op.public.public_raw)
    listed = run(home, capsys, "key", "list")[1]
    assert listed["trust_fingerprint"] == out["trust_fingerprint"] and listed["keys"][0]["status"] == "active"


@pytest.mark.parametrize(
    "case",
    ["other_signer", "other_subject", "wrong_revision", "too_long", "expired", "future"],
)
def test_enrol_rejections(home, capsys, tmp_path, case):
    op, other = FakeOperator.make(), FakeOperator.make()
    kw: dict[str, Any] = {}
    if case == "other_signer":
        kw["signer"] = other
    elif case == "other_subject":
        kw["subject"] = key_subj(other)
    elif case == "wrong_revision":
        kw["revision"] = "trust:" + "1" * 64
    elif case == "too_long":
        pass  # built below with resign: build_payload itself refuses over-long lifetimes
    elif case == "expired":
        kw.update(issued_at=NOW - 7200, lifetime=3600)
    else:
        kw["issued_at"] = NOW + 3600
    if case == "too_long":  # D-37: key.rotate max 1 h, enforced again at verification
        ap = resign(op.approve(A.KEY_ROTATE, key_subj(op), f"trust:{EMPTY}"), op, expires_at=NOW + 7200)
        code, out = run(
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
        assert code == cli.EXIT_BLOCKED and out["code"] == "expiry_too_long"
        return
    code, out = enrol(home, capsys, tmp_path, op, **kw)
    assert code == cli.EXIT_BLOCKED, out
    assert TrustStore().fingerprint() == EMPTY


def test_enrol_only_once(op1, home, capsys, tmp_path):
    code, out = enrol(home, capsys, tmp_path, FakeOperator.make())
    assert code == cli.EXIT_BLOCKED and out["code"] == "enrol_after_init"


@pytest.mark.parametrize(
    "bad",
    [
        {"key_id": "ed25519:" + "0" * 32, "algorithm": "ed25519", "public_hex": "00" * 32},
        {"key_id": "x", "algorithm": "rsa", "public_hex": "00"},
        {"key_id": "x"},
        [],
    ],
)
def test_malformed_key_files(home, capsys, tmp_path, bad):
    ap = FakeOperator.make().approve(A.KEY_ROTATE, {"type": "operator_key"}, "x")
    code, _ = run(
        home,
        capsys,
        "key",
        "enrol",
        "--key",
        f(tmp_path, bad),
        "--approval",
        f(tmp_path, ap),
        "--operator",
        "o",
        "--expires-at",
        str(NOW + 10),
    )
    assert code == cli.EXIT_INVALID


def test_enrol_rejects_bad_operator_and_expiry(home, capsys, tmp_path):
    op = FakeOperator.make()
    ap = op.approve(A.KEY_ROTATE, key_subj(op), f"trust:{EMPTY}")
    for name, exp in (("", str(NOW + 10)), ("o", str(NOW - 1)), ("o", "soon")):
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
            name,
            "--expires-at",
            exp,
        )
        assert code == cli.EXIT_INVALID


# ── rotation ───────────────────────────────────────────────────────────────
def test_rotation_and_replay(op1, home, capsys, tmp_path):
    new = FakeOperator.make("ecdsa-p256-sha256")
    ap = op1.approve(A.KEY_ROTATE, key_subj(new), f"trust:{trust_fp()}")
    code, out = rotate(home, capsys, tmp_path, new, op1, approval=ap)
    assert code == 0 and out["added"] == new.public.key_id
    # replay: one-time nonce consumed (and trust state changed)
    third = FakeOperator.make()
    code, _ = rotate(home, capsys, tmp_path, new, op1, approval=ap)
    assert code == cli.EXIT_BLOCKED
    assert rotate(home, capsys, tmp_path, third, new)[0] == 0  # the new key can now authorise


def test_rotation_rejections(op1, home, capsys, tmp_path):
    new = FakeOperator.make()
    code, out = rotate(home, capsys, tmp_path, new, op1, fp="0" * 64)
    assert code == cli.EXIT_BLOCKED and out["code"] == "trust_fingerprint_mismatch"
    code, out = rotate(home, capsys, tmp_path, new, new)
    assert code == cli.EXIT_BLOCKED  # unknown key / self-authorisation
    code, out = rotate(home, capsys, tmp_path, op1, op1)
    assert out["code"] == "duplicate_key"
    stale = op1.approve(A.KEY_ROTATE, key_subj(new), "trust:" + "2" * 64)
    assert rotate(home, capsys, tmp_path, new, op1, approval=stale)[1]["code"] == "wrong_revision"
    swapped = op1.approve(A.KEY_ROTATE, key_subj(FakeOperator.make()), f"trust:{trust_fp()}")
    assert rotate(home, capsys, tmp_path, new, op1, approval=swapped)[1]["code"] == "wrong_subject"


def test_payload_substitution_rejected(op1, home, capsys, tmp_path):
    new = FakeOperator.make()
    ap = op1.approve(A.KEY_ROTATE, key_subj(FakeOperator.make()), f"trust:{trust_fp()}")
    forged = Approval({**ap.payload, "subject": key_subj(new)}, ap.signature)  # signature over other bytes
    code, out = rotate(home, capsys, tmp_path, new, op1, approval=forged)
    assert code == cli.EXIT_BLOCKED and out["code"] == "bad_signature"


def test_run_key_cannot_approve(op1, home, capsys, tmp_path):
    from sentinel.crypto.signing import Ed25519Signer

    run_key = Ed25519Signer.generate()
    new = FakeOperator.make()
    good = op1.approve(A.KEY_ROTATE, key_subj(new), f"trust:{trust_fp()}")
    p = {**good.payload, "key_id": run_key.key_id}
    forged = Approval(p, run_key.sign(canonical.encode(p)))
    assert rotate(home, capsys, tmp_path, new, op1, approval=forged)[1]["code"] == "unknown_key"


# ── revocation ─────────────────────────────────────────────────────────────
def test_revocation(op1, home, capsys, tmp_path):
    new = FakeOperator.make()
    assert rotate(home, capsys, tmp_path, new, op1)[0] == 0
    code, _ = revoke(home, capsys, tmp_path, op1.public.key_id, new)
    assert code == 0
    # revoked key can no longer approve anything
    third = FakeOperator.make()
    assert rotate(home, capsys, tmp_path, third, op1)[1]["code"] == "revoked_key"
    assert revoke(home, capsys, tmp_path, op1.public.key_id, new)[1]["code"] == "already_revoked"
    assert revoke(home, capsys, tmp_path, "ed25519:" + "9" * 32, new)[1]["code"] == "unknown_key"


def test_last_active_key_cannot_be_revoked(op1, home, capsys, tmp_path):
    code, out = revoke(home, capsys, tmp_path, op1.public.key_id, op1)
    assert code == cli.EXIT_BLOCKED and out["code"] == "last_active_key"


def test_revoke_replay(op1, home, capsys, tmp_path):
    new, third = FakeOperator.make(), FakeOperator.make()
    rotate(home, capsys, tmp_path, new, op1)
    rotate(home, capsys, tmp_path, third, op1)
    ap = op1.approve(
        A.KEY_REVOKE, {"type": "operator_key", "key_id": third.public.key_id}, f"trust:{trust_fp()}"
    )
    assert revoke(home, capsys, tmp_path, third.public.key_id, op1, approval=ap)[0] == 0
    assert revoke(home, capsys, tmp_path, third.public.key_id, op1, approval=ap)[0] == cli.EXIT_BLOCKED


# ── non-interactive and agent callers ──────────────────────────────────────
@pytest.mark.parametrize("variant", ["non_interactive", "agent_caller"])
def test_admin_refused_from_agents_and_non_interactive(home, capsys, tmp_path, variant):
    if variant == "non_interactive":
        home.interactive = lambda: False
    else:
        home.env = {"CLAUDECODE": "1"}
    code, out = enrol(home, capsys, tmp_path, FakeOperator.make())
    assert code == cli.EXIT_BLOCKED and out["code"] == variant
    assert TrustStore().fingerprint() == EMPTY
    log = (state_dir() / "history" / "admin-log.jsonl").read_text()
    assert f'"code":"{variant}"' in log and ".refused" in log


def test_no_cli_code_path_signs_as_operator():
    src = Path(cli.__file__).read_text()
    assert ".sign(" not in src and "sign_payload" not in src and "sign_with_presence" not in src


# ── audit history ──────────────────────────────────────────────────────────
def test_history_records_and_verifies(op1, home, capsys, tmp_path):
    rotate(home, capsys, tmp_path, FakeOperator.make(), op1, fp="0" * 64)  # a refused attempt
    code, out = run(home, capsys, "history", "verify")
    assert code == 0 and out["admin_log_entries"] >= 2
    events = [
        json.loads(line)["event"]
        for line in (state_dir() / "history" / "admin-log.jsonl").read_text().splitlines()
    ]
    assert events[:2] == ["key.enrol", "key.rotate.refused"]


@pytest.mark.parametrize("how", ["edit", "truncate_middle", "reorder"])
def test_history_tampering_detected(op1, home, capsys, tmp_path, how):
    rotate(home, capsys, tmp_path, FakeOperator.make(), op1)
    p = state_dir() / "history" / "admin-log.jsonl"
    lines = p.read_text().splitlines()
    if how == "edit":
        e = json.loads(lines[0])
        e["data"]["key_id"] = "ed25519:" + "0" * 32
        lines[0] = canonical.encode(e).decode()
    elif how == "truncate_middle":
        lines = lines[1:]
    else:
        lines = lines[::-1]
    p.write_text("\n".join(lines) + "\n")
    assert run(home, capsys, "history", "verify")[0] == cli.EXIT_INTEGRITY


# ── review decisions, accepted risks, suppressions ─────────────────────────
def finding_target(tmp_path) -> tuple[Path, str]:
    t = target(tmp_path, "app", "ok\nSENTINEL-FIXTURE-FINDING\n")
    return t, target_revision(t)


def audit(deps, capsys, tmp_path, t) -> dict[str, Any]:
    code, out = run(deps, capsys, "audit", "--config", config(tmp_path, t))
    _, _, result = cli.verified_run(out["audit_id"])
    return {"code": code, **out, "result": result}


def entry(fp: str, rev: str, kind="suppress", **kw) -> dict[str, Any]:
    e = {
        "kind": kind,
        "finding": fp,
        "revision": rev,
        "reason": "test fixture finding, not exploitable",
        "author": "owner",
        "created_at": NOW,
        "expires_at": NOW + 86400,
    }
    if kind == "accept_risk":
        e.update(approver="owner", compensating_controls="network isolated; no secrets in reach")
    e.update(kw)
    return e


def sign_entry(op, e, action=None, **kw):
    act = action or (A.SUPPRESS if e["kind"] == "suppress" else A.REVIEW_ACCEPT_RISK)
    return op.approve(
        act,
        {"type": "suppression_entry", "sha256": canonical.digest(e)},
        e["revision"],
        rationale=kw.pop("rationale", e["reason"]),
        lifetime=kw.pop("lifetime", 2 * 86400),
        **kw,
    )


def add(deps, capsys, tmp_path, cmd, e, ap) -> tuple[int, Any]:
    return run(deps, capsys, *cmd, "--entry", f(tmp_path, e), "--approval", f(tmp_path, ap))


SUPPRESS, RISK = ("suppress", "add"), ("review", "accept-risk")


def test_human_review_state_is_distinct(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    ap = op1.approve(
        A.REVIEW_VERIFY_NO_EVIDENCE,
        {"type": "finding", "fingerprint": fp},
        rev,
        rationale="reproduced manually on staging",
        lifetime=86400,
    )
    code, _ = run(
        home, capsys, "review", "verify", "--finding", fp, "--revision", rev, "--approval", f(tmp_path, ap)
    )
    assert code == 0
    a = audit(home, capsys, tmp_path, t)
    (fin,) = a["result"]["findings"]
    assert fin["state"] == "HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE" and fin["severity"] == "medium"
    s = a["result"]["summary"]
    assert s["verified"] == 0 and s["human_verified_no_deterministic_evidence"] == 1
    md = cli.reports.to_markdown(a["result"]).decode()
    assert "## Human-verified without deterministic evidence" in md and "reproduced manually" in md


def test_review_rejections(op1, home, capsys, tmp_path):
    fp = "a" * 64
    short = op1.approve(
        A.REVIEW_VERIFY_NO_EVIDENCE, {"type": "finding", "fingerprint": fp}, "r", rationale="ok"
    )
    assert (
        run(
            home,
            capsys,
            "review",
            "verify",
            "--finding",
            fp,
            "--revision",
            "r",
            "--approval",
            f(tmp_path, short),
        )[0]
        == cli.EXIT_INVALID
    )
    good = op1.approve(
        A.REVIEW_VERIFY_NO_EVIDENCE,
        {"type": "finding", "fingerprint": fp},
        "r",
        rationale="checked by hand carefully",
    )
    assert (
        run(
            home,
            capsys,
            "review",
            "verify",
            "--finding",
            "b" * 64,
            "--revision",
            "r",
            "--approval",
            f(tmp_path, good),
        )[0]
        == cli.EXIT_BLOCKED
    )
    assert (
        run(
            home,
            capsys,
            "review",
            "verify",
            "--finding",
            fp,
            "--revision",
            "other",
            "--approval",
            f(tmp_path, good),
        )[0]
        == cli.EXIT_BLOCKED
    )


def test_review_for_other_revision_not_applied(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    ap = op1.approve(
        A.REVIEW_VERIFY_NO_EVIDENCE,
        {"type": "finding", "fingerprint": fp},
        rev,
        rationale="reproduced manually on staging",
    )
    run(home, capsys, "review", "verify", "--finding", fp, "--revision", rev, "--approval", f(tmp_path, ap))
    (t / "extra.txt").write_text("changes the revision")
    a = audit(home, capsys, tmp_path, t)
    assert a["result"]["findings"][0]["state"] == "suspected" and a["decisions"]["other_revision"] == 1


def test_accepted_risk_applies_without_hiding_or_softening(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    first = audit(home, capsys, tmp_path, t)
    fp = first["result"]["findings"][0]["fingerprint"]
    e = entry(fp, rev, "accept_risk")
    assert add(home, capsys, tmp_path, RISK, e, sign_entry(op1, e))[0] == 0
    a = audit(home, capsys, tmp_path, t)
    (fin,) = a["result"]["findings"]
    assert fin["state"] == "accepted_risk" and fin["severity"] == first["result"]["findings"][0]["severity"]
    assert fin["suppression"]["compensating_controls"] and fin["suppression"]["expires_at"] == e["expires_at"]
    assert a["code"] == cli.EXIT_FINDINGS and a["overall"] == "FAIL"  # check status unchanged
    assert "Exclusions" in cli.reports.to_markdown(a["result"]).decode()


def test_accepted_risk_expiry(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    e = entry(fp, rev, "accept_risk", expires_at=NOW + 600)
    add(home, capsys, tmp_path, RISK, e, sign_entry(op1, e))
    home.clock = lambda: NOW + 601
    a = audit(home, capsys, tmp_path, t)
    assert a["result"]["findings"][0]["state"] == "suspected"
    assert [r["code"] for r in a["decisions"]["rejected"]] == ["expired"]


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda e: e.pop("compensating_controls"), cli.EXIT_INVALID),
        (lambda e: e.update(reason="short"), cli.EXIT_INVALID),
        (lambda e: e.update(expires_at=NOW + 10 * 86400), cli.EXIT_INVALID),  # outlives its approval
        (lambda e: e.update(expires_at=NOW - 1), cli.EXIT_INVALID),
        (lambda e: e.update(finding="nothex"), cli.EXIT_INVALID),
        (lambda e: e.update(extra="x"), cli.EXIT_INVALID),
    ],
)
def test_accepted_risk_entry_validation(op1, home, capsys, tmp_path, mutate, code):
    e = entry("c" * 64, "rev", "accept_risk")
    mutate(e)
    ap = op1.approve(
        A.REVIEW_ACCEPT_RISK,
        {"type": "suppression_entry", "sha256": canonical.digest(e)},
        "rev",
        rationale=e.get("reason", "x"),
        lifetime=2 * 86400,
    )
    assert add(home, capsys, tmp_path, RISK, e, ap)[0] == code


def test_entry_changed_after_signing_and_cross_kind(op1, home, capsys, tmp_path):
    e = entry("c" * 64, "rev")
    ap = sign_entry(op1, e)
    assert (
        add(home, capsys, tmp_path, SUPPRESS, {**e, "expires_at": NOW + 3600}, ap)[1]["code"]
        == "wrong_subject"
    )
    assert (
        add(home, capsys, tmp_path, SUPPRESS, e, sign_entry(op1, e, rationale="different reason here"))[0]
        == 4
    )
    risk_entry = entry("c" * 64, "rev", "accept_risk")
    assert (
        add(home, capsys, tmp_path, RISK, risk_entry, sign_entry(op1, risk_entry, action=A.SUPPRESS))[0] == 3
    )
    assert add(home, capsys, tmp_path, RISK, e, ap)[0] == cli.EXIT_INVALID  # suppress entry as accepted risk


def test_suppression_scope_and_expiry(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    other = entry("d" * 64, rev)
    add(home, capsys, tmp_path, SUPPRESS, other, sign_entry(op1, other))
    wrong_rev = entry(fp, "tree-sha256:" + "0" * 64)
    add(home, capsys, tmp_path, SUPPRESS, wrong_rev, sign_entry(op1, wrong_rev))
    a = audit(home, capsys, tmp_path, t)
    assert a["result"]["findings"][0]["suppression"] is None and a["decisions"]["other_revision"] == 1
    good = entry(fp, rev, expires_at=NOW + 100)
    add(home, capsys, tmp_path, SUPPRESS, good, sign_entry(op1, good))
    a = audit(home, capsys, tmp_path, t)
    fin = a["result"]["findings"][0]
    assert fin["suppression"]["type"] == "suppress" and fin["state"] == "suspected"
    assert a["result"]["summary"]["suppressed"] == 1 and a["overall"] == "FAIL"
    sarif = json.loads(cli.reports.to_sarif(a["result"]))
    assert sarif["runs"][0]["results"][0]["suppressions"][0]["justification"] == good["reason"]
    home.clock = lambda: NOW + 100
    assert audit(home, capsys, tmp_path, t)["result"]["findings"][0]["suppression"] is None


def test_standing_nonce_semantics(op1, home, capsys, tmp_path):
    e = entry("e" * 64, "rev")
    ap = sign_entry(op1, e)
    assert add(home, capsys, tmp_path, SUPPRESS, e, ap)[0] == 0
    assert add(home, capsys, tmp_path, SUPPRESS, e, ap)[1]["code"] == "duplicate_decision"
    e2 = entry("e" * 64, "rev", reason="a different suppression reason")
    replay = resign(sign_entry(op1, e2), op1, nonce=ap.payload["nonce"])
    assert add(home, capsys, tmp_path, SUPPRESS, e2, replay)[1]["code"] == "nonce_rebound"


def test_tampered_decision_file_is_reported_not_applied(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    e = entry(fp, rev)
    add(home, capsys, tmp_path, SUPPRESS, e, sign_entry(op1, e))
    (p,) = (state_dir() / "decisions").iterdir()
    p.chmod(0o600)
    d = json.loads(p.read_text())
    d["entry"]["expires_at"] = NOW + 80000  # still within the approval, but not what was signed
    p.write_text(json.dumps(d))
    a = audit(home, capsys, tmp_path, t)
    assert a["result"]["findings"][0]["suppression"] is None
    assert [r["code"] for r in a["decisions"]["rejected"]] == ["wrong_subject"]
    planted = state_dir() / "decisions" / "suppress-planted.json"
    planted.write_text("{}")
    assert run(home, capsys, "decisions", "list")[1]["problems"]


def test_decisions_from_revoked_key_stop_applying(op1, home, capsys, tmp_path):
    t, rev = finding_target(tmp_path)
    fp = audit(home, capsys, tmp_path, t)["result"]["findings"][0]["fingerprint"]
    e = entry(fp, rev)
    add(home, capsys, tmp_path, SUPPRESS, e, sign_entry(op1, e))
    new = FakeOperator.make()
    rotate(home, capsys, tmp_path, new, op1)
    revoke(home, capsys, tmp_path, op1.public.key_id, new)
    a = audit(home, capsys, tmp_path, t)
    assert a["result"]["findings"][0]["suppression"] is None
    assert a["decisions"]["rejected"][0]["code"] == "revoked_key"


def test_decision_commands_refused_non_interactive(op1, home, capsys, tmp_path):
    home.interactive = lambda: False
    e = entry("f" * 64, "rev")
    code, out = add(home, capsys, tmp_path, SUPPRESS, e, sign_entry(op1, e))
    assert code == cli.EXIT_BLOCKED and out["code"] == "non_interactive"
    assert run(home, capsys, "decisions", "list")[1]["decisions"] == []
