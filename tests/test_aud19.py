# ruff: noqa: F811  (pytest fixtures imported from sibling test modules)
"""AUD-19: focused regression tests for the 18 security checks that no test caught.

Each test names the mutant id from scripts/mutation/mutations.py that it is meant to catch, and asserts
the invariant (not the implementation): what must be refused, and which reason code the operator sees.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from sentinel import canonical, cli, decisions, policy, prepare, redaction, reports
from sentinel import findings as F
from sentinel.approvals import NonceLedger, save_approval_file
from sentinel.domain.enums import ApprovalAction as A
from sentinel.errors import BlockedError, ValidationError
from sentinel.redaction import RedactionError

from .conftest import FIXTURE_ONLY, NOW, FakeOperator
from .test_cli import MemBackend
from .test_findings_reports import REV, result, scanner_finding
from .test_trust_admin import EMPTY, deps, enrol, entry, f, home, key_subj, run, sign_entry  # noqa: F401

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


# ── 1. eng-policy-validate-non-consuming ───────────────────────────────────
def test_policy_validate_does_not_consume_the_approval(tmp_path, operator, trust, ledger):
    raw = canonical.encode({"owned_assets": ["app"]})
    pp, pa = tmp_path / "policy.json", tmp_path / "policy-approval.json"
    pp.write_bytes(raw)
    ap = operator.approve(
        A.POLICY_CHANGE, {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}, "policy-prev:none"
    )
    save_approval_file(pa, ap)
    policy.validate_policy_file(pp, pa, trust, ledger, NOW + 1)
    assert ap.payload["nonce"] not in NonceLedger(ledger.path).entries  # read-only: nothing recorded
    assert policy.load_policy(pp, pa, trust, ledger, NOW + 2).owned_assets == ("app",)


# ── 2. eng-cli-run-id-validation ───────────────────────────────────────────
def test_run_id_must_be_a_uuid_even_if_the_path_exists(home, capsys):
    outside = cli.runs_dir().parent / "not-a-run"
    outside.mkdir(parents=True)
    (cli.runs_dir()).mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValidationError, match="lowercase UUID"):
        cli.run_path("../not-a-run")


# ── 3. eng-cli-input-size ──────────────────────────────────────────────────
def test_oversized_input_is_refused_before_it_is_read(tmp_path, monkeypatch):
    big = tmp_path / "big.json"
    big.write_bytes(b"{}" + b" " * 64)
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("oversized input was read into memory"))
    with pytest.raises(ValidationError, match="larger than"):
        cli.read_input(str(big), "config", limit=16)


# ── 4. eng-admin-enrol-only-when-empty ─────────────────────────────────────
def test_refused_second_enrolment_does_not_burn_its_approval(home, capsys, tmp_path):
    first = FakeOperator.make()
    assert enrol(home, capsys, tmp_path, first)[0] == 0
    second = FakeOperator.make()
    ap = second.approve(A.KEY_ROTATE, key_subj(second), f"trust:{EMPTY}")
    path = f(tmp_path, ap)
    code, out = run(home, capsys, "key", "enrol", "--key", f(tmp_path, _keyfile(second)), "--approval", path,
                    "--operator", "owner", "--expires-at", str(NOW + 365 * 86400))  # fmt: skip
    assert code == cli.EXIT_BLOCKED and out["code"] == "enrol_after_init"
    assert ap.payload["nonce"] not in NonceLedger().entries


def _keyfile(op: FakeOperator) -> dict[str, str]:
    return {
        "key_id": op.public.key_id,
        "algorithm": op.public.algorithm,
        "public_hex": op.public.public_raw.hex(),
    }


# ── 5. eng-admin-enrol-self-signed ─────────────────────────────────────────
def test_enrolment_signed_by_another_key_says_why(home, capsys, tmp_path):
    new, other = FakeOperator.make(), FakeOperator.make()
    code, out = enrol(home, capsys, tmp_path, new, signer=other)
    assert code == cli.EXIT_BLOCKED and out["code"] == "not_self_signed"


# ── 6. eng-dec-entry-expiry-at-use ─────────────────────────────────────────
def test_decision_entry_expires_before_its_approval(operator, trust, ledger):
    e = entry("c" * 64, "rev", expires_at=NOW + 600)
    d = decisions.build("suppress", sign_entry(operator, e, lifetime=86400), entry=e)
    decisions.verify_decision(d, trust, ledger, NOW + 1)
    with pytest.raises(BlockedError) as exc:
        decisions.verify_decision(d, trust, NonceLedger(ledger.path.with_name("other.json")), NOW + 601)
    assert exc.value.code == "expired"


# ── 7. eng-dec-compensating-controls-required ──────────────────────────────
@pytest.mark.parametrize("controls", ["", "x", "   "])
def test_accepted_risk_needs_real_compensating_controls(controls):
    with pytest.raises(ValidationError, match="compensating_controls"):
        decisions.validate_entry(entry("c" * 64, "rev", "accept_risk", compensating_controls=controls))


# ── 8. eng-dec-file-name-integrity ─────────────────────────────────────────
def test_renamed_decision_file_is_reported_not_applied(operator, tmp_path):
    e = entry("c" * 64, "rev")
    d = decisions.build("suppress", sign_entry(operator, e), entry=e)
    store = decisions.DecisionStore(tmp_path / "decisions")
    real = store.add(d)
    os.rename(real, real.with_name("suppress-" + "0" * 64 + ".json"))
    loaded, problems = store.load()
    assert loaded == [] and len(problems) == 1 and "file name" in problems[0]["problem"]


# ── 9 / 10. findings: suppression bound to its finding and to the signed entry ──
def _sup(operator, f_: Any, **kw: Any) -> tuple[dict[str, Any], Any]:
    e = {"kind": "suppress", "finding": f_.fingerprint, "revision": REV, "reason": "known test fixture",
         "author": "owner", "created_at": NOW, "expires_at": NOW + 3600, **kw}  # fmt: skip
    ap = operator.approve(A.SUPPRESS, {"type": "suppression_entry", "sha256": canonical.digest(e)}, REV,
                          rationale=e["reason"])  # fmt: skip
    return e, ap


def test_suppression_cannot_be_applied_to_another_finding(operator, trust, ledger):
    a, b = scanner_finding(rule="r1"), scanner_finding(rule="r2")
    e, ap = _sup(operator, a)
    with pytest.raises(BlockedError) as exc:
        F.apply_suppression(b, e, ap, trust, ledger, NOW + 1)
    assert exc.value.code == "wrong_subject" and b.suppression is None


@pytest.mark.parametrize("change", [{"expires_at": NOW + 9 * 86400}, {"author": "someone-else"}])
def test_suppression_entry_edited_after_signing_is_refused(operator, trust, ledger, change):
    fin = scanner_finding()
    e, ap = _sup(operator, fin)
    with pytest.raises(BlockedError):
        F.apply_suppression(fin, {**e, **change}, ap, trust, ledger, NOW + 1)
    assert fin.suppression is None


# ── 11. eng-reports-exclusions-listed ──────────────────────────────────────
def test_markdown_report_lists_exclusions(operator, trust, ledger):
    fin = scanner_finding()
    e, ap = _sup(operator, fin)
    F.apply_suppression(fin, e, ap, trust, ledger, NOW + 1)
    r = result()
    r["findings"] = [fin.to_json()]
    md = reports.to_markdown(r).decode()
    section = md.split("## Exclusions (suppressed and accepted risk)", 1)[1].split("##", 1)[0]
    assert fin.fingerprint[:16] in section and "None." not in section


# ── 12. eng-prep-rationale-is-reason ───────────────────────────────────────
def test_prepare_refuses_a_rationale_that_differs_from_the_entry_reason(operator, trust):
    e = entry("c" * 64, "rev")
    with pytest.raises(ValidationError, match="entry reason"):
        prepare.prepare("suppress", trust=trust, now=NOW, key_id=operator.public.key_id, lifetime=2 * 86400,
                        entry=e, rationale="a different, misleading rationale")  # fmt: skip


# ── 13 / 14. eng-dec-revocation-subject / -revision ────────────────────────
@pytest.mark.parametrize("wrong", ["subject", "revision"])
def test_revocation_for_something_else_is_unverifiable_not_revoked(operator, trust, tmp_path, wrong):
    e = entry("c" * 64, "rev")
    d = decisions.build("suppress", sign_entry(operator, e), entry=e)
    store = decisions.DecisionStore(tmp_path / "decisions")
    store.add(d)
    subject = decisions.revocation_subject(d)
    revision = d.revision
    if wrong == "subject":
        subject = {**subject, "entry_sha256": "0" * 64}
    else:
        revision = "some-other-revision"
    rv = operator.approve(A.REVOKE_RECORD, subject, revision, rationale="withdrawn by owner after review")
    store.revocations.mkdir(parents=True, exist_ok=True)
    save_approval_file(store.revocation_path(d.decision_id), rv)
    assert store.revocation_state(d, trust) == "unverifiable"


# ── 15 / 16. eng-red-cli-output / eng-red-cli-raw-output ───────────────────
@pytest.fixture
def cli_deps() -> cli.Deps:
    from sentinel.keys.runkey import RunKeyManager

    from .test_cli import HOST

    backend = MemBackend()
    return cli.Deps(
        run_keys=lambda: RunKeyManager(backend),
        host=lambda: HOST,
        clock=lambda: NOW,
        env={},
        agent_version=lambda a: None,
        adapters=FIXTURE_ONLY,
    )


@pytest.mark.parametrize("as_json", [True, False])
def test_cli_redacts_structured_output_last(cli_deps, capsys, monkeypatch, as_json):
    # The payload is valid for the `version` contract (D-40) but carries secrets in string fields.
    def cmd_version(a, d):
        return 0, {
            "sentinel_version": "0",
            "schema_version": "1.0",
            "python": f"token={SECRET}",
            "platform": SECRET,
            "machine": "x",
        }

    monkeypatch.setattr(cli, "cmd_version", cmd_version)
    assert cli.main(["--json", "version"] if as_json else ["version"], cli_deps) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and "[REDACTED:" in out


def test_cli_withholds_output_that_violates_its_contract(cli_deps, capsys, monkeypatch):
    """D-40: a payload outside its command's contract is never printed (exit 7)."""

    def cmd_version(a, d):
        return 0, {"note": "not a version payload", "nested": ["x"]}

    monkeypatch.setattr(cli, "cmd_version", cmd_version)
    assert cli.main(["--json", "version"], cli_deps) == cli.EXIT_INTERNAL
    captured = capsys.readouterr()
    assert captured.out == "" and "schema_violation" in captured.err


def test_cli_redacts_raw_output_last(cli_deps, capsys, monkeypatch):
    monkeypatch.setattr(cli, "cmd_report", lambda a, d: (0, {"_raw": f"token: {SECRET}\n".encode()}))
    assert cli.main(["report", "r", "--format", "md"], cli_deps) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and "[REDACTED:" in out


# ── 17. eng-red-key-length ─────────────────────────────────────────────────
@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_malformed_redaction_key_file_is_refused_on_load(size):
    p = redaction.redaction_key_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"k" * size)
    with pytest.raises(RedactionError, match="malformed"):
        redaction.load_or_create_key()


def test_init_refuses_a_corrupt_redaction_key(cli_deps, capsys):
    p = redaction.redaction_key_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"short")
    assert cli.main(["--json", "init"], cli_deps) == cli.EXIT_INTERNAL
    assert json.loads(capsys.readouterr().out)["error"] == "redaction_failed"


# ── 18. eng-red-custom-empty-match ─────────────────────────────────────────
@pytest.mark.parametrize("regex", ["^(?!x)", "a*", "(?:)"])
def test_custom_pattern_that_matches_empty_input_is_refused(regex):
    with pytest.raises(ValidationError, match="empty input"):
        redaction.compile_custom([{"name": "t", "regex": regex}])
