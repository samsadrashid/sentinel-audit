"""D-40 boundary wiring: for every artifact, a schema failure fails closed.

Each test forces exactly one contract to fail (by intercepting the validator's root call for that
contract) and asserts that the protected step never happens: no trust decision, nothing persisted,
nothing signed, nothing printed, and never PASS.
"""

# ruff: noqa: F811  (pytest fixtures imported from sibling test modules)
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sentinel import approvals, canonical, cli, decisions, policy, reports, schema
from sentinel.domain.enums import ApprovalAction as A
from sentinel.domain.enums import CheckStatus
from sentinel.errors import IntegrityError, ValidationError
from sentinel.keys.operator import TrustStore
from sentinel.orchestrator import run_audit
from sentinel.schema import SchemaError, SchemaViolation

from .conftest import NOW, FakeOperator
from .test_cli import audit as cli_audit
from .test_cli import deps, ready  # noqa: F401
from .test_pipeline import cfg, make_target, request

SIGNED = Path(__file__).parent / "fixtures/schemas/historical/signed"


@pytest.fixture
def fail_contract(monkeypatch):
    """Make validation of one named contract fail at its root."""

    def arm(name: str) -> None:
        real = schema._errors

        def forced(ctx, v, s, file, path, depth):  # type: ignore[no-untyped-def]
            if depth == 0 and path == "$" and file == name:
                return "$: forced failure for boundary test"
            return real(ctx, v, s, file, path, depth)

        monkeypatch.setattr(schema, "_errors", forced)

    return arm


# ── inputs ─────────────────────────────────────────────────────────────────
def test_audit_config_boundary(ready, capsys, tmp_path, fail_contract):
    fail_contract("audit-config")
    code, out = cli_audit(ready, capsys, tmp_path)
    assert code == cli.EXIT_INVALID and out["code"] == "schema_invalid"
    assert not any((cli.runs_dir()).glob("*")) if cli.runs_dir().exists() else True


def test_policy_boundary_blocks_before_applied_record(tmp_path, operator, trust, ledger, fail_contract):
    raw = canonical.encode({"owned_assets": ["x"]})
    pf = tmp_path / "p.json"
    pf.write_bytes(raw)
    ap = operator.approve(
        A.POLICY_CHANGE, {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}, "policy-prev:none"
    )
    af = tmp_path / "p.ap.json"
    approvals.save_approval_file(af, ap)
    fail_contract("policy")
    with pytest.raises(SchemaError):
        policy.validate_policy_file(pf, af, trust, ledger, NOW + 1)


def test_applied_policy_boundary(fail_contract, tmp_path):
    p = policy._applied_policy_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(canonical.encode({"current": None, "previous": None}))
    fail_contract("applied-policy")
    with pytest.raises(SchemaError):
        policy._expected_previous("a" * 64)


def test_authorization_record_boundary(operator, trust, ledger, fail_contract):
    from sentinel import authorization

    from .test_authorization_policy import approve_record, record

    rec = record()
    ap = approve_record(operator, rec)
    fail_contract("authorization-record")
    with pytest.raises(SchemaError):
        authorization.verify_record(rec, ap, trust, ledger, NOW + 1, policy.Policy(owned_assets=("app",)))


def test_approval_file_boundary(fail_contract):
    fail_contract("approval")
    with pytest.raises(SchemaError):
        approvals.load_approval_file(SIGNED / "policy.approval.json")


def test_decision_file_boundary_never_applies(tmp_path, fail_contract):
    import shutil

    shutil.copytree(SIGNED / "decisions", tmp_path / "decisions")
    store = decisions.DecisionStore(tmp_path / "decisions")
    assert len(store.load()[0]) == 3
    fail_contract("decision")
    loaded, problems = store.load()
    assert loaded == [] and len(problems) == 3


def test_operator_key_file_boundary(fail_contract):
    from sentinel import admin

    op = FakeOperator.make()
    data = {
        "key_id": op.public.key_id,
        "algorithm": op.public.algorithm,
        "public_hex": op.public.public_raw.hex(),
    }
    admin.parse_key_file(data)
    fail_contract("operator-public-key")
    with pytest.raises(SchemaError):
        admin.parse_key_file(data)


def test_trust_store_boundary_trusts_nothing(tmp_path, fail_contract):
    from .test_d49_signing import _legacy_p256_store

    p = tmp_path / "trust.json"
    _legacy_p256_store(p)
    assert TrustStore(p).fingerprint()
    fail_contract("trust-store")
    with pytest.raises(SchemaError):
        TrustStore(p)


def test_nonce_ledger_boundary(tmp_path, fail_contract):
    p = tmp_path / "n.json"
    p.write_bytes((SIGNED / "nonces.json").read_bytes())
    fail_contract("nonce-ledger")
    with pytest.raises(SchemaError):
        approvals.NonceLedger(p)


def test_malformed_ledger_fails_closed_without_forcing(tmp_path):
    p = tmp_path / "n.json"
    p.write_bytes(canonical.encode({"nonces": {"zz": {}}, "revoked": []}))
    with pytest.raises(ValidationError):
        approvals.NonceLedger(p)


def test_run_key_metadata_boundary(ready, fail_contract):
    from sentinel.keys.runkey import run_public_key

    assert run_public_key() is not None
    fail_contract("run-key-metadata")
    with pytest.raises(SchemaError):
        run_public_key()


def test_log_entry_boundary_is_integrity_error(tmp_path, fail_contract):
    from sentinel.evidence import AuditLog

    log = AuditLog(tmp_path / "log.jsonl")
    log.append("x", {})
    fail_contract("log-entry")
    with pytest.raises((IntegrityError, SchemaViolation)):
        log.head()


# ── engine pipeline ────────────────────────────────────────────────────────
def test_adapter_findings_boundary_is_check_error_never_pass(tmp_path, trust, ledger, fail_contract):
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    fail_contract("adapter-findings")
    out = run_audit(request(tmp_path, trust, ledger, cfg(t)))
    c = out.checks[0]
    assert c.status == CheckStatus.ERROR and c.reason == "schema_invalid"
    assert out.findings == [] and out.overall != "PASS"
    ev = out.run_dir / "evidence"
    assert not ev.exists() or not any(ev.iterdir())


def test_malformed_adapter_findings_without_forcing(tmp_path, trust, ledger):
    from sentinel.adapters.base import ExecutionResult
    from sentinel.adapters.fixture import FixtureAdapter

    from .test_pipeline import ALLOW

    t = make_target(tmp_path, "t", "x")

    class Bad(FixtureAdapter):
        def execute(self, check, root, timeout_s, max_output, runner=None):  # type: ignore[override]
            return ExecutionResult(
                CheckStatus.FAIL, raw_output=b"x", findings=[{"rule": "r"}], isolation=runner.name
            )

    out = run_audit(request(tmp_path, trust, ledger, cfg(t), adapters=[Bad(allowlisted_sha256=ALLOW)]))
    assert out.checks[0].status == CheckStatus.ERROR and out.checks[0].reason == "schema_invalid"
    assert out.findings == [] and out.overall != "PASS"


@pytest.mark.parametrize(
    "contract_name",
    ["evidence-record", "audit-result", "run-manifest", "manifest-signature", "sarif-profile"],
)
def test_output_violations_stop_before_signing_or_writing(
    tmp_path, trust, ledger, fail_contract, contract_name, monkeypatch
):
    from sentinel.crypto.signing import Ed25519Signer

    signed: list[bytes] = []
    real_sign = Ed25519Signer.sign
    t = make_target(tmp_path, "t", "SENTINEL-FIXTURE-FINDING\n")
    fail_contract(contract_name)

    def spy(self, msg):  # type: ignore[no-untyped-def]
        if msg.startswith(b"sentinel/v1/run/manifest"):
            signed.append(msg)
        return real_sign(self, msg)

    monkeypatch.setattr(Ed25519Signer, "sign", spy)
    with pytest.raises(SchemaViolation):
        run_audit(request(tmp_path, trust, ledger, cfg(t)))
    runs = list((tmp_path / "runs").iterdir())
    assert len(runs) == 1
    run = runs[0]
    if contract_name in ("evidence-record", "audit-result", "run-manifest"):
        assert signed == [] and not (run / "manifest.json").exists()
    if contract_name == "evidence-record":
        assert not any((run / "evidence").iterdir())
    if contract_name == "manifest-signature":
        assert not (run / "manifest.sig.json").exists()
    if contract_name == "sarif-profile":
        assert not (run / "reports" / "report.sarif").exists()
    else:
        assert not (run / "reports").exists() or not any((run / "reports").iterdir())


def test_stored_result_boundary(ready, capsys, tmp_path, fail_contract):
    code, out = cli_audit(ready, capsys, tmp_path, content="SENTINEL-FIXTURE-FINDING\n")
    rid = out["audit_id"]
    fail_contract("audit-result")
    with pytest.raises(IntegrityError, match="stored result malformed"):
        cli.verified_run(rid)


def test_manifest_read_boundary(ready, capsys, tmp_path, fail_contract):
    code, out = cli_audit(ready, capsys, tmp_path)
    fail_contract("run-manifest")
    with pytest.raises(IntegrityError, match="manifest malformed"):
        cli.verified_run(out["audit_id"])


def test_manifest_signature_read_boundary(ready, capsys, tmp_path, fail_contract):
    code, out = cli_audit(ready, capsys, tmp_path)
    fail_contract("manifest-signature")
    with pytest.raises(IntegrityError, match="signature file malformed"):
        cli.verified_run(out["audit_id"])


# ── persistence of state ───────────────────────────────────────────────────
def test_state_writes_refuse_malformed_output(tmp_path, fail_contract):
    t = TrustStore(tmp_path / "trust.json")
    led = approvals.NonceLedger(tmp_path / "n.json")
    fail_contract("trust-store")
    with pytest.raises(SchemaViolation):
        t.save()
    assert not (tmp_path / "trust.json").exists()
    fail_contract("nonce-ledger")
    with pytest.raises(SchemaViolation):
        led.save(NOW)
    assert not (tmp_path / "n.json").exists()


def test_approval_and_decision_writes_refuse_malformed_output(tmp_path, operator, fail_contract):
    ap = operator.approve(A.SUPPRESS, {"type": "finding", "fingerprint": "f" * 64}, "r")
    fail_contract("approval")
    with pytest.raises(SchemaViolation):
        approvals.save_approval_file(tmp_path / "a.json", ap)
    assert not (tmp_path / "a.json").exists()


def test_decision_store_add_refuses_malformed(tmp_path, operator, fail_contract):
    e = {
        "kind": "suppress",
        "finding": "c" * 64,
        "revision": "r",
        "reason": "test fixture finding",
        "author": "o",
        "created_at": NOW,
        "expires_at": NOW + 60,
    }
    ap = operator.approve(
        A.SUPPRESS, {"type": "suppression_entry", "sha256": canonical.digest(e)}, "r", rationale=e["reason"]
    )
    d = decisions.build("suppress", ap, entry=e)
    store = decisions.DecisionStore(tmp_path / "decisions")
    fail_contract("decision")
    with pytest.raises(SchemaViolation):
        store.add(d)
    assert not (tmp_path / "decisions").exists() or not any((tmp_path / "decisions").iterdir())


def test_cli_error_envelope_and_command_contracts_cover_every_command():
    defs = schema.ensure_loaded().contracts["cli-output"]["$defs"]
    names = {n for n in dir(cli) if n.startswith("cmd_")}
    assert set(cli.CLI_CONTRACT) == names
    assert set(cli.CLI_CONTRACT.values()) <= set(defs)
    assert "error" in defs


def test_printed_cli_output_is_valid(ready, capsys, tmp_path):
    for argv in (
        ["version"],
        ["status"],
        ["runs", "list"],
        ["key", "list"],
        ["decisions", "list"],
        ["history", "verify"],
    ):
        code = cli.main(["--json", *argv], ready)
        out = json.loads(capsys.readouterr().out)
        if "error" in out:
            schema.validate(out, "cli-output", "error")
        else:
            schema.validate(out, "cli-output", cli.CLI_CONTRACT["cmd_" + "_".join(argv)])
        assert isinstance(code, int)


def _unused(_: Any) -> None:  # keep imports used for type context
    return None


# ── order: strict decoding → schema → domain (nothing downstream runs on schema-invalid data) ──
@pytest.fixture
def tripwire(monkeypatch):
    """Replace downstream steps with functions that fail the test if they are ever reached."""
    reached: list[str] = []

    def arm(target: Any, name: str, *, classmethod_: bool = False) -> None:
        def boom(*a: Any, **k: Any) -> Any:
            reached.append(f"{getattr(target, '__name__', target)}.{name}")
            raise AssertionError(f"{name} reached on schema-invalid data")

        monkeypatch.setattr(target, name, classmethod(boom) if classmethod_ else boom)

    arm.reached = reached  # type: ignore[attr-defined]
    return arm


def _no_storage(tripwire):  # type: ignore[no-untyped-def]
    from sentinel import paths
    from sentinel.keys import operator as op_mod

    tripwire(paths, "atomic_write")
    tripwire(op_mod, "atomic_write")
    tripwire(approvals, "atomic_write")


def _no_signature_or_trust(tripwire):  # type: ignore[no-untyped-def]
    from sentinel.crypto.signing import PublicKey

    tripwire(PublicKey, "verify")
    tripwire(approvals, "verify")


def test_order_audit_config(ready, capsys, tmp_path, fail_contract, tripwire):
    from sentinel.domain.models import AuditConfig

    tripwire(AuditConfig, "from_dict", classmethod_=True)
    tripwire(policy, "load_policy")
    fail_contract("audit-config")
    code, out = cli_audit(ready, capsys, tmp_path)
    assert code == cli.EXIT_INVALID and out["code"] == "schema_invalid"
    assert tripwire.reached == []


@pytest.mark.parametrize("consume", [True, False])
def test_order_policy_before_approval_nonce_or_state(
    tmp_path, operator, trust, ledger, fail_contract, tripwire, consume
):
    raw = canonical.encode({"owned_assets": ["x"]})
    pf, af = tmp_path / "p.json", tmp_path / "p.ap.json"
    pf.write_bytes(raw)
    ap = operator.approve(
        A.POLICY_CHANGE, {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}, "policy-prev:none"
    )
    approvals.save_approval_file(af, ap)
    fail_contract("policy")
    tripwire(policy, "_verify_policy_approval")
    _no_signature_or_trust(tripwire)
    _no_storage(tripwire)
    with pytest.raises(SchemaError):
        (policy.load_policy if consume else policy.validate_policy_file)(pf, af, trust, ledger, NOW + 1)
    assert tripwire.reached == []


def test_real_invalid_policy_consumes_no_nonce_and_writes_no_state(tmp_path, operator, trust, ledger):
    raw = canonical.encode({"owned_assets": ["x"], "limits": {"max_runtime_s": "ten"}})
    pf, af = tmp_path / "p.json", tmp_path / "p.ap.json"
    pf.write_bytes(raw)
    ap = operator.approve(
        A.POLICY_CHANGE, {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}, "policy-prev:none"
    )
    approvals.save_approval_file(af, ap)
    before = dict(ledger.entries)
    with pytest.raises(SchemaError):
        policy.load_policy(pf, af, trust, ledger, NOW + 1)
    assert ledger.entries == before and not policy._applied_policy_path().exists()


def test_order_authorization_record(operator, trust, ledger, fail_contract, tripwire):
    from sentinel import authorization

    from .test_authorization_policy import approve_record, record

    rec = record()
    ap = approve_record(operator, rec)
    fail_contract("authorization-record")
    _no_signature_or_trust(tripwire)
    tripwire(authorization, "record_scope")
    with pytest.raises(SchemaError):
        authorization.verify_record(rec, ap, trust, ledger, NOW + 1, policy.Policy(owned_assets=("app",)))
    assert tripwire.reached == []


def test_domain_classifications_survive_for_shape_valid_records(operator, trust, ledger):
    """Business rules stay domain errors: the schema checks shape only, so B3 is still `b3_prohibited`."""
    from sentinel import authorization
    from sentinel.errors import BlockedError

    from .test_authorization_policy import approve_record, record

    rec = record(permitted_activities=["B3"])
    with pytest.raises(BlockedError) as exc:
        authorization.verify_record(
            rec, approve_record(operator, rec), trust, ledger, NOW + 1, policy.Policy(owned_assets=("app",))
        )
    assert exc.value.code == "b3_prohibited"


def test_order_approval(fail_contract, tripwire):
    import base64 as b64

    fail_contract("approval")
    _no_signature_or_trust(tripwire)
    tripwire(b64, "b64decode")  # the domain step decodes the signature
    with pytest.raises(SchemaError):
        approvals.load_approval_file(SIGNED / "policy.approval.json")
    assert tripwire.reached == []


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda p: p.update(action="allowlist.change"), "unknown approval action"),
        (lambda p: p.update(context="sentinel/v1/approval/key.rotate"), "context does not match"),
    ],
)
def test_approval_schema_failures_keep_their_classification(change, message, tripwire):
    data = json.loads((SIGNED / "policy.approval.json").read_text())
    change(data["payload"])
    _no_signature_or_trust(tripwire)
    with pytest.raises(SchemaError, match=message) as exc:
        approvals.Approval.from_json(data)
    assert isinstance(exc.value, ValidationError) and exc.value.code == "schema_invalid"


def test_order_decision(tmp_path, fail_contract, tripwire):
    import shutil

    shutil.copytree(SIGNED / "decisions", tmp_path / "decisions")
    fail_contract("decision")
    tripwire(approvals.Approval, "from_json", classmethod_=True)
    _no_signature_or_trust(tripwire)
    loaded, problems = decisions.DecisionStore(tmp_path / "decisions").load()
    assert loaded == [] and len(problems) == 3 and tripwire.reached == []


def test_order_operator_key_file(fail_contract, tripwire):
    from sentinel import admin
    from sentinel.crypto.signing import P256, PublicKey

    op = FakeOperator.make(P256)
    data = {"key_id": op.public.key_id, "algorithm": P256, "public_hex": op.public.public_raw.hex()}
    admin.parse_key_file(data)
    fail_contract("operator-public-key")
    tripwire(PublicKey, "from_raw", classmethod_=True)
    with pytest.raises(SchemaError):
        admin.parse_key_file(data)
    assert tripwire.reached == []


def test_order_trust_store(tmp_path, fail_contract, tripwire):
    from sentinel.keys import operator as op_mod

    p = tmp_path / "trust.json"
    p.write_bytes((SIGNED / "trust.json").read_bytes())
    fail_contract("trust-store")
    tripwire(op_mod, "_key_from_json")
    with pytest.raises(SchemaError):
        TrustStore(p)
    assert tripwire.reached == []


def test_order_manifest_before_signature_verification(ready, capsys, tmp_path, fail_contract, tripwire):
    from sentinel.crypto.signing import PublicKey

    code, out = cli_audit(ready, capsys, tmp_path)
    fail_contract("run-manifest")
    tripwire(PublicKey, "verify")
    with pytest.raises(IntegrityError, match="manifest malformed"):
        cli.verified_run(out["audit_id"])
    assert tripwire.reached == []


def test_order_stored_result_before_comparison(ready, capsys, tmp_path, fail_contract, monkeypatch):
    code, out = cli_audit(ready, capsys, tmp_path)
    rid = out["audit_id"]
    real = canonical.digest
    calls: list[Any] = []
    fail_contract("audit-result")
    monkeypatch.setattr(canonical, "digest", lambda o: calls.append(o) or real(o))
    with pytest.raises(IntegrityError, match="stored result malformed"):
        cli.verified_run(rid)
    assert not any(isinstance(c, dict) and "overall_result" in c for c in calls)


# ── raw CLI output (`report` bodies) ─────────────────────────────────────
@pytest.mark.parametrize("fmt", ["json", "sarif", "md", "html"])
def test_raw_report_bodies_print_and_json_ones_match_their_contract(ready, capsys, tmp_path, fmt):
    code, out = cli_audit(ready, capsys, tmp_path, content="SENTINEL-FIXTURE-FINDING\n")
    assert cli.main(["report", out["audit_id"], "--format", fmt], ready) == 0
    body = capsys.readouterr().out.encode()
    if fmt in cli.RAW_CONTRACT:
        schema.validate(canonical.decode_strict(body), cli.RAW_CONTRACT[fmt])
    else:
        with pytest.raises(ValueError):
            json.loads(body)


@pytest.mark.parametrize(
    "argv, fn, body",
    [
        (["version"], "cmd_version", b'{"exit_code": 0, "anything": true}'),  # JSON via raw from elsewhere
        (["report", "r", "--format", "md"], "cmd_report", b'{"overall_result": "PASS"}'),  # JSON as text
        (["report", "r", "--format", "json"], "cmd_report", b'{"overall_result": "PASS"}'),  # off-contract
        (["report", "r", "--format", "json"], "cmd_report", b"not json"),
        (["report", "r", "--format", "sarif"], "cmd_report", b'{"version": "2.1.0"}'),
        (["report", "r", "--format", "md"], "cmd_report", "text, not bytes"),
    ],
)
def test_raw_output_cannot_bypass_contract_validation(ready, capsys, monkeypatch, argv, fn, body):
    monkeypatch.setattr(cli, fn, lambda a, d: (0, {"_raw": body}))
    assert cli.main(argv, ready) == cli.EXIT_INTERNAL
    cap = capsys.readouterr()
    assert cap.out == "" and "output withheld" in cap.err  # str bodies already fail redaction


def test_report_file_output_is_checked_before_writing(ready, capsys, tmp_path, monkeypatch):
    code, out = cli_audit(ready, capsys, tmp_path)
    monkeypatch.setitem(reports.RENDERERS, "json", lambda r: b'{"overall_result": "PASS"}')
    dest = tmp_path / "r.json"
    assert cli.main(["report", out["audit_id"], "--format", "json", "--output", str(dest)], ready) != 0
    assert not dest.exists()


# ── targeted kills for boundaries the generic tests left uncovered ─────────
def test_parse_policy_validates_on_its_own(fail_contract):
    """`_parse_policy` is also reached from `prepare` without the load-time precheck."""
    fail_contract("policy")
    with pytest.raises(SchemaError):
        policy._parse_policy(canonical.encode({"owned_assets": ["x"]}), "t")


def test_applied_policy_write_is_checked(tmp_path, operator, trust, ledger, monkeypatch):
    raw = canonical.encode({"owned_assets": ["x"]})
    pf, af = tmp_path / "p.json", tmp_path / "p.ap.json"
    pf.write_bytes(raw)
    ap = operator.approve(
        A.POLICY_CHANGE, {"type": "policy_file", "sha256": canonical.sha256_hex(raw)}, "policy-prev:none"
    )
    approvals.save_approval_file(af, ap)
    real = schema._errors

    def forced(ctx, v, s, file, path, depth):  # type: ignore[no-untyped-def]
        if depth == 0 and file == "applied-policy" and isinstance(v, dict) and v.get("current"):
            return "$: forced output failure"
        return real(ctx, v, s, file, path, depth)

    monkeypatch.setattr(schema, "_errors", forced)
    with pytest.raises(SchemaViolation):
        policy.load_policy(pf, af, trust, ledger, NOW + 1)
    assert not policy._applied_policy_path().exists()


def test_stored_result_unsupported_version_is_reported_as_such(ready, capsys, tmp_path):
    code, out = cli_audit(ready, capsys, tmp_path)
    report = cli.run_path(out["audit_id"]) / "reports" / "report.json"
    data = canonical.decode_strict(report.read_bytes())
    data["schema_version"] = "2.0"
    report.write_bytes(canonical.encode(data))
    with pytest.raises(SchemaError) as exc:
        cli.verified_run(out["audit_id"])
    assert exc.value.code == "unsupported_version"


def test_manifest_unsupported_version_is_reported_before_signature_check(ready, capsys, tmp_path):
    from sentinel.crypto.signing import PublicKey

    code, out = cli_audit(ready, capsys, tmp_path)
    mf = cli.run_path(out["audit_id"]) / "manifest.json"
    data = canonical.decode_strict(mf.read_bytes())
    data["schema_version"] = "2.0"
    mf.write_bytes(canonical.encode(data))
    real_verify = PublicKey.verify
    called: list[int] = []
    PublicKey.verify = lambda *a, **k: called.append(1) or real_verify(*a, **k)  # type: ignore[method-assign]
    try:
        with pytest.raises(SchemaError) as exc:
            cli.verified_run(out["audit_id"])
    finally:
        PublicKey.verify = real_verify  # type: ignore[method-assign]
    assert exc.value.code == "unsupported_version" and called == []


def test_first_log_entry_is_checked_before_append(tmp_path, fail_contract):
    from sentinel.evidence import AuditLog

    log = AuditLog(tmp_path / "log.jsonl")
    fail_contract("log-entry")
    with pytest.raises(SchemaViolation):
        log.append("audit.started", {})
    assert not (tmp_path / "log.jsonl").exists()


def test_run_key_metadata_checked_before_secret_or_file_is_stored(tmp_path, fail_contract):
    from sentinel.keys.runkey import RunKeyManager
    from sentinel.paths import state_dir

    from .test_cli import MemBackend

    be = MemBackend()
    fail_contract("run-key-metadata")
    with pytest.raises(SchemaViolation):
        RunKeyManager(be).create()
    assert be.data == {} and not (state_dir() / "keys" / "run-key.json").exists()


@pytest.mark.parametrize("raw", [b"plain text", b'{"a": 1}'])
def test_raw_output_refused_for_any_command_but_report(raw):
    import argparse

    for fmt in ("md", "json"):
        args = argparse.Namespace(fn=cli.cmd_version, format=fmt)
        with pytest.raises(SchemaViolation, match="only allowed for `report`"):
            cli._check_raw_output(args, raw)
