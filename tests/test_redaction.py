"""Redaction engine and AUD-16 regression tests. All secrets here are synthetic."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from sentinel import approvals, canonical, cli, policy, redaction
from sentinel.adapters.base import ExecutionResult
from sentinel.adapters.fixture import FIXTURE_SCRIPT, FixtureAdapter, script_sha256
from sentinel.crypto.signing import Ed25519Signer
from sentinel.domain.enums import ApprovalAction as A
from sentinel.domain.enums import CheckStatus
from sentinel.domain.models import AuditConfig
from sentinel.errors import BlockedError, ValidationError
from sentinel.orchestrator import AuditRequest, run_audit
from sentinel.redaction import RedactionError, Redactor

from .conftest import NOW, FakeOperator, resign
from .isolation_testing import make_test_host

KEY = b"k" * 32
R = Redactor(KEY)

# Synthetic secrets (never real credentials).
AWS_ID = "AKIA" + "Q" * 16
GH = "ghp_" + "a1B2" * 9
SLACK = "xoxb-" + "1234567890-abcdefghij"
STRIPE = "sk_live_" + "Z" * 24
GOOGLE = "AIza" + "S" * 35
ANTHROPIC = "sk-ant-api03-" + "x" * 40
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVlLXg"
PW = "Tr0ub4dor&3-horse"
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MmOWzEXAMPLEonly\n"
    "c2VjcmV0LWtleS1ib2R5LXN5bnRoZXRpYw==\n"
    "-----END RSA PRIVATE KEY-----"
)
ALL = [AWS_ID, GH, SLACK, STRIPE, GOOGLE, ANTHROPIC, JWT, PW]


def red(s: str) -> tuple[str, dict[str, int]]:
    return R.redact_text(s)


# ── known formats ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "text,secret,rule",
    [
        (f"key id {AWS_ID} in log", AWS_ID, "aws_access_key_id"),
        (f"push with {GH}", GH, "github_token"),
        ("token glpat-" + "a" * 20, "glpat-" + "a" * 20, "gitlab_token"),
        (f"slack {SLACK}", SLACK, "slack_token"),
        (f"stripe {STRIPE}", STRIPE, "stripe_key"),
        (f"maps {GOOGLE}", GOOGLE, "google_api_key"),
        (f"claude {ANTHROPIC}", ANTHROPIC, "anthropic_key"),
        ("openai sk-proj-" + "q" * 30, "sk-proj-" + "q" * 30, "openai_key"),
        ("npm npm_" + "n" * 36, "npm_" + "n" * 36, "npm_token"),
        (f"session {JWT}", JWT, "jwt"),
        ("DefaultEndpointsProtocol=https;AccountKey=" + "A" * 86 + "==;", "A" * 86, "azure_account_key"),
        ("https://acct.blob.core.windows.net/c?sv=2020&sig=" + "s" * 40, "s" * 40, "azure_sas_signature"),
        (f"password={PW}", PW, "credential_assignment"),
        (f"db_passwd: {PW}", PW, "credential_assignment"),
        (f'"client_secret": "{PW}"', PW, "credential_assignment"),
        (f"aws_secret_access_key = {'w' * 40}", "w" * 40, "credential_assignment"),
    ],
)
def test_known_formats(text, secret, rule):
    out, counts = red(text)
    assert secret not in out and f"[REDACTED:{rule}:" in out and counts.get(rule) == 1


def test_multiline_escaped_and_truncated_private_keys():
    for pem in (PEM, PEM.replace("RSA ", ""), PEM.replace("RSA", "OPENSSH"), PEM.replace("RSA", "ENCRYPTED")):
        out, c = red(f"before\n{pem}\nafter")
        assert (
            "MIIE" not in out and out.startswith("before\n[REDACTED:private_key:") and out.endswith("\nafter")
        )
    escaped = json.dumps({"private_key": PEM})  # GCP service-account style, \n escaped
    assert "MIIE" not in red(escaped)[0]
    truncated, _ = red(PEM.split("-----END")[0])  # no END marker: redact to end of input
    assert "MIIE" not in truncated and "c2Vj" not in truncated


def test_nested_json_and_yaml():
    doc = {
        "db": {"url": f"postgres://app:{PW}@db.local/x", "items": [{"api_key": GH}, {"note": "fine"}]},
        "auth": {"token": STRIPE},
        "enabled": True,
        "count": 3,
        "nothing": None,
    }
    out = R.redact_obj(doc)
    blob = json.dumps(out)
    assert all(s not in blob for s in (PW, GH, STRIPE))
    assert out["enabled"] is True and out["count"] == 3 and out["db"]["items"][1]["note"] == "fine"
    yaml = f"database:\n  user: app\n  password: {PW}\napi:\n  token: '{GH}'\nlist:\n  - secret: {STRIPE}\n"
    y, _ = red(yaml)
    assert all(s not in y for s in (PW, GH, STRIPE)) and "user: app" in y


def test_env_file_and_placeholders():
    env = (
        f"export AWS_SECRET_ACCESS_KEY={'w' * 40}\nDATABASE_URL=postgres://u:{PW}@h/db\n"
        f'MY_TOKEN="quoted value with spaces"\nDEBUG=true\nPASSWORD=\nAPI_KEY=null\n'
    )
    out, _ = red(env)
    assert "w" * 40 not in out and PW not in out and "quoted value" not in out
    assert "DEBUG=true" in out and "PASSWORD=\n" in out and "API_KEY=[REDACTED" in out  # env lines are strict


def test_authorization_headers_and_connection_strings():
    for h in (
        f"Authorization: Bearer {JWT}",
        "authorization: Basic " + base64.b64encode(b"u:p4ss").decode(),
        "Proxy-Authorization: token abcd1234efgh",
        f'{{"Authorization": "Bearer {GH}"}}',
    ):
        out, c = red(h)
        assert "[REDACTED:" in out and h.split()[-1].strip('"}') not in out
        assert ("Bearer" in out) == ("Bearer" in h) and ("Basic" in out) == ("Basic" in h)
    for url in (f"mysql://root:{PW}@10.0.0.5:3306/db", f"redis://:{PW}@cache:6379", f"amqp://u:{PW}@mq/v"):
        out, _ = red(url)
        assert PW not in out and "@" in out and out.split("://")[0] in url


def test_encoded_malformed_and_unicode_input():
    raw = b"\xff\xfe garbage " + GH.encode() + b" \xc3\x28 more " + AWS_ID.encode()
    out, counts = R.redact_bytes(raw)
    assert GH.encode() not in out and AWS_ID.encode() not in out and out.startswith(b"\xff\xfe")
    u, _ = red(f"пароль 🔑 password={PW} — ключ {GH}\nzweite Zeile")
    assert PW not in u and GH not in u and "🔑" in u and "zweite Zeile" in u
    b64 = base64.b64encode(GH.encode()).decode()
    assert red(f"blob {b64}")[0] == f"blob {b64}"  # documented blind spot: encoded secrets aren't detected


def test_markers_are_deterministic_keyed_and_idempotent():
    out1, _ = red(f"a {GH} b {GH}")
    markers = [w for w in out1.split() if w.startswith("[REDACTED")]
    assert len(markers) == 2 and markers[0] == markers[1]
    assert Redactor(b"j" * 32).redact_text(GH)[0] != R.redact_text(GH)[0]  # keyed, not a plain hash
    import hashlib

    assert hashlib.sha256(GH.encode()).hexdigest()[:12] not in out1
    for s in [f"password={PW}", f"Authorization: Bearer {JWT}", PEM, json.dumps({"token": GH})]:
        once, _ = red(s)
        twice, c = red(once)
        assert twice == once and c == {}


def test_oversized_and_bad_input_fail_closed(monkeypatch):
    monkeypatch.setattr(redaction, "MAX_REDACT_BYTES", 100)
    with pytest.raises(RedactionError):
        R.redact_bytes(b"x" * 101)
    with pytest.raises(RedactionError):
        R.redact_obj({"x": object()})
    with pytest.raises(RedactionError):
        R.redact_bytes("not bytes")  # type: ignore[arg-type]
    with pytest.raises(RedactionError):
        Redactor(b"short")


def test_key_file_problems_fail_closed():
    p = redaction.redaction_key_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"too short")
    with pytest.raises(RedactionError):
        Redactor.default()
    p.unlink()
    target = p.with_name("elsewhere")
    target.write_bytes(b"k" * 32)
    p.symlink_to(target)
    with pytest.raises(RedactionError):
        Redactor.default()


# ── custom patterns ────────────────────────────────────────────────────────
def test_custom_patterns_apply_and_validate():
    pol = policy._parse_policy(
        canonical.encode({"redaction_patterns": [{"name": "acme_id", "regex": "ACME-[0-9]{6}"}]}), "t"
    )
    r = Redactor(KEY, redaction.compile_custom(pol.redaction_patterns))
    out, c = r.redact_text("order ACME-123456 shipped")
    assert "ACME-123456" not in out and c == {"custom_acme_id": 1}
    for bad in (
        [{"name": "x", "regex": ""}],
        [{"name": "x", "regex": "a*"}],  # matches empty input
        [{"name": "x", "regex": "("}],
        [{"name": "Bad Name", "regex": "a"}],
        [{"name": "jwt", "regex": "a"}],  # collides with a built-in
        [{"name": "x", "regex": "a"}, {"name": "x", "regex": "b"}],
        [{"name": "x", "regex": "a", "flags": "i"}],
        [{"name": f"p{i}", "regex": "a"} for i in range(33)],
        [{"name": "x", "regex": "a" * 513}],
        "not a list",
    ):
        with pytest.raises(ValidationError):
            policy._parse_policy(canonical.encode({"redaction_patterns": bad}), "t")


# ── no leakage through any data path ───────────────────────────────────────
class HostileAdapter(FixtureAdapter):
    """TEST ONLY: an adapter whose every output field carries secrets."""

    def __init__(self, mode: str = "fail") -> None:
        super().__init__(allowlisted_sha256=script_sha256(FIXTURE_SCRIPT))
        self.mode = mode

    def execute(self, planned, root, timeout, max_output, runner=None) -> ExecutionResult:  # type: ignore[override]
        raw = f"scan log\npassword={PW}\n{PEM}\nAuthorization: Bearer {JWT}\n{GH}\n".encode()
        if self.mode == "error":
            return ExecutionResult(
                CheckStatus.ERROR, f"scanner crashed: token={GH}", raw_output=raw, isolation=runner.name
            )
        return ExecutionResult(
            CheckStatus.FAIL,
            raw_output=raw,
            isolation=runner.name,
            findings=[
                {
                    "rule": "leak",
                    "file": f"conf/{AWS_ID}.env",
                    "line": 2,
                    "message": f"hardcoded password={PW} and key {STRIPE}",
                    "severity": "high",
                }
            ],
        )


def _audit(tmp_path, trust, ledger, adapter, pol=None) -> Any:
    t = tmp_path / "target"
    t.mkdir(exist_ok=True)
    (t / "app.txt").write_text("content")
    cfg = AuditConfig.from_dict(
        {
            "scope": {
                "assets": [{"id": "target", "kind": "local_path", "locator": str(t), "environment": "local"}]
            }
        }
    )
    return run_audit(
        AuditRequest(
            cfg,
            pol or policy.default_policy(),
            trust,
            ledger,
            Ed25519Signer.generate(),
            [adapter],
            tmp_path / "runs",
            clock=lambda: NOW,
            host=make_test_host(),
            env={},
        )
    )


def _all_bytes(root: Path) -> bytes:
    return b"\n".join(p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file())


SECRETS = [PW, GH, JWT, AWS_ID, STRIPE, "MIIEpAIB", "c2VjcmV0LWtleS1ib2R5"]


@pytest.mark.parametrize("mode", ["fail", "error"])
def test_no_secret_reaches_evidence_reports_logs_or_manifest(tmp_path, trust, ledger, mode):
    out = _audit(tmp_path, trust, ledger, HostileAdapter(mode))
    blob = _all_bytes(out.run_dir)
    leaked = [s for s in SECRETS if s.encode() in blob]
    assert leaked == [], leaked
    assert b"[REDACTED:" in blob
    meta = next((out.run_dir / "evidence").glob("*.meta.json"))
    red_meta = json.loads(meta.read_text())["redaction"]
    assert red_meta["total"] >= 4 and "private_key" in red_meta["rules"]
    if mode == "fail":
        (f,) = out.result["findings"]
        assert "[REDACTED:" in f["title"] and "[REDACTED:" in f["location"]["file"]


def test_redaction_failure_holds_artifact_back(tmp_path, trust, ledger, monkeypatch):
    def boom(self, data):
        raise RedactionError("simulated")

    monkeypatch.setattr(Redactor, "redact_bytes", boom)
    with pytest.raises(RedactionError):  # result redaction also fails: no manifest or report written
        _audit(tmp_path, trust, ledger, HostileAdapter())
    runs = list((tmp_path / "runs").iterdir())
    assert not (runs[0] / "manifest.json").exists() and not list((runs[0] / "evidence").iterdir())


def test_evidence_redaction_failure_is_check_error(tmp_path, trust, ledger, monkeypatch):
    real = Redactor.redact_bytes

    def fail_on_evidence(self, data):
        if b"scan log" in data:
            raise RedactionError("simulated")
        return real(self, data)

    monkeypatch.setattr(Redactor, "redact_bytes", fail_on_evidence)
    out = _audit(tmp_path, trust, ledger, HostileAdapter())
    (c,) = out.checks
    assert c.status == CheckStatus.ERROR and c.reason == "redaction_failed" and out.findings == []
    assert not list((out.run_dir / "evidence").iterdir()) and out.overall != "PASS"


def test_store_without_redactor_refuses(tmp_path):
    from sentinel.evidence import RunStore, uuid7

    with pytest.raises(RedactionError):
        RunStore.create(tmp_path, uuid7()).put_evidence(b"x", {})


def test_custom_policy_pattern_reaches_evidence(tmp_path, trust, ledger):
    class Acme(HostileAdapter):
        def execute(self, *a, **k):  # type: ignore[override]
            return ExecutionResult(CheckStatus.PASS, raw_output=b"customer ACME-654321 ok")

    from dataclasses import replace

    pol = replace(policy.default_policy(), redaction_patterns=({"name": "acme", "regex": "ACME-[0-9]{6}"},))
    out = _audit(tmp_path, trust, ledger, Acme(), pol)
    assert b"ACME-654321" not in _all_bytes(out.run_dir)


def test_admin_log_and_cli_output_are_redacted(tmp_path, capsys):
    from sentinel.evidence import AuditLog

    log = AuditLog(tmp_path / "log.jsonl")
    log.append("x", {"note": f"token={GH}"}, Ed25519Signer.generate(), checkpoint=True)
    assert GH not in (tmp_path / "log.jsonl").read_text()
    bad = tmp_path / f"{GH}.json"
    code = cli.main(["--json", "audit", "--config", str(bad)], cli.Deps(env={}))
    out = capsys.readouterr()
    assert code == cli.EXIT_INVALID and GH not in out.out + out.err and "[REDACTED:" in out.out


def test_signed_content_with_secrets_is_refused(operator):
    from sentinel import decisions, prepare
    from sentinel.keys.operator import OperatorKey, TrustStore

    ts = TrustStore()
    ts.enrol(OperatorKey(operator.public.key_id, "o", operator.public, "active", NOW + 86400))
    with pytest.raises(ValidationError, match="secret"):
        prepare.prepare(
            "review",
            trust=ts,
            now=NOW,
            key_id=operator.public.key_id,
            lifetime=60,
            rationale=f"checked with password={PW}",
            finding="a" * 64,
            revision="r",
        )
    ap = operator.approve(
        A.REVIEW_VERIFY_NO_EVIDENCE,
        {"type": "finding", "fingerprint": "a" * 64},
        "r",
        rationale=f"reproduced using {GH}",
    )
    with pytest.raises(ValidationError, match="secret"):
        decisions.build("review", ap, finding="a" * 64, revision="r")


# ── AUD-16: standing-approval revocation binding ───────────────────────────
SUBJ = {"type": "finding", "fingerprint": "f" * 64}


def _target(op):
    return op.approve(A.SUPPRESS, SUBJ, "commit:abc")


def _rev(op, target, revision=None, **kw):
    return op.approve(
        A.REVOKE_RECORD,
        {"type": "approval", "sha256": target.payload_hash},
        revision if revision is not None else target.payload["revision"],
        **kw,
    )


@pytest.mark.parametrize("revision", ["n/a", "commit:other", "", "commit:abc "])
def test_revocation_must_bind_exact_target_revision(operator, trust, ledger, revision):
    target = _target(operator)
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(operator, target, revision), target, trust, ledger, NOW + 1)
    assert e.value.code == "wrong_revision"
    assert target.payload_hash not in ledger.revoked


def test_revocation_binds_target_hash(operator, trust, ledger):
    target, other = _target(operator), operator.approve(A.SUPPRESS, SUBJ, "commit:abc")
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(operator, other), target, trust, ledger, NOW + 1)
    assert e.value.code == "wrong_subject"


def test_revocation_rejects_expired_stale_and_revoked_key(operator, trust, ledger):
    target = _target(operator)
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(operator, target), target, trust, ledger, NOW + 3600)
    assert e.value.code == "expired"
    other = FakeOperator.make()
    from sentinel.keys.operator import OperatorKey

    trust.apply_rotation(OperatorKey(other.public.key_id, "b", other.public, "active", NOW + 86400))
    trust.apply_revocation(other.public.key_id)
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(other, target), target, trust, ledger, NOW + 1)
    assert e.value.code == "revoked_key"
    good = _rev(operator, target)
    approvals.apply_revocation(good, target, trust, ledger, NOW + 1)
    with pytest.raises(BlockedError):  # one-time: replay refused
        approvals.apply_revocation(good, target, trust, ledger, NOW + 2)


def test_revocation_rejects_malformed_targets(operator, trust, ledger):
    target = _target(operator)
    forged = approvals.Approval(target.payload, b"\x00" * 64)
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(operator, forged), forged, trust, ledger, NOW + 1)
    assert e.value.code == "malformed_target"
    norev = resign(target, operator, revision="")
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(operator, norev, "x"), norev, trust, ledger, NOW + 1)
    assert e.value.code == "malformed_target"
    stranger = FakeOperator.make().approve(A.SUPPRESS, SUBJ, "commit:abc")
    with pytest.raises(BlockedError) as e:
        approvals.apply_revocation(_rev(operator, stranger), stranger, trust, ledger, NOW + 1)
    assert e.value.code == "malformed_target"


def test_correct_revocation_blocks_target_everywhere(operator, trust, ledger):
    target = _target(operator)
    approvals.verify(
        target, approvals.Expectation(A.SUPPRESS, SUBJ, "commit:abc"), trust, ledger, NOW + 1, consume=True
    )
    approvals.apply_revocation(_rev(operator, target), target, trust, ledger, NOW + 2)
    with pytest.raises(BlockedError) as e:
        approvals.verify(
            target,
            approvals.Expectation(A.SUPPRESS, SUBJ, "commit:abc"),
            trust,
            ledger,
            NOW + 3,
            consume=False,
        )
    assert e.value.code == "revoked"


def test_all_callers_bind_the_target_revision():
    root = Path(__file__).resolve().parents[1]
    for p in [*(root / "src").rglob("*.py"), *(root / "tests").rglob("*.py")]:
        text = p.read_text()
        if "apply_revocation(" in text and p.name not in ("operator.py", "test_redaction.py"):
            assert '"n/a"' not in text, p
