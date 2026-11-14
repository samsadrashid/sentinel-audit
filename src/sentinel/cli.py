"""Sentinel command-line interface (§14.1). The only entry point to the engine.

The CLI parses arguments, reads input files, calls the engine and maps outcomes to exit codes. It makes
no policy or authorisation decisions of its own (§3): scope, mode, classes, authorisation records,
approvals and isolation are all enforced engine-side, and nothing on the command line can relax them.

- Read-only by default: `audit` runs READ unless the config file asks for VALIDATE, which the engine
  refuses without a verified authorisation record (D-21).
- Running the CLI is never operator approval (D-27). Approvals are accepted only as pre-signed files
  and are verified by the engine. The CLI never prompts and never signs anything as the operator.
- No secret is ever printed: only key IDs, public keys and fingerprints.

Exit codes (stable contract):
  0  success; for `audit`, overall PASS
  1  audit finished with findings (overall FAIL)
  2  audit incomplete or cancelled (some checks NOT_RUN or ERROR)
  3  blocked by policy or authorisation
  4  invalid input or usage
  5  integrity failure (evidence, manifest, log or report)
  6  required host capability unavailable
  7  internal engine error
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

from . import (
    SCHEMA_VERSION,
    __version__,
    admin,
    canonical,
    compare,
    controls,
    decisions,
    fixplan,
    integrations,
    plugins,
    policy,
    prepare,
    recovery,
    release,
    reports,
    retention,
    schema,
    signing_protocol,
)
from .adapters.archive import ArchiveAdapter
from .adapters.blocked import blocked_adapters
from .adapters.fixture import FixtureAdapter
from .adapters.mobsf import MobsfAdapter
from .adapters.native_registry import native_adapters
from .adapters.scanners import third_party_adapters
from .approvals import Approval, NonceLedger
from .disclosure import detect as detect_disclosure
from .domain.models import AuditConfig
from .errors import BlockedError, CapabilityUnavailable, IntegrityError, SentinelError, ValidationError
from .evidence import AuditLog, RunStore
from .isolation import HostCapabilities, privilege_problem
from .isolation import detect as detect_host
from .keys.operator import OPERATOR_ROLE, TrustStore, available_provider
from .keys.runkey import RunKeyManager, run_public_key
from .keys.secure_enclave import helper_status
from .orchestrator import AuditRequest, run_audit, verify_run
from .paths import ensure_private_dir, state_dir
from .plugins import plugin_adapters
from .redaction import RedactionError, Redactor, load_or_create_key

EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_BLOCKED = 0, 1, 2, 3
EXIT_INVALID, EXIT_INTEGRITY, EXIT_CAPABILITY, EXIT_INTERNAL = 4, 5, 6, 7

MAX_INPUT_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
RUN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CALLER = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
OVERALL_EXIT = {"PASS": EXIT_OK, "FAIL": EXIT_FINDINGS, "BLOCKED": EXIT_BLOCKED}
REPORT_EXT = {"json": "json", "sarif": "sarif", "md": "md", "html": "html"}


def _confirm_on_tty(ids: list[str]) -> bool:
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        return False
    sys.stderr.write("These runs will be permanently deleted:\n" + "".join(f"  {i}\n" for i in ids))
    sys.stderr.write(f"Type DELETE {len(ids)} to confirm: ")
    sys.stderr.flush()
    return sys.stdin.readline().strip() == f"DELETE {len(ids)}"


def default_adapters(pol: Any) -> list[Any]:
    return [
        FixtureAdapter(allowlisted_sha256=pol.adapter_allowlist.get("fixture")),
        *native_adapters(pol.adapter_allowlist),
        *third_party_adapters(pol.pins),
        *plugin_adapters(pol.plugins),
        ArchiveAdapter(),
        MobsfAdapter(),
        *blocked_adapters(),
    ]


@dataclass
class Deps:
    """Injected host services, so tests never touch the real keychain or sandbox probe."""

    run_keys: Callable[[], RunKeyManager] = RunKeyManager
    host: Callable[[], HostCapabilities] = detect_host
    clock: Callable[[], int] = field(default=lambda: int(time.time()))
    env: dict[str, str] | None = None
    interactive: Callable[[], bool] = field(default=lambda: sys.stdin.isatty() and sys.stdout.isatty())
    #: The adapter set for an audit. Production: the fixture adapter plus every M2 scanner, so an
    #: unapproved scanner is reported NOT_RUN instead of silently missing (D-54, AC-03).
    adapters: Callable[[Any], list[Any]] = field(default=lambda pol: default_adapters(pol))
    #: AC-18: interactive confirmation for `prune --delete` (shows the run list, needs typed consent).
    confirm: Callable[[list[str]], bool] = field(default=lambda ids: _confirm_on_tty(ids))
    #: D-41: the agent's own `--version` output, or None if it exposes none.
    agent_version: Callable[[str], str | None] = integrations.detect_version_text


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValidationError(f"usage: {message}")


# ── input helpers ──────────────────────────────────────────────────────────
def read_input(path: str, what: str, limit: int = MAX_INPUT_BYTES) -> bytes:
    p = Path(path)
    try:
        st = p.stat()
    except OSError as exc:
        raise ValidationError(f"{what}: cannot read {path}") from exc
    if not p.is_file():
        raise ValidationError(f"{what}: not a regular file: {path}")
    if st.st_size > limit:
        raise ValidationError(f"{what}: file larger than {limit} bytes")
    data = p.read_bytes()
    if len(data) > limit:
        raise ValidationError(f"{what}: file larger than {limit} bytes")
    return data


def read_json(path: str, what: str) -> Any:
    return canonical.decode_strict(read_input(path, what), max_bytes=MAX_INPUT_BYTES)


def runs_dir() -> Path:
    return state_dir() / "runs"


def run_path(run_id: str) -> Path:
    if not RUN_ID.match(run_id):
        raise ValidationError("run id must be a lowercase UUID")
    p = runs_dir() / run_id
    if not p.is_dir() or p.is_symlink():
        raise ValidationError(f"no such run: {run_id}")
    return p


def verified_run(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Verify manifest signature, evidence and log, then the stored result against the manifest."""
    root = run_path(run_id)
    pub = run_public_key()
    if pub is None:
        raise CapabilityUnavailable("run-key", "no run key metadata; run `sentinel init`")
    manifest = verify_run(root, pub)
    report = root / "reports" / "report.json"
    if not report.is_file():
        raise IntegrityError("run has no stored result")
    raw = report.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise IntegrityError("stored result too large")
    result = canonical.decode_strict(raw, max_bytes=MAX_MANIFEST_BYTES)
    schema.check_version(result)
    try:
        schema.validate(result, "audit-result")  # D-40: schema before the result is compared or used
    except schema.SchemaError as exc:
        raise IntegrityError(f"stored result malformed: {exc}") from exc
    if not isinstance(result, dict) or canonical.digest(result) != manifest.get("result_sha256"):
        raise IntegrityError("stored result does not match the signed manifest")
    return root, manifest, result


# ── commands ───────────────────────────────────────────────────────────────
def cmd_version(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    return EXIT_OK, {
        "sentinel_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def cmd_init(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    home = ensure_private_dir(state_dir())
    for sub in ("runs", "keys", "ledger", "policy"):
        ensure_private_dir(home / sub)
    load_or_create_key()  # per-installation redaction key (keyed fingerprints, §6.4)
    pub = run_public_key()
    created = False
    if pub is None:
        pub = deps.run_keys().create()
        created = True
    else:
        deps.run_keys().signer()  # existing key must still be usable from the keystore
    trust = TrustStore()
    return EXIT_OK, {
        "state_dir": str(home),
        "run_key": {"key_id": pub.key_id, "algorithm": pub.algorithm, "created": created},
        "operator_keys": len(trust._as_json()["keys"]),
        "note": "Operator keys are not created by init. Operator signing needs the Secure Enclave helper, "
        "which is not enabled (D-38).",
    }


def cmd_status(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    host = deps.host()
    pub = run_public_key()
    try:
        backend = deps.run_keys().backend.name
    except CapabilityUnavailable as exc:
        backend = f"unavailable: {exc.reason}"
    try:
        provider = available_provider().name
    except CapabilityUnavailable as exc:
        provider = f"unavailable: {exc.reason}"
    trust = TrustStore()
    pin = None
    pol = policy.default_policy()
    if args.policy is not None:
        read_input(args.policy, "policy")
        pol = policy.validate_policy_file(
            Path(args.policy),
            Path(args.policy_approval) if args.policy_approval else None,
            trust,
            NonceLedger(),
            deps.clock(),
        )
        pin = pol.se_helper_sha256
    from .isolation.podman import probe_status

    return EXIT_OK, {
        "se_helper": helper_status(pin),
        "host": host.report(),
        "isolation": {cls: host.isolation_for(cls) for cls in _classes()},
        "container_isolation": probe_status(pol.pins.podman),
        "scanners": {a.manifest.name: a.health() for a in third_party_adapters(pol.pins)},
        "run_key": {"key_id": pub.key_id if pub else None, "keystore": backend},
        "operator_signing": provider,
        "operator_trust": {"keys": len(trust._as_json()["keys"]), "fingerprint": trust.fingerprint()},
        "state_dir": str(state_dir()),
    }


def _classes() -> list[Any]:
    from .domain.enums import ActivityClass

    return [c for c in ActivityClass if c != ActivityClass.B3]


def _agent_integration(caller: str | None, version_text: str | None, deps: Deps) -> dict[str, Any] | None:
    """D-41: an agent-invoked run must pass the integration's compatibility check before it starts."""
    env = deps.env if deps.env is not None else dict(os.environ)
    agent = integrations.integration_for(caller, detect_disclosure(caller, env)["agents"])
    if agent is None:
        return None
    if version_text is None:
        version_text = deps.agent_version(agent)
    return integrations.check(agent, version_text)


def cmd_agent_check(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """Report (and enforce) the D-41 compatibility check for an agent integration."""
    text = args.agent_version if args.agent_version is not None else deps.agent_version(args.agent)
    return EXIT_OK, {
        **integrations.check(args.agent, text),
        "skill_path": integrations.skill_path(args.agent),
    }


def cmd_audit(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    if args.caller is not None and not CALLER.match(args.caller):
        raise ValidationError("--caller must be a short lowercase name")
    if (args.authorization is None) != (args.approval is None):
        raise ValidationError("--authorization and --approval must be given together")
    if (args.policy is None) and args.policy_approval is not None:
        raise ValidationError("--policy-approval needs --policy")
    raw_config = read_json(args.config, "audit config")
    schema.validate(raw_config, "audit-config")  # D-40: schema before domain parsing and the audit
    config = AuditConfig.from_dict(raw_config)
    now = deps.clock()
    trust, ledger = TrustStore(), NonceLedger()
    pol = policy.load_policy(
        Path(args.policy) if args.policy else None,
        Path(args.policy_approval) if args.policy_approval else None,
        trust,
        ledger,
        now,
    )
    authz = None
    if args.authorization is not None:
        authz = (
            read_json(args.authorization, "authorisation record"),
            Approval.from_json(read_json(args.approval, "approval")),
        )
    agent = _agent_integration(args.caller, getattr(args, "agent_version", None), deps)
    signer = deps.run_keys().signer()

    def once() -> Any:
        return run_audit(
            AuditRequest(
                config=config,
                policy=pol,
                trust=trust,
                ledger=ledger,
                run_signer=signer,
                adapters=deps.adapters(pol),
                runs_dir=runs_dir(),
                authorization=authz,
                caller=args.caller,
                clock=deps.clock,
                host=deps.host(),
                env=deps.env,
                decisions=decisions.DecisionStore(),
                agent_integration=agent,
            )
        )

    outcome = once()
    restarted_from = None
    if outcome.result.get("control", {}).get("restart_required"):
        # AC-17/§8.2: the source changed while paused. The interrupted run stays Cancelled (never PASS);
        # a fresh audit runs once against the new revision, with every check authorised again.
        restarted_from = outcome.audit_id
        outcome = once()
    code = OVERALL_EXIT.get(outcome.overall, EXIT_INCOMPLETE)
    if code == EXIT_INCOMPLETE and any(c.status.value == "BLOCKED" for c in outcome.checks):
        code = EXIT_BLOCKED  # a check denied by authorisation is reported as blocked, not merely incomplete
    return code, {
        "audit_id": outcome.audit_id,
        "state": outcome.state.value,
        "overall": outcome.overall,
        "checks": {c.check_id: c.status.value for c in outcome.checks},
        "findings": len(outcome.findings),
        "decisions": outcome.result["decisions"],
        "run_dir": str(outcome.run_dir),
        "reports": {k: str(v) for k, v in outcome.report_paths.items()},
        **({"restarted_from": restarted_from} if restarted_from else {}),
    }


def cmd_runs_list(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    runs = []
    root = runs_dir()
    if root.is_dir():
        for p in sorted(root.iterdir()):
            if not RUN_ID.match(p.name) or not p.is_dir() or p.is_symlink():
                continue
            entry: dict[str, Any] = {"run_id": p.name, "verified": False}
            try:
                m = canonical.decode_strict(
                    read_input(str(p / "manifest.json"), "manifest", MAX_MANIFEST_BYTES), MAX_MANIFEST_BYTES
                )
                if isinstance(m, dict):
                    entry.update({k: m.get(k) for k in ("state", "overall", "mode", "level")})
            except SentinelError:
                entry["state"] = "unreadable"
            runs.append(entry)
    return EXIT_OK, {"runs": runs, "note": "Listing is unverified; use `runs show` or `evidence verify`."}


def cmd_runs_show(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    _, m, result = verified_run(args.run_id)
    return EXIT_OK, {
        "run_id": m["audit_id"],
        "verified": True,
        "state": m["state"],
        "overall": m["overall"],
        "mode": m["mode"],
        "level": m["level"],
        "revision": m["revision"],
        "authorization_ref": m["authorization_ref"],
        "policy_source": m["policy_source"],
        "checks": {c["check_id"]: c["status"] for c in m["checks"]},
        "findings": len(result["findings"]),
        "host_isolation": m["host_isolation"],
        "integrity_note": result.get("integrity_note"),
    }


def cmd_evidence_verify(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    root, m, _ = verified_run(args.run_id)
    pub = run_public_key()
    assert pub is not None
    entries = AuditLog(RunStore(root).log_path).verify(pub)
    return EXIT_OK, {
        "run_id": m["audit_id"],
        "manifest_signature": "valid",
        "evidence_files": len(m["evidence_index"]),
        "audit_log_entries": entries,
        "result_matches_manifest": True,
        "run_key_id": m["run_key_id"],
        "integrity_note": "Valid relative to the run key only (D-34).",
    }


def cmd_control(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """AC-17: cancel, pause or resume a running audit. Commands only reduce what runs."""
    return EXIT_OK, controls.send(args.audit_id, args.control, deps.clock())


def _prune_policy(args: argparse.Namespace, deps: Deps) -> Any:
    return (
        policy.load_policy(
            Path(args.policy) if args.policy else None,
            Path(args.policy_approval) if args.policy_approval else None,
            TrustStore(),
            NonceLedger(),
            deps.clock(),
        )
        if args.policy
        else policy.default_policy()
    )


def cmd_prune(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """AC-18: `--list` reads only; `--delete` needs an interactive human and typed confirmation."""
    pol = _prune_policy(args, deps)
    days = pol.limits.evidence_retention_days
    now = deps.clock()
    if not args.delete:
        return EXIT_OK, {
            "retention_days": days,
            "runs": retention.candidates(runs_dir(), now, days),
            "deleted": [],
        }
    ctx = _admin(deps, "retention.delete", {"retention_days": days})  # refuses agents and non-interactive
    out = retention.delete_expired(runs_dir(), now, days, record=ctx.record, confirm=deps.confirm)
    return EXIT_OK, {"retention_days": days, "runs": [], **out}


def cmd_plugin_inspect(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """M6: read-only validation of a plugin directory; prints the manifest hash to pin. Pins nothing."""
    out = plugins.inspect(Path(args.directory))
    return (EXIT_OK if out["valid"] else EXIT_INVALID), out


def cmd_fix_plan(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """D-50: deterministic, read-only remediation plan for a verified run. Never writes into the run."""
    root, m, result = verified_run(args.run_id)
    plan = fixplan.build(m, result)
    body = fixplan.render(plan)
    digest = canonical.sha256_hex(body)
    if args.output is None:
        return EXIT_OK, {"plan": plan, "plan_sha256": digest}
    out = Path(args.output)
    resolved = out.parent.resolve() / out.name
    if resolved.is_relative_to(root.resolve()) or resolved.is_relative_to(state_dir().resolve()):
        raise ValidationError("--output must be outside the run and the Sentinel state directory (D-50)")
    _write_new(out, body)
    return EXIT_OK, {"output": str(out), "plan_sha256": digest}


def cmd_mcp_serve(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """Only reached for argv other than exactly `[--json] mcp serve`, which `main` serves directly."""
    raise ValidationError("usage: sentinel mcp serve (no other arguments)")


def cmd_compare(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """M9: read-only comparison of two verified runs of the same target (new / fixed / persisting)."""
    _, m_old, old = verified_run(args.before)
    _, m_new, new = verified_run(args.after)
    out = compare.compare(m_old, old, m_new, new)
    return EXIT_OK, {"comparison": out, "comparison_sha256": canonical.sha256_hex(canonical.encode(out))}


def cmd_self_check(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """M10: verify the installed package against its RECORD. Unverifiable is never a pass."""
    out = release.self_check()
    code = {"verified": EXIT_OK, "unverifiable": EXIT_INCOMPLETE}.get(out["status"], EXIT_INTEGRITY)
    return code, out


def cmd_report(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    _, m, result = verified_run(args.run_id)
    body = reports.RENDERERS[args.format](result)
    if args.output is None:
        return EXIT_OK, {"_raw": body}
    _check_raw_output(args, body)  # D-40: the same contract as printed report bodies, before writing
    out = Path(args.output)
    _write_new(out, body)
    return EXIT_OK, {"run_id": m["audit_id"], "format": args.format, "output": str(out), "bytes": len(body)}


def cmd_policy_validate(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    if args.policy is None:
        if args.policy_approval is not None:
            raise ValidationError("--policy-approval needs --policy")
        return EXIT_OK, {"valid": True, "policy": policy.default_policy().describe()}
    read_input(args.policy, "policy")  # size and type checks before the engine reads it
    pol = policy.validate_policy_file(
        Path(args.policy),
        Path(args.policy_approval) if args.policy_approval else None,
        TrustStore(),
        NonceLedger(),
        deps.clock(),
    )
    return EXIT_OK, {"valid": True, "policy": pol.describe(), "note": "Approval verified, not consumed."}


# ── trust administration and review decisions ─────────────────────────────
def _admin(deps: Deps, event: str, data: dict[str, Any]) -> admin.AdminContext:
    """Build the admin context and refuse agent or non-interactive callers (logged), before any change."""
    ctx = admin.AdminContext(TrustStore(), NonceLedger(), deps.run_keys().signer(), deps.clock())
    env = deps.env if deps.env is not None else dict(os.environ)
    try:
        admin.require_human_channel(deps.interactive(), env)
    except BlockedError as exc:
        ctx.record(f"{event}.refused", {**data, "code": exc.code, "reason": exc.reason})
        raise
    return ctx


def _approval(path: str) -> Approval:
    """Ordinary operator approvals only. A recovery approval file is refused here (D-45, D-47)."""
    data = read_json(path, "approval")
    if isinstance(data, dict) and "webauthn" in data:
        raise BlockedError(
            "recovery assertions can only authorise key.rotate and key.revoke", "wrong_key_role"
        )
    return Approval.from_json(data)


def _key_approval(path: str) -> Approval | recovery.RecoveryApproval:
    """key.rotate / key.revoke: an operator approval or a recovery approval (separate verifiers)."""
    return recovery.load_any(read_json(path, "approval"))


def _expiry(value: str) -> int:
    if not value.isdigit() or len(value) > 12:
        raise ValidationError("--expires-at must be a unix timestamp")
    return int(value)


def cmd_key_list(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    trust = TrustStore()
    keys = [
        {
            "key_id": k["key_id"],
            "operator": k["operator"],
            "algorithm": k["algorithm"],
            "public_sha256": canonical.sha256_hex(bytes.fromhex(k["public"])),
            "status": k["status"],
            "expires_at": k["expires_at"],
            "role": k["role"],
            "permitted_actions": k["permitted_actions"],
        }
        for k in trust._as_json()["keys"]
    ]
    return EXIT_OK, {"trust_fingerprint": trust.fingerprint(), "keys": keys}


def cmd_key_enrol(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    key = admin.parse_key_file(read_json(args.key, "key file"))
    ctx = _admin(deps, "key.enrol", {"key_id": key.public.key_id})
    k = admin.enrol(
        ctx, key, _approval(args.approval), operator=args.operator, expires_at=_expiry(args.expires_at)
    )
    return EXIT_OK, {
        "enrolled": k.key_id,
        "public_sha256": key.public_sha256,
        "trust_fingerprint": ctx.trust.fingerprint(),
        "note": "Compare public_sha256 with your out-of-band record of this key.",
    }


def cmd_key_rotate(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    key = admin.parse_key_file(read_json(args.key, "key file"))
    ctx = _admin(deps, "key.rotate", {"key_id": key.public.key_id})
    k = admin.rotate(
        ctx,
        key,
        _key_approval(args.approval),
        operator=args.operator,
        expires_at=_expiry(args.expires_at),
        expected_trust_fingerprint=args.trust_fingerprint,
    )
    return EXIT_OK, {
        "added": k.key_id,
        "public_sha256": key.public_sha256,
        "trust_fingerprint": ctx.trust.fingerprint(),
    }


def cmd_key_revoke(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    ctx = _admin(deps, "key.revoke", {"key_id": args.key_id})
    admin.revoke(
        ctx, args.key_id, _key_approval(args.approval), expected_trust_fingerprint=args.trust_fingerprint
    )
    return EXIT_OK, {"revoked": args.key_id, "trust_fingerprint": ctx.trust.fingerprint()}


def _record_decision(deps: Deps, kind: str, d_args: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    ctx = _admin(deps, f"decision.{kind}", {"kind": kind})
    try:
        d = decisions.build(kind, **d_args)
        decisions.record(d, decisions.DecisionStore(), ctx.trust, ctx.ledger, ctx.now)
    except BlockedError as exc:
        ctx.record(f"decision.{kind}.refused", {"code": exc.code, "reason": exc.reason})
        raise
    ctx.record(f"decision.{kind}", d.summary())
    return EXIT_OK, {"recorded": d.summary()}


def cmd_review_verify(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    return _record_decision(
        deps,
        "review",
        {"approval": _approval(args.approval), "finding": args.finding, "revision": args.revision},
    )


def cmd_review_accept_risk(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    entry = read_json(args.entry, "accepted-risk entry")
    return _record_decision(deps, "accept_risk", {"approval": _approval(args.approval), "entry": entry})


def cmd_suppress_add(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    entry = read_json(args.entry, "suppression entry")
    return _record_decision(deps, "suppress", {"approval": _approval(args.approval), "entry": entry})


def _operator_signature_valid(trust: TrustStore, ap: Approval) -> bool:
    """Informational only. A raw signature counts only for an operator-role key (D-45, D-47)."""
    k = trust.get(str(ap.payload.get("key_id")))
    return bool(k is not None and k.role == "operator" and k.public.verify(ap.signature, ap.payload_bytes))


def cmd_decisions_list(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    store, trust = decisions.DecisionStore(), TrustStore()
    ds, problems = store.load()
    now = deps.clock()
    out = []
    for d in ds:
        s = d.summary()
        s["revocation"] = store.revocation_state(d, trust)
        s["signature_valid"] = _operator_signature_valid(trust, d.approval)
        s["expired"] = now >= min(
            int(s["approval_expires_at"]), int(s.get("entry_expires_at", s["approval_expires_at"]))
        )
        out.append(s)
    return EXIT_OK, {
        "decisions": out,
        "problems": problems,
        "note": "Listing is not a verification; every decision is verified again when an audit applies it.",
    }


def cmd_decisions_revoke(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    ctx = _admin(deps, "decision.revoke", {"decision_id": args.decision_id})
    try:
        d = decisions.revoke(
            args.decision_id,
            _approval(args.approval),
            decisions.DecisionStore(),
            ctx.trust,
            ctx.ledger,
            ctx.now,
        )
    except BlockedError as exc:
        ctx.record("decision.revoke.refused", {"decision_id": args.decision_id, "code": exc.code})
        raise
    ctx.record("decision.revoke", {**decisions.revocation_subject(d), "kind": d.kind, "finding": d.finding})
    return EXIT_OK, {
        "revoked": d.decision_id,
        "kind": d.kind,
        "finding": d.finding,
        "note": "Original decision kept.",
    }


def cmd_approval_prepare(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """Read-only: builds an unsigned payload. Writes nothing except the optional new --output file."""
    if not args.lifetime.isdigit() or len(args.lifetime) > 9:
        raise ValidationError("--lifetime must be a whole number of seconds")
    inputs: dict[str, Any] = {}
    if args.key:
        inputs["key"] = admin.parse_key_file(read_json(args.key, "key file"))
    if args.target_key_id:
        inputs["target_key_id"] = args.target_key_id
    if args.finding:
        inputs["finding"] = args.finding
    if args.revision:
        inputs["revision"] = args.revision
    if args.entry:
        inputs["entry"] = read_json(args.entry, "entry")
    if args.decision_id:
        inputs["decision_id"] = args.decision_id
    if args.policy:
        inputs["policy_bytes"] = read_input(args.policy, "policy")
    if args.record:
        inputs["record"] = read_json(args.record, "authorisation record")
    if args.dist:
        inputs["dist"] = _dist_dir(args.dist)
    if args.commit:
        inputs["commit"] = args.commit
    out = prepare.prepare(
        args.kind,
        trust=TrustStore(),
        now=deps.clock(),
        key_id=args.key_id,
        lifetime=int(args.lifetime),
        rationale=args.rationale,
        **inputs,
    )
    if args.output:
        _write_new(Path(args.output), (json.dumps(out["payload"], sort_keys=True, indent=1) + "\n").encode())
        out["output"] = args.output
    return EXIT_OK, out


def cmd_approval_inspect(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """Show any payload or approval file canonically, with its hash. Never consumes or registers a nonce."""
    raw = read_json(args.file, "payload or approval")
    if isinstance(raw, dict) and set(raw) == {"payload", "webauthn"}:
        rap = recovery.RecoveryApproval.from_json(raw)
        out = prepare.describe(rap.payload)
        rk = TrustStore().get(str(rap.payload.get("key_id")))
        try:
            ok = rk is not None and recovery.check_assertion(rap, rk) >= 0
        except BlockedError:
            ok = False
        out["signature_valid_for_registered_key"] = ok
        out["note"] = "Recovery assertion check only (D-47). Whether it may be used is decided at use time."
        return EXIT_OK, out
    signed = isinstance(raw, dict) and set(raw) == {"payload", "signature"}
    payload = Approval.from_json(raw).payload if signed else raw
    out = prepare.describe(payload)
    if signed:
        ap = Approval.from_json(raw)
        out["signature_valid_for_registered_key"] = _operator_signature_valid(TrustStore(), ap)
        out["note"] = "Signature check only. Whether it may be used is decided when an operation verifies it."
    return EXIT_OK, out


def _volume(path: str) -> Path:
    p = Path(path)
    if not p.is_dir():
        raise ValidationError("--volume must be the mounted transfer volume directory")
    return p


def _protocol_log(deps: Deps, event: str, data: dict[str, Any]) -> None:
    """D-49 / protocol §6.5: the admin log records request emission and reception."""
    AuditLog(admin.admin_log_path()).append(event, data, deps.run_keys().signer(), checkpoint=True)


def cmd_approval_request(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """Write a sign request (protocol v1) for an UNSIGNED payload to the transfer volume. Signs nothing."""
    payload = read_json(args.payload, "unsigned payload")
    enrol = admin.parse_key_file(read_json(args.enrol_key, "key file")) if args.enrol_key else None
    out = signing_protocol.emit_request(
        payload, _volume(args.volume), TrustStore(), deps.clock(), enrol_key=enrol
    )
    _protocol_log(deps, "approval.request_emitted", {k: out[k] for k in ("request_id", "payload_sha256")})
    return EXIT_OK, {
        **out,
        "note": "Take the volume to the signing device. A response is verified against this pending payload.",
    }


def cmd_approval_receive(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """Read signing-device responses; store verified approvals in engine state. Applies nothing."""
    results = signing_protocol.receive_responses(_volume(args.volume), TrustStore(), deps.clock())
    for r in results:
        _protocol_log(
            deps,
            "approval.received" if r["status"] == "received" else "approval.receive_refused",
            {k: r[k] for k in ("request_id", "status") if k in r}
            | ({"code": r["code"]} if "code" in r else {}),
        )
    code = EXIT_OK if all(r["status"] == "received" for r in results) else EXIT_BLOCKED
    return code, {
        "responses": results,
        "note": "Received approvals are verified again, in full, when an operation uses them.",
    }


def _dist_dir(path: str) -> Path:
    p = Path(path)
    if p.is_symlink() or not p.is_dir():
        raise ValidationError("--dist must be the release directory (wheel, sdist, SBOM and SHA256SUMS)")
    return p


def cmd_release_attach(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """D-74: verify a received `release.publish` approval against the release directory and the trust
    store (the key must be usable now, with the D-45 role and permission), then write it next to
    SHA256SUMS. Signs nothing; refuses to overwrite an existing approval file."""
    dist = _dist_dir(args.dist)
    raw = release.load_approval_file(Path(args.approval))
    ap = Approval.from_json(raw)
    key = TrustStore().authorise(
        str(ap.payload["key_id"]), release.RELEASE_ACTION, deps.clock(), role=OPERATOR_ROLE
    )
    out = release.verify_release(dist, raw, key.public, trusted=key)
    dest = dist / release.APPROVAL_NAME
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError as exc:
        raise ValidationError(f"{release.APPROVAL_NAME} already exists; refusing to overwrite") from exc
    with os.fdopen(fd, "wb") as fh:
        fh.write(canonical.encode(ap.to_json()))
    _protocol_log(deps, "release.attached", {"version": out["version"], "commit": out["commit"]})
    return EXIT_OK, {
        **out,
        "key_source": "trust_store",
        "approval_file": str(dest),
        "note": "Publish this file with SHA256SUMS and the release key file; verifiers run `release verify`.",
    }


def cmd_release_verify(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    """D-74: verify a signed release directory. Read-only. With --key, the key file is the published
    release key the verifier obtained independently (its D-45 role can't be checked without a trust
    store); without it, the engine trust store supplies the key, its role, permission and status."""
    dist = _dist_dir(args.dist)
    path = Path(args.approval) if args.approval else dist / release.APPROVAL_NAME
    raw = release.load_approval_file(path)
    ap = Approval.from_json(raw)
    if args.key:
        cand = admin.parse_key_file(read_json(args.key, "key file"))
        if cand.role != OPERATOR_ROLE:
            raise BlockedError("a release is signed by an operator key, not a recovery key", "wrong_key_role")
        out, source = release.verify_release(dist, raw, cand.public), "key_file"
    else:
        trusted = TrustStore().get(str(ap.payload["key_id"]))
        if trusted is None:
            raise BlockedError(
                "the signing key is not in this trust store; pass --key with the published release key",
                "unknown_key",
            )
        out, source = release.verify_release(dist, raw, trusted.public, trusted=trusted), "trust_store"
    return EXIT_OK, {
        **out,
        "key_source": source,
        "note": "Compare key_id with the release key you obtained independently; a key file shipped "
        "inside the release proves nothing on its own.",
    }


def _write_new(out: Path, body: bytes) -> None:
    if not out.parent.is_dir():
        raise ValidationError("--output directory does not exist")
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as exc:
        raise ValidationError("--output already exists; refusing to overwrite") from exc
    with os.fdopen(fd, "wb") as fh:
        fh.write(body)


def cmd_history_verify(args: argparse.Namespace, deps: Deps) -> tuple[int, dict[str, Any]]:
    pub = run_public_key()
    if pub is None:
        raise CapabilityUnavailable("run-key", "no run key metadata; run `sentinel init`")
    log = AuditLog(admin.admin_log_path())
    n = log.verify(pub)
    return EXIT_OK, {
        "admin_log_entries": n,
        "head": log.head(),
        "note": "Valid relative to the run key only (D-34).",
    }


# ── parser and dispatch ────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="sentinel", description="Sentinel security audit engine")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)
    sub.add_parser("version").set_defaults(fn=cmd_version)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    st = sub.add_parser("status")
    st.add_argument("--policy", help="approved policy file, to report the Secure Enclave helper pin")
    st.add_argument("--policy-approval")
    st.set_defaults(fn=cmd_status)
    a = sub.add_parser("audit")
    a.add_argument("--config", required=True, help="audit config JSON (scope, mode, level, classes)")
    a.add_argument("--authorization", help="signed authorisation record JSON")
    a.add_argument("--approval", help="operator approval JSON for the authorisation record")
    a.add_argument("--policy", help="policy file")
    a.add_argument("--policy-approval", help="operator approval for the policy file")
    a.add_argument("--caller", help="declared caller, e.g. operator, ci, claude-code")
    a.add_argument("--agent-version", help="the agent's own --version output (D-41; untrusted)")
    a.set_defaults(fn=cmd_audit)
    runs = sub.add_parser("runs").add_subparsers(dest="runs_cmd", required=True, parser_class=_Parser)
    runs.add_parser("list").set_defaults(fn=cmd_runs_list)
    show = runs.add_parser("show")
    show.add_argument("run_id")
    show.set_defaults(fn=cmd_runs_show)
    ev = sub.add_parser("evidence").add_subparsers(dest="ev_cmd", required=True, parser_class=_Parser)
    v = ev.add_parser("verify")
    v.add_argument("run_id")
    v.set_defaults(fn=cmd_evidence_verify)
    r = sub.add_parser("report")
    r.add_argument("run_id")
    r.add_argument("--format", choices=sorted(reports.RENDERERS), default="md")
    r.add_argument("--output", help="write to this new file instead of stdout")
    r.set_defaults(fn=cmd_report)
    for name in ("cancel", "pause", "resume"):
        c = sub.add_parser(name, help=f"{name} a running audit (AC-17)")
        c.add_argument("audit_id")
        c.set_defaults(fn=cmd_control, control=name)
    pr_ = sub.add_parser("prune", help="list or delete runs past the retention limit (AC-18)")
    g = pr_.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--delete", action="store_true")
    pr_.add_argument("--policy")
    pr_.add_argument("--policy-approval")
    pr_.set_defaults(fn=cmd_prune)
    pl = sub.add_parser("plugin").add_subparsers(dest="plugin_cmd", required=True, parser_class=_Parser)
    pli = pl.add_parser("inspect", help="validate a plugin directory (read-only, M6)")
    pli.add_argument("directory")
    pli.set_defaults(fn=cmd_plugin_inspect)
    ag = sub.add_parser("agent").add_subparsers(dest="agent_cmd", required=True, parser_class=_Parser)
    agc = ag.add_parser("check", help="D-41 compatibility check for an agent integration")
    agc.add_argument("--agent", required=True, choices=sorted(integrations.MIN_VERSIONS))
    agc.add_argument("--agent-version", help="the agent's --version output; detected if omitted")
    agc.set_defaults(fn=cmd_agent_check)
    sub.add_parser("self-check", help="verify installed files against the wheel RECORD (M10)").set_defaults(
        fn=cmd_self_check
    )
    mcp_ = sub.add_parser("mcp", help="local stdio MCP server (M7)").add_subparsers(
        dest="mcp_cmd", required=True, parser_class=_Parser
    )
    mcp_.add_parser("serve", help="serve MCP over stdin/stdout (local only, target-read-only)").set_defaults(
        fn=cmd_mcp_serve
    )
    cmp_ = sub.add_parser("compare", help="read-only comparison of two verified runs (M9)")
    cmp_.add_argument("before")
    cmp_.add_argument("after")
    cmp_.set_defaults(fn=cmd_compare)
    fp = sub.add_parser("fix-plan", help="read-only remediation plan for a verified run (D-50)")
    fp.add_argument("run_id")
    fp.add_argument("--output", help="write the plan to this new file (outside the run)")
    fp.set_defaults(fn=cmd_fix_plan)
    pol = sub.add_parser("policy").add_subparsers(dest="pol_cmd", required=True, parser_class=_Parser)
    pv = pol.add_parser("validate")
    pv.add_argument("--policy")
    pv.add_argument("--policy-approval")
    pv.set_defaults(fn=cmd_policy_validate)
    key = sub.add_parser("key").add_subparsers(dest="key_cmd", required=True, parser_class=_Parser)
    key.add_parser("list").set_defaults(fn=cmd_key_list)
    for name, fn in (("enrol", cmd_key_enrol), ("rotate", cmd_key_rotate)):
        k = key.add_parser(name)
        k.add_argument("--key", required=True, help="public key file (Secure Enclave metadata or public_hex)")
        k.add_argument("--approval", required=True, help="pre-signed key.rotate approval")
        k.add_argument("--operator", required=True)
        k.add_argument("--expires-at", required=True)
        if name == "rotate":
            k.add_argument("--trust-fingerprint", required=True, help="trust fingerprint you expect now")
        k.set_defaults(fn=fn)
    kr = key.add_parser("revoke")
    kr.add_argument("--key-id", required=True)
    kr.add_argument("--approval", required=True, help="pre-signed key.revoke approval")
    kr.add_argument("--trust-fingerprint", required=True)
    kr.set_defaults(fn=cmd_key_revoke)
    rv = sub.add_parser("review").add_subparsers(dest="review_cmd", required=True, parser_class=_Parser)
    rvv = rv.add_parser("verify")
    rvv.add_argument("--finding", required=True)
    rvv.add_argument("--revision", required=True)
    rvv.add_argument("--approval", required=True, help="pre-signed review.verify_no_evidence approval")
    rvv.set_defaults(fn=cmd_review_verify)
    rva = rv.add_parser("accept-risk")
    rva.add_argument("--entry", required=True)
    rva.add_argument("--approval", required=True, help="pre-signed review.accept_risk approval")
    rva.set_defaults(fn=cmd_review_accept_risk)
    sp = sub.add_parser("suppress").add_subparsers(dest="suppress_cmd", required=True, parser_class=_Parser)
    spa = sp.add_parser("add")
    spa.add_argument("--entry", required=True)
    spa.add_argument("--approval", required=True, help="pre-signed suppress approval")
    spa.set_defaults(fn=cmd_suppress_add)
    dl = sub.add_parser("decisions").add_subparsers(dest="dec_cmd", required=True, parser_class=_Parser)
    dl.add_parser("list").set_defaults(fn=cmd_decisions_list)
    dr = dl.add_parser("revoke")
    dr.add_argument("--decision-id", required=True)
    dr.add_argument("--approval", required=True, help="pre-signed one-time revoke_record approval")
    dr.set_defaults(fn=cmd_decisions_revoke)
    apv = sub.add_parser("approval").add_subparsers(dest="ap_cmd", required=True, parser_class=_Parser)
    pr = apv.add_parser("prepare", help="build an UNSIGNED payload for operator review and signing")
    pr.add_argument("kind", choices=prepare.KINDS)
    pr.add_argument("--key-id", required=True, help="operator key that will sign")
    pr.add_argument("--lifetime", required=True, help="seconds (D-37 maximum per action)")
    pr.add_argument("--rationale")
    for opt in (
        "--key",
        "--target-key-id",
        "--finding",
        "--revision",
        "--entry",
        "--decision-id",
        "--policy",
        "--record",
        "--dist",
        "--commit",
        "--output",
    ):
        pr.add_argument(opt)
    pr.set_defaults(fn=cmd_approval_prepare)
    ins = apv.add_parser("inspect")
    ins.add_argument("file")
    ins.set_defaults(fn=cmd_approval_inspect)
    rq = apv.add_parser("request", help="write a protocol-v1 sign request for the signing device")
    rq.add_argument("--payload", required=True, help="UNSIGNED payload (from `approval prepare --output`)")
    rq.add_argument("--volume", required=True, help="mounted transfer volume")
    rq.add_argument(
        "--enrol-key", help="first enrolment only: the signing device's pub-<key_id>.json (still untrusted)"
    )
    rq.set_defaults(fn=cmd_approval_request)
    rc = apv.add_parser("receive", help="read and verify signing-device responses from the volume")
    rc.add_argument("--volume", required=True)
    rc.set_defaults(fn=cmd_approval_receive)
    rl = sub.add_parser("release").add_subparsers(dest="rel_cmd", required=True, parser_class=_Parser)
    rlv = rl.add_parser("verify", help="verify a signed release directory (D-74)")
    rlv.add_argument("dist")
    rlv.add_argument("--key", help="the published release key file; default: the engine trust store")
    rlv.add_argument("--approval", help=f"default: <dist>/{release.APPROVAL_NAME}")
    rlv.set_defaults(fn=cmd_release_verify)
    rla = rl.add_parser(
        "attach", help="verify a received release.publish approval and place it in the release"
    )
    rla.add_argument("--approval", required=True, help="the received approval (from `approval receive`)")
    rla.add_argument("--dist", required=True)
    rla.set_defaults(fn=cmd_release_attach)
    hv = sub.add_parser("history").add_subparsers(dest="hist_cmd", required=True, parser_class=_Parser)
    hv.add_parser("verify").set_defaults(fn=cmd_history_verify)
    return p


ERROR_EXIT: list[tuple[type[Exception], int, str]] = [
    (RedactionError, EXIT_INTERNAL, "redaction_failed"),
    (schema.SchemaViolation, EXIT_INTERNAL, "schema_violation"),
    (schema.SchemaDefinitionError, EXIT_INTERNAL, "schema_definition_invalid"),
    (BlockedError, EXIT_BLOCKED, "blocked"),
    (ValidationError, EXIT_INVALID, "invalid"),
    (IntegrityError, EXIT_INTEGRITY, "integrity"),
    (CapabilityUnavailable, EXIT_CAPABILITY, "capability_unavailable"),
    (SentinelError, EXIT_INTERNAL, "engine_error"),
]


#: D-40: the cli-output contract definition each command's printed payload must match.
RAW_CONTRACT = {"json": "audit-result", "sarif": "sarif-profile"}
RAW_TEXT_FORMATS = frozenset({"md", "html"})


def _check_raw_output(args: argparse.Namespace, raw: Any) -> None:
    """D-40 contract for raw stdout. Only `report` may print raw bytes; JSON-bearing formats are
    validated like any other output; text formats are refused if they would decode as JSON."""
    if args.fn is not cmd_report or not isinstance(raw, bytes):
        raise schema.SchemaViolation("raw output is only allowed for `report`")
    fmt = getattr(args, "format", None)
    if fmt in RAW_CONTRACT:
        try:
            doc = canonical.decode_strict(raw)
        except (ValueError, SentinelError) as exc:
            raise schema.SchemaViolation(f"{fmt} report body is not strict JSON") from exc
        schema.check_output(doc, RAW_CONTRACT[fmt])
        return
    if fmt not in RAW_TEXT_FORMATS:
        raise schema.SchemaViolation(f"no output contract for report format {fmt!r}")
    try:
        json.loads(raw)
    except ValueError:
        return
    raise schema.SchemaViolation("text report body decodes as JSON; refusing to bypass its contract")


CLI_CONTRACT = {
    "cmd_version": "version",
    "cmd_init": "init",
    "cmd_status": "status",
    "cmd_audit": "audit",
    "cmd_runs_list": "runs_list",
    "cmd_runs_show": "runs_show",
    "cmd_evidence_verify": "evidence_verify",
    "cmd_report": "report",
    "cmd_policy_validate": "policy_validate",
    "cmd_key_list": "key_list",
    "cmd_key_enrol": "key_enrol",
    "cmd_key_rotate": "key_rotate",
    "cmd_key_revoke": "key_revoke",
    "cmd_review_verify": "decision_recorded",
    "cmd_review_accept_risk": "decision_recorded",
    "cmd_suppress_add": "decision_recorded",
    "cmd_decisions_list": "decisions_list",
    "cmd_decisions_revoke": "decisions_revoke",
    "cmd_approval_prepare": "approval_prepare",
    "cmd_approval_inspect": "approval_inspect",
    "cmd_approval_request": "approval_request",
    "cmd_fix_plan": "fix_plan",
    "cmd_agent_check": "agent_check",
    "cmd_control": "control",
    "cmd_plugin_inspect": "plugin_inspect",
    "cmd_compare": "compare",
    # `mcp serve` streams JSON-RPC (served by `main` before dispatch); this stub only ever raises, so the
    # only printed output it can produce is the error envelope.
    "cmd_mcp_serve": "error",
    "cmd_self_check": "self_check",
    "cmd_prune": "prune",
    "cmd_approval_receive": "approval_receive",
    "cmd_history_verify": "history_verify",
    "cmd_release_verify": "release_verify",
    "cmd_release_attach": "release_verify",
}


def _human(obj: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:\n{_human(v, indent + 1)}")
            else:
                lines.append(f"{pad}{k}: {v}")
        return "\n".join(lines)
    if isinstance(obj, list):
        return "\n".join(f"{pad}- " + _human(x, indent + 1).lstrip() for x in obj)
    return f"{pad}{obj}"


def main(argv: Sequence[str] | None = None, deps: Deps | None = None) -> int:
    deps = deps or Deps()
    argl = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argl
    try:
        schema.ensure_loaded()  # D-40: a damaged contract set prevents every command from running
        # M7: `mcp serve` is stdio JSON-RPC; it is refused under privilege exactly like every command.
        serve_mcp = [x for x in argl if x != "--json"] == ["mcp", "serve"]
        args = None if serve_mcp else build_parser().parse_args(argl)
        if args is None or args.fn is not cmd_version:
            # D-32 / §10.2: refuse root and elevated capabilities before anything is read or written.
            problem = privilege_problem()
            if problem is not None:
                raise BlockedError(problem, "privileged_execution")
        if args is None:
            from . import mcp

            return mcp.serve()
        code, payload = args.fn(args, deps)
        code = int(code)
    except SystemExit as exc:  # --help
        return EXIT_OK if exc.code in (0, None) else EXIT_INVALID
    except Exception as exc:  # noqa: BLE001 - every failure maps to a documented exit code
        code, kind = EXIT_INTERNAL, "engine_error"
        for cls, c, k in ERROR_EXIT:
            if isinstance(exc, cls):
                code, kind = c, k
                break
        detail = getattr(exc, "code", None)
        msg = str(exc) if isinstance(exc, SentinelError) else "unexpected internal error"
        try:
            msg = Redactor.for_output().redact_text(msg)[0]
        except RedactionError:
            msg = "error detail withheld: redaction failed"
        err = {"error": kind, "code": detail if isinstance(detail, str) else kind, "message": msg[:4000]}
        if as_json:
            sys.stdout.write(json.dumps(err, sort_keys=True) + "\n")
        else:
            sys.stderr.write(f"sentinel: {kind}: {msg}\n")
        return code
    # §13.4: everything the CLI prints (which an agent may read) passes through redaction. If redaction
    # can't complete, nothing is printed.
    try:
        out = Redactor.for_output()
        if "_raw" in payload:
            payload = {"_raw": out.redact_bytes(payload["_raw"])[0]}
        else:
            payload = out.redact_obj(payload)
    except RedactionError:
        sys.stderr.write("sentinel: redaction_failed: output withheld\n")
        return EXIT_INTERNAL
    if "_raw" in payload:
        # D-40: raw bytes are only report bodies. JSON and SARIF bodies are checked against their own
        # contracts after redaction; Markdown and HTML (the documented exception) must not be JSON.
        try:
            _check_raw_output(args, payload["_raw"])
        except (schema.SchemaViolation, schema.SchemaDefinitionError):
            sys.stderr.write("sentinel: schema_violation: output withheld\n")
            return EXIT_INTERNAL
    if "_raw" not in payload:
        # D-40: the printed contract is checked after redaction and before anything is printed.
        try:
            schema.check_output(
                {"exit_code": code, **payload}, "cli-output", CLI_CONTRACT.get(args.fn.__name__, "?")
            )
        except (schema.SchemaViolation, schema.SchemaDefinitionError):
            sys.stderr.write("sentinel: schema_violation: output withheld\n")
            return EXIT_INTERNAL
    if "_raw" in payload:
        sys.stdout.buffer.write(payload["_raw"])
        sys.stdout.flush()
    elif as_json:
        sys.stdout.write(json.dumps({"exit_code": code, **payload}, sort_keys=True, default=str) + "\n")
    else:
        sys.stdout.write(_human(payload) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
