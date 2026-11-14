"""Audit orchestration (§3 pipeline, §5, §8 lifecycle, §10.1 limits, §11 enforcement).

Pipeline: validate config → resolve policy and scope → verify authorisation → enforce mode and classes
→ plan checks → run each check (re-authorised immediately before it runs) → store evidence →
normalise findings → final state → signed manifest → reports.

Fail-closed rules enforced here:
- every planned check ends in an explicit status; a missing scanner, hash mismatch, timeout, crash or
  bad output is NOT_RUN or ERROR, never PASS;
- the maximum audit duration makes remaining checks NOT_RUN (`audit_timeout`) and the audit Incomplete;
- authorisation (record, approval, revocation, expiry, scope) is re-checked immediately before each
  check (R-03, D-36); any failure gives BLOCKED for that check (R-10);
- a third-party adapter with no implemented isolation layer is NOT_RUN (`host_isolation_unavailable`)
  and never falls back to weaker isolation (D-32). Only engine-owned adapters may run without one,
  and that is recorded as `isolation_ref` in evidence, the manifest and every report;
- only a Completed audit whose checks all finished can read PASS (§8.2).

Integrity limits (D-34): the manifest and audit log are signed with the automatic run key. That proves
integrity relative to that key only, not against a same-user process that can use it.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION, __version__, canonical, controls, domains, policy, reports, schema
from .adapters.base import PlannedCheck, ScannerAdapter
from .approvals import NonceLedger
from .authorization import VerifiedRecord, authorize_operation, verify_record
from .crypto.signing import Ed25519Signer
from .decisions import DecisionStore, apply_decisions
from .disclosure import detect as detect_disclosure
from .discovery import discover
from .domain.enums import (
    ActivityClass,
    AuditState,
    CheckStatus,
    Environment,
    FindingOrigin,
)
from .domain.models import Asset, AuditConfig, CheckResult
from .errors import BlockedError, IntegrityError
from .evidence import AuditLog, RunStore, uuid7
from .findings import Finding, canonical_advisory, deduplicate, new_finding, summary
from .isolation import HostCapabilities
from .isolation import detect as detect_host
from .keys.operator import TrustStore
from .lifecycle import AuditStateMachine, final_state, overall_result
from .redaction import PII_CLASSES, PII_NOT_COVERED, RedactionError, Redactor

INTEGRITY_NOTE = (
    "The manifest and audit log are signed with the automatic run key. A valid signature shows integrity "
    "relative to that key only. It does not detect a same-user process that can rewrite the run folder and "
    "use the run key (D-34). A signature never proves that a finding is real."
)

REDACTION_NOTE = (
    "Pattern-based redaction ran on evidence, findings, check reasons, logs and this result. It is not "
    "complete secret detection; see docs/m1/redaction.md for known blind spots."
)

#: Hook called after each check finishes (used by tests to simulate events such as revocation).
CheckHook = Callable[[CheckResult], None]


@dataclass
class AuditRequest:
    config: AuditConfig
    policy: policy.Policy
    trust: TrustStore
    ledger: NonceLedger
    run_signer: Ed25519Signer
    adapters: list[ScannerAdapter]
    runs_dir: Path
    authorization: tuple[Any, Any] | None = None  # (record dict, Approval)
    caller: str | None = None
    clock: Callable[[], int] = field(default=lambda: int(time.time()))
    host: HostCapabilities | None = None
    after_check: CheckHook | None = None
    env: dict[str, str] | None = None
    #: Kill switch: once set, checks not yet started are NOT_RUN and the audit is Cancelled.
    cancel: threading.Event | None = None
    #: Signed review decisions, accepted risks and suppressions to apply (None: no decisions).
    decisions: DecisionStore | None = None
    #: D-41 compatibility result for an agent-invoked run (None: not an agent integration run).
    agent_integration: dict[str, Any] | None = None


@dataclass
class AuditOutcome:
    audit_id: str
    state: AuditState
    overall: str
    checks: list[CheckResult]
    findings: list[Finding]
    run_dir: Path
    result: dict[str, Any]
    report_paths: dict[str, Path]


@dataclass
class _Planned:
    check_id: str
    asset: Asset
    adapter: ScannerAdapter | None
    planned: PlannedCheck | None
    activity: ActivityClass
    preset: CheckResult | None = None  # a final status decided at planning time


def target_revision(root: Path) -> str:
    """Content hash of the target tree (files only; symlinks recorded, never followed)."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                h.update(f"L:{rel}->{os.readlink(p)}\0".encode())
                continue
            h.update(f"F:{rel}\0".encode())
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
    return "tree-sha256:" + h.hexdigest()


class Orchestrator:
    def __init__(self, req: AuditRequest) -> None:
        self.req = req
        self.audit_id = uuid7()
        self.sm = AuditStateMachine()
        self.host = req.host or detect_host()
        self.redactor = Redactor.default(req.policy.redaction_patterns)
        self.run = RunStore.create(req.runs_dir, self.audit_id, self.redactor)
        self.log = AuditLog(self.run.log_path, self.redactor)
        self._lock = threading.Lock()
        self._started = 0
        self.record: VerifiedRecord | None = None
        self.raw_findings: list[Finding] = []
        # AC-17: the kill switch always exists; `req.cancel` (tests, embedding) and the control channel
        # (`sentinel cancel`) both set it.
        self.cancel = req.cancel if req.cancel is not None else threading.Event()
        self.paused = threading.Event()
        self.restart_required = False
        self.transitions: list[dict[str, Any]] = []
        self._started_plans: set[int] = set()
        self._reauth_blocked: dict[int, CheckResult] = {}
        self._plans: list[_Planned] = []
        self.sboms: dict[str, bytes] = {}
        self.check_notes: dict[str, dict[str, str]] = {}
        self.db_snapshots: dict[str, str] = {}
        self._reauth_count = 0

    # ── helpers ────────────────────────────────────────────────────────────
    def _event(self, event: str, data: dict[str, Any], checkpoint: bool = False) -> None:
        with self._lock:
            self.log.append(event, data, self.req.run_signer, checkpoint=checkpoint)

    def _deadline_passed(self) -> bool:
        return self.req.clock() - self._started >= self.req.policy.limits.max_audit_duration_s

    # ── planning ───────────────────────────────────────────────────────────
    def _plan(self) -> list[_Planned]:
        cfg = self.req.config
        plans: list[_Planned] = []
        seq = 0
        for asset in cfg.scope.assets:
            for cls in cfg.activity_classes:
                adapters = [a for a in self.req.adapters if a.manifest.activity_class == cls]
                if not adapters:
                    seq += 1
                    plans.append(
                        _Planned(
                            f"{self.audit_id}:none:{cls}:{seq}",
                            asset,
                            None,
                            None,
                            cls,
                            CheckResult(
                                f"{asset.asset_id}/{cls}", "none", CheckStatus.NOT_RUN, "no_adapter_for_class"
                            ),
                        )
                    )
                    continue
                for adapter in adapters:
                    seq += 1
                    cid = f"{self.audit_id}:{adapter.manifest.name}:{asset.asset_id}:{seq}"
                    label = f"{asset.asset_id}/{adapter.manifest.name}"
                    if asset.kind != "local_path":
                        plans.append(
                            _Planned(
                                cid,
                                asset,
                                adapter,
                                None,
                                cls,
                                CheckResult(
                                    label,
                                    adapter.manifest.name,
                                    CheckStatus.NOT_RUN,
                                    "asset_kind_not_supported_in_m1",
                                ),
                            )
                        )
                        continue
                    # D-32/D-53: no adapter is exempt, and there is no unsandboxed fallback.
                    kind = getattr(adapter, "isolation_kind", lambda: None)()
                    if self.host.runner_for(cls, self.req.policy.limits, self.req.policy.pins, kind) is None:
                        plans.append(
                            _Planned(
                                cid,
                                asset,
                                adapter,
                                None,
                                cls,
                                CheckResult(
                                    label,
                                    adapter.manifest.name,
                                    CheckStatus.NOT_RUN,
                                    "host_isolation_unavailable",
                                ),
                            )
                        )
                        continue
                    root = Path(asset.locator).resolve()
                    if not root.is_dir():
                        plans.append(
                            _Planned(
                                cid,
                                asset,
                                adapter,
                                None,
                                cls,
                                CheckResult(
                                    label, adapter.manifest.name, CheckStatus.NOT_RUN, "target_not_found"
                                ),
                            )
                        )
                        continue
                    for pc in adapter.plan(root):
                        plans.append(_Planned(cid, asset, adapter, pc, cls))
        return plans

    # ── one check ──────────────────────────────────────────────────────────
    def _run_check(self, p: _Planned) -> CheckResult:
        if p.preset is not None:
            return p.preset
        assert p.adapter is not None and p.planned is not None
        adapter, label = p.adapter, f"{p.asset.asset_id}/{p.adapter.manifest.name}"
        # AC-17: while paused, no new check starts.
        while self.paused.is_set() and not self.cancel.is_set():
            time.sleep(controls.POLL_S)
        with self._lock:
            if id(p) in self._reauth_blocked:  # refused when the audit was resumed
                return self._reauth_blocked[id(p)]
            if self.cancel.is_set():
                return CheckResult(label, adapter.manifest.name, CheckStatus.NOT_RUN, "cancelled")
            self._started_plans.add(id(p))
        if self._deadline_passed():
            return CheckResult(label, adapter.manifest.name, CheckStatus.NOT_RUN, "audit_timeout")
        root = Path(p.asset.locator).resolve()
        # Immediately before the operation: re-check authorisation and scope (R-03, D-36).
        try:
            self._gate(p, root)
        except BlockedError as exc:
            self._event("check.blocked", {"check": label, "code": exc.code, "reason": exc.reason})
            return CheckResult(label, adapter.manifest.name, CheckStatus.BLOCKED, f"{exc.code}: {exc.reason}")
        return self._execute_gated(p, root, label)

    def _gate(self, p: _Planned, root: Path) -> None:
        """Authorisation and scope gate, run immediately before a check and again on resume (AC-17)."""
        assert p.adapter is not None and p.planned is not None
        adapter = p.adapter
        if self.record is not None:
            authorize_operation(
                self.record,
                asset_locator=p.asset.locator,
                environment=p.asset.environment,
                activity=p.activity,
                operation=p.planned.check_name,
                trust=self.req.trust,
                ledger=self.req.ledger,
                now=self.req.clock(),
            )
        # Engine-side scope check, independent of the adapter's own (R-08, §5): every planned
        # target must resolve inside this asset's root. An adapter can't widen its scope.
        for t in p.planned.targets:
            tr = Path(t).resolve()
            if tr != root and root not in tr.parents:
                raise BlockedError(f"adapter planned a target outside the asset root: {t}", "scope_expansion")
        adapter.validate_scope([p.planned], root)

    def _execute_gated(self, p: _Planned, root: Path, label: str) -> CheckResult:
        assert p.adapter is not None and p.planned is not None
        adapter = p.adapter
        remaining = self.req.policy.limits.max_audit_duration_s - (self.req.clock() - self._started)
        timeout = max(1, min(self.req.policy.limits.scanner_timeout_s, remaining))
        # D-32 (X-5): every adapter, engine-owned or not, runs only inside a verified isolation layer.
        # There is no unsandboxed fallback: without a runner the adapter is never invoked.
        kind = getattr(adapter, "isolation_kind", lambda: None)()
        runner = self.host.runner_for(p.activity, self.req.policy.limits, self.req.policy.pins, kind)
        if runner is None:
            self._event("check.isolation_unavailable", {"check": label, "class": p.activity.value})
            return CheckResult(
                label, adapter.manifest.name, CheckStatus.NOT_RUN, "host_isolation_unavailable"
            )
        runner.cancel_event = self.cancel  # the kill switch reaches the running process tree
        extra: dict[str, Any] = {}
        if getattr(adapter, "needs_sbom", False):  # D-61: the SBOM produced earlier for this asset
            extra["sbom"] = self.sboms.get(p.asset.asset_id)
        res = adapter.execute(
            p.planned, root, timeout, self.req.policy.limits.max_scanner_output_bytes, runner=runner, **extra
        )
        if (
            res.reason == "cancelled"
            or self.cancel.is_set()
            and res.status
            not in (
                CheckStatus.PASS,
                CheckStatus.FAIL,
            )
        ):
            # A check stopped by the kill switch is BLOCKED (R-04); nothing it produced is kept.
            self._event("check.cancelled", {"check": label})
            return CheckResult(label, adapter.manifest.name, CheckStatus.BLOCKED, "cancelled")
        if res.status == CheckStatus.NOT_RUN:
            # The adapter declined to run (missing scanner, hash mismatch, ...). Nothing it returned
            # is kept: no evidence, no findings, whatever isolation it reports.
            self._event("check.not_run", {"check": label, "reason": res.reason})
            return CheckResult(label, adapter.manifest.name, CheckStatus.NOT_RUN, res.reason or "not_run")
        if res.isolation != runner.name:
            # The adapter ignored the sandbox it was given: never accept its results (D-32).
            self._event("check.isolation_not_used", {"check": label, "reported": res.isolation})
            return CheckResult(label, adapter.manifest.name, CheckStatus.ERROR, "isolation_not_used")
        if res.workspace_removed is False:
            self._event("check.workspace_cleanup_failed", {"check": label})
        isolation = runner.name
        evidence: tuple[str, ...] = ()
        try:
            # D-40: adapter-normalised findings are untrusted until they match their contract.
            schema.validate(list(res.findings), "adapter-findings")
        except schema.SchemaError as exc:
            self._event("check.schema_invalid", {"check": label, "reason": str(exc)[:300]})
            return CheckResult(label, adapter.manifest.name, CheckStatus.ERROR, "schema_invalid")
        if res.raw_output:
            try:
                rec = self.put_evidence_for(p, adapter, res, isolation)
            except RedactionError as exc:
                # §6.4: the artifact is held back; no evidence, no findings, check ERROR.
                self._event("check.redaction_failed", {"check": label, "reason": str(exc)})
                return CheckResult(label, adapter.manifest.name, CheckStatus.ERROR, "redaction_failed")
            evidence = (rec.evidence_id,)
        if getattr(res, "artifact", b"") and res.status in (CheckStatus.PASS, CheckStatus.FAIL):
            with self._lock:
                self.sboms.setdefault(p.asset.asset_id, res.artifact)  # memory only; never persisted
        for k, v in getattr(res, "notes", {}).items():
            with self._lock:
                self.check_notes.setdefault(p.asset.asset_id, {})[f"{adapter.manifest.name}.{k}"] = v
        if getattr(res, "db_snapshot", None) is not None and res.status in (
            CheckStatus.PASS,
            CheckStatus.FAIL,
        ):
            with self._lock:
                self.db_snapshots[getattr(adapter, "database", None) or adapter.manifest.name] = str(
                    res.db_snapshot
                )
        if res.status == CheckStatus.FAIL and evidence:
            for f in res.findings:
                self.raw_findings.append(self._finding(p, adapter, f, evidence[0]))
        reason = res.reason if res.status not in (CheckStatus.PASS, CheckStatus.FAIL) else ""
        return CheckResult(label, adapter.manifest.name, res.status, reason, evidence, res.duration_ms)

    def _reproducibility(self, checks: list[CheckResult]) -> dict[str, Any]:
        """D-29: which pinned snapshots were used, and whether any vulnerability-database check lacked one.
        A run is `non_reproducible` when a database-backed check didn't run on a pinned, verified snapshot."""
        db_adapters = {a.manifest.name: a for a in self.req.adapters if getattr(a, "database", None)}
        reasons = sorted(
            {
                f"{c.adapter}: {c.reason}"
                for c in checks
                if c.adapter in db_adapters and c.status not in (CheckStatus.PASS, CheckStatus.FAIL)
            }
        )
        return {
            "status": "non_reproducible" if reasons else "reproducible",
            "snapshots": dict(sorted(self.db_snapshots.items())),
            "reasons": reasons,
        }

    def _finding(self, p: _Planned, adapter: Any, f: dict[str, Any], evidence_id: str) -> Finding:
        """Normalise one adapter finding with full provenance (D-58, D-62): domain mapping, scanner,
        scanner rule, database snapshot and evidence. Dependency vulnerabilities share a
        scanner-independent identity (package plus canonical advisory ID) so OSV-Scanner, Trivy and Grype
        deduplicate while every contributing source stays listed."""
        dependency = "package" in f
        rule = f["rule"]
        location_key: str | None = None
        if dependency:
            rule = "vuln." + canonical_advisory(f.get("aliases") or [rule.split(".", 1)[-1]])
            location_key = str(f["package"])
        mapped = domains.domain_for(f["rule"], f.get("resource", ""), dependency)
        domain = mapped if mapped != domains.UNMAPPED else getattr(adapter, "domain", "fixture")
        return new_finding(
            domain=domain,
            rule=rule,
            title=f["message"],
            file=f["file"],
            line=f["line"],
            component=p.asset.asset_id,
            severity=f["severity"],
            origin=FindingOrigin.SCANNER,
            evidence_id=evidence_id,
            producer=adapter.manifest.name,
            liveness=f.get("liveness"),
            location_key=location_key,
            source={
                "producer": adapter.manifest.name,
                "rule": f["rule"],
                "evidence": evidence_id,
                "db_snapshot": f.get("db_snapshot"),
                # M6: verified plugin manifest and entry hashes of the bytes that produced this finding
                **({"plugin": f["plugin"]} if "plugin" in f else {}),
            },
        )

    # ── pipeline ───────────────────────────────────────────────────────────
    def put_evidence_for(self, p: _Planned, adapter: ScannerAdapter, res: Any, isolation: str) -> Any:
        """Store a check's output as evidence. RunStore redacts it first and records what was masked."""
        return self.run.put_evidence(
            res.raw_output,
            {
                "audit_id": self.audit_id,
                "check_id": p.check_id,
                "producer": {
                    "adapter": adapter.manifest.name,
                    "adapter_version": adapter.manifest.version,
                    "scanner": adapter.manifest.scanner,
                    "scanner_version": res.scanner_version,
                    "binary_sha256": res.binary_sha256,
                },
                "input": {"asset": p.asset.asset_id, "revision": self.revision},
                "authorization_ref": self.auth_ref,
                "isolation_ref": isolation,
                "collected_at": self.req.clock(),
                "redaction": {},  # replaced by RunStore with the actual redaction summary
                "parent": None,
                "truncated": res.truncated,
            },
        )

    def execute(self) -> AuditOutcome:
        cfg, req = self.req.config, self.req
        self._started = req.clock()
        first = next((a for a in cfg.scope.assets if a.kind == "local_path"), None)
        self.revision = (
            target_revision(Path(first.locator).resolve())
            if first and Path(first.locator).is_dir()
            else "unversioned"
        )
        self.auth_ref = "read-only-default"
        self._event(
            "audit.created", {"audit_id": self.audit_id, "mode": cfg.mode.value, "level": cfg.level.value}
        )
        self.sm.to(AuditState.PLANNED)
        checks: list[CheckResult] = []
        blocked_reason: str | None = None
        try:
            policy.check_mode_level(cfg.mode, cfg.level)
            if req.authorization is not None:
                rec, approval = req.authorization
                self.record = verify_record(rec, approval, req.policy, req.trust, req.ledger, req.clock())
                self.auth_ref = f"{self.record.record['id']}:{self.record.record['version']}"
            policy.check_mode_authorization(cfg.mode, has_record=self.record is not None)
            for cls in cfg.activity_classes:
                policy.check_activity(cfg.mode, cls, has_record=self.record is not None)
            for a in cfg.scope.assets:
                if a.environment == Environment.PRODUCTION and cfg.mode.value == "VALIDATE":
                    raise BlockedError("VALIDATE never targets production in V1 (D-21)", "prod_validate")
        except BlockedError as exc:
            blocked_reason = f"{exc.code}: {exc.reason}"
        if blocked_reason is not None:
            self._event("audit.blocked", {"reason": blocked_reason}, checkpoint=True)
            self.sm.to(AuditState.BLOCKED)
            checks = [
                CheckResult(f"{a.asset_id}/{c}", "policy", CheckStatus.BLOCKED, blocked_reason)
                for a in cfg.scope.assets
                for c in cfg.activity_classes
            ]
            state = AuditState.BLOCKED
        else:
            self.discovery = [
                {"asset": a.asset_id, **discover(Path(a.locator).resolve()).to_json()}
                for a in cfg.scope.assets
                if a.kind == "local_path" and Path(a.locator).is_dir()
            ]
            plans = self._plans = self._plan()
            self.sm.to(AuditState.AUTHORIZED)
            self.sm.to(AuditState.RUNNING)
            self._event("audit.running", {"planned_checks": len(plans)})
            workers = max(1, req.policy.limits.max_concurrent_scanners)
            stop = threading.Event()
            controls.register(self.audit_id)
            watcher = threading.Thread(target=self._watch_controls, args=(stop,), daemon=True)
            watcher.start()
            try:
                # D-61: SBOM consumers (Grype) run after every SBOM producer has finished.
                producers = [p for p in plans if not getattr(p.adapter, "needs_sbom", False)]
                consumers = [p for p in plans if getattr(p.adapter, "needs_sbom", False)]
                for phase in (producers, consumers):
                    with ThreadPoolExecutor(max_workers=workers) as pool:
                        for check in pool.map(self._run_check_hooked, phase):
                            checks.append(check)
            finally:
                stop.set()
                watcher.join(timeout=5)
                controls.unregister(self.audit_id)
            cancelled = self.cancel.is_set()
            with self._lock:
                if self.sm.state == AuditState.PAUSED:
                    self.sm.to(AuditState.CANCELLED if cancelled else AuditState.RUNNING)
            state = final_state([c.status for c in checks], cancelled)
            if self.sm.state != state:
                self.sm.to(state)
        overall = overall_result(state, [c.status for c in checks])
        findings = deduplicate(self.raw_findings)
        self.decision_report: dict[str, Any] = {"applied": [], "rejected": [], "other_revision": 0}
        if req.decisions is not None and findings:
            self.decision_report = apply_decisions(
                findings, self.revision, req.decisions, req.trust, req.ledger, req.clock()
            )
            self._event("decisions.applied", self.decision_report)
        counts: dict[str, int] = {}
        # §6.4/§13.4: one redaction pass over everything that reaches the manifest, reports and the CLI.
        result = self.redactor.redact_obj(self._result(state, overall, checks, findings), counts)
        result["redaction"] = {
            "result": counts,
            "note": REDACTION_NOTE,
            "pii": {
                "covered": list(PII_CLASSES),
                "not_covered": list(PII_NOT_COVERED),
                "note": "PII detection is format matching only (D-57); it never verifies an identity.",
            },
        }
        # D-40: the result must match its contract before anything is signed or reported.
        schema.check_output(result, "audit-result")
        self._event("audit.finished", {"state": state.value, "overall": overall}, checkpoint=True)
        self._write_manifest(result)
        report_paths = self._write_reports(result)
        self.sm.to(AuditState.REPORTED)
        return AuditOutcome(
            self.audit_id, state, overall, checks, findings, self.run.root, result, report_paths
        )

    # ── AC-17 control channel ─────────────────────────────────────────────
    def _transition(self, event: str, data: dict[str, Any]) -> None:
        entry = {"event": event, "at": self.req.clock(), **data}
        self.transitions.append(entry)
        self._event(event, data, checkpoint=True)

    def _watch_controls(self, stop: threading.Event) -> None:
        seen = 0
        while not stop.is_set():
            cmd = controls.read(self.audit_id)
            if cmd is not None and cmd["seq"] > seen:
                seen = cmd["seq"]
                self.apply_control(cmd["command"])
            stop.wait(controls.POLL_S)

    def apply_control(self, command: str) -> None:
        """Apply cancel, pause or resume. Commands only ever reduce what runs."""
        with self._lock:
            state = self.sm.state
        if command == "cancel":
            self.cancel.set()
            self.paused.clear()
            self._transition("audit.cancel_requested", {"from": state.value})
            with self._lock:
                if self.sm.state in (AuditState.RUNNING, AuditState.PAUSED):
                    self.sm.to(AuditState.CANCELLED)
        elif command == "pause" and state == AuditState.RUNNING and not self.cancel.is_set():
            self.paused.set()
            with self._lock:
                self.sm.to(AuditState.PAUSED)
            self._transition("audit.paused", {})
        elif command == "resume" and state == AuditState.PAUSED and not self.cancel.is_set():
            self._reauthorise_remaining()
            with self._lock:
                self.sm.to(AuditState.RUNNING)
            self.paused.clear()
            self._transition(
                "audit.resumed",
                {"reauthorised": self._reauth_count, "refused": len(self._reauth_blocked)},
            )
        else:
            self._transition("audit.control_ignored", {"command": command, "state": state.value})

    def _reauthorise_remaining(self) -> None:
        """§8.2: on resume, every check that has not started passes the authorisation gate again; a
        changed source revision means the audit restarts instead."""
        self._reauth_count = 0
        first = next((a for a in self.req.config.scope.assets if a.kind == "local_path"), None)
        current = (
            target_revision(Path(first.locator).resolve())
            if first and Path(first.locator).is_dir()
            else "unversioned"
        )
        with self._lock:
            remaining = [p for p in self._plans if id(p) not in self._started_plans and p.preset is None]
        if current != self.revision:
            self.restart_required = True
            for p in remaining:
                assert p.adapter is not None
                self._reauth_blocked[id(p)] = CheckResult(
                    f"{p.asset.asset_id}/{p.adapter.manifest.name}",
                    p.adapter.manifest.name,
                    CheckStatus.BLOCKED,
                    "revision_changed",
                )
            self._transition("audit.restart_required", {"reason": "source revision changed while paused"})
            self.cancel.set()
            return
        for p in remaining:
            assert p.adapter is not None
            self._reauth_count += 1
            try:
                self._gate(p, Path(p.asset.locator).resolve())
            except BlockedError as exc:
                self._reauth_blocked[id(p)] = CheckResult(
                    f"{p.asset.asset_id}/{p.adapter.manifest.name}",
                    p.adapter.manifest.name,
                    CheckStatus.BLOCKED,
                    f"{exc.code}: {exc.reason}",
                )

    def _run_check_hooked(self, p: _Planned) -> CheckResult:
        r = self._run_check(p)
        self._event("check.finished", {"check": r.check_id, "status": r.status.value, "reason": r.reason})
        if self.req.after_check is not None:
            self.req.after_check(r)
        return r

    def _result(
        self, state: AuditState, overall: str, checks: list[CheckResult], findings: list[Finding]
    ) -> dict[str, Any]:
        cfg = self.req.config
        return {
            "schema_version": SCHEMA_VERSION,
            "sentinel_version": __version__,
            "audit_id": self.audit_id,
            "mode": cfg.mode.value,
            "level": cfg.level.value,
            "state": state.value,
            "overall": overall,
            "target": {
                "assets": [
                    {"id": a.asset_id, "kind": a.kind, "environment": a.environment.value}
                    for a in cfg.scope.assets
                ],
                "revision": self.revision,
            },
            "authorization_ref": self.auth_ref,
            "policy_source": self.req.policy.source,
            "checks": [c.to_json() for c in checks],
            "checks_not_finished": [c.to_json() for c in checks if not c.finished],
            "findings": [f.to_json() for f in findings],
            "summary": summary(findings),
            "decisions": self.decision_report,
            "disclosure": self._disclosure(),
            "operator_trust_fingerprint": self.req.trust.fingerprint(),
            "host_isolation": self.host.report(),
            "integrity_note": INTEGRITY_NOTE,
            "discovery": getattr(self, "discovery", []),
            "control": {"transitions": list(self.transitions), "restart_required": self.restart_required},
            "reproducibility": self._reproducibility(checks),
            "check_notes": dict(sorted(self.check_notes.items())),
            "domain_coverage": domains.coverage_report(
                getattr(self, "discovery", []),
                [f.to_json() for f in findings],
                [c.to_json() for c in checks],
            ),
        }

    def _disclosure(self) -> dict[str, Any]:
        d = detect_disclosure(self.req.caller, self.req.env)
        if self.req.agent_integration is not None:
            d["agent_integration"] = dict(self.req.agent_integration)
            if self.req.agent_integration["status"] == "unverified":
                d["statement"] += (
                    f" The {self.req.agent_integration['agent']} integration exposed no version, so its"
                    " compatibility is unverified (D-41)."
                )
        return d

    def _write_manifest(self, result: dict[str, Any]) -> None:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "audit_id": self.audit_id,
            "sentinel_version": __version__,
            "python": sys.version.split()[0],
            "host": {"platform": platform.platform()},
            "revision": self.revision,
            "mode": result["mode"],
            "level": result["level"],
            "scope": result["target"],
            "authorization_ref": self.auth_ref,
            "policy_source": result["policy_source"],
            "limits": self.req.policy.limits.__dict__,
            "adapters": [
                {
                    "name": a.manifest.name,
                    "version": a.manifest.version,
                    "binary_sha256": a.detect()[2],
                    "engine_owned": a.manifest.engine_owned,
                }
                for a in self.req.adapters
            ],
            "vulnerability_db_snapshots": result.get("reproducibility", {}).get("snapshots", {}),  # D-29
            "checks": result["checks"],
            "state": result["state"],
            "overall": result["overall"],
            "finding_fingerprints": sorted(f["fingerprint"] for f in result["findings"]),
            "result_sha256": canonical.digest(result),
            "evidence_index": self.run.evidence_index(),
            "audit_log_head": self.log.head(),
            "run_key_id": self.req.run_signer.key_id,
            "host_isolation": result["host_isolation"],
        }
        self.run.write_manifest(manifest, self.req.run_signer)
        self.run.verify_manifest(self.req.run_signer.public)  # never leave an unverifiable run behind

    def _write_reports(self, result: dict[str, Any]) -> dict[str, Path]:
        from .paths import atomic_write

        out = {}
        ext = {"json": "json", "sarif": "sarif", "md": "md", "html": "html"}
        for fmt, render in reports.RENDERERS.items():
            path = self.run.root / "reports" / f"report.{ext[fmt]}"
            atomic_write(path, render(result))
            out[fmt] = path
        return out


def run_audit(req: AuditRequest) -> AuditOutcome:
    return Orchestrator(req).execute()


def verify_run(run_dir: Path, run_signer_public: Any) -> dict[str, Any]:
    """Re-verify a finished run: manifest signature, evidence hashes, audit log chain (D-34 limits)."""
    store = RunStore(run_dir)
    if not store.manifest_path.exists():
        raise IntegrityError("run has no manifest")
    return store.verify_manifest(run_signer_public)
