"""AC-15: PII minimisation before persistence, across evidence, findings, reports, logs and CLI output.

The corpus (tests/pii_corpus.py) has 60 synthetic, format-valid instances of each of the 10 in-scope
classes. Measured result: zero raw instances in any stored or emitted artifact. A detector failure
holds the artifact back. Detection is format matching only, never identity verification (D-57).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from sentinel import cli, redaction
from sentinel.adapters.scanners import GitleaksAdapter
from sentinel.domain.enums import ActivityClass
from sentinel.evidence import AuditLog
from sentinel.keys.runkey import RunKeyManager
from sentinel.redaction import PII_CLASSES, PII_NOT_COVERED, RedactionError, Redactor

from .conftest import NOW
from .isolation_testing import TestHost
from .m2_fakes import ok, pins_with, seatbelt
from .pii_corpus import N, clean_corpus, corpus, raw_values
from .test_cli import MemBackend, config, target


def test_corpus_has_at_least_50_instances_per_class_and_all_are_detected():
    c = corpus()
    assert len(c) == 10 and all(len(v) >= 50 for v in c.values()) and N >= 50
    r = Redactor(b"k" * 32)
    for cls, vals in c.items():
        for v in vals:
            out, counts = r.redact_text(f"value: {v} end")
            assert counts.get(cls), (cls, v)
            raw = v.split(": ", 1)[1] if cls == "pii_bd_nid" and ": " in v else v
            assert raw not in out


def test_false_positive_rate_on_the_clean_corpus_is_measured_and_zero():
    """Recorded in docs/m2/pii.md: 0 false positives per class on 18,000 look-alike lines."""
    r = Redactor(b"k" * 32)
    fp: Counter[str] = Counter()
    lines = clean_corpus()
    for ln in lines:
        _, counts = r.redact_text(ln)
        fp.update({k: v for k, v in counts.items() if k.startswith("pii_")})
    assert len(lines) == 18000
    assert dict(fp) == {}


class _Host(TestHost):
    __test__ = False

    def runner_for(self, cls: ActivityClass, limits: Any, pins: Any = None, kind: Any = None) -> Any:
        return self.runner if cls == ActivityClass.S1 else None


def _pii_scanner_output(values: list[str]) -> bytes:
    """Each instance appears in a finding's description, its file path and the scanner's match."""
    findings = []
    for i, v in enumerate(values):
        findings.append(
            {
                "RuleID": "generic-api-key",
                "Description": f"secret near {v}",
                "File": f"/target/data/{v.replace('/', '_')}.txt",
                "StartLine": i + 1,
                "Secret": f"sk-{i:020d}abcdefghij",
                "Match": v,
            }
        )
    return json.dumps(findings).encode()


def _all_artifacts(home: Path) -> list[tuple[str, bytes]]:
    return [(str(p), p.read_bytes()) for p in home.rglob("*") if p.is_file() and not p.is_symlink()]


def test_no_raw_pii_in_any_stored_or_emitted_artifact(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("SENTINEL_HOME", str(home))
    c = corpus()
    values = raw_values(c)
    t = target(tmp_path, "t", "clean")
    pins = pins_with(tmp_path, gitleaks="binary")
    runner = seatbelt(ok(_pii_scanner_output([v for vals in c.values() for v in vals])))
    host = _Host("darwin", "s1-macos-seatbelt", None, None, False, runner=runner)
    backend = MemBackend()
    deps = cli.Deps(
        run_keys=lambda: RunKeyManager(backend),
        host=lambda: host,
        clock=lambda: NOW,
        env={},
        agent_version=lambda a: None,
        adapters=lambda pol: [GitleaksAdapter(pins)],
    )
    assert cli.main(["--json", "init"], deps) == 0
    capsys.readouterr()
    emitted: list[str] = []
    code = cli.main(["--json", "audit", "--config", config(tmp_path, t)], deps)
    out = capsys.readouterr().out
    emitted.append(out)
    assert code == cli.EXIT_FINDINGS, out
    rid = json.loads(out)["audit_id"]
    for argv in (
        ["--json", "runs", "show", rid],
        ["--json", "evidence", "verify", rid],
        ["report", rid, "--format", "json"],
        ["report", rid, "--format", "sarif"],
        ["report", rid, "--format", "md"],
        ["report", rid, "--format", "html"],
        ["--json", "fix-plan", rid],
    ):
        assert cli.main(argv, deps) == 0
        emitted.append(capsys.readouterr().out)
    # logs: the run log and the admin log both redact event data
    log = AuditLog(tmp_path / "extra-log.jsonl", Redactor.default())
    log.append("pii.test", {"values": [v for vals in c.values() for v in vals]})
    artifacts = _all_artifacts(home) + [("extra-log", (tmp_path / "extra-log.jsonl").read_bytes())]
    artifacts += [(f"cli[{i}]", e.encode()) for i, e in enumerate(emitted)]
    leaks = [(name, v) for name, blob in artifacts for v in values if v.encode() in blob]
    assert leaks == [], leaks[:5]
    result = json.loads(emitted[3])
    assert result["redaction"]["pii"]["not_covered"] == list(PII_NOT_COVERED)
    assert result["redaction"]["pii"]["covered"] == list(PII_CLASSES)
    assert "identity" in result["redaction"]["pii"]["note"]


def test_a_detector_failure_blocks_persistence(tmp_path, monkeypatch):
    from sentinel.evidence import RunStore

    def boom(v: bytes) -> bool:
        raise RuntimeError("detector crashed")

    rules = tuple(
        redaction.Rule(r.name, r.pattern, r.group, boom) if r.name == "pii_payment_card" else r
        for r in redaction.BUILTIN_RULES
    )
    r = Redactor(b"k" * 32)
    r.rules = rules
    with pytest.raises(RedactionError):
        r.redact_text("card 4111 1111 1111 1111")
    store = RunStore.create(tmp_path / "runs", "01a1c049-fd7e-7acb-ae9e-3406332d7387", r)
    with pytest.raises(RedactionError):
        store.put_evidence(b"card 4111 1111 1111 1111", {})
    assert not any((store.root / "evidence").iterdir())


def test_format_matching_is_never_described_as_identity_verification():
    doc = (Path(__file__).resolve().parents[1] / "docs/m2/pii.md").read_text()
    assert "not identity verification" in doc
    for cls in ("Bangladesh NID", "Aadhaar", "SSN", "National Insurance"):
        assert cls in doc


@pytest.mark.parametrize(
    "text",
    [
        "4111 1111 1111 1112",  # Luhn-invalid card
        "2341 2341 2345",  # Verhoeff-invalid Aadhaar
        "000-12-3456",
        "666-12-3456",
        "912-12-3456",
        "123-00-3456",
        "123-45-0000",  # reserved SSN ranges
        "BG 12 34 56 A",
        "GB 12 34 56 A",
        "NT 12 34 56 A",  # reserved NINO prefixes
        "18991234567890123",  # 17 digits but no plausible birth year
        "10.1.2.3.4",  # five-part version, not IPv4
    ],
)
def test_structurally_invalid_values_are_not_reported_as_pii(text):
    out, counts = Redactor(b"k" * 32).redact_text(f"value {text} end")
    assert not {k for k in counts if k.startswith("pii_")}, (text, counts)
