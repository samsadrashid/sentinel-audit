"""AC-18: retention pruning. `--list` never deletes; `--delete` deletes only expired runs, only with
interactive confirmation, leaves 0 files, writes a hash-only log entry, and the log chain verifies."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sentinel import canonical, cli
from sentinel.keys.runkey import RunKeyManager

from .conftest import FIXTURE_ONLY
from .test_cli import HOST, MemBackend, config, target

DAY = 86400


def tree(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p).encode())
        if p.is_file() and not p.is_symlink():
            h.update(p.read_bytes())
    return h.hexdigest()


def make_deps(clock, *, interactive=True, confirm=lambda ids: True, env=None):  # type: ignore[no-untyped-def]
    backend = MemBackend()
    return backend, cli.Deps(
        run_keys=lambda: RunKeyManager(backend),
        host=lambda: HOST,
        clock=clock,
        env=env if env is not None else {},
        interactive=lambda: interactive,
        agent_version=lambda a: None,
        adapters=FIXTURE_ONLY,
        confirm=confirm,
    )


def run(d, capsys, *argv):  # type: ignore[no-untyped-def]
    code = cli.main(["--json", *argv], d)
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip().startswith("{") else out


def two_runs(tmp_path, capsys, monkeypatch):  # type: ignore[no-untyped-def]
    """One run 100 days old and one fresh run (default retention 90 days). The run's age comes from
    its own first audit-log entry, which uses the wall clock, so the old run's log is backdated."""
    import time as _time

    import sentinel.evidence as ev

    real = _time.time()
    now = [int(real)]
    backend, d = make_deps(lambda: now[0])
    assert run(d, capsys, "init")[0] == 0
    monkeypatch.setattr(ev.time, "time", lambda: real - 100 * DAY)
    old = run(d, capsys, "audit", "--config", config(tmp_path, target(tmp_path, "a", "clean")))[1]["audit_id"]
    monkeypatch.setattr(ev.time, "time", lambda: real)
    new = run(d, capsys, "audit", "--config", config(tmp_path, target(tmp_path, "b", "clean")))[1]["audit_id"]
    return now, d, old, new


def test_list_never_deletes_anything(tmp_path, capsys, monkeypatch):
    now, d, old, new = two_runs(tmp_path, capsys, monkeypatch)
    before = tree(cli.runs_dir())
    code, out = run(d, capsys, "prune", "--list")
    assert code == 0 and tree(cli.runs_dir()) == before
    expired = {r["run_id"]: r["expired"] for r in out["runs"]}
    assert expired == {old: True, new: False} and out["deleted"] == [] and out["retention_days"] == 90


def test_delete_removes_only_expired_runs_completely_and_logs_hash_only(tmp_path, capsys, monkeypatch):
    now, d, old, new = two_runs(tmp_path, capsys, monkeypatch)
    manifest_sha = canonical.sha256_hex((cli.run_path(old) / "manifest.json").read_bytes())
    new_tree = tree(cli.run_path(new))
    code, out = run(d, capsys, "prune", "--delete")
    assert code == 0 and out["deleted"] == [old] and out["remaining_files"] == 0
    assert not (cli.runs_dir() / old).exists()
    assert not any(old in str(p) for p in cli.runs_dir().rglob("*"))
    assert tree(cli.run_path(new)) == new_tree  # the fresh run is untouched
    log = (cli.state_dir() / "history" / "admin-log.jsonl").read_text()
    entries = [json.loads(ln) for ln in log.splitlines()]
    deleted = [e for e in entries if e["event"] == "retention.deleted"]
    assert len(deleted) == 1
    data = deleted[0]["data"]
    assert data["run_id_sha256"] == hashlib.sha256(old.encode()).hexdigest()
    assert data["manifest_sha256"] == manifest_sha and old not in json.dumps(deleted[0])
    assert any(e["event"] == "retention.delete_completed" for e in entries)
    code, hist = run(d, capsys, "history", "verify")
    assert code == 0, hist


def test_delete_is_refused_without_an_interactive_human(tmp_path, capsys, monkeypatch):
    now, d, old, new = two_runs(tmp_path, capsys, monkeypatch)
    before = tree(cli.runs_dir())
    _, nd = make_deps(lambda: now[0], interactive=False)
    nd = cli.Deps(**{**nd.__dict__, "run_keys": d.run_keys})
    code, out = run(nd, capsys, "prune", "--delete")
    assert code == cli.EXIT_BLOCKED and out["code"] == "non_interactive"
    _, ad = make_deps(lambda: now[0], env={"CLAUDECODE": "1"})
    ad = cli.Deps(**{**ad.__dict__, "run_keys": d.run_keys})
    code, out = run(ad, capsys, "prune", "--delete")
    assert code == cli.EXIT_BLOCKED and out["code"] == "agent_caller"
    assert tree(cli.runs_dir()) == before


def test_delete_without_confirmation_deletes_nothing(tmp_path, capsys, monkeypatch):
    now, d, old, new = two_runs(tmp_path, capsys, monkeypatch)
    before = tree(cli.runs_dir())
    _, nd = make_deps(lambda: now[0], confirm=lambda ids: False)
    nd = cli.Deps(**{**nd.__dict__, "run_keys": d.run_keys})
    code, out = run(nd, capsys, "prune", "--delete")
    assert code == cli.EXIT_BLOCKED and out["code"] == "not_confirmed"
    assert tree(cli.runs_dir()) == before
    log = (cli.state_dir() / "history" / "admin-log.jsonl").read_text()
    assert "retention.delete_declined" in log and "retention.deleted" not in log


def test_confirmation_shows_exactly_the_runs_to_delete(tmp_path, capsys, monkeypatch):
    now, d, old, new = two_runs(tmp_path, capsys, monkeypatch)
    seen: list[list[str]] = []
    _, nd = make_deps(lambda: now[0], confirm=lambda ids: seen.append(ids) or True)
    nd = cli.Deps(**{**nd.__dict__, "run_keys": d.run_keys})
    run(nd, capsys, "prune", "--delete")
    assert seen == [[old]]


def test_runs_of_unknown_age_are_never_deleted(tmp_path, capsys, monkeypatch):
    now, d, old, new = two_runs(tmp_path, capsys, monkeypatch)
    log = cli.run_path(old) / "audit-log.jsonl"
    log.chmod(0o600)
    log.write_text("garbage\n")
    code, out = run(d, capsys, "prune", "--list")
    assert code == 0, out
    row = next(r for r in out["runs"] if r["run_id"] == old)
    assert row["status"] == "age_unknown" and row["expired"] is False
    code, out = run(d, capsys, "prune", "--delete")
    assert out["deleted"] == [] and (cli.runs_dir() / old).exists()
