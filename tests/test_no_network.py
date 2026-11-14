"""Privacy/network review: the Sentinel engine process opens no network connection and does no DNS lookup.

Scope (stated precisely): this covers the engine process running init, audit, reports in every format,
fix-plan, compare, runs/evidence verification, policy validation, self-check and the MCP server. Child
processes (scanners, analyzers, plugins) run only inside verified isolation with network denied; that
is proven separately by the real-sandbox and real-Podman tests (hostile plugin, `--network=none`). The
sandbox *self-test* deliberately attempts a loopback connection inside the sandbox to prove denial.
"""

# ruff: noqa: F811
from __future__ import annotations

import io
import json
import socket

import pytest

from sentinel import cli, mcp

from .test_cli import config, deps, ready, run, target  # noqa: F401

FINDING = "SENTINEL-FIXTURE-FINDING\n"


@pytest.fixture
def no_network(monkeypatch):  # type: ignore[no-untyped-def]
    attempts: list[str] = []

    def deny(name):  # type: ignore[no-untyped-def]
        def f(*a, **k):  # type: ignore[no-untyped-def]
            attempts.append(f"{name}{a[:2]!r}")
            raise OSError("network disabled by test")

        return f

    monkeypatch.setattr(socket.socket, "connect", deny("connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", deny("connect_ex"))
    monkeypatch.setattr(socket.socket, "sendto", deny("sendto"))
    monkeypatch.setattr(socket, "create_connection", deny("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", deny("getaddrinfo"))
    monkeypatch.setattr(socket, "gethostbyname", deny("gethostbyname"))
    return attempts


def test_engine_commands_make_no_network_calls(ready, capsys, tmp_path, no_network):
    t = target(tmp_path, "t", FINDING)
    _, a = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    (t / "app.txt").write_text("clean")
    _, b = run(ready, capsys, "audit", "--config", config(tmp_path, t))
    for argv in (
        ["runs", "list"],
        ["runs", "show", a["audit_id"]],
        ["evidence", "verify", a["audit_id"]],
        ["fix-plan", a["audit_id"]],
        ["compare", a["audit_id"], b["audit_id"]],
        ["status"],
        ["policy", "validate"],
        ["self-check"],
        ["version"],
    ):
        run(ready, capsys, *argv)
    for fmt in ("json", "sarif", "md", "html"):
        cli.main(["report", a["audit_id"], "--format", fmt], ready)
        capsys.readouterr()
    assert no_network == []


def test_mcp_server_makes_no_network_calls(ready, capsys, no_network):
    def run_cli(argv):  # type: ignore[no-untyped-def]
        code = cli.main(argv, ready)
        return code, capsys.readouterr().out

    out = io.StringIO()
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "runs_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "status", "arguments": {}}},
    ]
    mcp.serve(io.StringIO("".join(json.dumps(m) + "\n" for m in msgs)), out, mcp.Server(run_cli=run_cli))
    assert len(out.getvalue().splitlines()) == 4
    assert no_network == []
