"""M1 task 7: the engine CI workflow runs every software gate on macOS and Linux, read-only."""

from __future__ import annotations

from pathlib import Path

WF = Path(__file__).resolve().parents[1] / ".github/workflows/engine-ci.yml"


def test_engine_workflow_runs_every_gate_on_both_platforms() -> None:
    text = WF.read_text()
    for required in (
        "os: [macos-26, ubuntu-24.04]",
        "uv lock --check",
        "uv sync --frozen --python 3.13",
        ".venv/bin/ruff check .",
        ".venv/bin/ruff format --check .",
        ".venv/bin/mypy --strict src scripts/mutation",
        "scripts/license_audit.py check --strict",
        "scripts/docs/check_architecture_docs.py .",
        "-m pytest -p no:randomly -rs",
        'SENTINEL_CI: "1"',
    ):
        assert required in text, required


def test_engine_workflow_creates_the_licence_build_env_before_using_it() -> None:
    """Regression: the strict licence audit and its tests need build/license-env (gitignored). It existed
    only on the development Mac, so a fresh checkout failed with build_env_missing."""
    text = WF.read_text()
    create = text.index("uv venv --python 3.13 build/license-env")
    install = text.index("--require-hashes -r licenses/build-lock.txt")
    assert create < install < text.index("scripts/license_audit.py check --strict")
    assert install < text.index("-m pytest -p no:randomly -rs")


def test_no_workflow_uses_a_retired_macos_runner() -> None:
    """Regression: macos-14 was retired on 2026-11-02, so the first remote run never got a macOS runner."""
    import re

    for wf in WF.parent.glob("*.yml"):
        code = "\n".join(line.split("#", 1)[0] for line in wf.read_text().splitlines())
        for label in re.findall(r"macos-(\d+)", code):
            assert int(label) >= 26, (wf.name, f"macos-{label}")


def test_engine_workflow_is_least_privilege() -> None:
    text = WF.read_text()
    assert "permissions:\n  contents: read\n" in text
    assert "persist-credentials: false" in text
    assert "secrets." not in text and "pull_request_target" not in text and "write" not in text


def test_every_action_is_pinned_by_full_commit_sha() -> None:
    import re

    for wf in WF.parent.glob("*.yml"):
        uses = re.findall(r"uses:\s*(\S+)", wf.read_text())
        assert uses, wf
        for u in uses:
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), (wf.name, u)


def test_no_workflow_keeps_checkout_credentials() -> None:
    for wf in WF.parent.glob("*.yml"):
        text = wf.read_text()
        assert text.count("actions/checkout@") == text.count("persist-credentials: false"), wf.name
