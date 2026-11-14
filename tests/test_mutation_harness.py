"""The mutation harness itself (AUD-19): baseline gate, setup checks and honest classification."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("mutation_harness", REPO / "scripts/mutation/harness.py")
assert _spec and _spec.loader
h = importlib.util.module_from_spec(_spec)
sys.modules["mutation_harness"] = h
_spec.loader.exec_module(h)
_cat = importlib.util.spec_from_file_location("mutation_catalogue", REPO / "scripts/mutation/mutations.py")
assert _cat and _cat.loader
cat = importlib.util.module_from_spec(_cat)
_cat.loader.exec_module(cat)

GATE = "def gate(x):\n    if x < 0:\n        raise ValueError('negative')\n    return x\n"
TESTS = (
    "import pytest\nfrom calc import gate\n\n\n"
    "def test_gate_rejects_negative():\n    with pytest.raises(ValueError):\n        gate(-1)\n\n\n"
    "def test_gate_passes_positive():\n    assert gate(2) == 2\n"
)


REAL_PREFLIGHT = h.session_preflight


@pytest.fixture(autouse=True)
def _host_independent_preflight(monkeypatch):
    """Harness logic tests must not depend on whether this Mac is locked; the preflight itself is
    tested explicitly through REAL_PREFLIGHT with injected ioreg output."""
    monkeypatch.setattr(h, "session_preflight", lambda: None)


def project(tmp: Path, *, tests: str = TESTS, extra: bool = True) -> Path:
    root = tmp / "proj"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "calc.py").write_text(GATE)
    (root / "tests" / "test_calc.py").write_text(tests)
    if extra:
        (root / "native").mkdir()
        (root / "native" / "helper.txt").write_text("needed by tests\n")
    return root


def mut(mid: str, anchor: str, replacement: str) -> dict[str, str]:
    return {
        "id": mid,
        "suite": "engine",
        "file": "src/calc.py",
        "anchor": anchor,
        "replacement": replacement,
        "label": mid,
    }


REMOVE_GATE = mut("remove-gate", "    if x < 0:\n", "    if False:\n")


def campaign(
    root: Path, muts: list[dict[str, str]], inputs: tuple[str, ...] = ("src", "tests", "native")
) -> dict:
    return h.run_campaign(muts, root=root, inputs=inputs, python=sys.executable, timeout=120)


def test_caught_mutant_records_failing_test(tmp_path: Path) -> None:
    r = campaign(project(tmp_path), [REMOVE_GATE])
    assert r["status"] == "all_caught" and r["baseline"]["engine"]["pytest_exit"] == 0
    (o,) = r["mutants"]
    assert o["status"] == "caught" and o["pytest_exit"] == 1
    assert o["failing_tests"] == ["tests/test_calc.py::test_gate_rejects_negative"]


def test_surviving_mutant(tmp_path: Path) -> None:
    root = project(tmp_path, tests="from calc import gate\n\n\ndef test_ok():\n    assert gate(2) == 2\n")
    r = campaign(root, [REMOVE_GATE])
    assert r["status"] == "survivors" and r["counts"]["survived"] == 1 and r["counts"]["caught"] == 0
    assert h.EXIT[r["status"]] == 1


def test_broken_baseline_runs_no_mutants(tmp_path: Path) -> None:
    root = project(tmp_path, tests="def test_broken():\n    assert False\n")
    r = campaign(root, [REMOVE_GATE])
    assert r["status"] == "baseline_failed" and r["mutants"] == [] and r["counts"]["caught"] == 0
    assert r["baseline"]["engine"]["pytest_exit"] == 1


def test_baseline_needing_uncopied_file_fails_instead_of_inflating_kills(tmp_path: Path) -> None:
    # The AUD-19 defect: a test needs native/, but the copy omits it. Every mutant would "fail".
    needs_native = TESTS + (
        "\n\ndef test_native_present():\n    from pathlib import Path\n"
        "    assert Path('native/helper.txt').is_file()\n"
    )
    root = project(tmp_path, tests=needs_native)
    r = campaign(root, [REMOVE_GATE], inputs=("src", "tests"))
    assert r["status"] == "baseline_failed" and r["mutants"] == []


def test_missing_input_stops_before_any_run(tmp_path: Path) -> None:
    r = campaign(project(tmp_path, extra=False), [REMOVE_GATE])
    assert r["status"] == "setup_failed" and "native" in r["detail"]
    assert r["baseline"] is None and r["mutants"] == []
    assert h.EXIT["setup_failed"] == 3


@pytest.mark.parametrize(
    ("m", "reason"),
    [
        (mut("absent", "    if x > 100:\n", "    if False:\n"), "occurs 0 times"),
        (mut("dup", "    ", "  "), "occurs 4 times"),
        (mut("noop", "    if x < 0:\n", "    if x < 0:\n"), "no-op"),
        (mut("syntax", "    if x < 0:\n", "    if x <<< 0:\n"), "does not compile"),
    ],
)
def test_invalid_mutants_are_not_caught(tmp_path: Path, m: dict[str, str], reason: str) -> None:
    r = campaign(project(tmp_path), [m])
    (o,) = r["mutants"]
    assert o["status"] == "invalid" and reason in o["detail"]
    assert r["counts"]["caught"] == 0 and r["status"] == "incomplete"


def test_import_error_is_infra_failure_not_caught(tmp_path: Path) -> None:
    m = mut("import-break", "def gate(x):\n", "import does_not_exist_anywhere\n\n\ndef gate(x):\n")
    r = campaign(project(tmp_path), [m])
    (o,) = r["mutants"]
    assert o["status"] == "infra_failed" and o["pytest_exit"] not in (0, 1)
    assert r["counts"]["caught"] == 0


def test_timeout_is_infra_failure(tmp_path: Path) -> None:
    m = mut("hang", "    return x\n", "    import time\n    time.sleep(60)\n    return x\n")
    r = h.run_campaign(
        [m], root=project(tmp_path), inputs=("src", "tests", "native"), python=sys.executable, timeout=5
    )
    (o,) = r["mutants"]
    assert o["status"] == "infra_failed" and o["detail"] == "timeout"


def test_exit_one_without_failing_test_ids_is_not_caught() -> None:
    o = h.classify(REMOVE_GATE, 1, "something odd\n", 0.1)
    assert o.status == "infra_failed"


def test_inputs_are_hashed_for_reproducibility(tmp_path: Path) -> None:
    root = project(tmp_path)
    a = campaign(root, [REMOVE_GATE])["inputs"]
    assert a == campaign(root, [REMOVE_GATE])["inputs"]
    (root / "src" / "calc.py").write_text(GATE + "\n# changed\n")
    assert campaign(root, [REMOVE_GATE])["inputs"]["src"] != a["src"]


def test_mutant_does_not_touch_the_source_tree(tmp_path: Path) -> None:
    root = project(tmp_path)
    campaign(root, [REMOVE_GATE])
    assert (root / "src" / "calc.py").read_text() == GATE


def test_malformed_catalogue_rejected() -> None:
    with pytest.raises(h.SetupError):
        h.validate_catalogue([REMOVE_GATE, REMOVE_GATE])
    with pytest.raises(h.SetupError):
        h.validate_catalogue([{**REMOVE_GATE, "suite": "nope"}])


def test_real_catalogue_is_well_formed_and_anchors_exist_once() -> None:
    h.validate_catalogue(cat.MUTATIONS)
    for m in cat.MUTATIONS:
        text = (REPO / m["file"]).read_text()
        assert text.count(m["anchor"]) == 1, m["id"]


def test_real_inputs_all_exist() -> None:
    h.check_inputs(REPO, h.COPY_INPUTS)


def test_mutant_runs_exclude_only_the_catalogue_meta_test(monkeypatch, tmp_path) -> None:
    """A mutation always removes its own anchor, so the anchor meta-test must not count as a catch."""
    seen: list[list[str]] = []
    monkeypatch.setattr(h, "make_copy", lambda root, inputs, copy: copy.mkdir(parents=True))
    monkeypatch.setattr(h, "apply_mutation", lambda copy, m: None)
    monkeypatch.setattr(h, "run_tests", lambda copy, tests, py, t: seen.append(tests) or (0, "", 0.0))
    m = cat.MUTATIONS[0]
    h.run_one(m, REPO, (), tmp_path, "python", 10)
    assert seen[0][: len(h.SUITE_TESTS[m["suite"]])] == h.SUITE_TESTS[m["suite"]]
    assert seen[0][len(h.SUITE_TESTS[m["suite"]]) :] == [f"--deselect={t}" for t in h.MUTANT_RUN_DESELECT]
    assert h.MUTANT_RUN_DESELECT == (
        "tests/test_mutation_harness.py::test_real_catalogue_is_well_formed_and_anchors_exist_once",
    )


META = "tests/test_mutation_harness.py::test_real_catalogue_is_well_formed_and_anchors_exist_once"


def _m() -> dict[str, str]:
    return {"id": "x", "label": "x", "file": "f", "suite": "engine"}


def test_anchor_only_failure_is_never_a_caught_mutant() -> None:
    o = h.classify(_m(), 1, f"FAILED {META} - AssertionError: x\n1 failed", 1.0)
    assert o.status != "caught" and o.status == "infra_failed" and "anchor-only" in o.detail


def test_behavioural_failure_alongside_meta_test_is_caught() -> None:
    out = f"FAILED {META} - x\nFAILED tests/test_approvals.py::test_expiry - x\n"
    assert h.classify(_m(), 1, out, 1.0).status == "caught"


def test_behavioural_failure_alone_is_caught_and_pass_survives() -> None:
    assert h.classify(_m(), 1, "FAILED tests/test_a.py::test_b - x\n", 1.0).status == "caught"
    assert h.classify(_m(), 0, "1 passed", 1.0).status == "survived"


def test_baseline_still_runs_the_catalogue_meta_test() -> None:
    import inspect

    src = inspect.getsource(h.run_campaign)
    baseline = src.split('f"baseline-{suite}"', 1)[1].split('report["baseline"]', 1)[0]
    assert "run_tests(copy, SUITE_TESTS[suite]" in baseline and "DESELECT" not in baseline
    assert META in h.MUTANT_RUN_DESELECT


def _plist(users: list[dict[str, object]]) -> bytes:
    import plistlib

    return plistlib.dumps({"IOConsoleUsers": users})


ON = {"kCGSSessionOnConsoleKey": True, "kCGSessionLoginDoneKey": True}


def test_preflight_passes_only_for_an_unlocked_console_session() -> None:
    assert REAL_PREFLIGHT("darwin", lambda: _plist([ON])) is None
    assert REAL_PREFLIGHT("linux", lambda: b"garbage") is None
    locked = REAL_PREFLIGHT("darwin", lambda: _plist([{**ON, "CGSSessionScreenIsLocked": True}]))
    assert locked and "locked" in locked and "-25308" in locked
    assert "no logged-in console" in (REAL_PREFLIGHT("darwin", lambda: _plist([])) or "")
    assert "cannot confirm" in (REAL_PREFLIGHT("darwin", lambda: b"not a plist") or "")

    def boom() -> bytes:
        raise OSError("ioreg missing")

    assert "cannot confirm" in (REAL_PREFLIGHT("darwin", boom) or "")


def test_locked_session_aborts_before_any_baseline(monkeypatch) -> None:
    ran: list[object] = []
    monkeypatch.setattr(h, "run_tests", lambda *a: ran.append(a) or (0, "", 0.0))
    rep = h.run_campaign(cat.MUTATIONS[:1], preflight=lambda: "macOS session is locked")
    assert rep["status"] == "environment_unsuitable" and "locked" in rep["detail"] and ran == []
    assert h.EXIT["environment_unsuitable"] not in (0, 1)


def test_lock_during_campaign_invalidates_results(monkeypatch) -> None:
    calls = iter([None, "macOS session is locked"])
    monkeypatch.setattr(h, "run_tests", lambda *a: (0, "", 0.0))
    monkeypatch.setattr(h, "make_copy", lambda root, inputs, copy: copy.mkdir(parents=True))
    monkeypatch.setattr(h, "apply_mutation", lambda copy, m: None)
    monkeypatch.setattr(h, "check_inputs", lambda root, inputs: {})
    rep = h.run_campaign(cat.MUTATIONS[:1], preflight=lambda: next(calls))
    assert rep["status"] == "environment_unsuitable" and "not valid" in rep["detail"]
