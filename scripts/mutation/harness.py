#!/usr/bin/env python3
"""Reproducible security mutation campaign (AUD-19).

For each mutant in ``scripts/mutation/mutations.py`` the harness copies the project's declared inputs
into a fresh scratch directory, applies exactly one textual mutation, and runs the suite's tests.

Guarantees:

* every declared input must exist, or the campaign stops before running anything (``setup_failed``);
* the **unmodified** baseline runs first, in an identical copy, and must pass, or no mutant runs
  (``baseline_failed``);
* each mutant gets one status, and only ``caught`` counts as caught:
  - ``caught``: pytest ran and at least one test failed (exit 1);
  - ``survived``: every test passed with the mutation applied (exit 0);
  - ``invalid``: the anchor is absent or repeated, the mutation is a no-op, or the mutated Python
    file does not compile. The mutant is not a meaningful experiment;
  - ``infra_failed``: timeout, collection or import error, interrupted run, or any other pytest exit
    code. Never counted as caught;
* the result file records the mutant id, file, status, pytest exit code, failing test ids, and the
  SHA-256 of the mutation catalogue and of every input, so a run can be reproduced and compared.

Exit codes: 0 all caught; 1 survivors; 2 baseline failed; 3 setup failed; 4 invalid or infra-failed
mutants (and no survivors).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
#: Everything the test suite reads. Missing entries stop the campaign (the AUD-19 root cause was a
#: copy that silently omitted native/).
COPY_INPUTS = (
    "src",
    "tests",
    "scripts",
    "licenses",
    "native",
    "docs/architecture",
    "docs/m1",
    "docs/user",
    "docs/m2",
    "docs/m3",
    "docs/roadmap",
    ".github/workflows",
    "pyproject.toml",
    "CHANGELOG.md",
    "uv.lock",
    "README.md",
    "THIRD_PARTY_NOTICES",
    "LICENSE",
    # Hash-pinned build backend env (licenses/build-lock.txt) read by the license audit tests.
    "build/license-env",
)
SUITE_TESTS = {
    "engine": ["tests"],
    "license": ["tests/test_license_audit.py"],
    # D-73 signing-device code (Swift SignerCore and the engine's protocol side). Swift mutants must also
    # compile; a mutant that doesn't is invalid, never caught (checked before the campaign).
    "signer": [
        "tests/test_signer_core_swift.py",
        "tests/test_signer_interop.py",
        "tests/test_enrolment_request.py",
        "tests/test_d74_release_signing.py",  # D-74 release signing (engine side)
    ],
}
# Meta-tests about the *unmutated* catalogue: every mutation removes its own anchor, so these would
# "catch" every mutant falsely. They run in the baseline only, never in mutant runs.
MUTANT_RUN_DESELECT = (
    "tests/test_mutation_harness.py::test_real_catalogue_is_well_formed_and_anchors_exist_once",
)
STATUSES = ("caught", "survived", "invalid", "infra_failed")
IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".build", ".swiftpm"
)


class SetupError(Exception):
    pass


@dataclass
class Outcome:
    id: str
    label: str
    file: str
    suite: str
    status: str
    pytest_exit: int | None = None
    failing_tests: list[str] = field(default_factory=list)
    detail: str = ""
    seconds: float = 0.0


def tree_sha256(path: Path) -> str:
    h = hashlib.sha256()
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    for p in files:
        if "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        h.update(p.relative_to(path.parent).as_posix().encode() + b"\0")
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def check_inputs(root: Path, inputs: tuple[str, ...]) -> dict[str, str]:
    missing = [i for i in inputs if not (root / i).exists()]
    if missing:
        raise SetupError(f"missing campaign inputs: {missing}")
    return {i: tree_sha256(root / i) for i in inputs}


def make_copy(root: Path, inputs: tuple[str, ...], dest: Path) -> None:
    dest.mkdir(parents=True)
    for i in inputs:
        src, dst = root / i, dest / i
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, ignore=IGNORE, symlinks=True)
        else:
            shutil.copy2(src, dst)


def apply_mutation(copy: Path, m: dict[str, str]) -> str | None:
    """Apply ``m`` in ``copy``. Returns a reason if the mutant is invalid, else None."""
    target = copy / m["file"]
    if not target.is_file():
        return f"file not found: {m['file']}"
    text = target.read_text(encoding="utf-8")
    count = text.count(m["anchor"])
    if count != 1:
        return f"anchor occurs {count} times (must be exactly 1)"
    if m["anchor"] == m["replacement"]:
        return "replacement equals anchor (no-op)"
    mutated = text.replace(m["anchor"], m["replacement"])
    if target.suffix == ".py":
        try:
            compile(mutated, str(target), "exec")
        except SyntaxError as exc:
            return f"mutated file does not compile: {exc.msg} (line {exc.lineno})"
    target.write_text(mutated, encoding="utf-8")
    return None


def child_env(copy: Path) -> dict[str, str]:
    path = ["/usr/bin", "/bin"]
    uv = shutil.which("uv")
    if uv:
        path.insert(0, str(Path(uv).parent))
    env = {"PYTHONPATH": str(copy / "src"), "PATH": os.pathsep.join(path), "PYTHONDONTWRITEBYTECODE": "1"}
    if "HOME" in os.environ:
        env["HOME"] = os.environ["HOME"]
    return env


_FAILED = re.compile(r"^(?:FAILED|ERROR) (\S+)", re.M)


def run_tests(copy: Path, tests: list[str], python: str, timeout: int) -> tuple[int | None, str, float]:
    cmd = [python, "-m", "pytest", "-x", "-q", "-rfE", "-p", "no:cacheprovider", *tests]
    start = time.monotonic()
    try:
        r = subprocess.run(
            cmd, cwd=copy, env=child_env(copy), capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None, "timeout", time.monotonic() - start
    return r.returncode, r.stdout + r.stderr, time.monotonic() - start


def classify(m: dict[str, str], rc: int | None, output: str, seconds: float) -> Outcome:
    o = Outcome(m["id"], m["label"], m["file"], m["suite"], "infra_failed", rc, seconds=round(seconds, 1))
    o.failing_tests = sorted(set(_FAILED.findall(output)))
    behavioural = [t for t in o.failing_tests if t not in MUTANT_RUN_DESELECT]
    if rc == 1 and behavioural:
        o.status = "caught"
    elif rc == 1 and o.failing_tests:
        # Only catalogue meta-tests failed: a mutation always removes its own anchor, so that is never
        # evidence that a behavioural test detects the mutant.
        o.detail = "anchor-only failure (catalogue meta-test); not a behavioural catch"
    elif rc == 0:
        o.status = "survived"
    elif rc is None:
        o.detail = "timeout"
    else:
        o.detail = (
            f"pytest exit {rc}: " + output.strip().splitlines()[-1][:300] if output.strip() else f"exit {rc}"
        )
    return o


def run_one(
    m: dict[str, str], root: Path, inputs: tuple[str, ...], work: Path, python: str, timeout: int
) -> Outcome:
    copy = work / m["id"]
    try:
        make_copy(root, inputs, copy)
        reason = apply_mutation(copy, m)
        if reason is not None:
            return Outcome(m["id"], m["label"], m["file"], m["suite"], "invalid", detail=reason)
        tests = [*SUITE_TESTS[m["suite"]], *(f"--deselect={t}" for t in MUTANT_RUN_DESELECT)]
        rc, out, secs = run_tests(copy, tests, python, timeout)
        return classify(m, rc, out, secs)
    finally:
        shutil.rmtree(copy, ignore_errors=True)


def validate_catalogue(mutations: list[dict[str, str]]) -> None:
    ids = [m.get("id") for m in mutations]
    if len(set(ids)) != len(ids):
        raise SetupError("duplicate mutant ids")
    for m in mutations:
        if (
            set(m) != {"id", "suite", "file", "anchor", "replacement", "label"}
            or m["suite"] not in SUITE_TESTS
        ):
            raise SetupError(f"malformed mutant entry: {m.get('id')!r}")


IOREG = "/usr/sbin/ioreg"


def _ioreg_root() -> bytes:
    return subprocess.run(
        [IOREG, "-n", "Root", "-d1", "-a"], capture_output=True, timeout=30, check=True
    ).stdout


def session_preflight(platform: str = sys.platform, read: Any = None) -> str | None:
    """Read-only macOS check: the Secure Enclave hardware test can only create keys while the console
    session is unlocked (kSecAttrAccessibleWhenUnlockedThisDeviceOnly). Return an error string if the
    session is locked or cannot be confirmed unlocked, else None. Never touches the Secure Enclave."""
    if platform != "darwin":
        return None
    import plistlib

    try:
        root = plistlib.loads((read or _ioreg_root)())
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return f"cannot confirm the macOS session is unlocked ({exc}); refusing to run the baseline"
    users = root.get("IOConsoleUsers") if isinstance(root, dict) else None
    console = [u for u in users or [] if isinstance(u, dict) and u.get("kCGSSessionOnConsoleKey")]
    if not console:
        return "no logged-in console session; the Secure Enclave hardware test cannot run"
    if any(u.get("CGSSessionScreenIsLocked") for u in console):
        return (
            "macOS session is locked: Secure Enclave key creation fails with errSecInteractionNotAllowed "
            "(-25308). Unlock the session and keep it unlocked for the whole campaign"
        )
    return None


def run_campaign(
    mutations: list[dict[str, str]],
    *,
    root: Path = REPO,
    inputs: tuple[str, ...] = COPY_INPUTS,
    python: str = sys.executable,
    jobs: int = 1,
    timeout: int = 900,
    only: set[str] | None = None,
    catalogue_sha256: str = "",
    preflight: Any = None,
) -> dict[str, Any]:
    preflight = preflight or session_preflight
    validate_catalogue(mutations)
    selected = [m for m in mutations if only is None or m["id"] in only]
    report: dict[str, Any] = {
        "python": python,
        "catalogue_sha256": catalogue_sha256,
        "inputs": {},
        "baseline": None,
        "mutants": [],
        "counts": dict.fromkeys(STATUSES, 0),
    }
    try:
        report["inputs"] = check_inputs(root, inputs)
    except SetupError as exc:
        report["status"] = "setup_failed"
        report["detail"] = str(exc)
        return report
    if "engine" in {m["suite"] for m in selected}:
        env_error = preflight()
        if env_error is not None:
            report["status"] = "environment_unsuitable"
            report["detail"] = env_error
            return report
    with tempfile.TemporaryDirectory(prefix="sentinel-mut-") as tmp:
        work = Path(tmp)
        base: dict[str, Any] = {}
        for suite in sorted({m["suite"] for m in selected}):
            copy = work / f"baseline-{suite}"
            make_copy(root, inputs, copy)
            rc, out, secs = run_tests(copy, SUITE_TESTS[suite], python, timeout)
            tail = out.strip().splitlines()[-1] if out.strip() else ""
            base[suite] = {"pytest_exit": rc, "summary": tail, "seconds": round(secs, 1)}
            shutil.rmtree(copy, ignore_errors=True)
        report["baseline"] = base
        if any(b["pytest_exit"] != 0 for b in base.values()):
            report["status"] = "baseline_failed"
            return report
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            outcomes = list(pool.map(lambda m: run_one(m, root, inputs, work, python, timeout), selected))
    report["mutants"] = [asdict(o) for o in outcomes]
    if "engine" in {m["suite"] for m in selected}:
        late = preflight()  # a lock during the run would turn hardware-test failures into false catches
        if late is not None:
            report["status"] = "environment_unsuitable"
            report["detail"] = f"after the campaign: {late}; results are not valid"
            for o in outcomes:
                report["counts"][o.status] += 1
            return report
    for o in outcomes:
        report["counts"][o.status] += 1
    c = report["counts"]
    report["status"] = (
        "survivors" if c["survived"] else "incomplete" if c["invalid"] or c["infra_failed"] else "all_caught"
    )
    return report


EXIT = {
    "all_caught": 0,
    "survivors": 1,
    "baseline_failed": 2,
    "setup_failed": 3,
    "incomplete": 4,
    "environment_unsuitable": 5,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel security mutation campaign")
    ap.add_argument("--suite", choices=sorted(SUITE_TESTS), action="append")
    ap.add_argument("--only", action="append", help="run only these mutant ids")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--out", type=Path, help="write the JSON report here")
    args = ap.parse_args(argv)
    sys.path.insert(0, str(Path(__file__).parent))
    from mutations import MUTATIONS

    cat = Path(__file__).with_name("mutations.py")
    muts = [m for m in MUTATIONS if not args.suite or m["suite"] in args.suite]
    report = run_campaign(
        muts,
        jobs=args.jobs,
        timeout=args.timeout,
        only=set(args.only) if args.only else None,
        catalogue_sha256=hashlib.sha256(cat.read_bytes()).hexdigest(),
    )
    if args.out:
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"baseline: {json.dumps(report.get('baseline'))}")
    for o in report["mutants"]:
        tests = ",".join(o["failing_tests"][:2])
        print(f"{o['status']:<12} {o['id']:<48} exit={o['pytest_exit']} {tests or o['detail']}")
    print(f"status: {report['status']} {report.get('detail', '')} counts: {report['counts']}")
    return EXIT[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
