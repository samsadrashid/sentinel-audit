# M1 release checklist

M1 is a milestone, not a publication: nothing is uploaded, tagged or pushed without a separate owner
decision. This checklist is what must hold for any M1 build handed to someone.

| # | Item | How it is checked | Status |
|---|---|---|---|
| 1 | Locked environment | `uv lock --check`; `uv sync --frozen` | automated (CI) |
| 2 | Lint, format, `mypy --strict` | engine CI | automated |
| 3 | Full test suite on macOS and Linux | engine CI | automated |
| 4 | Secure Enclave helper hardware tests | `pytest tests/test_se_helper.py` on a Mac with a Secure Enclave and an **unlocked** session | manual (host) |
| 5 | Security mutation campaign: 0 survived, 0 invalid, 0 infrastructure-failed | `scripts/mutation/harness.py --jobs 4` with the session preflight passing | manual (host) |
| 6 | Strict licence gate | `scripts/license_audit.py check --strict` | automated |
| 7 | Wheel and sdist contents | `tests/test_license_audit.py`, `tests/test_schema_distribution.py` (all 24 contracts and both Skills byte-identical; installed-wheel load) | automated |
| 8 | Historical artifacts: hashes and signatures | `tests/test_schemas.py` (fixtures `tests/fixtures/schemas/historical/`) | automated |
| 9 | Architecture docs checker | `scripts/docs/check_architecture_docs.py .` | automated |
| 10 | Artifact hashes recorded | SHA-256 of the wheel and sdist recorded in the completion report for the build handed over | per build |
| 11 | Metadata | `pyproject.toml`: name `sentinel-audit`, version, MIT, `License-File` entries | automated (#7) |
| 12 | Changelog | `CHANGELOG.md` | manual |
| 13 | Production signing disabled | `sentinel status` reports operator signing unavailable; `production_provider` has no success path (tests) | automated |
| 14 | First remote CI run | needs a commit and a remote | **blocked: owner action** |
| 15 | Owner acceptance | M1 completion report reviewed | owner |
