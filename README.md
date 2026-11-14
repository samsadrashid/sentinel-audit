# Sentinel-RedTeam

Sentinel is a local-first security auditing framework for software and infrastructure you own or are authorised to assess. It reads by default and fails closed. The engine, not any AI agent, is the security boundary.

**Status:** release candidate. It is **not production-ready**: production operator signing is disabled until the signing-device ceremony, and only macOS has been tested. What works, what is limited and what is blocked: [`docs/roadmap/sentinel-final-release-report.md`](docs/roadmap/sentinel-final-release-report.md) and [`docs/user/limitations.md`](docs/user/limitations.md). User documentation: [`docs/user/`](docs/user/README.md). Architecture: [`docs/architecture/discovery.md`](docs/architecture/discovery.md); decisions: [`docs/architecture-discovery-plan.md`](docs/architecture-discovery-plan.md).

## Developer setup

Requirements: Python 3.12 or newer, and [uv](https://docs.astral.sh/uv/). M1 targets macOS and Linux hosts.

```bash
uv venv --python 3.13 .venv
```

```bash
uv sync
```

`uv sync` installs the package in editable mode with the locked runtime dependency (`cryptography`) and the dev tools (`pytest`, `ruff`, `mypy`) from `uv.lock`.

## Running tests and checks

```bash
uv run pytest
```

```bash
uv run ruff check src tests
```

```bash
uv run mypy
```

## Building a local package

```bash
uv build
```

This writes a wheel and sdist to `dist/`. Nothing is published.

## Verifying a release

Releases are signed on a separate signing device (D-74). A signed release directory holds the wheel, the
sdist, the SBOM, `SHA256SUMS` and `SHA256SUMS.approval.json`. With the release key file obtained
independently of the release itself:

```bash
sentinel release verify path/to/release --key pub-<key_id>.json
```

It fails unless every file, `SHA256SUMS`, the version, the key and the signature all match. **No release
has been signed yet:** production signing stays disabled until the signing-device hardware tests and
ceremony are done.

## Licence

MIT.
