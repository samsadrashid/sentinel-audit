# Installation

## Requirements

- macOS 14 or later (the only tested host). The S1 sandbox is macOS Seatbelt. Linux and Windows are
  untested; on a host without verified isolation, checks are `NOT_RUN` or `BLOCKED`, never run unconfined.
- Optional, for container scanners: rootless Podman, a share-free Podman machine (created with
  `--volume ""`; see `configuration.md`) and approved scanner images, pinned in the approved policy
  (`scanners`, `podman` including `podman.machine`, `osv_database`). Sentinel never downloads a scanner
  or a database.
- Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).
  uv-managed, python.org and Homebrew interpreters all work. python.org and Homebrew are macOS framework
  builds; Seatbelt runs their real binary inside `Python.app` (see `sandbox_interpreter`), because the
  `bin/python3.x` launcher re-executes it, which the sandbox would refuse.
- One runtime dependency: `cryptography` (locked in `uv.lock`).

## Install from a source checkout

```bash
uv sync --frozen
```

```bash
uv run sentinel --json version
```

## Install a built wheel

```bash
uv build
```

```bash
uv pip install dist/sentinel_audit-*.whl
```

## First-time setup

```bash
sentinel --json init
```

`init` creates the private state directory (`~/.local/state/sentinel`, mode 0700, or `$SENTINEL_HOME`) and the
run key (Ed25519; its seed is kept in the OS secret store, the macOS keychain on macOS). The run key signs run manifests and audit-log
checkpoints; it can never approve anything.

```bash
sentinel --json status
```

`status` reports the host's isolation capabilities, the run key, the trust-store fingerprint and the
operator-signing state (always "unavailable": production signing is disabled).

## Verify the installation

```bash
sentinel --json self-check
```

A wheel install reports `verified`. An editable or source-checkout install reports `unverifiable` (exit 2): it is never reported as verified.
