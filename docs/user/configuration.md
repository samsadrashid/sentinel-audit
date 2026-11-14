# Configuration

All inputs are strict canonical-compatible JSON: duplicate keys, unknown keys, floats and oversized
files are refused, and every file is checked against its versioned schema (`src/sentinel/schemas/`,
D-40) before anything else reads it.

## Audit config (`audit --config`)

```json
{
  "mode": "READ",
  "level": "L2",
  "activity_classes": ["S1"],
  "scope": {
    "assets": [
      {"id": "app", "kind": "local_path", "locator": "/path/to/project", "environment": "local"}
    ],
    "exclusions": []
  }
}
```

- `mode`: `READ` (default) or `VALIDATE`. `VALIDATE` needs a verified authorisation record.
- `level`: `L1` or `L2` in `READ`; `L3` in `VALIDATE`.
- `activity_classes`: `S1`, `S2`, `B1`, `B2`; `A1` only in `VALIDATE` with a record. `B3` is always
  refused (D-15).
- `scope.assets[].kind`: `local_path`, `artifact` or `host`.

## Policy file (`--policy`, `--policy-approval`)

Optional. Without it the built-in default policy applies. A policy file is used **only** with a valid
`policy.change` approval over its exact bytes, bound to the previously applied policy.

```json
{
  "limits": {"scanner_timeout_s": 900, "max_audit_duration_s": 14400},
  "adapter_allowlist": {"fixture": "<sha256>"},
  "owned_assets": ["app"],
  "se_helper_sha256": "<sha256>",
  "redaction_patterns": []
}
```

Scanners, databases and plugins are enabled only by pins in the approved policy. Without a pin, the check is `NOT_RUN` (never `PASS`):

```json
{
  "scanners": {
    "gitleaks": {"kind": "binary", "path": "/abs/path/gitleaks", "sha256": "<sha256>"},
    "semgrep": {"kind": "image", "image": "docker.io/semgrep/semgrep@sha256:<digest>"}
  },
  "podman": {"path": "/abs/path/podman", "sha256": "<sha256>", "probe_image": "docker.io/library/busybox@sha256:<digest>", "machine": "sentinel-b2"},
  "osv_database": {"path": "/abs/path/osv-db", "manifest_sha256": "<sha256>"},
  "plugins": {"my-plugin": {"path": "/abs/path/plugin-dir", "manifest_sha256": "<from `sentinel plugin inspect`>"}}
}
```

- **Images** must be pinned by digest. Sentinel never pulls them.
- **Plugins:** the pin name must equal the plugin manifest's `name`. The manifest and its entry script are re-verified before every run, and the verified bytes are what runs.

`policy validate` checks a policy and its approval without consuming the approval or changing state.

## Authorisation records (`--authorization`, `--approval`)

Needed for `VALIDATE` and for `A1`. A record lists exact assets, permitted activity classes,
operations, limits, exclusions and a validity window, and is approved with an `authorize_record`
approval. Production assets must be exact (no wildcards), and `A1` against production is excluded from
V1 (D-21, D-37).

## Share-free Podman machine (D-70, D-71)

Every container check (the M2 and M3 scanners and B2) runs in one dedicated, **share-free** Podman machine. It has no host volumes, so nothing a container does can reach your disk (this resolves M2-SA-12). The target is streamed into a per-run volume inside the VM and mounted read-only. Scanner databases are copied into a VM-local volume named after the database manifest, and re-verified against the manifest before every use. Nothing from the host is bind-mounted. One-time setup, using the already-cached machine image (no downloads):

```bash
podman machine init sentinel-b2 --image ~/.local/share/containers/podman/machine/applehv/cache/<cached>.raw.zst --volume "" --cpus 4 --memory 4096 --disk-size 60
```

```bash
podman machine start sentinel-b2
```

Load the approved scanner images into that machine (for example with `podman save` from an existing machine, then `podman --connection sentinel-b2 load`), and pin the machine name in the approved policy. `podman.machine` is **required**:

```json
{"podman": {"path": "/abs/path/podman", "sha256": "<sha256>", "probe_image": "docker.io/library/busybox@sha256:<digest>", "machine": "sentinel-b2"}}
```

**Disk space.** The machine's disk file grows as volumes are written, and doesn't shrink by itself. If the host disk fills, the VM's filesystem records write errors and containers fail with `overlay ... input/output error` (fail closed, but no checks run). Reclaim space with `podman machine ssh sentinel-b2 -- sudo fstrim /var`; after a disk-full event, restart the machine. Sentinel re-hashes each image's stored layers before it runs it, and refuses a damaged one (`NOT_RUN image_integrity_failed`); re-pull or re-load that image by its pinned digest.

## B2 archive inspection (APK, AAB, IPA; D-70)

B2 runs in the same share-free machine. Its containers have no mounts at all: the archive goes in on stdin and the result comes out on stdout. Pin the approved interpreter image:

```json
{"b2": {"machine": "sentinel-b2", "image_id": "sha256:<image id>"}}
```

B2 runs in the same pass as the container scanners. There is no VM switching.

## MobSF 4.6.4 (D-72)

MobSF runs in the same share-free machine, on built artifacts only (APK, AAB, IPA), never on source trees. Its container has no mounts and no network: the artifact goes in on stdin, and MobSF's static-analysis views run in-process. This is accepted with a recorded risk (GHSA-j7g2-gm7j-mfvm, fixed in the unreleased 4.6.5). Pin the image by its ID:

```json
{"mobsf": {"machine": "sentinel-b2", "image_id": "sha256:<image id>"}}
```

Before pinning, check the stored image is intact. `podman --connection sentinel-b2 save --format docker-archive <id> > /dev/null` fails with `file integrity checksum failed` if a layer on disk is damaged (for example after the VM disk filled).

If the pinned machine isn't running, has any host-share filesystem mounted, or lacks a pinned image, the check is `NOT_RUN` (`podman_host_share_present`, `b2_machine_not_active`, …). A database volume that no longer matches its manifest is deleted and the check is `NOT_RUN database_volume_mismatch`; the next run re-imports it.
