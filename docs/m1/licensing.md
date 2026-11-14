# Third-party licenses and supply-chain inventory (D-03)

**Status (session 13):** all components reviewed; `check --strict` passes. The build backend is pinned and inventoried. Sentinel's own `LICENSE` exists (MIT, Copyright (c) 2026 Samsad Rashid Ony, as confirmed by the owner).

## Files

| File | What it is | Edited by |
|---|---|---|
| `scripts/license_audit.py` | Reproducible audit. Reads `uv.lock`, the installed packages' own `METADATA`, license files and `RECORD`, and the review register. No network, no installs, no upgrades | Code review |
| `licenses/review.json` | Human-reviewed register: version, scope, license, license-file hashes, status, attribution requirement, embedded components, notes. Also the native-helper components | A reviewer, by hand |
| `licenses/build-lock.txt` | Hash-pinned build backend (hatchling and its dependencies). Must match `[build-system].requires` and `[tool.uv].build-constraint-dependencies` | `uv pip compile` (see the file header) |
| `licenses/texts/` | License texts obtained from upstream, each recorded in the register with its source URL and SHA-256 | A reviewer |
| `licenses/inventory.json` | Generated machine-readable inventory | `license_audit.py inventory` |
| `THIRD_PARTY_NOTICES` | Generated notices with verified license texts | `license_audit.py notices` |

Sentinel's own license (MIT, from `pyproject.toml`) is kept separate: it is not part of `THIRD_PARTY_NOTICES`.

## Commands

```bash
# one-time: the build env the audit inspects (hash-pinned, isolated, gitignored under build/)
uv venv --python 3.13 build/license-env
uv pip install --python build/license-env/bin/python --require-hashes -r licenses/build-lock.txt
.venv/bin/python scripts/license_audit.py check            # CI gate
.venv/bin/python scripts/license_audit.py check --strict   # release gate: also fails on needs_review
.venv/bin/python scripts/license_audit.py inventory        # regenerate licenses/inventory.json
.venv/bin/python scripts/license_audit.py notices          # regenerate THIRD_PARTY_NOTICES
```

Exit codes: 0 clean, 1 audit issues, 2 usage or environment error.

**The gate fails on:**
- unreviewed runtime, dev or build dependencies;
- changed versions, scopes, licenses or license-file hashes;
- a runtime or build entry with no attribution (`missing_attribution`);
- a missing or `RECORD`-mismatched license file;
- a build requirement that isn't exactly pinned to the hash-pinned lock (`unpinned_build_dependency`);
- a missing build environment;
- an embedded notice or upstream text whose hash doesn't verify;
- a stale or hand-edited `THIRD_PARTY_NOTICES` or inventory.

None of these can be acknowledged in `accepted_issues`.

`tests/test_license_audit.py` runs the real-repository check, so CI fails on any unreviewed change.

## How it decides

- **Inventory:** every package reachable from `sentinel-audit`'s runtime dependencies is `runtime`; everything else reachable from the dev group is `dev`. A package reachable from both counts as runtime.
  - Packages behind environment markers are never dropped; their markers are recorded. If a package isn't installed on this host, that's reported as `not_installed`.
  - A locked package reachable from neither root is reported as `orphan_locked`.
- **License source:** in order, the `License-Expression` field (SPDX), then a `License` field only if it is a single identifier. Otherwise none.
  - Trove classifiers are recorded but only produce `ambiguous_license`.
  - A license is never inferred from a package name or from free-form text.
- **License text:** a license file counts as verified only if its SHA-256 matches the package's own `RECORD`. Only verified texts are copied into the notices; any other file is marked "TEXT NOT REPRODUCED".
- **Runtime policy:** a runtime license expression must be satisfiable from {0BSD, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MIT, MIT-0, PSF-2.0, Zlib}.
  - For `OR`, any one branch is enough; for `AND`, every operand must be allowed.
  - A `WITH` exception needs review.
  - Unknown SPDX identifiers are flagged.
- **Register comparison:**
  - A package missing from the register fails as `unreviewed_package`.
  - Any difference in version, scope, license or license-file hash fails as `unreviewed_change`.
  - A register entry that is no longer locked fails as `stale_review`.
  - A reviewer may acknowledge a known gap with `accepted_issues`. Unreviewed changes, stale reviews, version mismatches and `RECORD` mismatches can never be acknowledged.
- **Duplicates:** a package locked twice (`duplicate_locked`, names normalised as in PEP 503) or installed twice (`duplicate_installed`) is flagged.
- **Outputs:** the generated files are deterministic. They contain no timestamps, keys are sorted, and they include the lockfile hash. `check` fails if either generated file is stale or edited by hand.

## Coverage (session 13)

| Scope | Count | Packages |
|---|---|---|
| Runtime | 3 | cryptography 46.0.7, cffi 2.1.1, pycparser 3.12 |
| Build (hash-pinned) | 6 | hatchling 1.33.0, packaging 26.3, pathspec 1.1.1, pluggy 1.7.0, tomlkit 0.15.2, trove-classifiers 2026.9.21.13 |
| Dev and test | 12 | pytest, iniconfig, packaging, pluggy, pygments, colorama (Windows only), mypy, mypy-extensions, librt, pathspec, typing-extensions, ruff |
| Native helper | 3 | Apple frameworks, the Swift runtime (OS-provided), the Xcode command-line tools |
| Embedded in cryptography | OpenSSL 3.5.6 plus 36 Rust crates | see the cryptography entry |

**Pinning:** the build backend was pinned to the version uv had been resolving (hatchling 1.33.0 and its dependencies). No version was upgraded. `uv.lock` gained only a `[manifest] build-constraints` block; no package versions changed.

## What is distributed

- **Wheel:** only `sentinel/` plus `THIRD_PARTY_NOTICES` in `.dist-info/licenses/` (PEP 639 `License-File`).
- **sdist:** an explicit allowlist: `src/sentinel`, `tests`, `scripts`, `licenses`, `native`, `docs/architecture`, `docs/m1`, `pyproject.toml`, `uv.lock`, `README.md` and `THIRD_PARTY_NOTICES`.
- **Not distributed:** no third-party code is vendored into Sentinel. Runtime dependencies are installed separately by the installer. The Secure Enclave helper binary is built locally by the operator.

## Review decisions (session 13)

| Component | License | Evidence | Decision | Remaining uncertainty |
|---|---|---|---|---|
| cryptography 46.0.7 | Apache-2.0 OR BSD-3-Clause | Wheel metadata and 3 `RECORD`-verified files. PyPI sdist (sha256 matches `uv.lock`) has the same expression and files | Approved | — |
| ↳ OpenSSL 3.5.6 (static) | Apache-2.0 | `otool -L` shows no libssl or libcrypto, so it is statically linked. The binary reports "OpenSSL 3.5.6 7 Apr 2026". Upstream `LICENSE.txt` at tag `openssl-3.5.6` (sha256 `7d5450cb…`) is stored in `licenses/texts/` and reproduced in the notices. No NOTICE file upstream (HTTP 404) | Approved | Assumes the PyPI wheel was built from unmodified upstream OpenSSL (cryptography's build process was not audited) |
| ↳ Rust crates (36) | MIT, Apache-2.0, BSD-3-Clause, MIT OR Apache-2.0, Apache-2.0 WITH LLVM-exception, (MIT OR Apache-2.0) AND Unicode-3.0 | sdist `Cargo.lock`, checked against crates.io (all checksums match) | Approved | These are crates.io-declared licenses; the crate license texts were not individually verified. Only crates linked into the binary matter for redistribution |
| cffi 2.1.1 | MIT-0, plus MIT for `cffi/_cffi_gen_src.py` | Wheel metadata and LICENSE. A per-file scan of the wheel found one MIT file (Copyright (c) 2024 Rose Davidson); its notice is hash-verified against `RECORD` and reproduced. The sdist vendors libffi 3.4.2 (MIT-style) for Windows; on macOS, `otool -L` shows the system `/usr/lib/libffi.dylib` | Approved | Windows wheels may embed libffi; not verified (not a supported Sentinel host) |
| pycparser 3.12 | BSD-3-Clause | Metadata and LICENSE (Eli Bendersky) | Approved | — |
| colorama 0.4.6 (dev, Windows) | BSD-3-Clause (reviewer reading) | PyPI wheel and sdist (sha256 match `uv.lock`). Classifier is "BSD License"; LICENSE.txt (Jonathan Hartley) has 3 conditions including non-endorsement | Approved | The metadata gives no SPDX expression; BSD-3-Clause is a reading of the text |
| hatchling 1.33.0 (build) | MIT | Metadata and LICENSE.txt in the hash-pinned build env | Approved | — |
| packaging 26.3 (build and dev) | Apache-2.0 OR BSD-2-Clause | Metadata and files | Approved | — |
| pathspec 1.1.1 (build and dev) | MPL-2.0 (reviewer reading) | Classifier and LICENSE; no SPDX metadata | Approved | Classifier-based |
| pluggy 1.7.0 (build and dev) | MIT | License field and LICENSE | Approved | — |
| tomlkit 0.15.2 (build) | MIT | Metadata and LICENSE | Approved | — |
| trove-classifiers 2026.9.21.13 (build) | Apache-2.0 (reviewer reading) | Classifier "Apache Software License"; LICENSE is the Apache License 2.0 text | Approved | Classifier-based |
| Swift runtime | Apache-2.0 WITH Swift Runtime Library Exception | The helper (sha256 `a6fdd469…`) links only the OS-provided `/usr/lib/swift` libraries (`otool -L`). Upstream `LICENSE.txt` is from tag `swift-6.4.2-RELEASE` (sha256 `770af829…`), matching the toolchain version | Approved | — |
| Other dev tools | as metadata | Unchanged from session 11 | Approved | Not distributed |

**Network evidence:** gathered once, in session 13. The PyPI artifacts were checked against the `uv.lock` hashes; crates.io and GitHub raw files were read. The audit itself stays offline.

## Residual risks (accepted by the owner in session 14; not fully verified)

These are **accepted limitations**. The review approved each component on the evidence above, but the following points were **not** verified and must not be read as such.

| ID | Residual risk | What was verified | What was not | When to revisit |
|---|---|---|---|---|
| LR-1 | **OpenSSL build process** in cryptography's PyPI wheels | It is statically linked (`otool -L`), its version string is 3.5.6, and the upstream 3.5.6 license is Apache-2.0 | How cryptography builds OpenSSL for its wheels (source provenance, patches, configure options); that the embedded code is unmodified upstream OpenSSL | Before redistributing cryptography's binary wheels; on any cryptography upgrade |
| LR-2 | **cffi on Windows / libffi** | macOS: `_cffi_backend` links the system `/usr/lib/libffi.dylib`, and the sdist's vendored libffi 3.4.2 headers are MIT-style | Whether Windows wheels embed libffi, and their license files and notices (no Windows wheel was inspected) | Before any Windows support claim (D-30) or Windows distribution |
| LR-3 | **Rust crate license texts** in cryptography | The 36 registry crates in `Cargo.lock` match crates.io checksums; the crates.io-declared licenses are all permissive | The license **texts** of each crate, and which crates are actually linked into `_rust.abi3.so` and which are build-only | Before redistributing cryptography's binary wheels |
| LR-4 | **Reviewer readings** | The license files shipped by colorama (BSD-3-Clause), pathspec (MPL-2.0) and trove-classifiers (Apache-2.0) | Any SPDX `License-Expression` from those projects (they declare none) | When those packages publish SPDX metadata |

Sentinel does not redistribute any of these components, so none of the risks is a release blocker for Sentinel's own wheel and sdist. All four become blockers for any bundled distribution, such as an installer, frozen app or container image, that ships these binaries.
