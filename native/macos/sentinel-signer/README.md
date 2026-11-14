# sentinel-signer (D-73)

The signing-device (SD) software for Architecture C, as specified in
`docs/architecture/separate-signing-device-design.md`, `docs/architecture/signing-protocol-v1.md` and
`docs/architecture/signing-protocol-final-review.md`. It runs on a **separate Mac**, never on the
development machine (DM).

**Status: software complete, not hardware-validated. Production signing stays disabled.** None of the
hardware tests SD-T01 to SD-T55, the physical FIDO2 recovery or the first-enrolment ceremony has been run.
Nothing in this directory is hardware validation, and no software test here may be reported as one.

## What exists

| Part | File | Spec |
|---|---|---|
| Strict canonical JSON | `Sources/SignerCore/Canonical.swift` | protocol §2 |
| Request validation, in order, before any display; key operations against the SD's own registry; enrolment; recovery limits; clock check; `release.publish` with the SHA256SUMS digest recomputed from the listed artifacts | `Sources/SignerCore/Validation.swift` | protocol §4, design §2.3, R3.5, D-45, D-74, SD-T55 |
| Registry (authoritative, engine-identical trust projection and fingerprint), R3.1 pending/commit/abandon state machine, trust-store audit | `Sources/SignerCore/Registry.swift` | design §2.1, §2.2, §2.4, R3.1 |
| Replay ledger and hash-chained SD log | `Sources/SignerCore/Ledger.swift` | protocol §5, §6.5 |
| USB transport: APFS only, not encrypted, mount flags checked before any file access; no-follow single-link reads; staged intake discarded on interruption; exclusive output | `Sources/SignerCore/Transport.swift` | protocol §6, R3.1, R3.2 |
| Recovery assertions: challenge, strict client-data and authenticator-data checks, counter policy, response envelope, ES256 attestation parsing | `Sources/SignerCore/Recovery.swift` | R3.4, final review §1.3, §2 |
| Signed registry checkpoints (D-46) and `signer.release` records with tree hashes | `Sources/SignerCore/Records.swift` | final review §3, §4, R3.7 |
| Device state and every state change (sign, deliver, re-issue, commit, abandon, ceremony, recovery session, checkpoint, restore, install) | `Sources/SignerCore/Device.swift` | — |
| Secure Enclave key with `.biometryCurrentSet`; approval text | `Sources/SignerCore/Signing.swift` | D-47 |
| CLI: approval window, Touch ID (no passcode fallback, 60 s), FIDO2 via AuthenticationServices | `Sources/sentinel-signer/main.swift` | design §4, §6, R3.5 |
| **TEST-ONLY** driver with software keys and a software authenticator | `Sources/signer-interop/main.swift` | — |

**Tests:** `swift test` (39 XCTests); `tests/test_signer_interop.py` (10 tests against the real engine, with a
full ceremony, rotation, recovery enrolment and revocation, abandon, checkpoint restore, signer release install
and a D-74 `release.publish` round trip);
`tests/test_signer_core_swift.py` runs `swift test` under pytest so the mutation harness covers the Swift code.

## Not verified or not implemented

- **AuthenticationServices FIDO2 (F-3)** compiles but hasn't been run with a security key. Whether it works
  offline from an ad-hoc-signed tool with the RP ID `sentinel-recovery.invalid` is exactly hardware test
  **SD-T35**. If it fails, OD-4 (the libfido2 review) applies.
- **QR transport** (deferred: SD-T05, SD-T06).
- **Release provenance steps on the SD** (git ancestry, diff review) are operator steps with `git` on the SD;
  `release sign` hashes the reviewed tree and binary itself and refuses symlinks and special files.
- **Restoring the registry from paper alone** is refused by design (D-46); restore needs a checkpoint.

## Build (on the SD, network off)

```bash
./build.sh ~/signer/versions/<commit>/sentinel-signer
```

The script runs the test suite first and stops on any failure. It prints the binary's SHA-256: record it
in the SD log and on the ceremony sheet. `signer-interop` is never built by this script.

## First-enrolment ceremony (design round 2 §6)

On the SD unless marked DM:

1. `sentinel-signer clock-check`, then `sentinel-signer ceremony start`.
2. `sentinel-signer create-key --operator "<name>" --expires-at <unix time>`. Write the fingerprint on paper.
3. Optional: `sentinel-signer register-recovery --operator "<name>" --expires-at <t>` (needs SD-T35 first).
4. `sentinel-signer export-pub --key-id <id> --volume /Volumes/SENTINEL-XFER` (drive read-write).
5. DM: `sentinel approval prepare key-enrol --key pub-<id>.json --key-id <id> --output enrol.json`, then
   `sentinel approval request --payload enrol.json --enrol-key pub-<id>.json --volume /Volumes/SENTINEL-XFER`.
6. `sentinel-signer intake --volume …` (drive read-only, `nobrowse,noexec,nosuid,nodev`), eject, then
   `sentinel-signer review`. Compare the fingerprint shown with **the paper**, then approve with Touch ID.
7. `sentinel-signer deliver --volume …` (drive read-write).
8. DM: `sentinel approval receive --volume …`, then
   `sentinel key enrol --key pub-<id>.json --approval <received file> --operator "<name>" --expires-at <t>`.
9. DM copies `trust.json` to `sentinel-v1/to-signer/trust-store-audit.json`; SD: `intake`, then `audit`
   (it shows the pending change present), then `pending commit`, then `audit` again: **MATCH**.
10. Test approval (step 11 of the design), then `sentinel-signer checkpoint write --volume /Volumes/SENTINEL-CKPT`
    and write the sequence and full hash on the sheet; re-type it when asked.
11. `sentinel-signer ceremony end`: write the ceremony hash on the sheet; sign and date it.

## Daily use

`intake` (read-only) → eject → `review` → `deliver` (read-write). Key operations stay **PENDING** until
`pending commit`, after you've confirmed the DM applied them. If the DM didn't: `pending abandon`, then
after the payload expires, intake a trust-store audit and run `pending resolve`. A failed delivery can be
re-sent byte for byte with `deliver --reissue <request id>`; nothing is ever re-signed.

State lives in `~/Library/Application Support/sentinel-signer` (registry, ledger, log, spool, outbox,
delivered, versions, key handles). A key handle is an opaque Secure Enclave reference bound to this device.

## Signing a Sentinel release (D-74)

A `release.publish` request arrives like any other: `intake` → eject → `review` → `deliver`. The device
refuses it unless the `SHA256SUMS` digest it recomputes from the listed artifacts equals the signed one,
the subject names `sentinel-audit` with a full commit, and the wheel's version matches. The review screen
shows the version, the commit and every artifact hash in groups of eight. **Compare each hash with the
remote CI build of the same commit, never with figures from the development Mac.** Only an operator key
may sign it; it is one-time, with a 1-hour window. The engine side is in `docs/user/operator-approvals.md`.

## Hardware acceptance (owner, outstanding)

SD-T01 to SD-T55 (design §8, round 2 §7, round 3, final review §6) must run on the real SD, with results
recorded. Software tests covering the same logic are **not** substitutes. Until every required SD-T passes,
the ceremony is complete and an activation decision is recorded, production signing (B-5) stays disabled.
