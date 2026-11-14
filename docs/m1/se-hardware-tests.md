# Secure Enclave helper: build, requirements and manual hardware tests

**Status:** the helper is built and its non-prompting paths have been tested automatically. **No hardware-backed signature has been produced or verified yet.** That requires the manual tests below, run by the owner at the Mac. `production_provider()` stays off until they pass and a new decision record enables it.

## Build (reproducible)

```bash
native/macos/se-helper/build.sh "$HOME/.local/state/sentinel/bin/sentinel-se-helper"
```

The production path is fixed: `<state dir>/bin/sentinel-se-helper` (by default `~/.local/state/sentinel`, or `$SENTINEL_HOME/bin`). The manual test script takes the path and pin as arguments; it is a test harness, not a production path.

- The script compiles `main.swift` with `swiftc -O -swift-version 5` for macOS 14, links CryptoKit, LocalAuthentication and Security, and ad-hoc signs the result.
- It prints the binary's SHA-256. That value is the pin passed to `NativeHelperBackend`, and later goes into operator-approved policy (contract §6).
- Rebuilding with the same toolchain gives a functionally identical binary. Byte-identical output across Xcode versions is **not** guaranteed, so re-pin after any toolchain change.

## Approving a helper build (pinning)

Trust in the helper comes **only** from `se_helper_sha256` in an operator-approved policy file. The path alone confers no trust.

1. Build the helper, and note the SHA-256 that `build.sh` prints. Rebuilding always needs a new approval; nothing updates the pin automatically.
2. Write the hash into the policy file as `"se_helper_sha256": "<64 lowercase hex>"`.
3. Prepare the approval:

   ```bash
   sentinel approval prepare policy-change --key-id <your key> --lifetime 86400 --policy policy.json --rationale "approve helper build <date>"
   ```

4. Review every field and the full `payload_sha256`, then sign the `canonical` bytes with your presence-backed key.
5. Check the result:

   ```bash
   sentinel status --policy policy.json --policy-approval approval.json
   ```

   It reports `pinned` and `hash_matches_pin`, and never runs the helper.

Behaviour when something is wrong:
- **Pin missing:** the helper is refused, with no fallback.
- **Pin malformed:** the policy is invalid.
- **Pin edited without a new approval:** the policy is blocked.
- **Binary replaced or rebuilt:** the hash is checked before every run, so the helper is refused without being executed.
- **Helper path is a symlink:** refused.

Even with a valid pin, `production_provider()` stays off until H1–H11 pass **and** a separate activation decision record exists.

## macOS requirements

- A Mac with a Secure Enclave (Apple silicon, or Intel with a T2 chip). `status` reports `false` otherwise, and signing fails with `no_secure_enclave`.
- macOS 14 or later, with a login password set. User presence is Touch ID or the device passcode (`.userPresence`).
- A logged-in graphical session. From SSH, a launch daemon or CI, the helper returns `not_interactive`.

## APIs and access control

| Step | API |
|---|---|
| Hardware check | `SecureEnclave.isAvailable` |
| Key creation | `SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl:)`, with `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence])` |
| Key handle | `dataRepresentation`: an opaque blob encrypted by this device's Secure Enclave. It is not the private key and is useless on another device |
| Session check | `SessionGetInfo` must report `sessionHasGraphicAccess` |
| User presence | A fresh `LAContext` per invocation with `touchIDAuthenticationAllowableReuseDuration = 0`, evaluated with `.deviceOwnerAuthentication`, then passed to the key as its `authenticationContext` |
| Signing | `PrivateKey.signature(for:)` (ECDSA P-256 over SHA-256 of the stdin bytes), self-verified before output; DER encoding |

- No entitlement or keychain item is needed. CryptoKit Secure Enclave keys aren't stored in the keychain, which avoids `errSecMissingEntitlement` (-34018) seen earlier with keychain user-presence items.
- There is no software key path in the helper.

## Payload binding

1. Sentinel shows the canonical payload and its full SHA-256 in the terminal (`approvals.display_text`).
2. Sentinel pipes exactly those bytes to the helper's stdin. The handle travels in a separate 0600 file in a private 0700 directory, never on stdin.
3. The helper hashes the bytes it received and puts the **full** digest in the system prompt. It ignores any caller-supplied reason or digest and never parses the payload.
4. The operator approves only if the prompt hash equals the terminal hash.
5. The helper signs those same bytes, then returns `message_sha256`.
6. Sentinel requires `message_sha256` to equal its own digest, and verifies the signature over its own bytes with the registered public key.

**Substitution:** if anything changes the bytes between display and signing, the prompt shows a different hash (the operator should cancel), and step 6 rejects the result anyway (`payload_mismatch`). A same-user process calling the helper directly still needs the operator to approve a prompt whose hash matches nothing on screen.

**Helper swap:** `NativeHelperBackend` hashes the helper against the pin, then executes a private copy, so the file can't be replaced between check and exec.

## Limitations

- **Not yet demonstrated on hardware.** Compilation and the automated tests prove neither user presence nor hardware backing.
- The operator's hash comparison is the human step of the binding. If the operator approves without comparing, only Sentinel's own checks in step 6 remain. They still block substituted payloads, but not a legitimate-looking payload the operator didn't read.
- The pin is passed in code today; storing it in operator-approved policy (D-20/D-22) is still to do.
- Ad-hoc signing only; no Developer ID or notarisation.
- Same-user processes can still request prompts, which is a nuisance and phishing risk, though not a silent signature.
- The timeout is enforced by the helper (`LAContext.invalidate()`), plus a process timeout in Python.

## Manual tests H1–H11

Run in Terminal.app, logged in at the Mac:

```bash
.venv/bin/python native/macos/se-helper/manual_hardware_tests.py "$HOME/.sentinel/bin/sentinel-se-helper" <sha256-printed-by-build>
```

The script uses a throwaway `SENTINEL_HOME`. It tells you what to do at each prompt and writes `hardware-results.json`.

| # | Script does | You do | Pass when |
|---|---|---|---|
| H1 | `status` | — | `secure_enclave: true` |
| H2 | `create`, enrol | — | key enrolled; ID recomputed by Sentinel |
| H3 | sign one approval | **Approve** | `approvals.verify` accepts it |
| H4 | asks you | Compare prompt hash with terminal hash | identical |
| H5 | sign | **Cancel** | `presence_cancelled` |
| H6 | sign with a 10 s timeout | Do nothing | `timeout` |
| H7 | sign twice | **Approve both**, count prompts | two prompts, two signatures |
| H8a | provider marked non-interactive | — | refused, no prompt |
| H8b | manual | `ssh` into the Mac and run `helper sign <handle-file> 10` with any stdin | `not_interactive`, no prompt on screen |
| H9 | revoke via `key.revoke` (approve once), then sign | Approve the revoke | `revoked_key`, no second prompt |
| H10 | manual | Copy `handle-for-H10.b64` to another Mac or user account; run `helper sign <file> 10` | `key_unusable` |
| H11 | alters one byte after display | **Approve anyway** | `payload_mismatch`; prompt hash differed from terminal |

Record the results file and any deviations. Only after all pass may a decision record switch on `production_provider()`.
