# Secure Enclave helper: integration contract (D-38)

**Status:** the helper is implemented (`native/macos/se-helper/main.swift`) and its non-prompting paths are tested. **No hardware signature has been verified yet**; see `docs/m1/se-hardware-tests.md` for the build and the manual tests H1–H11.

## 1. Purpose

A minimal native macOS program that does two things, and only these:

1. Creates an ECDSA P-256 private key inside the Apple Secure Enclave, whose access control requires **user presence for every use**.
2. Signs one message with that key, after the operator authenticates.

The private key never leaves the Secure Enclave. The helper holds no policy logic: Python decides what may be signed, and verifies every result independently.

## 2. Authentication requirements

- The key's access control must require user presence (biometric or device passcode) **for every signature**. No reuse window, no "remember" option.
- The helper must not cache an authentication context between invocations.
- The prompt text must include the **full** SHA-256 the helper computed itself over the bytes it received (see §4). The helper must not use a digest or reason supplied by the caller.
- If there is no interactive user session, the helper must fail with `not_interactive` rather than block indefinitely.
- The helper must enforce the timeout it is given and fail with `timeout`.
- No fallback of any kind: if the Secure Enclave is unavailable, it fails with `no_secure_enclave`.

## 3. Public-key and handle format

| Item | Format |
|---|---|
| Public key | Uncompressed X9.63 point: 65 bytes starting with `0x04`, sent as lowercase hex |
| Algorithm identifier | `ecdsa-p256-sha256` |
| Key ID | Computed **by Sentinel**, never by the helper: `p256:` plus the first 32 hex characters of SHA-256 over (`ecdsa-p256-sha256`, a zero byte, the public key) |
| Key handle | The Secure Enclave's opaque key representation, base64, at most 4096 bytes. Only usable on this device, and only with user presence |
| Signature | DER-encoded ECDSA over SHA-256 of the message, base64, at most 80 bytes |

## 4. Invocation protocol

One command per process. The input is the message on standard input; the output is **exactly one JSON object** on standard output. No other output is allowed on standard output.

| Command | Input | Success output (exact keys) |
|---|---|---|
| `status` | none | `{"secure_enclave": true or false}` |
| `create` | none | `{"public_x963_hex": "...", "handle_b64": "..."}` |
| `sign <handle-file> <timeout-seconds>` | message bytes on stdin (1 to 65,536 bytes). The handle file holds canonical base64 with no whitespace; its path must be absolute. Timeout is 1–300, no leading zero | `{"signature_der_b64": "...", "message_sha256": "<hex>", "key_id": "<Sentinel key ID of the handle's key>"}` |

**Error output:** `{"error": "<code>", "message": "<text>"}` with a non-zero exit status. These are the only codes allowed:

| Code | Meaning | Sentinel result |
|---|---|---|
| `cancelled` | Operator dismissed the prompt | `BLOCKED` (`presence_cancelled`) |
| `timeout` | No authentication within the timeout | `BLOCKED` (`presence_timeout`) |
| `auth_failed` | Authentication failed | `BLOCKED` (`presence_auth_failed`) |
| `no_secure_enclave` | Hardware unavailable | `BLOCKED` (`presence_no_secure_enclave`) |
| `key_unusable` | Handle not usable on this device | `BLOCKED` (`presence_key_unusable`) |
| `not_interactive` | No interactive session | `BLOCKED` (`presence_not_interactive`) |
| `invalid_request` | Bad command, arguments, handle file or stdin size (exit status 2) | `BLOCKED` (`backend_malformed`) |

Success uses exit status 0; `invalid_request` uses 2; every other error uses 1. Any other code, a mismatched exit status, extra keys, missing keys, non-JSON output or an unexpected exit status is treated as **malformed** (`backend_malformed`) and blocks.

## 5. What Sentinel checks regardless of the helper's output

1. The metadata is valid. The key ID is recomputed from the public key, the algorithm must be P-256, and the backend name must match.
2. The key is active, unexpired, and in the trust store with the identical public key.
3. `key_id` in the response equals the registered key.
4. `message_sha256` equals Sentinel's own hash of the canonical payload it displayed.
5. The signature verifies against the registered public key.
6. The resulting approval then goes through the normal approval checks (context, action, subject, revision, scope, expiry, nonce, revocation).

## 6. Process boundary

- **Helper location and integrity:** the helper lives at a fixed path under Sentinel's state directory, and its SHA-256 is pinned in operator-approved policy (D-20, D-22).
- **Invocation:** it is called without a shell, with a minimal environment, a timeout, and an output cap.
- **Trust status:** a backend is marked `genuine_hardware` only for this helper. Fake backends (tests) are refused by the production path.

## 7. Manual hardware tests required before enabling

The owner must run these at the Mac. They can't be automated, because they need a human at the prompt.

| # | Test | Expected |
|---|---|---|
| H1 | `status` on this Mac | `secure_enclave: true` |
| H2 | `create`, then enrol the key | Public key registered; key ID recomputed by Sentinel matches |
| H3 | Sign an approval and **approve** the prompt | Signature verifies; approval accepted by `approvals.verify` |
| H4 | Prompt shows the payload hash | The hash in the system prompt equals the hash Sentinel printed in the terminal |
| H5 | Sign and **cancel** the prompt | `BLOCKED` (`presence_cancelled`); no signature |
| H6 | Sign and let the prompt time out | `BLOCKED` (`presence_timeout`) |
| H7 | Sign twice in a row | **Two** separate prompts; no silent second signature |
| H8 | Run from a non-interactive context (no TTY, background job) | Refused before or by the helper; no signature |
| H9 | Revoke the key through `key.revoke`, then try to sign | `BLOCKED` (`revoked_key`) |
| H10 | Copy the handle to another Mac or user account and try to sign | Fails (`key_unusable`) |
| H11 | Tamper with stdin between display and signing (test harness) | `BLOCKED` (`payload_mismatch`) |

Only after H1–H11 pass may `production_provider()` be switched on. That needs a new decision record.
