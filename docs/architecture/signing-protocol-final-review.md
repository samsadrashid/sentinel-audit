# Signing protocol: final review, round 4 (2026-11-09)

**Scope:** close the items that block recording D-45 and amending D-38.

**Status:** analysis and **final proposed wording only.**
- No code, keys or dependencies were added.
- No network access was used, and nothing was recorded in the decision register.
- Production signing stays disabled. **The architecture is not frozen.**

**Labels:** [V] verified (local SDK or source); [A] assumption needing a test; [U] unknown.

---

## 1. WebAuthn feasibility with the RP ID `sentinel-recovery.invalid`

### 1.1 What can and can't be settled offline

| Question | Answer | Basis |
|---|---|---|
| Does AuthenticationServices expose a security-key assertion API with a caller-chosen RP ID and challenge? | Yes. `ASAuthorizationSecurityKeyPublicKeyCredentialProvider initWithRelyingPartyIdentifier:` and `createCredentialAssertionRequestWithChallenge:` (macOS 12+). The result has `rawAuthenticatorData`, `rawClientDataJSON`, `signature` and `credentialID` | [V-SDK] |
| Does it accept `sentinel-recovery.invalid` for an ad-hoc-signed tool, offline? | **Unknown.** The headers don't state an entitlement or Associated Domains requirement. If the OS validates the RP ID against Associated Domains, a reserved `.invalid` name can't be associated, and validating any real domain needs Apple's network service | [U] |
| Was a live probe run? | **No.** Invoking the API may make the OS contact Apple's domain-association service (a network access this round forbids), and it may show a system sheet that needs an authenticator | — |
| Is assertion **verification** possible offline? | **Yes.** It is pure computation: SHA-256 plus ECDSA P-256 over `authenticatorData ‖ SHA-256(clientDataJSON)` with the registered public key. No network or platform service is involved | [V, by construction] |
| Is assertion **generation** possible offline with libfido2? | Expected yes: CTAP2 over USB HID needs no network, and any RP ID string is accepted by CTAP [A] | Test SD-T35b |

### 1.2 Decision procedure (no weakening)

1. **SD-T35a, AuthenticationServices.** On the signing Mac, with networking **physically off**, run registration and assertion with RP ID `sentinel-recovery.invalid` from the ad-hoc-signed signer. Record the exact errors, any system UI, the produced `clientDataJSON` bytes, and `origin`.
   - **Pass** requires all of: no network; an assertion produced; and `clientDataJSON` passing the strict checks in §1.3 **unmodified**.
2. **If SD-T35a fails for any reason** (entitlement, domain association, a non-conforming client data): **don't** change the RP ID or the origin rules to fit. Use **libfido2** (SD-T35b), subject to the D-03 review (OD-4).
3. **Real-domain alternative (documented, not chosen):** an RP ID equal to a domain the operator controls, with the Associated Domains entitlement and an `apple-app-site-association` file served from it.
   - It needs paid provisioning, the network at registration time, and **ties recovery to domain and DNS control**, which adds an external dependency and attack surface.
   - It is kept only as a fallback if both 35a and 35b are infeasible.

### 1.3 Strict RP ID and origin validation (used by the SD self-check and by the DM)

Constants per recovery credential: `rp_id = "sentinel-recovery.invalid"`, recorded in the registry and the trust store.

| Check | Rule (exact) |
|---|---|
| Client data encoding | Valid UTF-8 JSON object; no duplicate keys |
| Client data keys | Exactly `{type, challenge, origin, crossOrigin}`, or `{type, challenge, origin}`. **Any other key** (`topOrigin`, `tokenBinding`, `other_keys_can_be_added_here`, …) means reject |
| `type` | Exactly `"webauthn.get"` |
| `challenge` | Exactly base64url without padding of the 32-byte challenge (§R3.4); compared byte for byte as a string |
| `origin` | **Exactly** `"https://" + rp_id`: no port, no path, no trailing slash, no case variation |
| `crossOrigin` | Absent or `false` |
| `rpIdHash` (authenticator data bytes 0–31) | Equals `SHA-256(rp_id)` |
| Flags (byte 32) | UP (0x01) **and** UV (0x04) set; AT (0x40) and ED (0x80) **not** set; no other flag bits interpreted |
| Length | `authenticatorData` is exactly 37 bytes, since there are no extensions in v1 |

**If a conforming platform API emits extra client-data keys,** the response is to choose the libfido2 path (where the signer builds the client data itself), **never** to relax this table.

---

## 2. Signature-counter policy

`signCount` is bytes 33–36 of `authenticatorData`, big-endian.

**Registry fields per recovery key:**
- `counter_mode`: `unset`, `zero` or `increasing`;
- `last_count`: an integer.

The mode is fixed at the **ceremony's test assertion** and never changes afterwards.

| Observed (`n` = new count, `s` = stored count) | Mode | Outcome |
|---|---|---|
| First assertion, `n == 0` | `unset` → `zero` | Accept; record `counter_mode = zero` |
| First assertion, `n > 0` | `unset` → `increasing` | Accept; record `last_count = n` |
| `n > s` | `increasing` | Accept; update `last_count = n` (committed with the operation, §3) |
| `n == s` | `increasing` | **Reject** (`counter_not_increasing`): possible clone or replayed assertion |
| `n < s` (rollback, or unexpected reset including `n == 0`) | `increasing` | **Reject** (`counter_rollback`). The key is marked `suspect`, refused for every action until the operator resolves it on the SD. Resolution means either revoking it, or (if the authenticator was reset by its owner, which also destroys the credential) enrolling a new recovery credential. **A suspect key is never auto-cleared** |
| `n == 0` | `zero` | Accept (a legitimate zero-counter authenticator) |
| `n > 0` | `zero` | **Reject** (`counter_mode_changed`): an unexpected behaviour change; mark `suspect` |

**Residual:** an authenticator in `zero` mode gives **no clone detection**. Cloning a FIDO2 credential normally needs extracting its private key from the hardware [A]. The mitigations are physical custody of the recovery key, its PIN, its use only on the SD, and the registry checkpoint (§3), which records every recovery use.

The DM applies the same rules to its own copy, but its copy is untrusted; the SD's state is authoritative.

---

## 3. Signed registry checkpoint

**Why:** a paper fingerprint anchors **one public key**. It can't restore roles, permissions, revocations, counters, pending state or the replay ledger.

### 3.1 Checkpoint content (canonical JSON)

```
{"checkpoint":"sentinel/v1/registry-checkpoint",
 "device":"<SD serial>",
 "sequence":<int, +1 per checkpoint>,
 "created_at":<int>,
 "previous_checkpoint_sha256":"<64hex>|genesis",
 "registry_revision":"<64hex: digest of the committed registry>",
 "expected_dm_trust_fp":"<64hex>",
 "keys":[{"key_id","role","permitted_actions":[…],"algorithm","public_x963_hex",
          "credential_id_b64"?,"rp_id"?,"counter_mode"?,"last_count"?,
          "status","enrolled_by":"<payload_sha256>","revoked_by":"<payload_sha256>|null","suspect":<bool>}],
 "state":{"machine":"IDLE|PENDING|ABANDONING","pending":null|{"request_id","payload_sha256","action","expires_at"}},
 "ledger":[{"nonce","payload_sha256","one_time","expires_at"}…],   # unexpired entries only
 "audit_head":{"seq":<int>,"hash":"<64hex>"},
 "signer":{"commit":"<40hex>","binary_sha256":"<64hex>"}}
```

### 3.2 Signing and storage

- **Signed only after explicit operator confirmation (D-46 item 1)** by the SD operator key (a Secure Enclave signature over the canonical bytes, with Touch ID) under a new SD-internal action, **`registry.checkpoint`**. The DM engine never consumes it.
- **Written:**
  - (a) after every `COMMITTED` or abandoned registry change;
  - (b) after every recovery use;
  - (c) at each maintenance window.
- **Stored on a dedicated APFS checkpoint drive** `SENTINEL-CKPT`, kept **with the recovery key and the paper sheet**, separate from the transfer drive and never connected to the DM. It is plaintext (it holds no secrets); integrity comes from the signature.
- **Optional second copy:** a printed copy of the latest checkpoint hash.
- **The paper sheet records, for each checkpoint:** `sequence`, `created_at`, and the first 32 hex characters of the checkpoint's SHA-256.

### 3.3 Restore on a replacement SD

1. Read the latest checkpoint from `SENTINEL-CKPT`, using the hardened APFS intake.
2. Verify (strengthened by D-46 items 4–7, §5; where they differ, §5 wins):
   - (a) the SHA-256 of the embedded operator public key equals the **paper fingerprint**;
   - (b) the signature verifies with that key;
   - (c) `sequence` and the hash prefix equal the **latest entry on the paper sheet**, to stop rollback to an older checkpoint;
   - (d) the `previous_checkpoint_sha256` chain links back to any older checkpoints present on the drive.
3. Load the keys, roles, permissions, revocations, counters, ledger and state. Show a summary on screen for the operator to confirm.
4. **The lost SD's operator key stays in the registry as `custody: lost`.** The recovery session (round 3, §R3.3) then enrols a replacement key and revokes the lost one.
5. If the checkpoint shows `PENDING`, the restore stays `PENDING`. The §R3.1 state machine applies; a trust-store audit decides.

**Residual:**
- Changes after the last checkpoint and before the device loss are lost.
- A missing ledger entry could permit replay of a still-unexpired approval. That window is bounded by D-37 maxima and closed by revoking the lost key immediately.

---

## 4. Release provenance

**Principle:** neither the DM nor its git bundle, nor any repository host the DM can push to, is a trust anchor. The **SD's own review chain** is the anchor.

1. **Genesis:**
   - at provisioning, the operator performs a **complete review** of the signer source tree on the SD (the signer tree must stay small: target ≤ 3,000 lines; this is an operator review limit);
   - the SD computes `tree_sha256` of that reviewed tree;
   - the operator writes the commit ID and the tree hash on the paper sheet;
   - the first `signer.release` is signed.
2. **Each update:**
   - (a) the bundle is untrusted;
   - (b) the SD requires the installed commit to be an ancestor;
   - (c) the SD shows the **complete diff** of the signer tree between the installed reviewed tree and the new one, which the operator reviews;
   - (d) the SD computes the new `tree_sha256`;
   - (e) the build runs locally and offline;
   - (f) the operator signs `signer.release` naming the commit, the tree hash, the binary hash and the previous commit.
   - **Trust flows only from the reviewed previous tree plus the reviewed diff.**
3. **External commit IDs are advisory:** for example, a repository web page viewed on a phone. The agent may control pushes to that repository through DM credentials. A mismatch **stops** the update, but a match **is not** proof.
4. **Changes outside the signer tree** in the bundle are never built into the signer. The build uses only the signer tree, whose hash is verified.
5. **Rollback:** a signed `signer.release` naming a kept previous version (§R3.4).

---

## 5. Final proposed decision wording (NOT recorded)

### D-45: per-key roles and permitted actions

> **D-45.** Every operator key carries a role and an explicit list of permitted actions, recorded in the signing device's registry and in Sentinel's trust store, and included in the trust-store fingerprint.
>
> **Roles:**
> - **Role `operator`** (ECDSA P-256 in the dedicated signing device's Secure Enclave) may sign:
>   - `authorize_record`, `revoke_record`, `review.verify_no_evidence`, `review.accept_risk`, `suppress`, `policy.change`, `key.rotate` and `key.revoke`;
>   - and, on the signing device only, `signer.release` and `registry.checkpoint`.
> - **Role `recovery`** (a FIDO2 ES256 credential) may sign only:
>   - (a) `key.rotate` that enrols a replacement key of role `operator`, whose public-key hash the signing device generated and verified in the same recovery session; and
>   - (b) `key.revoke` of a key other than itself.
>
> **A recovery key never authorises** ordinary approvals, reviews, accepted risks, suppressions, policy changes, audits, signer releases or registry checkpoints, and never revokes itself.
>
> **Enforcement:** the signing device and Sentinel Core each enforce these permissions independently. Any signature or assertion for an action outside its key's permitted actions is rejected (`BLOCKED`, `action_not_permitted`).
>
> **Key operations:** these are prepared against the trust state computed by the signing device from its own registry. A registry change takes effect on the device only after explicit operator confirmation. While a change is pending, further key operations are refused.

### D-38 amendment: operator signing and FIDO2 recovery assertions

> **D-38 (amended).** Sentinel V1 has two operator-key classes with distinct verification.
>
> **(1) Operator signing:**
> - ECDSA P-256 (SHA-256) with a key held in the Apple Secure Enclave of a dedicated signing device that runs no untrusted agents;
> - access control `.biometryCurrentSet`: every signature requires a current biometric match, with **no passcode fallback**;
> - each signature covers exactly the canonical approval payload, after the device has validated it and displayed every security-relevant field;
> - the development Mac never holds or uses an operator signing key.
>
> **(2) Recovery assertions:**
> - a FIDO2 credential with COSE algorithm ES256 (P-256), RP ID `sentinel-recovery.invalid`, and required user verification;
> - used only through the signing device's trusted display;
> - it produces a WebAuthn assertion over `authenticatorData ‖ SHA-256(clientDataJSON)`, whose challenge is SHA-256(`"sentinel/v1/recovery-assertion"` ‖ 0x00 ‖ canonical approval payload).
>
> **Verification of recovery assertions** uses a separate procedure: the exact client-data key set, `type`, challenge, `origin == "https://" + rp_id`, `crossOrigin`, `rpIdHash`, UP and UV set, AT and ED clear, the credential ID, the counter policy, the signature, and D-45 permissions. Origin and RP ID checks are never relaxed to suit an API. **A recovery assertion is never accepted as an operator signature, or vice versa.**
>
> **Not used in V1:** Ed25519 FIDO2 operator keys.
>
> **Fail closed:** if the Secure Enclave, biometry or the recovery authenticator is unavailable, the affected actions fail closed. There is no software-only fallback.

### OD-2: recovery RP ID

> **OD-2.** The recovery RP ID is `sentinel-recovery.invalid`.
>
> - It is used with AuthenticationServices only if SD-T35a passes **offline**, producing client data that passes the strict checks unmodified.
> - Otherwise the signing device uses libfido2 (OD-4), with the same RP ID and origin rules.
> - A real operator-controlled domain is a documented fallback only, requiring a separate decision.

### OD-3: signature counters

> **OD-3.** The counter mode (`zero` or `increasing`) is fixed at the recovery credential's first, ceremony, assertion.
>
> - In `increasing` mode, every assertion must carry a strictly greater count. Equal, lower or reset counts are rejected, and the key is marked `suspect` until the operator revokes or replaces it.
> - In `zero` mode, the count must stay 0. Any non-zero count is rejected and the key marked `suspect`.
> - Zero-counter authenticators are accepted. The absence of clone detection for them is a documented residual risk, mitigated by physical custody, PIN and signing-device-only use.

### OD-4: library

> **OD-4.** AuthenticationServices is preferred if SD-T35a passes.
>
> - Otherwise libfido2 is adopted for the signing device only, after a D-03 licence and supply-chain review of libfido2 and its transitive dependencies.
> - Its source is obtained once, under a separately approved network fetch or by verified media, checked against upstream signatures, built on the signing device, and pinned.
> - It is never part of the Sentinel wheel.

### OD-5: release provenance

> **OD-5.** The signer's trust anchor is the operator's complete review of the genesis signer tree on the signing device, recorded on the paper sheet, followed by the review of each complete diff on the signing device.
>
> - Each installed version requires a `signer.release` record signed by an operator-role key, naming the commit, tree hash, binary hash and previous commit.
> - Development-Mac bundles and repository hosts are untrusted transport; external commit IDs are advisory and only able to stop an update.

### OD-6: timing

> **OD-6.**
> - The Touch ID or FIDO2 user-verification prompt times out after 60 seconds; a timeout means no signature.
> - The clock tolerance for `issued_at` is ±300 seconds.
> - The signing device's clock is checked against an operator-verified time source at each maintenance window and before every ceremony.
> - An unchecked clock older than 30 days blocks signing.

### D-46: signed registry checkpoints (strengthened per operator correction, 2026-11-09)

> **D-46.** The signing device maintains signed registry checkpoints.
>
> **Contents:** the registry revision; every key with role, permitted actions, algorithm, public key, recovery credential data, counter mode and last count, status, suspect flag, and enrolment and revocation provenance; the pending/committed state, including any pending change; all unexpired replay-ledger entries (nonce, payload hash, one-time flag, expiry) and seen request IDs; the audit-log head; and the installed signer release.
>
> 1. **Explicit confirmation.** Every checkpoint requires explicit operator confirmation on the signing device. It is a `registry.checkpoint` record signed by an operator-role Secure Enclave key with Touch ID. A checkpoint is never created, signed or written automatically. The device *prompts* for one after every committed or abandoned registry change, after every recovery use, and at each maintenance window, and records any prompt that was declined.
> 2. **Display.** Before signing, the device displays the checkpoint **sequence number** and the **full 64-hex SHA-256 of the canonical checkpoint**, plus a field-by-field summary (keys, roles, permissions, statuses, state machine, ledger size, audit head).
> 3. **Paper anchor in the ceremony.** The paper-anchor update is part of the checkpoint ceremony: the operator writes the sequence number and the full hash on the paper sheet, then re-types the hash on the device. A checkpoint is complete only when the re-typed hash matches; otherwise it is marked `unanchored` and is not usable for restoration.
> 4. **Strict restoration.** Restoration verifies:
>    - that the embedded operator public key's SHA-256 equals the paper key fingerprint;
>    - the signature;
>    - that the checkpoint's sequence number and full hash equal **exactly the latest paper anchor**, as typed by the operator during restoration;
>    - the `previous_checkpoint_sha256` chain.
>
>    **Any mismatch refuses restoration.** There is no override.
> 5. **No automatic selection.** The device never automatically restores the newest, or any, checkpoint found on removable media. The operator selects a checkpoint by typing its sequence number and full hash from paper, and the device loads only the file whose canonical hash equals that value.
> 6. **State preservation.** Restoration preserves all replay protection (ledger entries and seen request IDs, never pruned during restore) and all security-relevant pending/committed state. A restored `PENDING` stays `PENDING` and is resolved only by the §R3.1 state machine.
> 7. **No silent rollback or reversal.** A checkpoint never authorises:
>    - a rollback of the registry to an older revision;
>    - a reversal of revocation state (a revoked key stays revoked);
>    - the clearing of a `suspect` flag;
>    - a decrease of a recovery counter.
>
>    If the device's current state is newer than the selected checkpoint (higher sequence, or keys revoked after it), restoration is refused. Restoration onto a device with an existing registry is refused unless that registry is empty. A paper fingerprint alone is never sufficient to reconstruct the registry.

---

## 6. Remaining hardware tests (before activation)

| ID | Test | Status |
|---|---|---|
| SD-T35a | AuthenticationServices registration and assertion, RP ID `sentinel-recovery.invalid`, offline, ad-hoc signer; strict client-data check unmodified | Needs a FIDO2 key and the SD |
| SD-T35b | libfido2 registration and assertion offline, same RP ID and rules (only if 35a fails, after the OD-4 review) | Needs the dependency approval |
| SD-T36 | Strict verification negatives, extended: every §1.3 row individually violated | Needs the verifier implementation |
| SD-T51 | Counter policy: first assertion sets the mode; increasing accepted; equal, lower or reset rejected with the key marked `suspect`; zero mode with a non-zero count rejected | Needs a FIDO2 key (or a simulated authenticator for negatives) |
| SD-T52 | Checkpoint written after a commit, an abandon, a recovery and maintenance; the chain links; the signature verifies | Needs the SD |
| SD-T53 | Restore on a replacement SD: paper fingerprint match; rollback to an older checkpoint detected by the paper sequence; a tampered checkpoint rejected; a `PENDING` state preserved | Needs a second SD (or the same SD erased) |
| SD-T54 | Release provenance: genesis review recorded; an update with history rewritten is refused; an advisory external commit mismatch stops it; changes outside the signer tree are excluded from the build | Needs the SD |
| SD-T55 | Clock: an unchecked clock older than 30 days blocks signing; skew beyond ±300 s refuses the request | Needs the SD |
| SD-T01 to SD-T50 | As in round 3 (QR tests SD-T05 and SD-T06 deferred) | Pending the SD build |

**Production signing stays disabled until** D-45, the D-38 amendment and D-46 are recorded, the signer is implemented, SD-T01 to SD-T55 pass (excluding the deferred QR tests), the first-enrolment ceremony is completed, and an activation decision record exists.


---

**Recorded 2026-11-09:** the decision register (`docs/architecture-discovery-plan.md` §4) now holds:
- **D-45** (per-key roles);
- **D-46** (checkpoints, in the strengthened wording);
- **D-47** (the D-38 amendment);
- **OD-2 to OD-6** (§4.1).

Where this document says "proposed" for these, the register is authoritative. **The architecture is not frozen.**

**Freeze (2026-11-09):** the architecture is frozen as a design baseline (D-48). This design is part of the baseline. It is **not** implemented or hardware-validated, and production signing stays disabled.
