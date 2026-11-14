# SE-03: separate signing device design (Architecture C)

**Date:** 2026-11-09. **Decision basis:** the operator **conditionally approved Architecture C** (`signing-trust-architecture.md` §9), with the directions recorded in §0.

**Status:** design and test matrix for review only.
- No code, keys, accounts, purchases or network access were involved.
- No decision-register change. Production signing stays disabled. **The architecture is not frozen.**

**Labels:**
- **[V]:** verified on the development Mac, or in earlier SE evidence;
- **[A]:** an assumption, to be tested;
- **[D]:** a requirement set by the operator's direction.

---

## 0. Operator directions (SE-03)

1. A dedicated second Mac is Sentinel's signing device (**SD**).
2. The SD runs **no** Claude Code, Codex, Sentinel agents or other untrusted development agents.
3. The SD parses and validates canonical approval payloads independently.
4. The SD displays **every** security-relevant field, with no truncation.
5. `.biometryCurrentSet`, Touch ID only.
6. It signs only after explicit operator approval.
7. The development Mac (**DM**) receives only the signed response and verifies it against an enrolled public key.
8. The SD never trusts caller-provided display text or instructions.

Transport: QR code for small payloads, removable media for large ones, with the same serialisation, hash, verification and replay protection.

---

## 1. Component architecture

```
Development Mac (DM), untrusted user session        Signing device (SD), dedicated Mac
------------------------------------------         ---------------------------------------------
sentinel CLI ── prepare ──> canonical payload        sentinel-signer app (signer account only)
   │                          │                       ├─ intake: QR camera reader | media reader
   │                    request envelope              ├─ validator: canonical + schema + policy
   │                          │                       ├─ device ledger (nonces, request IDs, trust mirror)
   │         ┌────── QR on DM screen ──────┐          ├─ renderer: full-field display (own window)
   │         └── file on removable media ──┘   ─────> ├─ presence: LAContext biometrics only
   │                                                  ├─ signer: SE P-256 key, .biometryCurrentSet
   │  <──── response (QR on SD screen, or file) ───── └─ response encoder
   │
   └─ verify: signature over the pending payload, with the enrolled SD public key (D-33, D-36, D-37)
```

**Components:**

| Component | Where | Trusted? | Responsibility |
|---|---|---|---|
| `sentinel` CLI | DM | **No** (the DM is assumed compromised) | Builds unsigned payloads (`approval prepare`), encodes requests, decodes responses, verifies signatures, applies approvals |
| Request and response carriers | QR codes on screens; files on removable media | No (data only) | Move bytes |
| `sentinel-signer` app | SD, in a standard account `signer` | **Yes** (its source is reviewed on the SD, §7) | Intake, validation, display, presence, signing, device ledger |
| SD Secure Enclave key | SD | Yes (hardware, non-exportable) | ECDSA P-256 signatures, `.biometryCurrentSet` |
| Recovery key | A FIDO2 authenticator kept offline (§5.4) | Yes (hardware) | Only `key.rotate` and `key.revoke` recovery |
| Enrolled public key and fingerprint | DM trust store, the SD's own record, and a paper record kept by the operator | The paper and SD records are the anchors | Verification |

**What changes in Sentinel later** (not now): the DM never runs a signer. `approval prepare` gains `--emit-request (qr|file)`, and a new `approval receive (qr|file)` verifies a response and stores the approval. **No DM code path can produce an operator signature** (unchanged rule).

---

## 2. Threat model

**The attacker** controls the DM's logged-in daily account fully (code execution, files, tools, the signing identity, fake dialogs and terminals). It can also **prepare any request** and **show any QR code**, or **write any file** to the transfer media. **Not assumed:** physical access to the SD, root or kernel access on the SD, or a compromised Apple Secure Enclave.

| Required outcome | How the design achieves it | Residual |
|---|---|---|
| The attacker can't sign arbitrary approvals | The key exists only in the SD's Secure Enclave. The SD signs only validated, displayed and biometrically approved payloads | **The operator approves a correctly displayed malicious payload** (human risk) |
| The attacker can't read the SD's private key | Secure Enclave keys are non-exportable [V-SDK, SE-01]. The SD is a separate machine | — |
| The attacker can't invoke signing without approval | The SD has no network signing interface. Every signature needs a Touch ID match on the SD (`.biometryCurrentSet`) | Malicious input exploiting a parser bug (mitigated: §3.3 parsing limits, §4 intake hardening) |
| The attacker can't change what the SD displays | The SD renders **only** from validated payload bytes. Envelope text is never displayed. The DM has no channel to the SD's screen | — |
| The attacker can't modify the SD's trust store or recovery key | They live on the SD or offline. There's no inbound channel except data carriers, and nothing on them is executed | Media-borne exploits against macOS itself (§4.2) |
| The attacker can't replay or substitute an approval | See §3.5 | — |
| (Honest limit) The DM's own enforcement is not trustworthy | With the daily account compromised, the agent can patch Sentinel on the DM so it skips verification, or delete approvals (D-34). **The SD guarantees that no valid operator signature exists without approval.** It can't make a compromised DM behave | Detection relies on verifiers outside the DM (CI, a second machine, the operator checking reports there) using the paper-recorded key fingerprint |

---

## 3. Payload protocol

### 3.1 Approval payload (unchanged, D-33)

The canonical approval payload is the §11.3 object, serialised with `canonical.encode` (sorted keys, no whitespace, UTF-8, integers only). **What's signed are exactly these bytes.** The SD additionally requires that every string be printable ASCII (`0x20`–`0x7E`) so the display is unambiguous; non-ASCII is refused.

### 3.2 Request envelope (DM → SD)

```
{"envelope":"sentinel/v1/sign-request","payload":<canonical payload object>,"payload_sha256":"<64 hex>","request_id":"<32 hex, 128-bit random>"}
```

- **The envelope is itself canonical JSON**, with exactly these four keys. There is **no** display text, label, instruction or comment field. Any unknown key means refusal.
- `payload_sha256` must equal SHA-256 of `canonical.encode(payload)`, recomputed on the SD. It only detects corruption; it carries no authority.
- `request_id` lets the DM match the response to its pending request. The SD records it (§3.5).

### 3.3 SD validation, before any display. Every failure is a refusal shown on the SD

1. **Size:** the envelope is at most 16,384 bytes.
2. **Strict JSON:** no duplicate keys, no floats; re-encoding canonically equals the input bytes, for both the envelope and the payload.
3. **Payload fields:** exactly the §11.3 set. `action` is one of the defined actions, and `context == "sentinel/v1/approval/" + action`.
4. **`key_id`** equals the SD key's own ID, or the recovery key's ID for recovery actions (§5.4).
5. **Time:** `issued_at` is within ±5 minutes of the SD clock, and `expires_at - issued_at` is no more than the D-37 maximum for the action. The SD keeps **its own copy** of the D-37 table, changeable only on the SD (§7).
6. **Device policy:**
   - the action is in the SD's allowed set;
   - production `authorize_record` payloads name no wildcard assets (D-37);
   - recovery actions only with the recovery key.
7. **Replay:** the nonce isn't in the device ledger for a different payload hash; a one-time nonce isn't already used; `request_id` hasn't been seen.
8. **Trust mirror** (for `key.rotate` and `key.revoke`): `revision == "trust:<fp>"` must equal the trust fingerprint the SD last recorded (§5.2). Otherwise the SD refuses and shows "the development Mac's trust store differs from this device's record".

### 3.4 Response envelope (SD → DM)

```
{"envelope":"sentinel/v1/sign-response","request_id":"<32 hex>","payload_sha256":"<64 hex>","key_id":"<id>","signature_der_b64":"<base64>"}
```

- Canonical JSON, exactly these keys.
- **The response has no authority of its own.** The DM:
  - takes the payload from **its own pending request** stored under `request_id`, not from the response;
  - checks `payload_sha256` against it;
  - verifies `signature_der_b64` over `canonical.encode(payload)` with the **enrolled** key for `key_id`;
  - then runs the existing `approvals.verify` checks (context, subject, revision, scope, expiry, nonce, D-36, D-37).

### 3.5 Replay and substitution

| Attack | Defence |
|---|---|
| Replay of an old response | DM: the pending-request table (single use) plus the nonce ledger (D-36) plus expiry (D-37). SD: refuses an already-seen `request_id` |
| Reuse of a one-time nonce with a new payload | SD device ledger (agent-unreachable) refuses, and so does the DM ledger |
| Substituted request (the agent swaps the payload) | The SD displays the **substituted** payload truthfully; the operator must reject it. The SD can't know the operator's intent |
| Substituted response (a signature over another payload) | The DM verifies against its own pending payload, so it is rejected |
| Response for another device's key | An unknown or unenrolled `key_id` is rejected |
| Stale trust state for key operations | The SD's trust mirror check (§3.3 item 8) |

---

## 4. Transport flows

### 4.1 QR flow (normal, small payloads)

1. **DM:** `sentinel approval prepare … --emit-request qr` shows a QR code (byte mode, error correction level M) in the terminal or a window.
   - **Limit:** an envelope of **1,800 bytes or fewer** for a single code. That is a conservative value **[A]**, to be fixed by test SD-T05 within the QR version 40-M byte capacity. **There's no multi-QR splitting:** larger requests use media.
2. **SD:** the signer's intake opens the camera. It accepts a single QR code containing **only** a request envelope; anything else is refused.
   - The camera image is decoded locally.
   - No other QR content type (a URL, Wi-Fi settings, text) is ever acted on.
3. **SD:** validation (§3.3), then display and Touch ID (§6), then signing.
4. **SD:** shows the response as a QR code (about 330 bytes). **DM:** `sentinel approval receive qr` reads it.
   - **Open choice:** reading needs a camera capture on the DM [A]. The alternative is to use media for the response too.
   - The DM side is untrusted either way. The response is integrity-checked, not trusted.

### 4.2 Removable-media flow (large payloads, or when no camera is available)

1. **DM:** `--emit-request file` writes `sentinel-request-<request_id>.json` (16,384 bytes or fewer) to a dedicated USB drive (APFS or exFAT), labelled `SENTINEL-XFER`.
2. **SD intake hardening:**
   - the drive is mounted read-only with `nobrowse,noexec,nosuid` [A, SD-T08];
   - Spotlight and Quick Look are off for the volume [A];
   - the signer reads **only** the single file matching the exact name pattern and size limit, via its own reader;
   - every other file is ignored and listed as a warning;
   - nothing on the drive is opened by Finder or executed.
3. Validation, display, Touch ID and signing are as in the QR flow.
4. The SD writes `sentinel-response-<request_id>.json` back. This is a separate write mount, or the operator moves the drive once more [A]. The DM reads it with `approval receive file`.
5. **Hygiene:**
   - the drive is used only for this purpose;
   - the SD wipes nothing automatically;
   - the operator deletes the request and response files after use;
   - **only these two file types ever cross.**

**Both flows** use the same envelopes, hashes, checks and ledgers. Only the carrier differs.

---

## 5. Key lifecycle and recovery

### 5.1 Creation (on the SD, by the signer app)

- A CryptoKit or `SecKey` Secure Enclave P-256 key with `[.privateKeyUsage, .biometryCurrentSet]`, `WhenUnlockedThisDeviceOnly`.
- **On the SD**, the key reference is stored in the `signer` account's protected container (0600). Because the SD runs no untrusted code (direction 2), the handle-on-disk weakness of SE-H1 is **contained by the device boundary**, not by code identity [D, A]. A data-protection keychain item is preferred if available without paid provisioning [U].
- **Output:**
  - the public key, its key ID, and a **fingerprint** (SHA-256 of the X9.63 public key, shown as 16 groups of 4 hex characters);
  - the SD shows the fingerprint, and the operator **writes it on paper**, the out-of-band anchor.

### 5.2 Enrolment on the DM

1. The SD exports **only** its public key (a QR code or file `sentinel-pubkey-<key_id>.json`).
2. The DM prepares the self-signed enrolment payload (`key.rotate`, subject equal to that key, revision `trust:<empty fp>`, D-27).
3. The SD validates it:
   - the subject public-key hash **must equal its own key**, so an agent substituting its own public key is refused;
   - the revision must match the SD trust mirror, which starts empty.
4. The SD displays it, the operator approves with Touch ID, and the SD signs.
5. The SD then records the new trust fingerprint it **expects** the DM to have (the empty store plus this key) in its trust mirror.

**First-use limitation:** a compromised DM could enrol an **attacker key first**, or instead of the SD key.
- The SD detects that at the **next** key operation (trust-mirror mismatch).
- Any external verifier detects it through the paper fingerprint.
- The DM's own verdicts can't be trusted after compromise anyway (§2, honest limit).

### 5.3 Rotation, revocation and biometric change

| Event | Procedure |
|---|---|
| Rotation (planned) | The SD makes a new key; the DM prepares `key.rotate` signed by the **old** SD key (subject: the new key; revision: the SD's mirror fingerprint). The SD validates, displays, signs and updates its mirror. The operator records the new fingerprint |
| Revocation | `key.revoke` signed by an active key (the SD's other key, or the recovery key). The SD updates its mirror |
| Biometric enrolment change | `.biometryCurrentSet` invalidates the SD key [V-SDK semantics], so **recovery** (§5.4) |
| SD lost, stolen or broken | Recovery (§5.4); then revoke the lost key's ID |

### 5.4 Recovery operator key

- **Holder:** a FIDO2 authenticator with a PIN and a touch (Ed25519, which D-38 allows). It is kept **offline**, in a safe place, and **never connected to the DM**.
- **Use:** only `key.rotate` (enrolling a replacement SD key) and `key.revoke`. **This needs a later decision:** the trust store must record per-key permitted actions, and the engine must enforce them, so a recovery key can't sign ordinary approvals.
- **Signing path:** the recovery key is used **through a signing device**, either the SD or a freshly provisioned replacement SD. That signer validates and **displays the payload completely**, then asks the FIDO2 key to sign the canonical bytes. That gives the recovery path the same trusted display, although the FIDO2 device itself has no display.
- **Enrolment:** at SD provisioning time, as a second operator key: self-signed by the FIDO2 key through the SD, and recorded on paper with its fingerprint.
- **Not on the DM:** the recovery key is never plugged into the DM, and the DM never sees anything but its public key.
- **Dependency:** a FIDO2 library on the SD. That is a new third-party component, needing D-03 review before adoption [A].

---

## 6. Trusted display and Touch ID flow (on the SD)

1. After validation, the signer opens a **full-screen window** that is its own and not a system dialog, so there's no length limit.
2. The window shows:
   - a fixed header naming the device role ("Sentinel signing device");
   - **every field** of the payload, one per line, in a fixed order: `action`, `context`, `subject` (canonical JSON, wrapped, never truncated), `revision`, `scope` (canonical JSON, wrapped), `issued_at` and `expires_at` (integer plus UTC date and time, plus lifetime), `nonce`, `key_id`, `rationale`;
   - the payload SHA-256 as a reference;
   - **a plain-language risk line generated by the signer from the action**, for example "This allows activity class A1 on 1 staging asset for 30 days". It is template-built from fields, and there's no caller text.
3. **Scrolling:** the window requires scrolling to the end before the **Approve** button enables (a usability safeguard against unread approvals).
4. **Approve:**
   - `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: <fixed text: "Approve the Sentinel operator action shown in the Sentinel signer window">)`;
   - the reason text is a **compile-time constant**, never built from input;
   - then `SecKeyCreateSignature` or CryptoKit `signature(for:)` over the **exact canonical payload bytes**, using that context;
   - then self-verification.
5. **Cancel, timeout or biometry unavailable:** no signature; the result is logged on the SD.
6. **SD log:** an append-only local log of every request: request ID, payload hash, action, decision and time. It lives on the SD, so it is agent-unreachable.

---

## 7. Device provisioning and update security

**Provisioning (once):**
1. Erase the SD and install macOS. Create a separate admin account and a standard `signer` account. Turn on FileVault, SIP and the firewall (block all incoming). Turn off AirDrop, Handoff, Universal Clipboard, iCloud Keychain and Apple ID sync, sharing services, and remote login.
2. **Network:** used only for macOS and Xcode updates during maintenance windows. Disconnected (Wi-Fi off, no cable) during normal signing [A, operator procedure].
3. **Software:** Xcode command-line tools only, so the signer can be built on the SD. **No agents, no IDE plugins, no package managers beyond the signer's build needs.**

**Building and updating the signer (no trust in the DM):**
1. The source arrives on the transfer drive as a `git bundle`.
2. **On the SD**, the operator checks that the commit ID matches the reviewed tag (from the repository's review record, read on a trusted screen), and **reviews the diff since the last installed version on the SD**.
3. The SD builds the signer locally (`swiftc` or `xcodebuild`, ad-hoc signed; the boundary is the device, not the code signature) and installs it in the `signer` account.
4. The SD records the installed commit and binary hash in its log.
5. **The DM never supplies a binary to the SD.** A source bundle is data; it is reviewed and built on the SD.
6. **macOS updates** are applied during maintenance windows, after which test SD-T01 runs again.

**Device policy changes** (allowed actions, D-37 maxima, trust mirror) happen **only through the SD's own admin account**, and are logged.

---

## 8. Hardware test matrix

All tests use **disposable keys** on the SD until activation. On the DM they use a throwaway `SENTINEL_HOME`.

| ID | Test | Pass criterion |
|---|---|---|
| SD-T01 | SD baseline: FileVault, SIP, firewall, AirDrop, Handoff, Universal Clipboard, iCloud Keychain off, no agents installed, `signer` is a standard user | All as specified (checklist recorded) |
| SD-T02 | Key creation with `.biometryCurrentSet`; the passcode is refused | Touch ID only; passcode attempts fail |
| SD-T03 | A fingerprint enrolment change invalidates the key | Signing fails closed; recovery path needed |
| SD-T04 | Request validation: non-canonical, duplicate keys, a float, an extra envelope field, an unknown action, a wrong context, a foreign `key_id`, over-maximum expiry, clock skew, a wildcard production asset, non-ASCII | Each refused before display, with the specific reason |
| SD-T05 | QR capacity: the largest envelope that scans reliably at level M on the SD camera | Fixes the QR limit (≤ version 40-M) |
| SD-T06 | QR intake ignores non-request content (a URL, Wi-Fi, text) | Refused, nothing acted on |
| SD-T07 | Display completeness at the 16 KiB maximum: every field visible after scrolling; Approve is disabled until the end | As specified |
| SD-T08 | Media intake: a read-only, `noexec`, no-browse mount; extra files ignored; a `.app` or script on the drive is never opened | As specified |
| SD-T09 | Replay: the same `request_id`; the same one-time nonce; the same standing nonce with a different payload | Refused on the SD |
| SD-T10 | Substituted request (payload B where A was intended) | The SD shows B's fields exactly; the operator cancels; no signature |
| SD-T11 | Substituted response (a signature over another payload, or an unknown `key_id`) | The DM rejects it |
| SD-T12 | Enrolment substitution (an attacker public key in the enrolment payload) | The SD refuses: the subject isn't its own key |
| SD-T13 | Trust-mirror mismatch (the DM trust store changed outside the SD) | The SD refuses key operations, with a mismatch warning |
| SD-T14 | Recovery: FIDO2 recovery key enrolment; the recovery key used only for `key.rotate` and `key.revoke` through the SD display; an ordinary approval with the recovery key | Rotate and revoke succeed; the ordinary approval is refused by the SD and by the DM engine (after the per-key-actions decision) |
| SD-T15 | Lost-SD drill: a replacement SD enrols a new key via the recovery key and revokes the old key | Old-key signatures rejected; new key accepted |
| SD-T16 | Signer update: a git bundle with a modified commit (not the reviewed tag) | The operator check catches it (procedure); the build log records the commit |
| SD-T17 | Fake-dialog resistance on the DM | No DM-side dialog can lead to a signature (structural; documented walkthrough) |
| SD-T18 | End-to-end: `authorize_record`, `policy.change`, `suppress`, `key.rotate` through QR and through media | The DM accepts each only after SD approval |

---

## 9. Operational and usability trade-offs

| Aspect | Effect |
|---|---|
| Hardware | A second Mac with Touch ID (keyboard or built-in), a camera for QR, a dedicated USB drive and a FIDO2 key. No Apple programme purchase |
| Per-approval time | QR: scan, read, Touch ID and scan back (estimated under a minute [A]). Media: longer |
| Availability | Approvals need physical access to the SD. If the SD is unavailable, no approvals happen (fail closed); READ audits still work |
| Recovery | Needs the offline FIDO2 key and a provisioned SD |
| Maintenance | macOS updates in windows; signer updates by source review on the SD |
| Human factor | The full display increases the reading burden. The plain-language risk line and scroll-to-approve help, but can't force understanding |

---

## 10. Remaining assumptions and risks

| ID | Item | Type |
|---|---|---|
| R-1 | The operator approves a correctly displayed malicious payload | Accepted human risk |
| R-2 | A compromised DM can patch Sentinel, ignore approvals or forge local verdicts (D-34); the SD only guarantees signature authenticity | Accepted; it needs external verification for assurance |
| R-3 | Malicious media exploits macOS itself on the SD (a filesystem or parser bug) | [A] mitigated by intake hardening; residual |
| R-4 | A malicious QR exploits the SD's QR decoder | [A] residual; uses Apple's Vision decoder |
| R-5 | First-enrolment substitution on the DM, before any SD record exists | Detected later (trust mirror, paper fingerprint) |
| R-6 | Handle storage on the SD (CryptoKit) relies on the SD running no untrusted code | [D, A] |
| R-7 | The recovery path needs a FIDO2 library: a new dependency, with a D-03 review | Open |
| R-8 | Per-key permitted actions (the recovery key's restriction) need a new decision and engine support | Open |
| R-9 | QR camera reading on the DM side, versus media for responses | Open design choice |
| R-10 | SD clock correctness (expiry checks) while offline | [A]; procedure checks the time at maintenance |

---

## 11. Daily account migration assessment (the daily account to a standard user; no change made)

**Current [V]:**
- the daily account is in `admin`, and so is a separate admin account;
- both hold FileVault Secure Tokens;
- `/opt/homebrew` is owned by the daily account;
- `/Applications` is `root:admin` and group-writable;
- `/usr/local` is `root:wheel`;
- sudo needs a password and has no Touch ID.

**After demotion:**

| Area | Effect | Mitigation |
|---|---|---|
| Homebrew (`/opt/homebrew` owned by the daily account) | Expected to keep working, since it's owned by the user [A] | Verify `brew` operations after demotion |
| App installs into `/Applications`, system settings, `/usr/local` writes | Need the admin account's credentials (prompt) | Use the admin account deliberately; never type it into a terminal the agent can see |
| FileVault unlock | Both accounts keep their Secure Tokens [V], so there's no change expected [A] | Confirm `sysadminctl -secureTokenStatus` after the change |
| Xcode and developer tools | Most work for standard users; some device-support installs may prompt [A] | Accept the prompts |
| Security gain | An agent can no longer turn a phished daily-account password into root. It would need the admin account's password, which is entered only in system prompts | — |
| Procedure (when approved) | The admin account removes the daily account from `admin` (System Settings → Users & Groups, or `dseditgroup -o edit -d <daily account> -t user admin`), then log out and in | Keep a tested the admin account login **before** demoting |

## 12. Apple Development identity audit (no change made)

| Question | Finding |
|---|---|
| Where | the daily account's `login.keychain-db`; one valid identity "Apple Development: <owner Apple ID, redacted> (<certificate ID>)", team `<TEAM-ID>` [V] |
| Usable without a prompt | Yes, by `codesign` (U-8) [V] |
| Used by Sentinel | **No.** No Sentinel source, build script or test references it. `build.sh` signs ad hoc. Only the SE review documents mention it [V] |
| Other likely users | Xcode development builds of the operator's other projects (Xcode `DerivedData` and `iOS DeviceSupport` exist) [V presence; usage not inspected] |
| Consequence of keeping it | The DM can produce team-signed code for any agent. That is **irrelevant to Architecture C**, because the SD's boundary doesn't depend on code identity. It stays a general host risk |
| Consequence of removing it | Xcode device builds of other projects would need re-provisioning (network sign-in) [A]. Sentinel is unaffected |
| Recommendation | Sentinel must not depend on it (already true). Leaving or removing it is the operator's choice for other projects. Optionally set its key's access control to always prompt [A] |

---

# Round 2 revision (2026-11-09)

**Architecture C is the preferred direction.** This revision closes the protocol and recovery questions. **Where this section conflicts with §0–§12, this section wins.**

- **The protocol is normative:** `docs/architecture/signing-protocol-v1.md`.
- **USB is the v1 transport** in both directions. QR codes are optional and later (§4.1 above is superseded).

## 2. Trust-state independence

### 2.1 The SD registry is authoritative

The SD keeps its own operator-key registry, `~signer/Library/Application Support/sentinel-signer/registry.json` (0600, canonical JSON).

| Field | Meaning |
|---|---|
| `key_id` | The Sentinel key ID |
| `algorithm` | `p256` (SD Secure Enclave) or the recovery key's algorithm (§3.3) |
| `public` | The public key, in hex |
| `fingerprint` | SHA-256 of the public key, as written on the paper record |
| `operator` | The operator name, as enrolled on the DM |
| `expires_at` | As enrolled |
| `status` | `active` or `revoked` |
| `role` | `operator` or `recovery` |
| `permitted_actions` | §3 |
| `custody` | `this-device` (the private key is in this SD's Secure Enclave), `external-fido2`, or `other-device` |
| `history` | The approval payload hashes that added or revoked it (enrolment, rotation, revocation) |

**Rules:**
- **The SD changes its registry only:**
  - (a) when it itself signs a `key.rotate` or `key.revoke` and the operator confirms that the DM accepted it; or
  - (b) through the SD admin account, during a ceremony (§6) or a recovery (§5).
- **The SD never imports registry state from the DM.**
- **DM claims about key status, revocation or trust fingerprints are never trusted.** The SD **computes** the expected DM trust-store fingerprint itself (§2.2).

### 2.2 Computing the expected DM trust fingerprint

The DM fingerprint is `canonical.digest({"keys":[{key_id, operator, algorithm, public, status, expires_at}, …]})`, sorted by `key_id` (`src/sentinel/keys/operator.py:83–99`) [V].

- The SD computes the same projection **from its own registry**, giving `expected_fp`.
- **Requirement on the engine (later code):** the DM trust store must hold exactly the keys the SD registry lists (both the operator and recovery keys), so the projections can match. The new `permitted_actions` field must become part of both projections (§3.2).

### 2.3 Verifying key operations on the SD

| Action | Additional SD checks (beyond protocol §4) |
|---|---|
| `key.rotate` (add a new key) | `revision == "trust:" + expected_fp`. The subject's `public_sha256` names a key whose public part the SD already holds: either one it just generated (`custody=this-device`, pending) or one registered during a ceremony (`external-fido2` or `other-device`). The signing key's `permitted_actions` includes `key.rotate`. Shown as "Add key <fp> as <role> with permissions <list>" |
| `key.revoke` | `revision == "trust:" + expected_fp`. The subject `key_id` exists in the SD registry and is `active`. Revoking the **last active operator key** is refused unless an explicit recovery flow is in progress. The signing key's `permitted_actions` includes `key.revoke` |
| Enrolment (`key.rotate` on an empty store) | The SD registry is empty; `revision == "trust:" + digest({"keys":[]})`; the subject equals **this SD's own new key**; the payload is self-signed by that key |

**After signing a key operation:**
- the SD marks the registry change as **pending**;
- it applies the change only when the operator confirms, on the SD, that the DM accepted the response;
- the optional trust-store audit (§2.4) shows a matching fingerprint.

**Until then,** further key operations are refused: their revision would be computed from a state that isn't settled.

### 2.4 Trust-store audit (SD as an independent verifier)

1. The operator copies the DM's `trust.json` to `to-signer/trust-store-audit.json`.
2. The SD parses it as untrusted input and compares it with its registry.
3. On the SD screen it shows: **MATCH**, or a table of differences (keys present only on the DM, keys only on the SD, status or permission differences).

This detects attacker-enrolled keys, silently "unrevoked" keys, and a rolled-back trust store. It does **not** detect a DM that shows one trust store to the audit and uses another; the DM's own verdicts stay untrusted (§2 limits).

## 3. Per-key permitted actions and recovery authority

### 3.1 Permission sets

| Role | `permitted_actions` |
|---|---|
| `operator` (SD key) | `authorize_record`, `revoke_record`, `review.verify_no_evidence`, `review.accept_risk`, `suppress`, `policy.change`, `key.rotate`, `key.revoke` |
| `recovery` | `key.rotate` **only when adding a replacement `operator` key**, and `key.revoke` **only for keys other than the recovery key itself** (rotating the recovery key needs the operator key and a ceremony) |

### 3.2 Enforcement in two independent places

1. **The SD** refuses a request whose `key_id` lacks the action, and applies the recovery restrictions in 3.1.
2. **The DM engine (later code):**
   - `OperatorKey` gains `role` and `permitted_actions`, included in the trust-store fingerprint;
   - `approvals.verify` refuses any approval whose signing key lacks the action (`action_not_permitted`).

**Needs a decision record** (proposed **D-45**): "Operator keys carry roles and permitted actions; a recovery key may only enrol replacement operator keys and revoke other keys."

### 3.3 FIDO2 recovery-key options (investigation only; no dependency added)

**Constraint [A, from the FIDO2 and WebAuthn design]:** FIDO2 authenticators don't sign arbitrary bytes. An assertion signs `authenticatorData || SHA-256(clientDataJSON)`. A Sentinel recovery signature would therefore be an **assertion whose challenge is `payload_sha256`**. Verification would check:
- the rpId hash;
- the user-presence and user-verification flags;
- that the challenge equals the payload hash;
- the counter, if the authenticator keeps one;
- the signature over the assertion.

So the recovery key's signature format differs from the SD key's. Sentinel's verifier needs a second, tightly specified path (decision UQ-4).

**Algorithm note:**
- Ed25519 (COSE −8) isn't supported by every authenticator. ES256 (P-256) is near-universal [A].
- D-38 allows "Ed25519 (for example on a FIDO2 authenticator)" or "P-256 in the Secure Enclave". **A P-256 FIDO2 key isn't covered by D-38's wording**, so it would need an amendment if ES256 is chosen.

| Option | What it is | Licence [A, to be verified by the D-03 audit] | Maintenance | Fit |
|---|---|---|---|---|
| F-1: Yubico `libfido2` (C), used from the Swift signer | A CTAP2 client library | BSD-2-Clause [A]; it pulls in `libcbor` (MIT [A]), OpenSSL (Apache-2.0 [A]) and zlib [A] | Actively maintained by Yubico [A]; C dependencies to build on the SD | Direct USB HID access; full control of the assertion |
| F-2: Yubico `python-fido2` | A Python CTAP2 and WebAuthn client | BSD-2-Clause [A] | Maintained [A]; Python on the SD | Simpler, but adds a Python runtime and packages to the SD |
| F-3: Apple AuthenticationServices (security-key credential APIs) | A system framework | Apple SDK | No third-party code | **[U]:** on macOS this may need app entitlements or associated domains, and its use outside a browser or app context is unverified |
| F-4: a custom minimal CTAP2 over IOKit HID | Own code | Sentinel MIT | Highest maintenance and risk | Not recommended |

**Recommendation for review:**
- **F-3 first** (no third-party code), if SD-T35 shows it works on the SD without paid provisioning.
- Otherwise **F-1**, under a D-03 licence and supply-chain review before adoption.
- Either way, the recovery key is used **only on the SD**, through the SD's display.

### 3.4 Recovery flows

**Lost or broken SD:**
1. Provision a replacement SD (§5).
2. Create a new Secure Enclave key there.
3. Manually register the recovery key's public key from the **paper record** (the fingerprint is checked on screen).
4. Register the old SD key from the paper record as `custody=other-device`.
5. Recover the trust state through a trust-store audit of the DM's file, with every difference resolved by the operator on screen.
6. The recovery key signs `key.rotate`, adding the new SD key as `operator`.
7. The recovery key signs `key.revoke` for the old SD key.
8. Record the new fingerprint on paper.

**Compromised SD key** (suspected): the same flow, run from the existing SD if it's trusted, otherwise from a fresh one.

## 4. Trusted display, field by field

All text is built by the signer from validated fields with fixed templates. **No string from the request is shown except validated field values**, and those are drawn in a monospaced "value" style that is visually distinct from the signer's own labels.

**Scrolling to the end before Approve is enabled is a UX measure, not a security control.**

| # | Section | Content (signer-built) |
|---|---|---|
| 1 | Header (fixed) | "SENTINEL SIGNING DEVICE — operator approval". The SD's name; the signer version (commit, short hash) |
| 2 | Signing key | `key_id`; role; fingerprint (16×4 hex); "this device" or "recovery key (FIDO2)" |
| 3 | Action | `action` plus a fixed description from a table, for example `policy.change` → "Replace the engine policy file" |
| 4 | Risk summary (template) | Per action, built from fields only. For example, for `authorize_record`: "Allows activity classes {scope.permitted_activities} on {N} assets in {environments} until {expires_at UTC}" |
| 5 | Subject | Every subject field on its own line (`type`, `sha256`, `fingerprint`, `key_id`, `public_sha256`, `decision_id`, `entry_sha256`, as the action requires), in full |
| 6 | Revision | Shown in full. For key operations also: "Device registry fingerprint: <expected_fp> — MATCH" (the check has already passed) |
| 7 | Scope | Recursive, complete: each key on its own line; lists as numbered lines, one element per line; nested objects indented. **Never elided** |
| 8 | Validity | `issued_at` and `expires_at` as integers, plus UTC ISO-8601, plus the lifetime in days, hours and minutes, plus the D-37 maximum for comparison |
| 9 | Nonce | 32 hex, in full; one-time or standing (from the action) |
| 10 | Rationale | Shown in full, wrapped, in the value style, with the label "Operator rationale (text entered when the request was prepared)" |
| 11 | Hashes | `payload_sha256` and `request_id` |
| 12 | Controls | **Cancel** (default) and **Approve with Touch ID**. Approve enables after scrolling to the end (UX) |

**Unknown subject types, or a scope too deep** (nesting over 8) **or too long** (over 1,000 rendered lines), mean refusal: "cannot display completely".

## 5. Trusted signer update process

**Inputs:** a `git bundle` from the DM is **untrusted input**.

1. **Provenance:**
   - (a) the bundle contains **the currently installed commit as an ancestor** (no history rewrite), checked with `git bundle verify` and `git merge-base --is-ancestor` on the SD;
   - (b) the operator obtains the **expected new commit ID from an independent source**, for example the repository's web UI on a phone, or a reviewed release note, and compares it with the bundle tip on the SD screen;
   - (c) **optional but recommended:** release tags are signed by the **SD operator key** itself, through a new action `signer.release` (needs a decision). The SD then verifies the tag signature locally.
2. **Review on the SD:** the SD shows `git diff <installed>..<new>` for the signer source tree only. The operator reviews it. Changes outside the signer tree are listed, and the operator acknowledges them.
3. **Local build:** a clean build on the SD (`swiftc` or `xcodebuild`, a pinned toolchain version recorded in the log), with **the network off**. The signer's own test suite runs on the SD.
4. **Verify the executable:**
   - record its SHA-256 and code-signature details (ad-hoc);
   - check that it reports its embedded commit ID equal to the reviewed one;
   - optional reproducibility: build twice and compare hashes, recording any difference.
5. **Operator approval:** the SD admin flow shows (old commit and hash) → (new commit and hash) and requires Touch ID. The approval is logged.
6. **Replacement with rollback:**
   - install to `versions/<commit>/sentinel-signer`;
   - atomically update the `current` file (a text file holding the commit, not a symlink);
   - **keep the previous version**, so rollback means setting `current` back to it (it also needs Touch ID).
7. **First run after an update:** a self-test plus SD-T01, before any real request.

## 6. First-enrolment ceremony (exact steps)

**Preconditions:**
- the SD is provisioned and SD-T01 passes;
- the DM has a fresh, empty Sentinel trust store;
- the operator has a paper ceremony sheet.

| Step | Where | Action | Evidence |
|---|---|---|---|
| 1 | SD | `sentinel-signer ceremony start`. The SD records the date and time, its hardware serial, the macOS build, and the signer commit and hash | SD log entry; written on the sheet |
| 2 | SD | Create the operator key (Secure Enclave, `.biometryCurrentSet`, Touch ID to confirm creation) | SD log: `key_id`, fingerprint |
| 3 | SD | Display the fingerprint (16×4 hex) and the key ID. **The operator writes them on the sheet** | Sheet |
| 4 | SD | (If adopted) register the FIDO2 recovery key; display its fingerprint; the operator writes it on the sheet | Sheet; SD log |
| 5 | SD → USB | Export `pub-<key_id>.json` (and the recovery key's) | SD log `output_written` |
| 6 | DM | `sentinel approval prepare key-enrol --key pub-<key_id>.json …` creates the enrolment request. **The DM shows a fingerprint, but that display is untrusted and isn't the comparison** | DM log |
| 7 | USB → SD | Intake; validation (registry empty, subject is this SD's key, self-signed); full display; the operator checks that the shown fingerprint equals **the sheet** (not the DM); Touch ID | SD log `approved`, `signed` |
| 8 | SD → DM | The response goes to the DM; `sentinel key enrol --approval …` | DM trust store |
| 9 | DM → SD | Trust-store audit (§2.4): the SD shows MATCH | SD log `audit: match` |
| 10 | SD | The operator confirms the DM accepted it, and the SD commits the registry entry | SD log `registry_changed` |
| 11 | DM → SD → DM | A **test approval**: a `policy.change` for a disposable policy file in a throwaway `SENTINEL_HOME`, with a 10-minute expiry. The SD shows it in full; Touch ID; the DM verifies it with the enrolled key. (Its subject only matches the throwaway file, so it has no production effect) | SD and DM logs |
| 12 | SD | `ceremony end` records a ceremony hash (over the log entries of steps 1–11) and displays it. **The operator writes it on the sheet and signs and dates the sheet** | Sheet stored with the recovery key |

**Independent fingerprint verification:** the only authoritative comparison is **SD screen ↔ paper sheet**. The DM's displays are never used for verification.

## 7. Expanded hardware test matrix (supersedes §8)

**SD-T01 to SD-T18 remain**, with SD-T05 and SD-T06 (QR) deferred to the optional QR transport. Added tests:

| ID | Category | Test | Pass criterion |
|---|---|---|---|
| SD-T19 | Compromised DM | The DM shows a false fingerprint during enrolment while the SD key is genuine | The operator compares with the SD screen only; the walkthrough shows the DM display is never used |
| SD-T20 | Compromised DM | The DM enrols an attacker key before the ceremony | Step-9 audit shows a mismatch; the SD refuses key operations |
| SD-T21 | Trust-state substitution | A request with `revision: trust:<fp>` from a modified or rolled-back DM store | Refused (`trust_mismatch`) |
| SD-T22 | USB | Mount options: read-only, `noexec`, `nobrowse`, `nosuid` are in effect during intake (`mount` output) | As specified |
| SD-T23 | USB | `req-*.json` is a symlink (to a file on the SD, or to `/dev/zero`) | Refused (`ELOOP`); nothing read |
| SD-T24 | USB | `req-*.json` is a FIFO, a device node or a directory; a file with a hard link count above 1; `to-signer` itself is a symlink | Refused |
| SD-T25 | USB | Oversized file (limit + 1); more than 16 requests; the name's ID differs from the inner `request_id` | Refused |
| SD-T26 | USB | Hostile extras: a `.app`, a `.command`, a `.webloc`, `._` files, a crafted `.DS_Store` | Ignored and logged; never opened |
| SD-T27 | USB TOCTOU | The file is replaced on the drive after intake | Processing uses the spool copy; the drive is ejected before display |
| SD-T28 | Replay | The same `request_id` twice; the same nonce with a different payload; a one-time nonce reused | Refused |
| SD-T29 | Duplicates | Two requests in one intake | Shown and decided one at a time; no batch approval |
| SD-T30 | Malformed canonical | Whitespace, unsorted keys, duplicate keys, a float, `1e3`, an integer beyond 2^53, `\u` escapes, non-ASCII, a trailing newline, a BOM | Each refused, with a specific reason |
| SD-T31 | Malformed payload | Missing or extra fields; an unknown subject type; a scope too deep or too long | Refused ("cannot display completely" where applicable) |
| SD-T32 | Recovery misuse | The recovery key used for `suppress`, `policy.change` or `authorize_record` | Refused on the SD; refused by the DM engine (D-45, once implemented) |
| SD-T33 | Recovery misuse | The recovery key revoking itself, or adding a non-operator key | Refused |
| SD-T34 | Recovery | The full lost-SD drill (§3.4) on disposable keys | The new key is accepted and the old key rejected; the audit shows a match |
| SD-T35 | Recovery | FIDO2 option F-3 feasibility on the SD (no paid provisioning); else F-1 | Records whether the option works |
| SD-T36 | Recovery | The recovery assertion's challenge differs from the payload hash; user-verification flag missing; wrong rpId | Rejected by the verifier |
| SD-T37 | Update tampering | The bundle tip differs from the independently obtained commit; history rewritten (installed commit not an ancestor) | The update stops before building |
| SD-T38 | Update tampering | A modified build output is substituted before installation | Hash mismatch with the recorded build; refused |
| SD-T39 | Update rollback | Install a new version, then roll back to the previous one | `current` points back; both builds are kept; Touch ID was required both times |
| SD-T40 | Fingerprint | The paper fingerprint matches the SD display; a deliberately altered paper value is detected in the comparison | Procedure check |
| SD-T41 | Display | A long rationale, a deep scope, and many assets are all fully shown; values are visually distinct from labels | As specified |
| SD-T42 | Pending registry | A second key operation while a registry change is pending | Refused until the operator confirms |

## 8. Unresolved questions (round 2)

| ID | Question |
|---|---|
| UQ-1, UQ-2, UQ-3, UQ-4 | See the protocol, §11 |
| UQ-5 | Whether AuthenticationServices security-key APIs work for a signer app on macOS without paid provisioning (SD-T35) |
| UQ-6 | Whether release tags should be signed with the SD operator key (a new action, `signer.release`) |
| UQ-7 | How the DM learns that the SD has committed a registry change. Proposed: the operator only. There's no automatic DM-to-SD channel |

## 9. Explicit security assumptions (in addition to protocol §10)

| ID | Assumption |
|---|---|
| SA-7 | The paper ceremony sheet is stored securely, with the recovery key, and away from the DM |
| SA-8 | The independent source of the expected signer commit (§5, step 1b) isn't controlled by the agent |
| SA-9 | The operator performs the diff review honestly. It's a human control |

## 10. Operator decisions requested

1. **O-P1:** no response for refusals (recommended), or a signed refusal record.
2. **D-45 (proposed wording, §3.2):** per-key roles and permitted actions, plus the recovery-key restriction.
3. **Recovery key format:**
   - FIDO2 ES256 (needs a D-38 amendment) or Ed25519 (fewer authenticators support it);
   - the WebAuthn assertion format for recovery signatures (UQ-4);
   - the library option: F-3 first, else F-1 under a D-03 review.
4. **exFAT:** refuse it, and require APFS (recommended), or allow it.
5. **`signer.release`:** have the SD key sign release tags (UQ-6).
6. **Registry commit:** confirmation by the operator only (UQ-7, recommended).

---

# Round 3 revision (2026-11-09): decisions applied

The protocol details are in `signing-protocol-v1.md` §R3. **Where this section differs from the earlier sections, it wins.**

## R3.1 Registry pending/commit state machine

```
            sign key.rotate / key.revoke (Touch ID)            operator confirms DM accepted
  IDLE ──────────────────────────────────────────────> PENDING ─────────────────────────────> COMMITTED → IDLE
   ^                                                      │  (optional: trust-store audit MATCH shown first)
   │                                                      │
   │             operator: "DM did not apply it"          v
   └──────────── after expires_at has passed AND ─── ABANDONING
                 a trust-store audit shows the change absent
```

| State | Meaning | Allowed operations |
|---|---|---|
| `IDLE` | The registry equals the last committed state | Every signed action, subject to D-45 |
| `PENDING` | A key-operation signature was issued; the registry change is recorded but **not applied** | Ordinary approvals are allowed. **All key operations are refused.** Commit or abandon need operator action |
| `COMMITTED` | The operator confirmed on the SD that the DM accepted the change | The change is applied; recorded in the log; back to `IDLE` |
| `ABANDONING` | The operator says the DM didn't apply it | Allowed only after the payload's `expires_at` has passed (at most 1 h, D-37) **and** a trust-store audit shows the change absent. Then back to `IDLE`. If the audit shows it **present**, the SD moves to `COMMITTED` (it was applied) |

**Rules:**
- **No automatic transition.** Timeouts never commit or abandon anything; a stale `PENDING` stays `PENDING` until the operator acts. That fails closed for key operations.
- **One pending change at a time.**
- **Expected fingerprint while pending:** `expected_fp` is computed from the **committed** registry, so a second key operation can't be prepared against an unsettled state.

## R3.2 Recovery authority (mandatory requirements as designed)

| Requirement | Where enforced |
|---|---|
| Recovery can't authorise ordinary approvals, audits, policy changes, accepted risks or suppressions | The SD refuses before display (D-45 table); the engine refuses at verification (separate WebAuthn path, `action_not_permitted`) |
| Recovery can't revoke itself | The SD check (protocol §R3.5); the engine check (subject `key_id` differs from the signing `key_id` for the recovery role) |
| Recovery enrolment binds the assertion to the exact replacement-key fingerprint and operation | The challenge is SHA-256 of a domain-separated canonical payload containing `action`, `subject.public_sha256`, `revision`, `nonce` and the validity window (§R3.4) |
| The SD independently validates the replacement key and shows its fingerprint | The key is generated on the SD in the recovery session; the SD recomputes `public_sha256`; the fingerprint is shown at creation and again on the approval screen |
| Pending changes stay pending until confirmation | §R3.1 |
| Timeouts, mismatches and interrupted transfers fail closed | Protocol §R3.1 |

## R3.3 Recovery session (lost or compromised SD key)

1. On a trusted SD (the existing one if trusted, otherwise a newly provisioned one), run `sentinel-signer recovery start`. This needs the SD admin account and Touch ID, and it is logged.
2. **If it's a new SD:** rebuild the registry from the **paper ceremony sheet**:
   - the operator types the fingerprints of every key on the sheet;
   - for each key, the SD needs its public key, imported from the DM's `trust.json` via a trust-store audit;
   - the SD **accepts a key only if the SHA-256 of its public key equals the typed paper fingerprint**;
   - keys without a paper match are flagged and not imported.
3. Generate the replacement Secure Enclave key (Touch ID). It is shown and the operator writes its fingerprint on a new sheet.
4. **Recovery enrolment:** a `key.rotate` request signed by the recovery key (§R3.4, R3.5), with the FIDO2 PIN and touch. The response goes to the DM; the DM confirms; then **COMMIT**.
5. **Recovery revocation:** a `key.revoke` for the lost or compromised key, signed by the recovery key (or by the new operator key). The response goes to the DM; the DM confirms; then **COMMIT**.
6. A trust-store audit shows MATCH. `recovery end` records a session hash on the new sheet.

## R3.4 Signer release and rollback protocol

1. **Untrusted input:** a git bundle from the DM.
2. **Provenance:**
   - the installed commit must be an ancestor of the bundle tip;
   - the operator compares the tip commit with an **independently obtained** commit ID;
   - the full diff of the signer tree is shown on the SD.
3. **Local build** on the SD, offline, with the pinned toolchain. Tests pass; `tree_sha256`, `binary_sha256` and the embedded commit are recorded.
4. **The SD builds a `signer.release` payload** (protocol §R3.7) and shows it field by field. The operator approves with Touch ID **using the SD operator key**.
5. **Install:**
   - the installer component (part of the current signer) refuses unless a valid `signer.release` record, signed by an operator-role key in the SD registry, names the new binary's exact hash;
   - it copies to `versions/<commit>/` and atomically rewrites `current`;
   - the previous version is kept.
6. **Rollback:** a new `signer.release` record naming the kept previous version (`binary_sha256` must match the file in `versions/`), signed the same way, then `current` is rewritten.
7. **What DM credentials can do:** nothing. The DM has no signer key, and git or CI credentials only produce untrusted bundles.

## R3.5 FIDO2 library: AuthenticationServices first (investigation)

**Verified from the local SDK [V]:**
- `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` exists on macOS 12.0+, with `initWithRelyingPartyIdentifier:`, `createCredentialRegistrationRequestWithChallenge:displayName:name:userID:` and `createCredentialAssertionRequestWithChallenge:`;
- the assertion exposes `rawAuthenticatorData`, `signature`, `userID`, and (through `ASPublicKeyCredential`) `rawClientDataJSON` and `credentialID`;
- `userVerificationPreference` exists on the assertion request;
- `ASAuthorizationPublicKeyCredentialParameters` takes a COSE algorithm identifier;
- a separate *web-browser* variant lets the caller supply its own client data (macOS 14.4+).

**Not determinable from the headers [A/U]:**
- whether a native app using the non-browser provider must hold an **Associated Domains (`webcredentials:`)** entitlement for its relying-party ID, verified over the network by Apple. If it must, an offline SD and a non-resolving rpId (`sentinel-recovery.invalid`) **don't work**, and paid provisioning would be needed;
- the *web-browser* variant is expected to need a restricted browser entitlement;
- **whether either works for an ad-hoc-signed tool.**

**Feasibility test SD-T35** (later, with a test FIDO2 key, on the SD): register and assert with the rpId above from an ad-hoc-signed signer, offline. **If it fails because of the entitlement or domain requirement, F-3 is infeasible for V1**, and the **libfido2 review** below applies.

**libfido2 review outline** (to complete only if F-3 fails; no dependency is added now; facts marked [A] need verification during the D-03 review):

| Item | Content |
|---|---|
| Component | Yubico `libfido2` (C), with transitive `libcbor` and a crypto library (OpenSSL or LibreSSL), plus `zlib` [A]. On macOS, USB HID goes through IOKit, with no udev [A] |
| Licences | libfido2 BSD-2-Clause; libcbor MIT; OpenSSL 3.x Apache-2.0; zlib Zlib [A]. All are runtime-compatible with Sentinel's allowed set (D-03 gate) |
| Supply chain | Source tarballs checked against upstream signatures on the SD (needs **one** approved network fetch, or bundles brought on media and verified by hash and signature). Built locally; versions pinned; added to `licenses/review.json` with scope `signer` |
| Footprint | Native C on the SD only; never shipped in the Sentinel wheel |
| Maintenance | Monitor upstream advisories; rebuild on the SD through the signer-release process (§R3.4) |
| API use | `fido_dev_get_assert` with `clientDataHash = SHA-256(client_data_json)`, where the signer builds `client_data_json` itself (§R3.4); `fido_assert_set_uv(FIDO_OPT_TRUE)`; COSE ES256 |

## R3.6 Test coverage (SD-T01 to SD-T42, updated, plus new tests SD-T43 to SD-T50)

**Changes to existing tests:**

| ID | Change |
|---|---|
| SD-T05, SD-T06 | **Deferred** (QR is optional and later) |
| SD-T08 | Replaced by SD-T22 to SD-T27 plus SD-T43 to SD-T45 (APFS-only intake) |
| SD-T14 | Now: the recovery key is registered as a WebAuthn ES256 credential; enrolment and revocation through the SD display with PIN and touch; ordinary actions refused |
| SD-T32, SD-T33 | Expanded: recovery refused for `authorize_record`, `revoke_record`, both review actions, `suppress`, `policy.change`, `signer.release` and the audit; recovery self-revocation refused |
| SD-T34 | Follows the §R3.3 recovery session, including the paper-fingerprint import |
| SD-T35 | The AuthenticationServices offline feasibility test (§R3.5) |
| SD-T36 | Expanded to every step of protocol §R3.4: wrong `type`, challenge, origin, `crossOrigin`, rpIdHash; UP or UV missing; AT or ED set; wrong `credentialID`; a non-increasing counter; a recovery assertion offered where plain ECDSA is expected and vice versa |
| SD-T37 to SD-T39 | Now also require a valid `signer.release` record; installing without one is refused |
| SD-T42 | Aligned with the §R3.1 state machine |

**New tests:**

| ID | Test | Pass criterion |
|---|---|---|
| SD-T43 | A non-APFS volume (exFAT, FAT32, HFS+) | Refused (`fs_not_apfs`) before any file access |
| SD-T44 | An encrypted APFS volume | Refused (`fs_encrypted`); no password prompt shown |
| SD-T45 | Hostile APFS content: a decmpfs bomb, a sparse file of declared size 10 GB, xattr- or resource-fork-only content, look-alike Unicode names | Refused or ignored as specified; no oversized read |
| SD-T46 | Interrupted transfers: the volume is pulled during intake, a truncated request, a `.tmp` leftover, output fails mid-write | The intake is discarded; no response; the output is re-issued idempotently for the same `request_id` |
| SD-T47 | Pending state machine: abandon before expiry; abandon after expiry when the audit shows the change present (moves to COMMITTED); a key operation while `PENDING` | As specified in §R3.1; no automatic transitions |
| SD-T48 | Recovery binding: an assertion over a payload for replacement key A is offered with the payload for key B; a payload whose nonce, revision or expiry differs | Rejected (challenge mismatch) |
| SD-T49 | Recovery enrolment of a key **not** generated on this SD in the session | Refused |
| SD-T50 | `signer.release` signed by the recovery key, or a DM-supplied release record | Refused |

**Coverage map** (the operator's required categories):

| Category | Tests |
|---|---|
| Compromised DM | SD-T19, SD-T20, SD-T21, SD-T27, SD-T46 |
| Trust-state substitution | SD-T13, SD-T21, SD-T42, SD-T47 |
| Recovery misuse | SD-T14, SD-T32, SD-T33, SD-T36, SD-T48 to SD-T50 |
| Malicious USB files | SD-T22 to SD-T27, SD-T43 to SD-T45 |
| Replay and duplicates | SD-T09, SD-T28, SD-T29 |
| Malformed canonical payloads | SD-T04, SD-T30, SD-T31 |
| Update tampering | SD-T16, SD-T37 to SD-T39, SD-T50 |
| Lost-device recovery | SD-T15, SD-T34 |
| Independent fingerprint verification | SD-T12, SD-T40, SD-T49 |

## R3.7 Remaining open decisions

| ID | Decision |
|---|---|
| OD-1 | Record D-45 and the D-38 amendment (wording in `signing-trust-architecture.md` §12) |
| OD-2 | The recovery rpId `sentinel-recovery.invalid`, or a real domain the operator controls (only if AuthenticationServices requires a verified domain and paid provisioning is accepted) |
| OD-3 | Whether to require a signature-counter-capable authenticator (counter > 0) |
| OD-4 | If F-3 fails: approve the libfido2 D-03 review and the one-time source fetch |
| OD-5 | The independent source for signer commit IDs (§R3.4, step 2) |
| OD-6 | The Touch ID timeout (60 s proposed) and the ±300 s clock skew |


---

**Recorded 2026-11-09:** the decision register (`docs/architecture-discovery-plan.md` §4) now holds:
- **D-45** (per-key roles);
- **D-46** (checkpoints, in the strengthened wording);
- **D-47** (the D-38 amendment);
- **OD-2 to OD-6** (§4.1).

Where this document says "proposed" for these, the register is authoritative. **The architecture is not frozen.**

**Freeze (2026-11-09):** the architecture is frozen as a design baseline (D-48). This design is part of the baseline. It is **not** implemented or hardware-validated, and production signing stays disabled.
