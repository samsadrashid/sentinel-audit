# SE-H1 evidence and Design A feasibility (SE-02)

**Date:** 2026-11-09. **Follows:** `secure-enclave-boundary-review.md` (SE-01).

**Operator decisions in force:**
- Design A is approved conditionally;
- `.biometryCurrentSet`, with no passcode fallback;
- SE-H1 first;
- no Apple Developer purchase.

**Constraints kept:**
- no production key created, migrated, rotated or deleted;
- no production signing, no network access, no installs;
- no change to the decision register;
- Git staging preserved;
- **the architecture is not frozen.**

Raw output is in `docs/m1/evidence/se-h1-raw.txt`. The test kit is `native/macos/se-boundary-tests/` (`run_se_h1.sh`, `attacker.swift`, `dp_probe.swift`). It is test-only and never used by Sentinel.

**Verdicts:**
- **Current design (a CryptoKit handle on disk): SE-H1 FAIL.** The same-user isolation doesn't exist.
- **Design A, same-user isolation: INCONCLUSIVE.** The preconditions were verified, but the decisive test couldn't be run without a provisioned, entitled helper.

---

## 1. Environment

| Item | Value (exact) |
|---|---|
| macOS | 26.6.2 (build 25G83) |
| Hardware | Mac15,6, Apple M3 Pro, arm64 |
| Toolchain | Apple Swift 6.4.2 (swiftlang-6.4.2.1.9, clang-2100.4.1.1), target arm64-apple-macosx26.0 |
| Genuine helper | Built by `native/macos/se-helper/build.sh`; ad-hoc signature, no TeamIdentifier, no entitlements |
| Attacker program | `attacker.swift`, built separately with `swiftc`. Ad-hoc, `Identifier=attacker-55554944f335c28a…`, `TeamIdentifier=not set`, **no entitlements**. A different code identity from the helper |
| State | Disposable directory `/tmp/sentinel-se-h1.jJKPNH` (mode 0700). `HOME` and `SENTINEL_HOME` pointed inside it for every step after the build. No Sentinel state or operator key exists on this host (`~/.local/state/sentinel` absent) |

## 2. SE-H1: can an independent same-user program use a copied key handle?

**Procedure:**
1. The genuine helper ran `create`, making a **throwaway** key: CryptoKit `SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl:)` with `[.privateKeyUsage, .userPresence]` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. No prompt appeared.
2. The script copied the key's `handle_b64` to a file.
3. The independent attacker program then called:
   - `SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle, authenticationContext: ctx)`;
   - `ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "approve a Sentinel operator action: suppress 1 low-severity test finding (ATTACKER TEXT, SE-H1)")`;
   - `key.signature(for: "SE-H1 ATTACKER-CHOSEN PAYLOAD E57B87D8-…")`.

**Result:**
- **Handle loaded:** yes. The CryptoKit initialiser accepted a handle created by a different program.
- **Authentication:** `evaluatePolicy` returned `ok = true`, `error = nil`. The operator authenticated the attacker's dialog.
- **Signature:** `signed: true`. The returned public key equals the helper-created throwaway key byte for byte.
- **Independent verification:** in Sentinel's venv, `cryptography` ECDSA P-256/SHA-256 verification **succeeds** over the attacker-chosen message. A control (the same signature over the message plus one byte) **fails**.

**Conclusion (verified):** under the current design, **any same-user program that can read the handle can show its own dialog text and get a valid operator-key signature over bytes of its choosing**. The helper hash pin, the helper's own dialog and Sentinel's checks are all bypassed. **SE-H1: FAIL.**

**Prompt observations:**

| Prompt | Status |
|---|---|
| Prompt 1, with attacker-supplied `localizedReason` | Authenticated by the operator. **The operator's description of the dialog text and the app name or icon shown was not entered** (the script stopped at that question). **It is not recorded and must not be assumed.** The API accepted the attacker's text (`evaluate_ok: true`). Whether the dialog displayed it verbatim, and which process identity it showed, is **open (U-1)** |
| Prompt 2, the system's default dialog with no app text | **Not run.** The script was stopped (Ctrl-C) before this step. **Open (U-2)** |

**Cleanup (verified):**
- The trap printed `cleanup: removed /tmp/sentinel-se-h1.jJKPNH`.
- `ls -d /tmp/sentinel-se-h1.*` finds nothing.
- The throwaway key existed only as a `dataRepresentation` blob in that directory; the helper creates no keychain item. With the blob deleted, no handle to it remains on disk.
- **Limitation:** the Secure Enclave's internal handling of an orphaned key isn't observable from userspace.

## 3. Design A feasibility probes (Phase 2)

Each probe ran in a second disposable directory, `/tmp/sentinel-se01-probe.6W2QTo`, which was removed afterwards (verified). Each probe tries to create a Secure Enclave key as a data-protection keychain item:
- `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, `kSecUseDataProtectionKeychain = true`;
- `kSecAttrIsPermanent = true` and `kSecAttrAccessGroup = "SE01TEST.org.sentinel.se01"`;
- access control `[.privateKeyUsage, .biometryCurrentSet]`;
- then a `SecItemCopyMatching` lookup in that group.

Creation needs no presence prompt, and none appeared.

| Probe | Code identity | Result (exact) |
|---|---|---|
| P1 | Ad-hoc, no entitlements | `created: false`, `OSStatus -34018` "failed to add key to keychain: <SecKeyRef:('com.apple.setoken')>". The lookup returned `-34018` |
| P2 | Ad-hoc, **self-claimed** `keychain-access-groups = [SE01TEST.org.sentinel.se01]`, no provisioning profile | **Killed at launch, exit 137 (SIGKILL)**, no output |

**Interpretation:**
- **Verified:** an unentitled program can neither create nor look up a data-protection keychain Secure Enclave key in an access group (`-34018`; read with SDK `SecItem.h:201–217`).
- **Verified:** claiming the entitlement ad hoc doesn't work; the system kills the process.
- **Inferred [A]:** the kill comes from macOS code-signing enforcement (AMFI) of a restricted entitlement without a matching provisioning profile. The unified log query returned nothing within the time window, so the enforcing component isn't confirmed.

## 4. Phase 2 answers

| # | Question | Answer | Status |
|---|---|---|---|
| 1 | Key creation and storage in the intended keychain | Unentitled creation in the data-protection keychain fails (P1). Creation by an entitled helper **wasn't possible to test** (no provisioned identity) | Partly verified |
| 2 | Exact access-group entitlement requirements | `keychain-access-groups` (or `application-identifier`) decides membership [SDK]. Self-claiming it without a profile is fatal (P2). **The exact profile requirement** (Developer ID versus development profile, bundle versus bare executable) **wasn't verified** | Partly verified; rest [A] |
| 3 | Does the entitlement restrict access to the intended team or app? | Membership is by group string; group strings carry the team prefix and are granted through signed profiles [A]. **Not tested:** a second team claiming the same string | INCONCLUSIVE |
| 4 | Can an independent same-user executable access or invoke the key after Design A? | **Unentitled: no** (P1: `-34018`, before any key or prompt). **Entitled by another team, or the genuine team's other binaries: not tested.** **Persistent-reference replay, and injection into the genuine helper: not tested** | INCONCLUSIVE |
| 5 | Can XPC peer validation restrict helper clients? | The API exists (`xpc_connection_set_peer_code_signing_requirement`, macOS 12+) [SDK]. **Not exercised.** Sentinel's caller is Python, so a client requirement doesn't identify Sentinel code | Not tested; limited value |
| 6 | Can the genuine helper be invoked with any payload and still show exactly what it signs? | **Yes, it can be invoked with any payload:** an entitled helper is still a same-user executable that anyone can run (as the current helper is). The full-payload display (D-39) is therefore **mandatory**, because the helper's own validation and display is the only protection on that path | By design; D-39 not implemented |
| 7 | Does the dialog identify the genuine helper, and can caller text replace it? | SE-H1 shows that **any process can supply its own `localizedReason`** and it is accepted. Under A, an attacker can't use the key, so it can still show a fake dialog but gets no signature. Whether the dialog names the requesting process is **U-1** (not recorded) | Partly verified |
| 8 | Replacement, re-signing, certificate revocation, entitlement change | **Ad-hoc re-signing with a claimed entitlement: killed** (P2). An unentitled replacement: no keychain access (P1). **Same-team updates, other-team re-signing, Developer ID revocation and entitlement removal: not tested** | Partly verified |

**What this shows:** A removes the bypass that SE-H1 demonstrated (any program using a copied handle). Its enforcement point, entitlement-gated keychain access, **does reject the programs tested here**. **It doesn't, by itself, solve the same-user threat:**
- (i) the genuine helper can still be driven with malicious payloads, so D-39 is required;
- (ii) a fake dialog can still be drawn, though with biometry-only access it yields no passcode and no signature;
- (iii) other-team, injection and persistent-reference paths are untested.

## 5. Revised Design A (Phase 3), for review; not implemented

**1. Key creation and enrolment**
- Only the entitled helper creates the key: `SecKeyCreateRandomKey` with the Secure Enclave token, `kSecUseDataProtectionKeychain`, `kSecAttrIsPermanent`, `kSecAttrAccessGroup = <TEAMID>.org.sentinel.operator`, a random `kSecAttrApplicationTag`, and access control `[.privateKeyUsage, .biometryCurrentSet]`.
- **There is no `dataRepresentation` export and nothing usable on disk.** Sentinel stores only the public key, the key ID and the tag.
- Enrolment stays as today (self-signed `key.rotate`, D-27), now signed through the D-39 flow.
- If biometry is unavailable or not enrolled, the helper refuses with `biometry_unavailable`, and there's no fallback.

**2. Keychain access control:** the access group restricts *which programs can use the key*, and `.biometryCurrentSet` restricts *who must approve each use*. Enrolment changes (an added or removed finger) invalidate the key; recovery is rotation by a second enrolled key, or re-enrolment through the D-27 procedure.

**3. Helper identity verification**
- **macOS enforces it:** only binaries whose signature grants the group can access the key (P1 and P2 show the rejection side).
- **Sentinel pins** the helper by **code-signing requirement** (team ID plus signing identifier plus Developer ID anchor), checked with `SecStaticCodeCheckValidity` before each run, instead of a file SHA-256, because Developer ID signatures aren't reproducible [A].
- Hardened runtime with library validation, and no `get-task-allow`.

**4. Approval payload validation:** D-39, unchanged.
- The helper reads stdin, checks it is canonical (re-encoding equals the input), checks the exact §11.3 field set, the context and action match, and that the `key_id` is its own.
- Printable-ASCII display safety, and a size cap measured by H15.
- **No caller-provided display string is accepted, ever.**

**5. Trusted display and biometric confirmation**
- The helper builds the `localizedReason` itself from the validated bytes: the full payload, every field, with no truncation. It refuses when the payload can't be shown in full on the running macOS version (H15 table).
- It then calls `SecKeyCreateSignature` with an `LAContext` whose evaluation used `.deviceOwnerAuthenticationWithBiometrics`, so the passcode is never accepted.

**6. Signing and verification**
- The helper signs exactly the stdin bytes (ECDSA P-256/SHA-256), self-verifies, and returns the signature, the SHA-256 of the message and the key ID.
- Sentinel verifies against the trust-store public key (existing code).

**7. Revocation and helper updates**
- **Operator key revocation:** `key.revoke` (D-36, D-37). The helper then deletes the keychain item when asked through an authenticated local operation, and the trust store marks the key revoked (existing).
- **Helper update:** a new build from the same team keeps group access [A, SE-H4]. Sentinel's requirement pin is unchanged unless the identifier changes.
- **Team change or a compromised certificate:** the key becomes inaccessible [A], so the procedure is enrolling a new key and revoking the old one.
- **Developer ID revocation:** behaviour unknown (U-3); it must be tested before activation.

## 6. Limitations and open questions

| ID | Open question | How to close |
|---|---|---|
| U-1 | The exact text and process identity in the dialog when a caller supplies `localizedReason`; the operator's observation wasn't recorded | Operator re-runs prompt 1 with a throwaway key and records it, or describes it from memory |
| U-2 | The default system dialog when no reason is supplied | Re-run prompt 2 |
| U-3 | Effect of Developer ID revocation on keychain access | Needs a provisioned identity |
| U-4 | Whether a different team can claim the same group string | Needs two teams (not feasible without membership); rely on Apple documentation once online review is allowed |
| U-5 | Persistent-reference replay and injection into the genuine helper | SE-H5 and SE-H6 with an entitled build |
| U-6 | The profile requirement for a bare command-line tool versus an `.app` bundle | First entitled build |
| U-7 | Which component kills a self-entitled binary (P2) | A log capture with a wider window |

**Feasibility verdict for Design A same-user isolation: INCONCLUSIVE.**
- **For A:** verified rejection of unentitled programs (P1) and of self-claimed entitlements (P2).
- **Against certainty:** no entitled build could be made without a provisioned identity, so U-3 to U-6 remain.
- **Firm in either case:**
  - **the current design FAILS (SE-H1)**;
  - D-39 is mandatory under A;
  - production signing stays disabled.

**Next steps, each needing operator approval:**
- (a) record or re-run the U-1 and U-2 observations with a throwaway key;
- (b) decide whether to obtain a provisioned identity to run SE-H2 to SE-H8. The Apple Development identity on this host might allow a development-profile test without a purchase; that is **unverified** and would need network access to Apple.

---

# Round 2 (2026-11-09): local signing feasibility with the existing Apple Development identity

**Operator direction:** the handle-on-disk design is **rejected** (SE-H1). Design A is preferred but INCONCLUSIVE.

**Constraints kept:**
- no network access and no purchases;
- disposable state only (`/tmp/sentinel-se02.s7bzlc`, removed and verified; 0 keychain items left matching the test tag);
- no production signing-code or decision changes.

## R2.1 What exists locally (verified)

| Item | Evidence |
|---|---|
| Signing identity | `Apple Development: <owner Apple ID, redacted> (<certificate ID>)`. Certificate subject `OU=<TEAM-ID>` (team ID), `O=<owner name>`, issuer Apple WWDR CA G3, valid 2026-06-10 to 2027-06-10 |
| Provisioning profiles | **None** on this host (`~/Library/MobileDevice/Provisioning Profiles` absent; none in Xcode `UserData` or `DerivedData`) |
| Whether the team is a paid team or a free Personal Team | **Unknown offline** |
| **Use of the identity by a same-user process** | **`codesign -s "<identity>"` succeeded three times from this agent session with no keychain prompt** (`--timestamp=none`). The private key's access control lets `codesign` use it without asking |

## R2.2 Development-signed probes (verified)

All three probes use the same `dp_probe`: create a Secure Enclave key in the data-protection keychain with `kSecAttrAccessGroup = <TEAM-ID>.org.sentinel.se02` and `[.privateKeyUsage, .biometryCurrentSet]`, then look it up.

| Probe | Signature and entitlements | Result |
|---|---|---|
| D1 | Team-signed (`TeamIdentifier=<TEAM-ID>`), no entitlements | `-34018` on create and on lookup |
| D2 | Team-signed, plus `keychain-access-groups = [<TEAM-ID>.org.sentinel.se02]`, no profile | **Killed at launch, exit 137** |
| D3 | Team-signed, plus `com.apple.application-identifier`, `com.apple.developer.team-identifier` and `keychain-access-groups` (consistent with the team), no profile | **Killed at launch, exit 137** |

**Conclusion:**
- A valid team signature **alone** grants no keychain-group access (D1).
- Claiming the entitlements without a **provisioning profile** is fatal even when the claims are consistent with the signing team (D2, D3).
- **A provisioning profile authorising the group is the gate.**
- **No profile can be created offline.** Obtaining one, even for a free Personal Team through Xcode, needs signing in to Apple (network). Whether a free team may use keychain access groups on macOS is **unverified**.

## R2.3 Critical finding: the same-user attacker can sign as the team

The team identity's private key sits in the operator's login keychain and can be used by `codesign` without a prompt (R2.1). So a same-user attacker can:
1. build its own program;
2. sign it with the operator's team identity;
3. copy the genuine helper's embedded provisioning profile (a public, signed file), if the profile's app ID isn't tied to something the attacker can't reproduce;
4. give its program the same bundle identifier and entitlements.

The system's checks (signature valid, team matches the profile, entitlements allowed by the profile) would then pass for the **attacker's** binary **[A, inferred from R2.2 plus how profiles bind team, app ID and entitlements; not testable without a profile]**.

**Consequence:** Design A's boundary holds **only if the signing identity's private key isn't usable by the operator's user account on the signing host.** Possible ways to arrange that:
- signing off-host, for example on a separate machine or CI with the key in a hardware token;
- removing the identity from the login keychain after the build;
- at minimum, restricting the key's access control to always prompt. A prompt alone is weak, because the agent can time it.

Developer ID has the same requirement. **Developer ID signing and access groups alone do not solve the same-user threat** (confirming the operator's caution).

## R2.4 Genuine helper with arbitrary payloads (task 7)

**Current helper (rejected design; code evidence):**
- `main.swift:136–170` reads stdin and checks only that it isn't empty and is within the size limit. **It doesn't parse or validate the payload.**
- It signs any bytes after presence, and its dialog shows a hash only.
- **So yes: it can be induced to sign arbitrary payloads, and its prompt is not informative.**

No prompt test was needed. The code path has no validation, so there's nothing a live test would add, and a live test would require another presence approval.

**Under Design A with D-39:** the same entitled helper can still be run by anyone with any stdin. The protections are then:
- (a) canonical and schema validation, with refusal before any prompt;
- (b) a complete, helper-built rendering;
- (c) biometry.

What remains is the operator approving a correctly displayed malicious payload. **It can't be tested until D-39 is implemented;** see matrix rows T-10 to T-13.

## R2.5 U-1 to U-7 status, plus new U-8

| ID | Question | Status | Evidence or what's missing |
|---|---|---|---|
| U-1 | Dialog text and identity when the caller supplies `localizedReason` | **Unresolved** | The API accepted attacker text (SE-H1 `evaluate_ok: true`); the operator's observation wasn't recorded |
| U-2 | The default dialog with no reason supplied | **Unresolved** | Not run |
| U-3 | Effect of Developer ID revocation | **Unresolved; needs paid infrastructure** | Needs a Developer ID certificate |
| U-4 | Whether another team can claim the same group | **Partly resolved** | Locally, the profile is the gate (D2, D3). A cross-team test needs a second provisioned team |
| U-5 | Persistent-reference replay; injection into the helper | **Unresolved; needs a profile** | Needs an entitled build |
| U-6 | Profile requirement for a bare tool versus a bundle | **Partly resolved** | A profile is required (D2, D3). Whether a bare executable can carry one, versus needing an `.app` bundle, isn't verified |
| U-7 | Which component kills self-entitled binaries | **Unresolved** | Exit 137 at launch; the unified log (including `--info --debug`) shows nothing to this user |
| **U-8 (new)** | Can a same-user process use the signing identity? | **Resolved: yes** | R2.1: three non-interactive `codesign` runs |

## R2.6 Test matrix

| ID | Test | Expected (Design A) | Needs | Status |
|---|---|---|---|---|
| T-01 | Copied handle used by an independent program (SE-H1) | n/a: no handle on disk under A | local | **Done: FAIL for the old design** |
| T-02 | Unentitled ad-hoc program, create or look up in the group | `-34018` | local | **Done: as expected** (P1) |
| T-03 | Ad-hoc program with self-claimed group | killed | local | **Done: killed** (P2) |
| T-04 | Team-signed, no entitlements | `-34018` | local | **Done** (D1) |
| T-05 | Team-signed, claims without a profile | killed | local | **Done** (D2, D3) |
| T-06 | Genuine provisioned helper creates a `.biometryCurrentSet` key in the group; no handle on disk | created; signing needs Touch ID; the passcode is refused | **profile** (development profile; network sign-in; possibly a free team [U]) | Blocked |
| T-07 | **Decisive:** an independently built attacker, signed by the **same team** (using the identity in the login keychain), with the copied profile, the same bundle ID and entitlements, tries to look up and use the key | **Expected to SUCCEED** if the identity is usable (R2.3), which proves the boundary needs off-host signing | profile | Blocked |
| T-08 | T-07 repeated with the identity removed from the host (signing off-host) | Attacker can't produce a valid team signature, so access is denied | profile + off-host signing | Blocked |
| T-09 | Same team, a different app ID or profile without the group | `-34018` or not found | profile | Blocked |
| T-10 | Genuine helper fed non-canonical, extra-field or unknown-action payloads | Refused before the prompt | D-39 implementation | Blocked (not implemented) |
| T-11 | Genuine helper fed a valid but malicious payload | Full fields shown in the dialog; the operator must cancel | D-39 + profile | Blocked |
| T-12 | Payload too large or non-ASCII | Refused before the prompt | D-39 | Blocked |
| T-13 | Display-limit measurement per macOS version (H15) | Table recorded | D-39 + hardware | Blocked |
| T-14 | `DYLD_INSERT_LIBRARIES` or a debugger attach to the hardened helper | Blocked | profile (hardened, entitled build) | Blocked |
| T-15 | Persistent-reference replay from another binary | Refused | profile | Blocked |
| T-16 | Biometry enrolment change | Key invalidated; signing fails closed | profile + hardware | Blocked |
| T-17 | Helper update by the same team (new build, same group) | Key still usable | profile | Blocked |
| T-18 | Developer ID certificate revocation | Record the actual behaviour | **Developer ID (paid)** | Blocked |
| T-19 | Notarised distribution build launches under Gatekeeper | Launches; key usable | **Developer ID + notarisation (paid, network)** | Blocked |

**Can be proven locally now (done):** T-01 to T-05, U-8.

**Needs a provisioning profile** (network sign-in; free versus paid team unknown): T-06, T-07, T-09, T-14 to T-17.

**Needs D-39 implemented:** T-10 to T-13.

**Needs paid Developer ID or notarisation:** T-18, T-19, and any distribution of the helper to other machines.

## R2.7 Key revocation, helper update and certificate revocation (design)

- **Operator key revocation:** a signed `key.revoke` (D-36, D-37). The trust store marks the key revoked, so verification refuses its signatures immediately. The helper deletes its keychain item on an authenticated revoke operation. Deleting the item is housekeeping, not the control.
- **Helper update:** a same-team build with the same app ID and group keeps key access [A, T-17]. Sentinel pins the helper by **code-signing requirement** (anchor, team ID and identifier) checked with `SecStaticCodeCheckValidity` before each run, not by file hash.
- **Signing-certificate revocation or expiry:** behaviour is unknown (U-3, T-18). The operating rule is to **assume the key can become unusable**. Keep a second enrolled operator key (rotation path, D-27), and treat any certificate compromise as requiring enrolling a new key under a new group and revoking the old key.
- **Entitlement or profile change:** removing the group from the profile is expected to cut access (T-09).

## R2.8 Recommendation and remaining blockers

**Verdict, Design A same-user isolation: still INCONCLUSIVE**, with one new **negative** finding.
- **Verified:** the system gates keychain-group access on a provisioning profile, and rejects unentitled, self-entitled and team-signed-without-profile binaries.
- **Verified (U-8):** a same-user process can sign code as the operator's team without a prompt. That **is expected to defeat** Design A's code-identity boundary on this host (T-07), unless the signing key is removed from the operator's user account and signing happens off-host.

**Recommendation:**
1. Keep Design A as the target, **amended**:
   - the code-signing private key must **never** be usable by the operator's macOS user on the operator host (sign off-host or in a separate account, and don't keep the identity in the login keychain);
   - the helper is pinned by code-signing requirement;
   - D-39 is mandatory;
   - `.biometryCurrentSet` only.
2. **Next step (needs separate approval):** a one-time network sign-in in Xcode to see whether the existing team (free or paid) can produce a **development** provisioning profile with a keychain access group for a minimal `.app` bundle on macOS. If it can, run T-06, T-07 (expected to succeed, which shows the risk), T-08 (expected to fail, which shows the mitigation), T-09 and T-14 to T-17 **without buying anything**.
3. Paid Developer ID is needed only for distribution and for T-18 and T-19, which can wait until release planning.

**Remaining blockers before any implementation decision:**
- U-1 and U-2 (operator observations);
- the profile-backed tests above;
- D-39 design approval (round 2, Part 2);
- the decision on off-host signing.

**Production signing stays disabled. The architecture is NOT frozen.**

---

# Round 3 assessment (2026-11-09, SE-02)

- **U-8 (resolved, negative):** the Apple Development identity can be used by `codesign` from a same-user agent session without a prompt. An agent can therefore produce binaries signed as the operator's team.
- **Revised Design A assessment:** **not approved for implementation** (operator, 2026-11-09). Design A's code-identity boundary holds only if:
  - (1) no code-signing credential usable by the operator's user exists on the approval Mac;
  - (2) the off-host signer signs only release-authorised builds, which the agent can't trigger through repository or CI credentials it holds;
  - (3) the agent never obtains root, which is a concern because the daily account is an administrator [V] and the admin password could be phished by a fake dialog.
- **Successor analysis:** `docs/architecture/signing-trust-architecture.md` compares off-host signing (A), a separate account (B) and a separate signing device (C). It recommends **C, a dedicated second Mac**, for review.
- **Unchanged:**
  - SE-H1 FAIL (the handle-on-disk design is rejected);
  - D-39 is mandatory in any design;
  - `.biometryCurrentSet` only;
  - production signing stays disabled.
