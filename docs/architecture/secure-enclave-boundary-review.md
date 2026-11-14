# SE-01: Secure Enclave key-boundary review

**Date:** 2026-11-09. **Scope:** whether Sentinel can ensure that only the intended signing component can use the enrolled Secure Enclave operator key, when an untrusted process (for example an AI agent) runs as the same macOS user.

**Status:** analysis only.
- No network access, no installs, and no code or decision changes.
- No key was created, rotated, deleted or used.
- **Production signing stays disabled. The architecture is not frozen.**

**Evidence labels:**
- **[V-SDK]:** verified from the local macOS SDK headers or Swift interfaces of the installed Xcode (`xcrun --show-sdk-path` → `/Applications/Xcode.app/.../MacOSX.sdk`). The header text is Apple's documentation shipped with the SDK.
- **[V-LOCAL]:** verified on this host by a read-only command, or in Sentinel's own source.
- **[A]:** an assumption from general platform knowledge, **not verified here**. Each needs an SE-H test (§6) before it is relied on.
- **[U]:** unknown; the local documentation doesn't settle it.

No claim below is a guarantee. Apple's online documentation was **not** consulted (no network).

---

## 1. Current design (as built)

| Aspect | Current state | Evidence |
|---|---|---|
| Key creation | CryptoKit `SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac)`, with `ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence])` | [V-LOCAL] `native/macos/se-helper/main.swift:108–119` |
| Keychain storage | **None.** The key is not a keychain item. The helper returns `key.dataRepresentation` (the "handle") to Sentinel | [V-LOCAL] `main.swift:119` |
| Handle storage | Base64 `handle_b64` in JSON metadata under the Sentinel state folder (`~/.local/state/sentinel/...` or `SENTINEL_HOME`), written by `KeyMetadataStore.save` | [V-LOCAL] `src/sentinel/keys/secure_enclave.py:106–121`, `paths.py:12–17` |
| Handle permissions | State folders are created owner-only; the operator's user, and every process running as that user, can read them | [V-LOCAL] `paths.ensure_private_dir` |
| Signing | `PrivateKey(dataRepresentation: handle, authenticationContext: ctx)`, then `ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: …)`, then `key.signature(for: message)` | [V-LOCAL] `main.swift:136–170` |
| Who may call it | The CryptoKit initialiser takes only the data and an optional `LAContext`. There is no caller-identity parameter | [V-SDK] `CryptoKit.swiftmodule/arm64e-apple-macos.swiftinterface:1213–1215` ("init(dataRepresentation: Data, authenticationContext: LAContext? = nil)") |
| What the handle is | The SDK says only "A data representation of the private key." **It doesn't say whether the representation is bound to the creating process, team or executable** | [V-SDK] `arm64e-apple-macos.swiftdoc` (string table); binding is **[U]** |
| User presence | `.userPresence` | [V-SDK] `SecAccessControl.h:51–53`: "User presence policy using biometry or Passcode. Biometry does not have to be available or enrolled." So the **device passcode is an accepted fallback** |
| Helper signature | Ad-hoc: `Signature=adhoc`, `TeamIdentifier=not set`, `Identifier=sentinel-se-helper-…` | [V-LOCAL] `codesign -dv` on the session-built helper |
| Signing identities on this host | One: "Apple Development: … (<certificate ID>)". **No Developer ID Application identity** | [V-LOCAL] `security find-identity -v -p codesigning` |
| Enrolled production key | None. `~/.local/state/sentinel` doesn't exist; H1–H3 used a throwaway `SENTINEL_HOME` | [V-LOCAL] |

**Consequence:**
- **Verified:** the API takes no caller identity.
- **Assumed [A], strongly suspected:** the Secure Enclave honours a `dataRepresentation` from any process running as the same user on the same device.

Under that assumption, any same-user program can load the handle, show **its own** `localizedReason`, and sign **any bytes** after one user-presence approval. The pinned helper hash is irrelevant to such a program. SE-H1 (§6) must confirm or refute this.

---

## 2. Threat model

**Asset:** the operator signature, which authorises trust-anchor actions (D-27, D-33): authorisation records, policy and allowlist changes, suppressions, accepted risks, reviews, and key rotation and revocation.

**Attacker:** an untrusted process running as the operator's macOS user, for example an AI coding agent with shell access. It can:
- **T-a:** read and write every file the user owns: the Sentinel state, the trust store, the handle, the venv, the helper binary if user-writable, and `~/Library/LaunchAgents`;
- **T-b:** run arbitrary code as the user: compile Swift or C, call `Security.framework`, CryptoKit and LocalAuthentication;
- **T-c:** run the genuine helper with arbitrary stdin;
- **T-d:** modify the Python engine in the venv;
- **T-e:** draw windows, including fake dialogs, and trigger prompts at chosen times;
- **T-f:** **possibly** drive the UI, if the user granted it Accessibility (TCC) permission [A].

**Out of scope:** root or a kernel compromise (D-32 refuses root anyway), physical access, a compromised Apple signing or notarisation service, and the operator deliberately approving a malicious payload.

**Required property (P):** an operator signature is produced only by the trusted signing component, **only** for a payload that the component itself displayed in full, and **only** after fresh user presence. **(P) fails today** if SE-H1 confirms §1.

---

## 3. Investigation answers

| # | Question | Answer | Basis |
|---|---|---|---|
| 1 | Current key creation, access control, storage, permissions, flow | See §1. The flags are `.privateKeyUsage + .userPresence`; there's no keychain item; the handle sits in the user-readable state folder | [V-LOCAL] |
| 2 | Can Keychain or Secure Enclave access control bind key use to a Developer ID-signed executable or a designated requirement? | **Not through `SecAccessControl`:** its flags are about user authentication (presence, biometry, passcode, companion, application password), with no code-identity flag [V-SDK `SecAccessControl.h:93–106`]. **Binding is possible through keychain access groups**, which are determined by the **entitlements** `application-identifier` and `keychain-access-groups`; on macOS they apply only to data-protection-keychain items (`kSecUseDataProtectionKeychain`) [V-SDK `SecItem.h:88, 201–217, 1033–1037`]. A Secure Enclave key can be a keychain item (`kSecAttrTokenIDSecureEnclave`, generated with `SecKeyGenerateKeyPair`/`SecKeyCreateRandomKey`) [V-SDK `SecItem.h:1088–1096`]. The binding is to **entitlements**, which the platform checks against the signing identity and provisioning [A]. It isn't to a designated requirement string | Mixed |
| 3 | Do access groups actually stop an arbitrary same-user process? | **For keychain lookups: by documented design, yes.** "Specifying this attribute in SecItemCopyMatching … limits the search to the specified access group (of which the calling application must be a member to obtain matching results)" [V-SDK `SecItem.h:209–213`]. Membership comes from entitlements that an unsigned or ad-hoc process can't legitimately claim [A: on macOS `keychain-access-groups` is a restricted entitlement needing a provisioning profile]. **Not verified:** that no other path exists, for example a persistent reference or a `SecKeyRef` exported another way. Hence SE-H2 and SE-H5 | [V-SDK] + [A] |
| 4 | Can an independently built helper, a modified helper or a direct Security.framework call use the key? | **Today:** likely yes, given the handle [A, SE-H1]. **With design A:** an independent or ad-hoc binary lacks the entitlement, so a modified helper loses its valid signature and (it's assumed) its entitlements; it should be refused [A, SE-H2, SE-H3]. A **genuine helper fed malicious stdin** can still sign, so the D-39 full-payload dialog is what protects that path | [A] |
| 5 | Does a separate signing service improve the boundary? | **Only marginally over A.** XPC can restrict peers by code-signing requirement (`xpc_connection_set_peer_code_signing_requirement`, macOS 12+: "requests that do not satisfy the requirement are dropped") [V-SDK `xpc/connection.h:772–803`]. But Sentinel's client is a Python interpreter, and a requirement on the interpreter admits any script. The service still needs A's key binding to keep the key private. Its gains are central policy (action allowlist, lifetime caps, rate limits), one trusted UI, and a service-owned log | [V-SDK] + reasoning |
| 6 | Do user presence, prompts and app identity stay meaningful? | **Presence:** it means a human authenticated, nothing more. With `.userPresence` the passcode is accepted [V-SDK], so a passcode-phishing fake dialog (T-e) is relevant. `.biometryCurrentSet` would require biometry and is invalidated by enrolment changes [V-SDK `SecAccessControl.h` constants], at the cost of locking out Macs without Touch ID. **Prompt text:** it is meaningful only when produced by the trusted component, which needs A plus D-39. **The identity shown in the dialog** (process name or icon): **[U]**, not relied on | Mixed |
| 7 | What happens when the helper is replaced, re-signed, updated or revoked? | **Today:** replacing it is irrelevant, because the attacker bypasses it. **Under A [A, needs SE-H3, SE-H4, SE-H8]:** replaced or ad-hoc re-signed means no entitlement, so the key is inaccessible; an update signed with the same team and access group keeps access; re-signing with another team loses access. **Revocation of the Developer ID certificate** affects Gatekeeper and launch policy; its effect on keychain access for already-installed binaries is **[U]**. **Sentinel's own pin** must move from a file SHA-256 to a code-signing requirement or CDHash, because Developer ID signatures are not reproducible byte for byte [A] | [A]/[U] |

---

## 4. Design comparison

### A. Entitled, signed helper; Secure Enclave key in the data-protection keychain, bound to an access group

- **Key:** `SecKeyCreateRandomKey` with `kSecAttrTokenID = SecureEnclave`, `kSecAttrIsPermanent = true`, `kSecUseDataProtectionKeychain = true`, and `kSecAttrAccessGroup = <TEAMID>.<sentinel-operator-group>`. Access control is `.privateKeyUsage` plus user presence (or `.biometryCurrentSet`, an operator decision).
- **No handle is stored on disk.** The helper looks the key up by tag inside its group.
- **Helper:** a Developer ID-signed, hardened-runtime, notarised executable inside a minimal `.app` bundle with an embedded provisioning profile granting `keychain-access-groups` [A: required on macOS for that entitlement]. It runs the D-39 parse, validate and full-display flow.

### B. Separate signing service

- A user-session LaunchAgent (the prompt needs the GUI session) built as in A, exposing a narrow XPC interface: `sign(canonical_payload) → signature | error`. It validates and renders as D-39, enforces the action allowlist, lifetime and rate limits, and keeps its own log.
- **The client check (a peer code-signing requirement) protects little, because the client is Python.**

### C. No Secure Enclave signing in V1

- **C1:** a FIDO2 authenticator (Ed25519, D-38 already allows it), or
- **C2:** a separate signing device or account that displays the payload, such as an offline second machine, a phone app, or a separate macOS user that receives payloads and returns signatures.

| Criterion | A: entitled helper plus access group | B: signing service | C1: FIDO2 key | C2: separate device or account |
|---|---|---|---|---|
| Attacker capabilities kept | T-a to T-f. Can call the genuine helper with any payload (T-c) | T-a to T-f. Can call the service with any payload; can remove or replace the LaunchAgent plist (T-a) | T-a to T-f. Can ask the authenticator to sign any bytes | T-a to T-f on the main account only |
| Security boundary | Keychain access-group membership (entitlements and signature) [A], plus fresh user presence in the Secure Enclave | The same as A, plus the service's policy layer | Physical authenticator plus touch | A second device or account plus the human transfer step |
| What macOS enforces | Access-group membership on keychain queries [V-SDK]; entitlement validity against the signature and profile [A]; the Secure Enclave's user-presence constraint [V-SDK flags] | A's enforcement, plus XPC peer requirements [V-SDK] (weak with a Python client) | Not macOS: the authenticator enforces a touch; there's **no on-device payload display** on typical keys [A] | Separate account: file and keychain isolation between users [A]; device: physical separation |
| Same-user resistance: using the key from own code | **Yes, if SE-H2 and SE-H5 pass** | Yes (as A) | Partial: the attacker can't extract the key, **but can get any payload signed with one touch** | Yes |
| Same-user resistance: misleading the operator about the payload | D-39 dialog (complete, trusted surface) [A: dialog text can't be altered by other processes] | Same as A, with policy limits on top | **No:** the payload isn't shown on the device | Strong, if the other side displays the payload |
| Fake-dialog passcode phishing | Present with `.userPresence`; removed with `.biometryCurrentSet` | Same | n/a | Reduced |
| Entitlements and certificates | Apple Developer Program membership, a Developer ID Application certificate, a provisioning profile with `keychain-access-groups` [A], hardened runtime, notarisation. **The host has only an Apple Development identity** [V-LOCAL] | All of A, plus a LaunchAgent install | None from Apple; a FIDO2 device | None, or a second device or account |
| Operational and distribution cost | High: paid membership, signing and notarisation in the release pipeline, an `.app` bundle, non-reproducible signatures (pin by requirement instead of hash), key loss when moving to a new team | Highest: A, plus a service lifecycle (install, upgrade, launchd), more code | Low to moderate: hardware per operator; a different library (`libfido2` or similar), which is a new dependency for D-03 review | High friction per approval |
| Hardware tests (§6) | SE-H1 to SE-H8, plus H1–H15 (D-39) | All of A, plus service tests (SE-H9 to SE-H11) | New FIDO2 test set; D-39-like display can't apply | New procedure tests |
| Residual risks | Operator approves without reading; unknown Developer ID revocation behaviour; the trust in the Apple signing chain; a compromised genuine binary on update; prompt-identity spoofing [U] | As A, plus the service as a new attack surface; plist replacement (denial of service only, if A holds) | Blind signing: **the payload isn't verifiable at the point of approval**; this fails the D-33 display rule | Transfer-channel integrity; usability may push operators to bypass it |
| Fits D-33, D-38 and the user's D-39 direction | **Yes**, if the tests pass | Yes | **No** (no display) | Yes, but it changes the D-38 mechanism |

---

## 5. Recommendation (for decision; nothing decided)

1. **Adopt design A as the V1 target.** It is the only option that satisfies all three: it keeps D-38's Secure Enclave mechanism, enforces the key boundary with a platform mechanism (access groups), and keeps D-39's complete display on a trusted path. **This is conditional on SE-H1 to SE-H8 passing.** If SE-H2 or SE-H5 shows that an unentitled process can still use the key, A fails and V1 must fall back to C2 or to keeping signing disabled.
2. **Don't build B in V1.** Its extra boundary is weak because the client is Python, and it doubles the operating cost. Reconsider if policy enforcement outside the engine becomes a requirement.
3. **Reject C1 as the sole V1 mechanism:** blind signing contradicts D-33's display rule.
4. **Decisions needed from the operator:**
   - (a) obtaining an Apple Developer Program membership and a Developer ID Application certificate. The existing Apple Development identity isn't for distribution [A];
   - (b) `.userPresence`, which accepts the passcode, versus `.biometryCurrentSet`, which needs Touch ID and invalidates the key on enrolment changes;
   - (c) replacing the helper's file-hash pin (`se_helper_sha256`) with a code-signing-requirement pin;
   - (d) running SE-H1 first, with a throwaway key, to confirm the current vulnerability before investing in A.
5. **Until then:** production signing stays disabled. D-38's activation record must cite SE-01 and the SE-H results.

---

## 6. Hardware tests (proposed; none run)

All tests use a **throwaway** key and `SENTINEL_HOME`, and are run by the operator at the Mac. None uses the production trust store.

| ID | Design | Test | Expected (if the assumption holds) |
|---|---|---|---|
| SE-H1 | Current | An **unrelated**, separately built ad-hoc program loads the stored `handle_b64` and signs arbitrary bytes with a custom `localizedReason` | **Succeeds** after presence. This confirms the vulnerability |
| SE-H2 | A | An unentitled or ad-hoc program queries the group's key (`SecItemCopyMatching` with that access group, and without it) | No result; no usable `SecKeyRef` |
| SE-H3 | A | The helper is copied, modified and re-signed ad hoc, then with a different team | Key inaccessible in both cases |
| SE-H4 | A | A genuine helper update signed by the same team with the same group | Key still accessible; old signatures still verify |
| SE-H5 | A | Persistent-reference replay (`kSecReturnPersistentRef` obtained by the genuine helper) used from another binary | Refused |
| SE-H6 | A | `DYLD_INSERT_LIBRARIES` or a debugger attach to the hardened-runtime helper | Blocked (hardened runtime, library validation) |
| SE-H7 | A | `.biometryCurrentSet` variant: passcode fallback absent; adding a fingerprint invalidates the key | As stated (if that option is chosen) |
| SE-H8 | A | Helper deleted; Developer ID certificate revoked (simulated where possible) | Records the actual behaviour: **unknown today** |
| SE-H9 to SE-H11 | B | XPC peer-requirement refusal; replaced LaunchAgent plist; service crash during a prompt | Only if B is pursued |

---

## 7. Verified vs. assumed: summary

**Verified [V-SDK, V-LOCAL]:**
- the current key isn't in the keychain;
- the handle sits in the user-readable state folder;
- the CryptoKit API takes no caller identity;
- `SecAccessControl` has no code-identity flag;
- `.userPresence` accepts the passcode;
- access-group membership is entitlement-based and limits keychain queries;
- macOS access groups need the data-protection keychain;
- Secure Enclave keys can be keychain items;
- XPC peer code-signing requirements exist (macOS 12+);
- the helper is ad-hoc signed;
- the host has no Developer ID identity.

**Assumed [A]:**
- a `dataRepresentation` is usable by any same-user process (SE-H1);
- `keychain-access-groups` needs a provisioning profile and an app bundle on macOS;
- unentitled processes can't obtain the key by any route (SE-H2, SE-H5);
- the dialog text can't be altered by other processes;
- hardened runtime blocks injection (SE-H6).

**Unknown [U]:**
- whether `dataRepresentation` is bound to the creating code;
- the identity shown in the LocalAuthentication dialog;
- the effect of Developer ID revocation on keychain access;
- the binding semantics of `LARight`/`LAPersistedRight`/`LAPrivateKey` (macOS 13+, headers present but undocumented on this point).

---

**Decision requested from the operator:**
1. Choose A (recommended), B or C.
2. Choose `.userPresence` or `.biometryCurrentSet`.
3. Decide whether to run SE-H1 first.
4. Approve the Developer Program membership and certificate step.

No work proceeds until you decide.
