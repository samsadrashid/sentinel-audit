# SE-02: signing trust architecture review

**Date:** 2026-11-09. **Inputs:**
- `secure-enclave-boundary-review.md` (SE-01);
- `secure-enclave-design-a-feasibility.md` (SE-H1 and round 2, including U-8);
- `discovery.md` §9, §11.2 and §13.7;
- D-27, D-33, D-34 and D-38.

**Status:** analysis only.
- No implementation, no key creation, no purchase, no network access, no decision-register change.
- Production signing stays disabled. **The architecture is not frozen.**

**Labels:**
- **[V]:** verified on this host (commands listed in §1.3) or in earlier SE evidence;
- **[A]:** an assumption from platform knowledge, not verified here;
- **[U]:** unknown.

---

## 1. Threat model and trust boundaries

### 1.1 What must be protected

**Asset:** the operator signature over a canonical approval payload (D-33), and with it every trust-anchor action:
- authorisation records;
- policy changes;
- suppressions, accepted risks and reviews;
- key rotation and revocation.

**Required property (P):** a valid operator signature exists **only** for a payload that:
- (1) the operator saw **completely** on a display the agent can't control;
- (2) the operator explicitly approved with fresh **biometric** presence;
- (3) was signed by a key the agent can't use in any other way.

### 1.2 The agent (as stated by the operator)

The agent (Ag) can:
- **Ag-1:** run arbitrary code as the logged-in user (here the daily account);
- **Ag-2:** read and write every file that user can;
- **Ag-3:** use every command-line tool and API available to that user;
- **Ag-4:** **sign executables with credentials available to that user.** Verified for the Apple Development identity (U-8);
- **Ag-5:** draw fake dialogs and fake terminals;
- **Ag-6:** run the genuine helper with arbitrary input.

**Not assumed:** root, kernel access, or physical access. Where an architecture's strength depends on that, it is said so explicitly.

### 1.3 Host facts relevant to the boundaries [V]

| Fact | Evidence |
|---|---|
| The daily account **is an administrator** (`admin` group, together with root and a second admin account) | `id -Gn`, `dscl . -read /Groups/admin` |
| A second, separate admin account exists | `dscl . -list /Users UniqueID` |
| `sudo` needs a password (no cached credential); Touch ID for sudo (`pam_tid`) is **not** configured; `pam_smartcard` is sufficient | `sudo -n true` → "a password is required"; `/etc/pam.d/sudo`, `sudo_local` |
| FileVault on; SIP enabled | `fdesetup status`, `csrutil status` |
| The Apple Development identity is usable by `codesign` with no prompt | U-8 (round 2) |

**Why the admin status matters [A, standard macOS behaviour]:** an agent running as an admin user can't become root without the password. But it can **ask for** the password with a convincing fake dialog (Ag-5), or wait for the operator to type it into a terminal it watches. Once it has the password it has root, and root defeats every same-machine boundary (B in particular, and A's install integrity). **Every same-machine design therefore rests on the operator never typing the admin password where the agent can capture it.** A standard (non-admin) daily account narrows this risk.

### 1.4 Trust boundaries

| ID | Boundary | Enforced by |
|---|---|---|
| TB-1 | Operator's user account ↔ other local accounts | POSIX permissions and per-user keychains [A]; void if Ag gets root |
| TB-2 | Host ↔ a separate physical device | Physical separation and a narrow transfer channel |
| TB-3 | Code-signing identity ↔ the approval host | Where the signing private key lives |
| TB-4 | Secure Enclave ↔ the OS | Hardware; keys are non-exportable [V-SDK, SE-01] |
| TB-5 | System authentication dialog ↔ app windows | The OS. The dialog's *text* is caller-supplied (SE-H1); only its *biometric result* is trustworthy |

---

## 2. Architectures

### A. Off-host code signing (Design A with the signing key removed from the approval Mac)

- The helper is code-signed **elsewhere**: a separate build machine, or CI with the key in a hardware security module or token.
- The approval Mac holds **no** usable code-signing private key (the Apple Development identity is removed from the login keychain).
- The operator key is a Secure Enclave key in the data-protection keychain, in an access group that only the signed helper's profile grants (`.biometryCurrentSet`).
- The helper does D-39 validation and full display.

### B. Separate macOS account

- A dedicated `sentinel-signer` account (standard, non-admin) owns the operator key and the helper.
- The handle-on-disk design would be acceptable **inside** that account, because the boundary is the account, not code identity.
- The operator switches to that account (fast user switching or login window) to approve. The signer UI reads a payload the daily account dropped into a shared inbox, validates it, displays it fully, signs with biometry, and writes the signature to an outbox.

### C. Separate trusted signing device

- A **dedicated device** runs only the signer: a second Mac with no agents, or an iPhone or iPad app.
- Payloads are moved by a narrow, data-only channel: a QR code shown on the host and scanned by the device, or a file on removable media. The signature travels back the same way.
- The device validates the canonical payload, **displays all of it on its own screen**, requires biometry, and signs with its own Secure Enclave key.
- It refuses non-canonical or unknown actions, and it never signs arbitrary bytes.

### 2.1 Comparison

| Criterion | A: off-host code signing | B: separate account | C: separate device |
|---|---|---|---|
| Where the operator key lives | Approval Mac's Secure Enclave, access-group bound | Approval Mac's Secure Enclave, in the signer account | The device's Secure Enclave |
| What stops Ag using the key | Keychain group gating on a provisioning-profile entitlement [V: gating rejects unentitled, self-entitled and team-signed-without-profile, round 2] **plus** Ag being unable to produce a team signature (TB-3) [A] | Per-user files and keychain (TB-1) [A] | Physical separation (TB-2) |
| Ag signing its own entitled binary | Blocked only if no team credential is reachable from the Mac, including the CI credentials the operator's account holds (§3, A-3) | Irrelevant: the key isn't code-identity-bound | Irrelevant |
| Ag invoking the genuine signer with a malicious payload | **Possible.** Protection: D-39 full display plus biometry; the operator must read it | Possible (it writes to the inbox); protection as A, but shown in the signer account | Possible (it shows a QR or file); protection: the **device's** display |
| Ag forging the display | Dialog text comes from the helper itself (D-39); a fake dialog yields no signature. Biometry-only avoids password capture | The signer UI runs in another session; Ag can't draw into it [A], though it can fake a "please switch user" message | Ag can't reach the device's screen |
| Dependence on Ag not getting root | **High:** root can tamper with the helper install and keychain policy [A] | **High:** root reads the signer account | **Low:** the device is separate |
| Needs Apple paid infrastructure | Development profile (free tier possibility unverified); Developer ID for distribution | No | Second Mac: no. iOS app: development provisioning (free profiles expire after a short period [A]) or paid for durable install |
| Fits D-38 | Yes (Secure Enclave P-256) | Yes | Yes (Secure Enclave P-256 on the device) |
| Fits D-33's display rule (the operator sees the exact payload) | Yes, with D-39, within the dialog's size limit (H15) | Yes, in a full window (no dialog size limit) | Yes, on the device screen (scrollable, complete) |
| Usability | Good: in-place Touch ID | Poor: switch accounts for each approval | Moderate: scan or transfer, then approve on the device |
| Availability and recovery | The Mac's keychain and Secure Enclave; enrolment change invalidates the key; needs a second key | Same, plus account maintenance | The device can be lost or broken; needs a second enrolled key or device |

---

## 3. Attack paths and expected outcomes

| # | Attack (Ag-n) | A | B | C |
|---|---|---|---|---|
| X-1 | Copy the key handle and sign with its own program (SE-H1) | No handle exists, so it fails [A, T-06] | The handle lives in the signer account; Ag can't read it, so it fails [A, B-T1] | No handle on the host, so it fails |
| X-2 | Build and sign its own binary with the local team identity (U-8) and the copied profile | **Fails only if the identity is removed from the Mac** (T-08); otherwise expected to **succeed** (T-07) | Not applicable | Not applicable |
| X-3 | Get the off-host signer to sign an attacker binary: push code to the repository or CI, using git or CI tokens the operator's account holds | **Real risk.** If CI signs whatever reaches a branch, Ag can get malicious helper code signed. Mitigation: §4 A-3 | Not applicable | Not applicable for code; the device app's update channel is the analogue (§4 C-2) |
| X-4 | Run the genuine signer with a malicious but valid payload | Dialog shows all fields; the operator must cancel | Signer window shows all fields; the operator must cancel | Device shows all fields; the operator must cancel |
| X-5 | Run the genuine signer with malformed or non-canonical bytes | Refused before the prompt (D-39) | Refused | Refused |
| X-6 | Fake dialog asking for Touch ID or a password | Touch ID on a fake dialog yields nothing; **a typed admin password would give root** | Same; a fake "log into signer" screen could phish the signer password | The device isn't reachable; host phishing yields nothing for the key |
| X-7 | Prompt timing or fatigue (trigger a prompt when the operator expects one) | Mitigated by full display; residual risk | Account switch makes the context explicit | Context is explicit (physical action) |
| X-8 | Downgrade: run an **older** genuine-signed helper lacking D-39 checks | Possible if any old signed build with the group exists. Mitigation: a new access group per security epoch, never granted to pre-D-39 builds | Same, for the signer app in that account | The device app version is pinned on the device |
| X-9 | Root via a captured admin password | Defeats A | Defeats B | Doesn't give the device key; Ag could still fake host-side transfers (X-4 still needs approval on the device) |
| X-10 | Tamper with the trust store or policy on the host to accept an attacker key | Trust-store change needs an operator-signed `key.rotate`; same-user deletion and rollback remain (D-34 residual) | Same | Same |

---

## 4. Required operating-system enforcement and procedural controls

**A, off-host code signing:**
1. **A-1 [needs a test]:** the data-protection keychain group gate (round 2 shows the rejection side; T-06 and T-09 need a profile).
2. **A-2:** the approval Mac has **no** code-signing private key usable by the daily account. That means removing the Apple Development identity from the login keychain, and confirming with `security find-identity -v -p codesigning` → 0. The development profile alone is public and harmless.
3. **A-3: release authorisation.** The off-host signer signs **only** builds from a tag created after human review. The tag is verified with a key the agent can't use (for example a hardware-token-backed git signing key, or a review on a second account). A reproducible-build hash is compared with the off-host build before signing. **Git and CI credentials on the approval Mac must not be able to cause signing** (X-3).
4. **A-4:** a hardened runtime, library validation and no `get-task-allow`, verified on the signed artifact (T-14).
5. **A-5:** a new access group per security epoch (X-8).

**B, separate account:**
1. **B-1:** a separate standard user with its home folder at mode 0700. Its keychain is unlocked only when that user logs in [A].
2. **B-2:** **the daily account must not be an administrator,** or the operator must never type the admin password in the daily session, where Ag-5 can fake a prompt. **Today the daily account is an admin [V].**
3. **B-3:** the inbox and outbox carry data only. The signer treats the inbox as untrusted input (D-39 validation) and never executes anything from it.

**C, separate device:**
1. **C-1:** the device runs only the signer, with no agents and no general development tools.
2. **C-2:** device app updates are installed and authorised by the operator on the device. The same release-authorisation principle as A-3 applies.
3. **C-3:** a data-only transfer channel (QR or a file), and the device validates everything (D-39). A QR code has a size limit [A], which may require splitting large approvals, like the H15 limit.

---

## 5. Key custody and recovery

| Topic | A | B | C |
|---|---|---|---|
| Operator key | One Secure Enclave key per approval Mac, in the group, `.biometryCurrentSet` | Secure Enclave key in the signer account | Secure Enclave key on the device |
| Second key (required in all designs) | A second enrolled operator key on another device or account, for rotation and revocation when the first is lost or invalidated (D-27 rotation; D-37 one-hour `key.rotate`) | Same | A second device |
| Code-signing key | **Off-host**, ideally in a hardware token; revocable with Apple | None needed | Only for the device app's build (off the host) |
| Biometry change | Invalidates the key, so rotate with the second key | Same | Same, on the device |
| Loss or theft | Revoke the key (`key.revoke`, signed by the second key); the trust store rejects it | Same | Same |
| Same-user deletion of revocation records | D-34 residual (G-8) | Same | Same |

---

## 6. Trusted display and user-presence design (common to all)

- **Input:** canonical payload bytes only. The signer re-encodes them and refuses any mismatch, unknown field or unknown action, or a `key_id` that isn't its own (D-39 §2.1).
- **Display:** the signer builds the text from the bytes: **every field in full**, printable ASCII only, and no caller-supplied strings anywhere.
  - **A:** in the system dialog, refusing when the payload is too long to display (H15).
  - **B:** in a dedicated, scrollable window.
  - **C:** on the device screen, scrollable.
- **Presence:** `.biometryCurrentSet` with `.deviceOwnerAuthenticationWithBiometrics`, and no passcode fallback. If biometry is unavailable, the signer fails closed.
- **What the operator must check:** the action, subject, revision, scope and expiry. Approving without reading is a residual risk in every design, made smaller by complete and unambiguous display.
- **Never trust:** the host terminal output, or any dialog text not produced by the signer (SE-H1 showed that callers can supply dialog text).

---

## 7. Hardware tests required

| ID | Design | Test | Expected |
|---|---|---|---|
| A-T1 | A | `security find-identity -v -p codesigning` on the approval Mac after the identity is removed | 0 identities |
| A-T2 | A | T-06: the profile-signed helper creates the group key; no handle on disk | Created |
| A-T3 | A | T-07 / T-08: a same-team attacker build with the copied profile, with the identity present and then removed | Succeeds when present; **fails when removed** |
| A-T4 | A | T-09, T-14 to T-17 (from round 2) | As listed there |
| A-T5 | A | Downgrade: an older signed helper outside the current group | `-34018` |
| B-T1 | B | Daily-account process reads the signer's home folder and queries the signer keychain | Permission denied; not found |
| B-T2 | B | Daily-account process signs with a copied signer handle (if it obtained one) | Can't obtain it; with root, this test is out of scope |
| B-T3 | B | Signer UI rejects malformed inbox payloads; full display; biometry only | As specified |
| C-T1 | C | Device rejects non-canonical, unknown-action or oversized payloads | Refused |
| C-T2 | C | Device displays the full payload, including the maximum-size case | Complete and scrollable |
| C-T3 | C | Host process tampers with the returned signature or payload | Sentinel's verification fails |
| All | — | D-39 tests H12–H15, and `.biometryCurrentSet` enrolment-change invalidation | As specified |

---

## 8. Operational and financial costs

Prices aren't stated: there was no network access to check current Apple pricing.

| | A | B | C |
|---|---|---|---|
| Apple programme | A development profile at least; whether the free tier can grant a keychain group on macOS is **[U]**. Developer ID (paid) is needed to distribute the helper to other Macs | None | Second Mac: none. iOS app: free development provisioning expires quickly [A], so durable use likely needs the paid programme |
| Hardware | Optional hardware token for the signing key; a separate build machine or CI | None | A second device the operator controls |
| Engineering | Highest: a profiled `.app` helper, an off-host signing pipeline, release authorisation, D-39 | Moderate: signer UI, inbox and outbox, D-39 | Moderate to high: signer app on the device, the transfer channel, D-39 |
| Per-approval friction | Low | High (an account switch) | Medium (a transfer plus approval on the device) |
| Strength against Ag without root | Strong, **if A-2 and A-3 hold** | Strong [A] | Strongest |
| Strength if Ag gets root | Broken | Broken | Holds for the key; display on the device still authoritative |

---

## 9. Recommendation

**Recommended: C, a separate trusted signing device: a dedicated second Mac** (no agents, operator-only), running the Sentinel signer with D-39 validation and full display, `.biometryCurrentSet`, and its own Secure Enclave key.

- **Transfer:** a file on removable media, or a QR code where the payload fits. **Signatures return as data** and are verified by Sentinel as today.
- **Why C over A:**
  - it removes both the code-signing dependency (U-8, X-2, X-3) and the reliance on the operator never leaking the admin password (X-9);
  - it needs no Apple paid infrastructure when the device is a Mac;
  - it gives the operator an unconstrained, trustworthy display.
- **Why not B as the target:** with the daily account as an administrator [V], B's boundary rests on the admin password never being phished in the agent's session. B is acceptable **only as an interim** design, and only if the daily account is made a standard user.
- **A** stays a possible later convenience upgrade for teams that can run off-host signing with release authorisation. It isn't recommended for V1.

**Consequences if approved** (to be recorded later as a decision, not now):
- D-38's mechanism stays (Secure Enclave P-256), but on a dedicated device.
- The "approval Mac" and the "signing device" become two roles.
- D-39 applies to the device signer.
- The current helper, with its handle on disk, is retired (it was already rejected by SE-H1).

---

## 10. Operator decisions requested

1. **Architecture:**
   - **C**, a dedicated signing device (recommended);
   - **B**, a separate account (interim, and only with a non-admin daily account);
   - **A**, off-host code signing.
2. **If C:** the device type (a second Mac, recommended, with no Apple programme needed; or an iOS device, which likely needs the paid programme for durable installs) and the transfer channel (file on removable media, QR code, or both).
3. **Daily account hardening** (any design): make the daily account a standard user and use the separate admin account only for administration, or accept the admin-password phishing risk explicitly.
4. **Second operator key** for recovery: on which device or account.
5. **Whether to remove the Apple Development identity** from the approval Mac's login keychain now (it matters for A, and is good hygiene in general).

**Production signing stays disabled. Nothing proceeds until you decide.**

---

## 11. Selected direction (SE-03, 2026-11-09)

**The operator conditionally approved Architecture C**, a dedicated second Mac as the signing device.

**Directions:**
- no agents on the signing Mac;
- independent canonical validation;
- complete display;
- `.biometryCurrentSet` with Touch ID only;
- explicit approval;
- the development Mac only verifies signed responses against an enrolled public key;
- no caller-provided display text;
- QR transfer for small payloads and removable media for large ones, with one protocol;
- a separately protected recovery key;
- a migration assessment for demoting the daily account (no change yet);
- an audit of the Apple Development identity (no change yet; Sentinel must not depend on it).

The detailed design and hardware test matrix are in `docs/architecture/separate-signing-device-design.md`. Not yet recorded as a decision; production signing stays disabled.

---

## 12. Proposed decision wording (NOT recorded; for operator review)

### Proposed D-45: per-key roles and permitted actions

> **D-45 (proposed). Operator keys carry a role and an explicit set of permitted actions, enforced independently by the signing device and by Sentinel Core.**
>
> **Roles:**
> - Role `operator` (a Secure Enclave key on the dedicated signing device) may sign `authorize_record`, `revoke_record`, `review.verify_no_evidence`, `review.accept_risk`, `suppress`, `policy.change`, `key.rotate`, `key.revoke` and the device-internal `signer.release`.
> - Role `recovery` (a FIDO2 credential) may sign only:
>   - (a) `key.rotate` that enrols a replacement key of role `operator`, whose public-key hash the signing device generated and verified in the same recovery session; and
>   - (b) `key.revoke` of a key other than itself.
>
> **A recovery key can never authorise** ordinary approvals, policy changes, accepted risks, suppressions, reviews, audits or signer releases, and can never revoke itself.
>
> **Records:** a key's role and permitted actions are recorded in the signing device's registry and in Sentinel's trust store, and are part of the trust-store fingerprint.
>
> **Verification:** any signature or assertion whose action isn't permitted for its key is rejected (`BLOCKED`, `action_not_permitted`).
>
> **Key operations:** these are prepared against the trust state computed by the signing device from its own registry. A registry change takes effect on the device only after explicit operator confirmation.

### Proposed amendment to D-38: operator signing vs. recovery assertions

> **D-38 (amendment, proposed). Two distinct key classes, with distinct verification.**
>
> - **(1) Operator signing:** ECDSA P-256 (SHA-256) with a key held in the Apple Secure Enclave of the **dedicated signing device**, with `.biometryCurrentSet` access control. Every signature requires a current biometric match: there is **no passcode fallback**. Each signature covers exactly the canonical approval payload. The development Mac never holds or uses an operator signing key.
> - **(2) Recovery assertions:** a FIDO2 credential with COSE algorithm ES256 (P-256) and required user verification. It is used only through the signing device's trusted display, and produces a **WebAuthn assertion**: a signature over `authenticatorData || SHA-256(clientDataJSON)`, whose challenge is SHA-256 of `"sentinel/v1/recovery-assertion" || 0x00 || canonical approval payload`.
>
> **Distinct verification:** recovery assertions are verified by a **separate procedure**. That procedure checks the type, the challenge, the origin and rpId hash, the UP and UV flags, the credential ID, the signature counter, the signature, and the D-45 permissions. **A recovery assertion is never accepted as an operator signature, and an operator signature is never accepted as a recovery assertion.**
>
> **Ed25519 FIDO2 operator keys** (the original D-38 example) are **not used** in V1.
>
> **Fail closed:** if the Secure Enclave, biometry or the recovery authenticator is unavailable, the affected actions fail closed. **There is no software-only fallback for any operator or recovery key.**

### Status

**Neither decision is recorded** in `docs/architecture-discovery-plan.md`. Recording them, and the other open decisions (`separate-signing-device-design.md` §R3.7), awaits operator review. Production signing stays disabled. **The architecture is not frozen.**


---

**Recorded 2026-11-09:** the decision register (`docs/architecture-discovery-plan.md` §4) now holds:
- **D-45** (per-key roles);
- **D-46** (checkpoints, in the strengthened wording);
- **D-47** (the D-38 amendment);
- **OD-2 to OD-6** (§4.1).

Where this document says "proposed" for these, the register is authoritative. **The architecture is not frozen.**

**Freeze (2026-11-09):** the architecture is frozen as a design baseline (D-48). This design is part of the baseline. It is **not** implemented or hardware-validated, and production signing stays disabled.
