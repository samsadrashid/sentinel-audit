# Sentinel signing protocol v1 (DM ↔ signing device, over USB)

**Status:** design for review.
- No code or keys exist yet, no dependency was added, and nothing was decided in the register.
- Production signing stays disabled. **The architecture is not frozen.**

**Roles:**
- **DM:** the development Mac. **Untrusted:** its user session is assumed fully compromised.
- **SD:** the signing device, a dedicated Mac running `sentinel-signer` in a standard `signer` account.
- **Operator:** the human at the SD.

**Normative words:** MUST, MUST NOT and SHOULD.

---

## 1. Principles

1. **The SD trusts nothing from the DM** except the *bytes* of a request, which it validates as untrusted input. It never trusts DM claims about key status, trust state, revocation, or what to display.
2. **What's signed is exactly the canonical approval payload** (D-33): `canonical.encode(payload)` (sorted keys, separators `,` and `:`, UTF-8, integers only, no floats), restricted further to printable-ASCII strings.
3. **Responses carry no authority.** The DM verifies a signature over **its own** pending payload, with the enrolled public key.
4. **Every artifact is canonical JSON with an exact key set.** Unknown keys, duplicate keys or non-canonical bytes mean refusal.
5. **USB is the v1 transport**, in both directions. QR codes are a later, optional transport using the same envelopes (§9).

---

## 2. Canonical encoding rules (both sides)

- **JSON value types:** object, array, string, integer (−2^53 < n < 2^53), `true`, `false`, `null`. **No floats or exponents.**
- **Objects:** keys sorted by Unicode code point, unique, with no insignificant whitespace.
- **Strings:** printable ASCII only (`0x20`–`0x7E`). `"` and `\` are escaped as `\"` and `\\`; no other escapes appear. The SD MUST refuse any other character, including `\n`, `\t`, `\u` escapes and non-ASCII bytes.
- **Validity test:** `decode(bytes)` re-encoded MUST equal `bytes` exactly.
- **Hashes:** lowercase hex SHA-256 of the canonical bytes.

---

## 3. Artifacts

### 3.1 Sign request: DM → SD (`*.req.json`)

```
{"envelope":"sentinel/v1/sign-request","payload":{…},"payload_sha256":"<64hex>","request_id":"<32hex>"}
```

| Key | Rule |
|---|---|
| `envelope` | Exactly `sentinel/v1/sign-request` |
| `payload` | A canonical approval payload (§4) |
| `payload_sha256` | SHA-256 of `canonical.encode(payload)`. The SD recomputes it and refuses on a mismatch. It is for integrity only |
| `request_id` | 128-bit random, 32 lowercase hex characters, unique per request |

**There are no display, label, note, instruction or priority fields.**

### 3.2 Sign response: SD → DM (`*.resp.json`)

```
{"envelope":"sentinel/v1/sign-response","key_id":"<id>","payload_sha256":"<64hex>","request_id":"<32hex>","signature_der_b64":"<base64>"}
```

- **Refusals are not written to the DM.** A refused request produces no response file; the reason is shown and logged on the SD only.
- That avoids an oracle and keeps the channel one-purpose. **Operator decision O-P1:** confirm this, or allow a signed refusal record instead.

### 3.3 Public-key export: SD → DM (`<key_id>.pub.json`)

```
{"envelope":"sentinel/v1/public-key","algorithm":"p256","fingerprint":"<64hex>","key_id":"<id>","public_x963_hex":"<130hex>","role":"operator"|"recovery"}
```

The DM MUST NOT treat it as trusted. Its fingerprint is only accepted after the out-of-band comparison (§7 of the device design).

### 3.4 Trust-store audit input: DM → SD (`trust-store.audit.json`)

The DM's `trust.json` bytes, copied verbatim. The SD compares them with its own registry (device design §2.4) and **reports only on the SD screen**.

---

## 4. Payload validation on the SD (in order; any failure means refusal)

1. The file passes the intake checks (§6).
2. The envelope and payload are canonical (§2), and the request key set is exact (§3.1).
3. `payload_sha256` matches.
4. **The payload key set** is exactly `{action, context, expires_at, issued_at, key_id, nonce, rationale, revision, scope, subject}`.
5. **Context and action:** `action` is one of `authorize_record`, `revoke_record`, `review.verify_no_evidence`, `review.accept_risk`, `suppress`, `policy.change`, `key.rotate`, `key.revoke`. If the D-42 removal is adopted, `allowlist.change` isn't in the list. `context == "sentinel/v1/approval/" + action`.
6. **Key permission:**
   - `key_id` is in the **SD registry**, `active`, unexpired, and stored on **this** SD;
   - **`action` is in that key's `permitted_actions`** (device design §3).
7. **Time:**
   - `issued_at` is within ±300 s of the SD clock;
   - `issued_at < expires_at`;
   - `expires_at - issued_at` is no more than the SD's copy of the D-37 maximum;
   - `expires_at > now`.
8. **Subject shape:**
   - `subject.type` must be the one expected for the action;
   - all fields are present, the hex lengths are exact, and there are no extra fields.
9. **Action-specific rules:**
   - `authorize_record` in production: no wildcards, and exact asset and activity lists (D-37);
   - `key.rotate` and `key.revoke`: the rules in the device design, §2.3;
   - any other action: the revision is a non-empty string of 512 characters or fewer.
10. **Replay** (SD ledger):
    - `request_id` hasn't been seen;
    - the nonce isn't registered to a different payload hash;
    - a one-time nonce (`revoke_record`, `key.rotate`, `key.revoke`) hasn't been used.
11. **Display:** the payload can be rendered completely (§7). There's no size limit beyond item 1's file limit, because the SD window scrolls.

**Only after all checks** does the SD show the approval screen.

---

## 5. Replay and duplicates

| Case | SD behaviour | DM behaviour |
|---|---|---|
| The same `request_id` again (same or different bytes) | Refused (`duplicate_request`), logged | Pending table: a `request_id` is consumed once |
| The same file name, different content | Refused: the name must equal `request_id` (§6.1), so this is the case above | — |
| Two request files in the inbox | Processed one at a time, ordered by name. Each is shown separately; there is **no** batching or multi-approve | — |
| A standing nonce reused with a different payload | Refused (`nonce_rebound`) | Refused (D-36) |
| A one-time nonce reused | Refused (`nonce_reused`) | Refused (D-36) |
| An old response replayed to the DM | n/a | Refused: unknown or consumed `request_id`; nonce ledger; expiry |
| A response whose `payload_sha256` differs from the pending payload | n/a | Refused |

**SD ledger retention:** entries are kept until 30 days after `expires_at`, then pruned. Pruning is logged.

---

## 6. USB transport

### 6.1 Volume and layout

- **Volume label:** `SENTINEL-XFER`. APFS **recommended** (no AppleDouble `._` files); exFAT is allowed.
- **Directories** at the volume root:
  ```
  sentinel-v1/
    to-signer/      DM writes requests, public-key requests, trust-store audits
    from-signer/    SD writes responses and public-key exports
  ```
- **File names** (exact regular expressions; anything else is ignored and logged):
  - `to-signer/req-[0-9a-f]{32}\.json`, where the 32 hex characters MUST equal the `request_id` inside;
  - `to-signer/trust-store-audit\.json`;
  - `from-signer/resp-[0-9a-f]{32}\.json`;
  - `from-signer/pub-[a-z0-9:_-]{1,80}\.json`.
- **Size limits:**
  - a request is 16,384 bytes or less;
  - a trust-store audit is 65,536 bytes or less;
  - a response is 2,048 bytes or less;
  - a public key is 2,048 bytes or less;
  - at most 16 request files per intake. More than that refuses the whole intake (`too_many_requests`).

### 6.2 Safe read-only intake (SD)

1. **Mounting:** the operator inserts the drive. The SD mounts it **read-only**, without browsing, executables or setuid (`nobrowse`, `rdonly`, `noexec`, `nosuid`) [A: exact `diskutil` or `mount` options to be confirmed by test SD-T22]. Spotlight indexing and Quick Look previews MUST NOT run on it (`nobrowse` plus the signer never asking Finder) [A].
2. **Opening files:** the signer walks only `sentinel-v1/to-signer`, opening each candidate relative to the directory (`openat`) with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`. It then:
   - runs `fstat` on the open descriptor and requires a regular file, `st_nlink == 1`, and a size within the limit;
   - **refuses** symlinks (`ELOOP`), directories, FIFOs, sockets, device nodes, files with more than one hard link, and oversized files;
   - also refuses a `to-signer` or `sentinel-v1` that is a symlink (checked with `lstat` and `O_NOFOLLOW | O_DIRECTORY`).
3. **Reading:** the signer reads at most limit + 1 bytes, refusing if more arrive. It closes the file, then **copies the bytes into the SD's private spool**, `~signer/Library/Application Support/sentinel-signer/spool/` (0700):
   - written to a temporary name (`O_CREAT | O_EXCL`, 0600), then `fsync`, then `rename` to `req-<id>.json`, then `fsync` of the directory;
   - all later processing reads **only the spool copy**, never the drive (no time-of-check/time-of-use gap).
4. **Ignored items:** any other file or directory, including `._*` AppleDouble files, `.DS_Store`, `.Trashes`, `.Spotlight-V100` and executables, is **ignored and listed in the SD log**. Nothing is ever opened by Finder or executed.
5. **Ejecting:** the volume is ejected after intake (`diskutil eject`) before any display, so later processing can't depend on the drive.

### 6.3 Atomic output (SD)

1. After signing, the operator reinserts the drive. The SD mounts it **read-write**, with no executables, no setuid and no browsing.
2. It writes `from-signer/.resp-<id>.json.tmp` with `O_CREAT | O_EXCL | O_NOFOLLOW` (0644), then `fsync`, then `rename` to `resp-<id>.json` (refusing if that exists), then `fsync` of the directory.
3. **It never overwrites or deletes DM files.**
4. It ejects.

### 6.4 DM side

- **Requests:** the DM writes them the same atomic way.
- **Responses:** it reads them with the same symlink and special-file refusal and size limit, into its own state, then verifies. The DM is untrusted, but the same robustness applies.
- **Cleanup:** the DM deletes `req-<id>.json` and `resp-<id>.json` from the drive after a successful `approval receive`. The SD never deletes.

### 6.5 Audit records

**SD log** (append-only, hash-chained, in `~signer/.../log.jsonl`): one entry per event:
- `intake` (volume UUID, the file list with sizes and hashes, ignored items);
- `refused` (`request_id`, reason code);
- `displayed`;
- `approved` or `cancelled` (with `biometry_ok`);
- `signed` (`request_id`, `payload_sha256`, `key_id`, signature hash);
- `output_written`;
- `ledger_pruned`;
- `registry_changed`;
- `update_installed`.

**DM log:** the existing admin log records `approval.request_emitted` and `approval.received` with `request_id` and `payload_sha256`.

---

## 7. Display contract

See the device design, §4. Every visible string is built by the signer from validated fields with fixed templates. **No request text is shown except validated field values.** Scrolling is a UX measure, not a security control.

---

## 8. DM verification of a response

1. Read the response (§6.4), with a canonical and exact key-set check.
2. Find the pending request by `request_id`; refuse if it's unknown or consumed.
3. `payload_sha256` must equal the pending payload's hash.
4. `key_id` must be enrolled and active in the DM trust store, and its `permitted_actions` must include `payload.action` (once per-key actions are implemented).
5. Verify `signature_der_b64` (DER ECDSA P-256/SHA-256, or the recovery key's format, device design §3.3) over `canonical.encode(pending_payload)`.
6. Store the approval, then run `approvals.verify` at use time as today (D-33, D-36, D-37).

---

## 9. QR (later, optional)

- **Same envelopes and the same validation.**
- **Single-code QR only, with no splitting.** The capacity is set by a test.
- The QR content MUST be exactly one request envelope; any other content type is ignored.
- Not part of v1.

---

## 10. Explicit security assumptions

| ID | Assumption |
|---|---|
| SA-1 | The SD runs no untrusted code (direction 2), and its `signer` account isn't compromised |
| SA-2 | The SD's Secure Enclave keys are non-exportable, and `.biometryCurrentSet` requires a current biometric match |
| SA-3 | macOS mount options and `O_NOFOLLOW`/`fstat` behave as documented on the SD's macOS version (SD-T22 to SD-T26) |
| SA-4 | Mounting a hostile filesystem image read-only doesn't compromise the SD kernel. This is a **residual**; APFS and exFAT drivers are attack surface |
| SA-5 | The SD clock is correct within ±300 s (checked at each maintenance window) |
| SA-6 | The operator reads the displayed payload before approving |

## 11. Unresolved questions

| ID | Question |
|---|---|
| UQ-1 | Exact `diskutil` or `mount` invocation for a read-only, no-browse, no-exec mount without Spotlight on the SD's macOS version |
| UQ-2 | Whether exFAT should be refused entirely (AppleDouble noise, weaker metadata) |
| UQ-3 | Whether a signed refusal record should be returned (O-P1) |
| UQ-4 | The recovery-key signature format (WebAuthn assertion versus raw), device design §3.3 |

---

# Round 3 (2026-11-09): operator decisions applied

**Decisions applied (SE-03 round 3):**
- **O-P1:** refusals produce no response; they are logged on the SD only;
- **D-45:** approved in principle (wording in `signing-trust-architecture.md` §12; **not recorded yet**);
- **recovery:** ES256/P-256 **WebAuthn assertions**, never treated as plain ECDSA signatures;
- **library:** AuthenticationServices investigated first;
- **USB:** APFS only;
- **`signer.release`:** signed by the SD key;
- **registry commit:** explicit operator confirmation only.

**Where this section differs from §1–§11, it wins.**

## R3.1 Failure semantics (mandatory)

**Every timeout, mismatch, parse error, interrupted transfer or unexpected state fails closed:**
- no signature is produced;
- no partial output is written;
- no registry change is made;
- the event is logged on the SD.

**Specifically:**
- A request or response file that is truncated, zero-length or oversized is refused.
- Temporary names (`.*.tmp`) are ignored on intake.
- If the SD loses the volume during intake, the whole intake is discarded (the spool is rolled back).
- A Touch ID prompt that times out (60 s), or a cancelled presence check, means no signature.
- If writing the output fails, there's no response. The SD records `output_failed`, and the operator may re-issue **the same** response for the same `request_id` (idempotent: identical bytes, recorded as `output_reissued`). It is never re-signed.

## R3.2 USB: APFS only

The SD checks the volume **before** any file access:
- `statfs.f_fstypename == "apfs"`; anything else is refused (`fs_not_apfs`);
- the volume isn't encrypted (an encrypted APFS volume is refused, `fs_encrypted`, so no password prompt is ever shown for transfer media);
- the volume is mounted read-only with `nobrowse`, `noexec`, `nosuid` and `nodev`;
- the protocol §6.2 per-file checks apply unchanged.

File names are ASCII-only regular expressions, so APFS Unicode-normalisation and case behaviour can't create look-alike names.

## R3.3 APFS intake threat model

**Attacker:** controls every byte of the drive (it was written on the compromised DM).

| Threat | Mitigation | Residual |
|---|---|---|
| Malicious APFS metadata targeting the kernel's APFS driver | Mount read-only; one minimal walk of a single directory | **Kernel parser vulnerability (SA-4)**: accepted residual; keep the SD's macOS patched |
| Symlinks and hard links to SD files or devices | `O_NOFOLLOW`; `fstat` must show a regular file with `st_nlink == 1`; `nodev` | — |
| FIFOs, sockets or device nodes that block or loop | `O_NONBLOCK`; type check; `nodev` | — |
| Huge sparse files, or transparently compressed (decmpfs) bombs | `st_size` must be within the limit before reading; read at most limit + 1 bytes | — |
| Extended attributes, resource forks, quarantine flags | Never read; only the data fork is read | — |
| Executables, apps, `.command` and `.webloc` files, aliases | Never opened; names don't match the patterns, so they're ignored and logged | — |
| Spotlight, Quick Look or Finder auto-parsing | `nobrowse`; the signer never hands files to Finder or Quick Look | [A] confirm with SD-T22 |
| Encrypted volume that triggers a password prompt (phishing) | Refused before mounting it for reading | — |
| Snapshots, clones, firmlinks | Not traversed; only `sentinel-v1/to-signer` is opened | — |
| Time-of-check/time-of-use change on the drive | Copy to the spool; eject before display (§6.2) | — |
| Name collisions (normalisation, case) | ASCII-only patterns | — |

## R3.4 Recovery assertion format (WebAuthn, ES256)

**Recovery credential:**
- a FIDO2 credential created on the recovery authenticator with COSE algorithm **−7 (ES256)**;
- relying-party ID **`sentinel-recovery.invalid`** (a reserved TLD that never resolves), unless AuthenticationServices requires a verified domain (see `separate-signing-device-design.md` R3.5);
- user verification **required** (PIN or on-device biometric);
- resident credential: not required.

**The registry and trust store record:**
- the COSE public key, converted to X9.63;
- the `credentialID`;
- the `rpId`;
- `alg = -7`;
- `role = recovery`.

**Challenge construction** (SD, for a validated recovery payload `P`):

```
binding_bytes = "sentinel/v1/recovery-assertion" || 0x00 || canonical.encode(P)
challenge     = SHA-256(binding_bytes)             # 32 bytes
```

`P` already contains `action`, `subject` (including the **replacement key's `public_sha256`** for enrolment, or the target `key_id` for revocation), `revision` (`trust:<expected_fp>` computed by the SD), `nonce`, `issued_at`, `expires_at` and `key_id` (the recovery key). So the challenge binds the **exact operation, the replacement-key fingerprint, the trust state, the time window and the nonce**.

**Client data:** built by the platform API or by the signer, per WebAuthn:

```
{"type":"webauthn.get","challenge":"<base64url(challenge), no padding>","origin":"https://sentinel-recovery.invalid","crossOrigin":false}
```

**Response for recovery** (replaces `signature_der_b64` for `role = recovery`):

```
{"envelope":"sentinel/v1/sign-response","key_id":"…","payload_sha256":"…","request_id":"…","webauthn":{"authenticator_data_b64":"…","client_data_json_b64":"…","credential_id_b64":"…","signature_der_b64":"…"}}
```

**Exactly one** of the top-level `signature_der_b64` or the `webauthn` object, determined by the key's role. Anything else is refused.

**Verification procedure** (both the SD self-check and the DM; every step is mandatory, and any failure rejects):

1. The registry or trust-store entry for `key_id` has `role == "recovery"`, `alg == -7`, and is `active`.
2. **`payload.action` is permitted for the recovery role** (D-45, §R3.5). The rules for the specific operation (§R3.5) hold.
3. Recompute `challenge` from **the verifier's own copy** of `P` (on the DM: the pending request; on the SD: the validated spool copy).
4. Decode `client_data_json` with **strict JSON** and check:
   - `type == "webauthn.get"`;
   - `challenge == base64url(challenge)`, exactly;
   - `origin == "https://" + rpId`;
   - `crossOrigin` is absent or `false`;
   - **no `tokenBinding`, and no unknown keys** beyond the WebAuthn-defined set.
5. `authenticator_data`:
   - the length is at least 37;
   - `rpIdHash == SHA-256(rpId)`;
   - the flags have **UP (0x01)** and **UV (0x04)** set;
   - the AT and ED flags are **not** set (an assertion carries no attested data or extensions in v1).
6. `credential_id == registry.credentialID`.
7. **Signature:** ECDSA P-256/SHA-256 over `authenticator_data || SHA-256(client_data_json)`, using the registered public key, in DER encoding.
8. **Signature counter:** if the stored counter is above 0, the new `signCount` must be greater than the stored one. If both are 0, the authenticator doesn't support counters (allowed; recorded).
9. **Expiry, nonce and revision** checks as for any approval (D-33, D-36, D-37).

**A recovery assertion is never accepted** where an ordinary ECDSA signature is expected, and vice versa. A **separate verification path** in the engine is required.

## R3.5 Recovery enrolment and revocation (protocol)

**Enrolling a replacement key** (`action = key.rotate`, signed by the recovery key):
- `subject = {"type":"operator_key","key_id":<new id>,"public_sha256":<SHA-256 of the new X9.63 key>}`;
- the SD requires:
  - (a) the new key was **generated on this SD in the current recovery session**, and its public key is in the SD's pending registry entry;
  - (b) `public_sha256` equals the SHA-256 the SD itself computes from that key;
  - (c) the new key's role is `operator`, with exactly the operator permission set;
  - (d) `revision == "trust:" + expected_fp`, computed from the SD registry;
  - (e) no other registry change is pending.
- **Display:** "Recovery: ENROL REPLACEMENT OPERATOR KEY". The new key's fingerprint is shown in 16×4 groups, with the instruction "compare with the fingerprint shown in the key-creation step on this screen".

**Revoking a key** (`action = key.revoke`, signed by the recovery or an operator key):
- `subject = {"type":"operator_key","key_id":<target>}`;
- the SD requires:
  - the target exists, is `active`, and **isn't the signing key itself** (in particular, **the recovery key can't revoke itself**);
  - `revision == "trust:" + expected_fp`;
  - no other change is pending.
- Revoking the last active `operator` key is allowed **only** with the recovery key, and only when a replacement enrolment for this recovery session is already committed (order: enrol, commit, revoke).

**Recovery is never accepted for:** `authorize_record`, `revoke_record`, `review.verify_no_evidence`, `review.accept_risk`, `suppress`, `policy.change`, `signer.release` and audits (policy §R3.6). The SD refuses these before display, and the engine refuses them at verification.

## R3.6 Action set

**Signed actions** (SD key, `role = operator`):

| Group | Actions |
|---|---|
| Authorisation | `authorize_record`, `revoke_record` |
| Reviews and exceptions | `review.verify_no_evidence`, `review.accept_risk`, `suppress` |
| Policy | `policy.change` |
| Keys | `key.rotate`, `key.revoke` |
| Signer | **`signer.release`** (new; SD-internal, never consumed by the DM engine) |

The **recovery role** has only `key.rotate` and `key.revoke`, under the §R3.5 rules. "Audits" (the SD trust-store audit) are unsigned SD-local operations and are never available with recovery authority.

## R3.7 `signer.release` record (SD-internal)

```
payload.action  = "signer.release"
payload.context = "sentinel/v1/approval/signer.release"
payload.subject = {"type":"signer_release","commit":"<40hex>","tree_sha256":"<64hex>","binary_sha256":"<64hex>","previous_commit":"<40hex>","toolchain":"<swift version string>"}
payload.revision= "signer:<installed commit>"
payload.scope   = {"device":"<SD serial>"}
payload.key_id  = the SD operator key
lifetime        ≤ 1 hour (one-time nonce)
```

- Built and signed **entirely on the SD**: there's no DM request and no USB step.
- **DM credentials can't authorise it.** The SD installs a signer version only if a valid `signer.release` record signed by an **operator-role key in the SD registry** names exactly that binary hash.
- **Rollback** is a new `signer.release` record whose `commit` and `binary_sha256` name the kept previous version; it is signed in the same way.

---

# Round 4 pointer (2026-11-09)

`signing-protocol-final-review.md` is **normative** for:
- strict RP ID and origin validation (§1.3, superseding the client-data rule in §R3.4 step 4);
- the counter policy (§2, superseding §R3.4 step 8);
- registry checkpoints (§3);
- release provenance (§4);
- the final proposed wording of D-45, the D-38 amendment, OD-2 to OD-6 and the proposed D-46 (§5).

None of these is recorded yet.

**D-46 (strengthened, 2026-11-09):** see `signing-protocol-final-review.md` §5. Checkpoints:
- require explicit confirmation;
- display the sequence and the full hash;
- include the paper-anchor update in their ceremony;
- restore only by the exact paper anchor typed by the operator, never automatically;
- preserve replay and pending state;
- never authorise rollback or revocation reversal.


---

**Recorded 2026-11-09:** the decision register (`docs/architecture-discovery-plan.md` §4) now holds:
- **D-45** (per-key roles);
- **D-46** (checkpoints, in the strengthened wording);
- **D-47** (the D-38 amendment);
- **OD-2 to OD-6** (§4.1).

Where this document says "proposed" for these, the register is authoritative. **The architecture is not frozen.**

**D-42 recorded (2026-11-09):** `allowlist.change` is removed. Protocol §4 item 5's action list therefore excludes it, and a request carrying it is refused before display.

**Freeze (2026-11-09):** the architecture is frozen as a design baseline (D-48). This design is part of the baseline. It is **not** implemented or hardware-validated, and production signing stays disabled.
