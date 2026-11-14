# Freeze remediation, round 2 (2026-11-09)

This is the follow-up to `freeze-remediation-proposal.md`, done under the operator's approvals of 2026-11-09.

**What this round contains:**
- the approved code corrections X-5 and D-32 (implemented; see Part 1);
- the D-39 helper-dialog design and security analysis, **for review only, not implemented**;
- the D-42 amendment wording, **not recorded**;
- proposed M2 acceptance criteria;
- a Mermaid renderer installation plan, **nothing installed or downloaded**.

D-39 to D-44 are **not** recorded in the decision register. **The architecture is not frozen.** Production Secure Enclave signing stays disabled.

---

## Part 1. Implemented: X-5 and D-32 (approved items 2 and 3)

### X-5: no unsandboxed adapter execution path remains

| Path | Before | After | Test |
|---|---|---|---|
| P1: no layer, third-party adapter | `NOT_RUN` | `NOT_RUN` (`host_isolation_unavailable`), adapter never called | `test_pipeline.py::test_no_isolation_means_not_run_for_every_adapter[False]` |
| P2: no layer, engine-owned fixture adapter | **ran unsandboxed on the host** | `NOT_RUN` (`host_isolation_unavailable`), adapter never called, decided at planning | `…[True]` |
| Execution-time gate (defence in depth) | n/a | if the host gives no runner at execution time, the adapter isn't invoked | `test_execution_time_isolation_gate_blocks_dispatch` |
| Adapter-level gate | fixture ran `run_bounded` on the host when `runner=None` | `FixtureAdapter.execute(runner=None)` returns `NOT_RUN` and starts no process | `test_fixture_adapter_refuses_to_run_without_a_runner` |
| P4: adapter ignores the runner | `ERROR` | `ERROR` (`isolation_not_used`), results discarded | `test_isolation.py::test_adapter_that_ignores_the_sandbox_is_rejected`, `test_adapter_that_ignores_a_runner_is_error` |
| P5: a layer name with no production runner | n/a | `NOT_RUN`: `HostCapabilities.runner_for` returns a runner **only** for the verified `s1-macos-seatbelt` profile | `test_layer_name_without_a_production_runner_is_not_run` |
| P6: root | fixture ran as root, unsandboxed | no layer is returned, so `NOT_RUN`; the CLI also refuses at start (D-32) | `test_root_host_never_runs_adapters`, `test_d32_privileges.py` |
| `NOT_RUN` returned by an adapter | the isolation check applied | evidence and findings are discarded | `test_not_run_results_keep_nothing` |

The unsandboxed label `none (engine-owned adapter run unsandboxed …)` is removed. `engine_owned` remains as metadata only.

**Test-only runner:** `tests/isolation_testing.py` provides `TestOnlyRunner` and `TestHost`, named `test-only-runner (NOT isolation)`.
- It lets tests execute the fixture on hosts without the sandbox. **It is not isolation.**
- Production code can't select it: `runner_for` knows only the Seatbelt profile.
- `test_test_only_runner_is_never_importable_from_production` checks that `src/` never references it.

### D-32: privileged execution refused

- `isolation.privilege_problem()` refuses:
  - an effective UID of 0 (`os.geteuid()`, which catches sudo and setuid);
  - on Linux, a non-zero `CapEff` in `/proc/self/status`;
  - on Linux, a missing, ambiguous, malformed or unreadable `CapEff` (fail closed).
- **macOS `admin` group membership isn't refused.**
- `cli.main` calls the check for every command except `version`, **before** the command runs. It exits 3 with code `privileged_execution`, and nothing is written (the state folder isn't created).
- Tests: `tests/test_d32_privileges.py` has 18 cases: five commands refused as root without creating state, `version` allowed, unprivileged allowed, admin group allowed, eight `CapEff` cases, the CLI with `CapEff`, and no isolation layer for a root host.
- The §10.2 wording is updated in `discovery.md` (approved).

**Known limit, not addressed:** other Linux privilege mechanisms are out of scope here: ambient-only capabilities are covered by `CapEff`, while SELinux and AppArmor contexts and file capabilities on the interpreter are not. Windows is out of scope until M10.

---

## Part 2. D-39 helper-dialog design and security analysis (for review; not implemented)

**Approved direction (item 1):** the helper must parse, validate and display the **exact canonical approval payload** it signs, with no truncation or ambiguous display, plus H12–H15. Production signing stays disabled, and the same-user trust limitation must be documented explicitly.

### 2.1 Dialog design

**Input validation, before any prompt.** The helper refuses with `invalid_request` unless every check passes:
1. stdin is 1 to 16,384 bytes (a new limit, tighter than the current 64 KiB, because everything must be displayable);
2. it is valid UTF-8 with **no** control characters: no newlines and no tabs (the canonical encoding contains none);
3. it parses as one JSON object;
4. re-encoding it with the canonical rules (keys sorted by code point, separators `,` and `:`, no whitespace, strings escaped as `canonical.encode` does, integers only, no floats, no duplicate keys) yields **exactly** the input bytes;
5. its key set is exactly `{context, action, subject, revision, scope, issued_at, expires_at, nonce, key_id, rationale}`;
6. `action` is one of the nine §11.3 actions, and `context == "sentinel/v1/approval/" + action`;
7. `key_id` equals the helper's own computed key ID for the key handle;
8. `issued_at < expires_at`, both integers. Maximum lifetimes stay enforced by Sentinel; the helper also shows the lifetime;
9. **display safety:** every string value, at any depth, uses only printable ASCII (`0x20`–`0x7E`). Anything else is refused (`payload_not_displayable`). That rules out homoglyphs, bidi overrides, zero-width characters and combining marks, at the cost of ASCII-only rationales (see 2.3).

**Rendering.** The `localizedReason` text is produced deterministically from the parsed payload:

```
Sentinel operator approval: <action>
SIGNING EXACTLY THE PAYLOAD BELOW (complete, not a summary)
context: <context>
action: <action>
subject: <canonical JSON of subject>
revision: <revision>
scope: <canonical JSON of scope>
issued_at: <int> (<UTC ISO-8601>)
expires_at: <int> (<UTC ISO-8601>), lifetime <h>h<m>m
nonce: <nonce>
key_id: <key_id>
rationale: <rationale>
payload sha256: <64 hex>
```

- **Every value is shown in full**, and nested objects are shown as their exact canonical JSON. No field is summarised, abbreviated or truncated.
- **The rendering is reversible:** from the displayed text, the canonical payload can be rebuilt byte for byte. A Swift unit test checks this by parsing the rendering back, and a Python test cross-checks it against `canonical.encode`.

**No truncation.** macOS may visually truncate or scroll a long `localizedReason`, and the point at which it does is **not documented and not assumed here**.
- H15 measures the longest rendering shown completely and readably on each supported macOS version.
- The helper embeds a table of measured macOS versions with their maximum.
- On any macOS version not in the table, or when the rendering is longer than the measured maximum, it refuses (`payload_too_large_to_display`).
- Large scopes must be split into several approvals.

**After display:** the current behaviour is kept. The helper signs exactly the stdin bytes, verifies its own signature, and returns `message_sha256` and `key_id`. Sentinel checks them (`secure_enclave.py:sign_with_presence`).

**New helper error codes:** `payload_not_canonical`, `payload_not_displayable` and `payload_too_large_to_display`. Each maps to `BLOCKED` in Python.

### 2.2 Hardware tests to add

| ID | Test | Pass criterion |
|---|---|---|
| H12 | Sign a typical `suppress` payload | The dialog shows every field of §2.1, matching the payload byte for byte |
| H13 | The test harness shows payload A in the terminal and feeds payload B to the helper | The dialog shows **B's** fields; the operator cancels; no signature |
| H14 | A non-canonical payload, a non-ASCII rationale, or a scope too large to display | Refused **before** any dialog, with the matching code |
| H15 | Increasing payload sizes on each supported macOS version | Records the largest rendering shown completely without truncation or hidden scrolling. The value is written into the helper's version table and into `se-hardware-tests.md` |

H1–H11 must be re-run on the new helper build. The helper hash and its pin change.

### 2.3 Security analysis

**What D-39 fixes:** the "terminal shows A, helper signs B" attack **through the real helper**. With D-39, the system dialog shows exactly what the pinned helper signs, rendered from the signed bytes, in a surface the calling process doesn't draw. An operator who reads the dialog sees the real payload.

**What D-39 does not fix: the same-user trust limitation** (to be documented explicitly, as directed). Evidence: `main.swift` creates the key with `SecAccessControlCreateWithFlags(..., [.privateKeyUsage, .userPresence])`, without a keychain access group or app binding. Sentinel stores the key's `dataRepresentation` (the handle) in the state folder (`secure_enclave.py`, `KeyMetadataStore`), readable by the operator's user. So:

1. **Any same-user process can use the key without the Sentinel helper.**
   - A process running as the operator's user, an AI agent included, can read the handle, write or compile its own small program against CryptoKit, and ask the Secure Enclave to sign **any bytes**, with **any** `localizedReason` text it chooses.
   - The pinned helper hash doesn't prevent this, because the attacker doesn't use the helper.
   - The dialog would look like a legitimate Sentinel approval while signing a different payload.
   - **The dialog text is therefore not a trustworthy statement of what is being signed** unless the key can only be used by the genuine helper.
2. **Requesting-process identity in the dialog:** macOS shows the requesting process's name or icon, depending on version. A same-user process can choose its own name. **Not verified here; it must not be relied on.**
3. **Passcode fallback and phishing:** `.userPresence` accepts the device passcode as well as biometrics. A same-user process could also draw a **fake** dialog to harvest the login password. That doesn't yield a Secure Enclave signature by itself, but it compromises the account.
4. **Prompt fatigue and timing:** an agent can trigger prompts when the operator expects one, or repeatedly.
5. **The operator approves without reading:** no mechanism removes this.

**Consequence:** D-39 is necessary but **not sufficient** to meet D-27 and D-33 against a same-user agent, which is exactly the T16 threat. It makes the honest path correct and the dialog complete. It doesn't stop a hostile same-user process from producing a convincing dialog of its own.

**Options to close the gap** (each needs an operator decision; none is decided here):

| Option | What it does | Cost and limits |
|---|---|---|
| (a) **App-bound key** | Create the key as a keychain item with an access group, in a **Developer ID-signed** helper with a keychain-access-group entitlement, so only that signed binary can use it. Store no usable handle on disk | Needs an Apple Developer Program identity, a signed and notarised helper, and an entitlement. Changes the build (`build.sh` uses ad-hoc signing today). Strongest option on macOS |
| (b) **FIDO2 authenticator with its own display or an explicit per-use touch** (D-38 already allows Ed25519 on FIDO2) | The signing device is outside the host | Most FIDO2 keys have no display, so the operator still can't see the payload on the device. It only proves a touch |
| (c) **Separate macOS user account for the signer** | The handle and helper live in an account the agent's user can't read | Operationally awkward; the transfer between accounts becomes the new boundary |
| (d) **Accept as residual** | Document that, against a same-user hostile process, operator approvals rest on the operator noticing an unexpected prompt | Weakest option; conflicts with T16's intent |

**Recommendation for review:** (a), together with D-39. Production signing stays disabled until the chosen option is implemented and H1–H15 pass. **This analysis also affects the D-38 activation decision.**

### 2.4 Files that D-39 would affect (later; not changed now)

`native/macos/se-helper/main.swift` and `build.sh` (also for option a), `docs/m1/se-helper-contract.md`, `docs/m1/se-hardware-tests.md`, `src/sentinel/keys/secure_enclave.py` (new codes, and the 16 KiB limit), `tests/test_se_helper.py`, `tests/test_secure_enclave.py`, `scripts/mutation/mutations.py`, `docs/architecture-discovery-plan.md` (D-39, when approved), and `discovery.md` §9, §11.2 and §11.3.

---

## Part 3. D-42 amendment wording (proposed, not recorded)

The operator directed removal rather than keeping an unused operation. Proposed exact wording for the decision register:

> **D-42 (proposed): remove `allowlist.change` (amends D-33, D-36, D-37 and discovery.md §11.2, §11.3, §11.3.1, §11.3.2).** Adapter allowlists and pinned scanner hashes are part of the operator-approved policy file and change only through a `policy.change` approval. The action `allowlist.change` is removed from the canonical action list, from the standing-approval class and from the maximum-expiry table. An approval payload whose action is `allowlist.change` is rejected as an unknown action (`BLOCKED`). D-20's requirement of human approval for adapter-allowlist and pinned-hash changes is met by `policy.change`. Any future separate allowlist file needs a new decision.

**Code consequences** (for implementation after the wording is approved):
- remove `ApprovalAction.ALLOWLIST_CHANGE` (`domain/enums.py:109`), its maximum in `approvals.py:41`, and its standing class;
- remove the refusal branch in `prepare.py:9–10`;
- add a test that an `allowlist.change` payload is rejected as an unknown action;
- update the mutation catalogue if any anchor moves.

**Doc consequences:** §11.2 (trust-anchor actions), §11.3 (action list), §11.3.1 (standing class), §11.3.2 (table row), and D-36 and D-37 (by amendment note, not by rewriting them).

---

## Part 4. Proposed M2 acceptance criteria (not yet decided)

Nothing here implies that redaction covers PII or classifies secrets today. **Current state:** secret-pattern redaction only; no PII detection; no live/test classification (`docs/m1/redaction.md`).

| ID | Area | Proposed M2 acceptance criterion |
|---|---|---|
| AC-15 | PII detection | Synthetic fixtures for each detector class: email address, phone number, postal-address lines, government-ID-shaped numbers, IP address, and payment-card-shaped numbers that pass Luhn. **≥ 95 %** of fixture instances are masked in evidence, reports, logs and CLI output. **0** raw instances remain in the fixture corpus outputs (extends AC-04). Every detector class has a documented false-positive list. A detector that fails is `ERROR` (`redaction_failed`), never silent. Reports state which PII classes are **not** covered |
| AC-16 | Secret classification | Each detected secret is recorded as `live`, `test` or `unknown` from **documented, deterministic** rules: known test prefixes, example keys and fixture markers. There are no network checks and no validity probing against providers (D-31). `unknown` is the default and is never shown as `test`. Fixtures cover all three outcomes, and a misclassification of a live-format fixture as `test` fails the criterion |
| AC-17 | Kill switch, pause and resume | `sentinel cancel <run>` stops every running check within **10 s** (process tree killed). Those checks become `BLOCKED` (R-04), the audit becomes `Cancelled`, and the overall result is never PASS. `pause` stops scheduling new checks. `resume` re-runs authorisation for every remaining check (§8.2) and restarts the audit if the source revision changed. Every transition is logged. Each of these is tested, including cancelling during the extraction of a large fixture |
| AC-18 | Retention deletion | `runs prune --list` lists runs older than the retention limit (90 days, D-19) without deleting anything. `runs prune --delete` deletes only listed runs, and only after interactive confirmation; in non-interactive mode it is refused. Deletion covers evidence, indexes, reports and workspaces (§13.5), and leaves a hash-only audit-log entry. A test checks that no file of a deleted run remains and that the log chain still verifies |

**JSON Schemas stay in M1** (D-40 direction, approved).

---

## Part 5. Mermaid renderer installation plan (nothing installed or downloaded)

**Version:** the exact `@mermaid-js/mermaid-cli` version **can't be stated without network access**, which this round didn't use. Step 1 obtains it, and only after approval.

1. **Version selection** (one approved network read): `npm view @mermaid-js/mermaid-cli version time --json`, then show the operator the latest version, its publish date, and the `dist.integrity` (sha512) from `npm view @mermaid-js/mermaid-cli@<V> dist --json`. The operator approves the exact `<V>` and integrity.
2. **Pinned manifest** in the repository:
   - `tools/diagram-render/package.json` with `"@mermaid-js/mermaid-cli": "<V>"` (exact, no range);
   - `tools/diagram-render/.npmrc` with `ignore-scripts=true` and `fund=false`;
   - `PUPPETEER_SKIP_DOWNLOAD=1` set in the install command, so **no browser is downloaded**.
3. **Lockfile:** `npm install --package-lock-only` (network: resolves the dependency tree with integrity hashes). Review and commit `package-lock.json`. Every dependency is then pinned by `integrity`.
4. **Install:** `PUPPETEER_SKIP_DOWNLOAD=1 npm ci --ignore-scripts --prefix tools/diagram-render`.
   - `npm ci` verifies every tarball against the lockfile integrity and fails on any mismatch.
   - Tarballs are cached by npm; later runs can use `npm ci --offline` (fully offline).
5. **Browser:** the locally installed Google Chrome (`/Applications/Google Chrome.app/...`, present on this host), through `PUPPETEER_EXECUTABLE_PATH`, and a `puppeteer-config.json` with `"executablePath"` only, keeping Chrome's own sandbox on (no `--no-sandbox`). No browser download.
6. **Render offline:** a small script extracts the 8 ```` ```mermaid ```` blocks from `discovery.md` into `build/diagrams/NN.mmd` (deterministic order), then runs `tools/diagram-render/node_modules/.bin/mmdc -p puppeteer-config.json -i NN.mmd -o NN.svg` and `-o NN.png`. Network can be disabled for this step (for example, by running with Wi-Fi off), because nothing fetches.
7. **Record:** `build/diagrams/manifest.json` records the `mmdc --version`, the Chrome version, each input's SHA-256 and each output's SHA-256.
8. **Inspect:**
   - (a) a non-zero exit or any parse error fails;
   - (b) each PNG is opened and checked against a per-diagram checklist: every node and edge from the source is present, the labels are legible, and no edge is hidden;
   - (c) the result is recorded in `discovery.md` §17.1, naming the renderer version and the manifest hash.

**Approvals needed** (separately): step 1 (network read of npm metadata), and steps 3–4 (download of the pinned packages).

---

## Part 6. Remaining blockers

**For the freeze:**
- D-39 design approval, and **a decision on the same-user key-use gap (§2.3)**;
- recording D-39 to D-44 after wording review;
- the D-42 wording;
- approval of the M2 criteria;
- rendering and inspecting the Mermaid diagrams;
- the remaining documentation corrections (C-a, C-b, C-e).

**For production signing:** D-39 implemented, the §2.3 gap closed (option a or another decision), H1–H15 passed, and an activation decision record.

**For M1:** JSON Schemas (`schemas/`), the integrations, `fix-plan`, the first remote CI run, the security self-audit, the user docs and the completion report.

---

**Resolved 2026-11-09:**
- D-39 is **withdrawn**, superseded by D-47.
- D-42 is recorded with the Part 3 wording.
- AC-15 to AC-18 are recorded as **mandatory M2 exit criteria** in `discovery.md` §15.3 and §16, strengthened: zero raw PII instances (as AC-04), zero live-format secrets labelled `test`, and measured minimum sample sizes. They are not optional targets.
