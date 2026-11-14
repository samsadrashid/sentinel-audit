# Redaction engine (§6.4, §13.4)

**Status:** implemented and unit-tested against synthetic secrets. **It is not complete secret detection.** It reduces the chance that a secret a scanner sees is stored or shown. It does not guarantee that no secret is ever stored or shown.

## Where it runs

| Sink | How |
|---|---|
| Evidence store | `RunStore.put_evidence` redacts before hashing and writing. Without a redactor it refuses to store anything. The evidence record's `redaction` field lists the rules that fired and their counts |
| Findings, check reasons, the result, the manifest and every report format | The orchestrator redacts the whole result once, before the manifest is signed and any report is rendered |
| Run audit log and admin log | `AuditLog.append` redacts event names and data before writing |
| CLI output (JSON, human-readable, raw report bytes, error messages) | `cli.main` redacts everything it prints; if redaction fails, nothing is printed (exit 7) |
| `report --output` exports | Same path as CLI raw output |
| Signed payloads and decisions | Can't be redacted after signing, so `approval prepare` and decision recording **refuse** secret-like content |

**Failure handling:**
- **Evidence:** if redaction fails, the check is `ERROR` with the reason `redaction_failed`, and no evidence or findings are kept for it.
- **Result:** if redaction of the result itself fails, the audit stops before any manifest or report is written.

## Markers

`[REDACTED:<rule>:<fingerprint>]`. The fingerprint is HMAC-SHA256 of the value, truncated to 12 hex characters, keyed with a per-installation 32-byte key at `<state>/keys/redaction.key` (mode 0600, created by `sentinel init` or on first use).
- **Deterministic:** within one installation, the same secret always gives the same marker, so repeated occurrences can be correlated.
- **Not reversible:** without the key, the marker reveals nothing about the value.

Assignment names, header names, URL schemes and hosts stay visible as context.

**Idempotent:** existing markers are never matched again.

## Built-in rules

| Rule | What it covers |
|---|---|
| Private keys | PEM private keys (RSA, EC, DSA, OpenSSH, PKCS#8, encrypted, PGP), multi-line or with JSON-escaped `\n`, and truncated keys (redacted to the end of input) |
| Cloud and provider tokens | AWS access key IDs; GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`); GitLab `glpat-`; Slack `xox?-`; Stripe; Google `AIza…`; Anthropic `sk-ant-`; OpenAI `sk-`; npm; JWTs; Azure `AccountKey=` and SAS `sig=` |
| Environment lines | Lines like `NAME=value` where the name contains SECRET, TOKEN, PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY, CREDENTIAL, DSN, DATABASE_URL, CONNECTION_STRING or AUTH; the whole value to end of line is redacted |
| `Authorization` and `Proxy-Authorization` | Header values, with or without a scheme |
| Connection strings | The password in `scheme://user:password@host` |
| Credential assignments | `name = value`, `name: value`, `"name": "value"` and escaped JSON, where the name contains password, passwd, pwd, passphrase, secret, token, api key, access key, private key, client secret, credential, auth token, session key or token, signing, encryption, master or account key, SAS token, or bearer |

## Custom patterns

Add `redaction_patterns: [{"name": "...", "regex": "..."}]` to the operator-approved policy file. Like any policy change, it needs a `policy.change` approval.

Limits:
- at most 32 patterns, each at most 512 characters;
- names must be lowercase identifiers that don't collide with a built-in rule;
- a pattern that fails to compile, or matches empty input, makes the policy invalid;
- the whole match is redacted.

Python's regex engine has no backtracking limit, so an approved pattern with catastrophic backtracking can stall an audit. Review patterns before approving them.

## Known blind spots (not detected)

- **Encoded values:** base64, hex, URL-encoded, UTF-16, gzip-compressed or otherwise encoded secrets, except that the value of an `Authorization: Basic` header is redacted.
- **Bare secrets with no recognisable prefix or key name:** random passwords, generic high-entropy strings and custom token formats, unless an operator adds a custom pattern. There is no entropy-based detection, by design: it has a high false-positive rate.
- **Secrets split across lines**, string concatenation, or values over 512 characters in an assignment (only the first 512 are redacted).
- **Names that don't contain a listed keyword**, for example `DB_PW=…` or `key=…` on its own.
- **Non-ASCII key names** or full-width characters.
- **Personal data** (names, emails, addresses): there is no PII detection yet (§13.4 PII minimisation is not implemented).
- **Finding fingerprints and file paths:** fingerprints are computed from the raw rule, location and component before redaction. A secret inside a file path could leak through a guessable fingerprint (low risk).
- **Signed content:** files on disk written by the user (decision files, policy files and approvals) are refused when secret-like, but files edited by hand afterwards aren't scanned.

## Known false positives

- **Values next to keyword names:** `password: changeme-in-production` or `token_count = 12` with values of 3+ characters are redacted. `null`, `none`, `true`, `false`, `undefined`, `***` and `xxx` are left alone.
- **Documentation examples:** sample keys and placeholder tokens that match a format, such as `AKIAIOSFODNN7EXAMPLE`, are redacted.
- **URLs with `user:pass@`:** the password part is redacted even when it isn't secret.
