# PII minimisation (AC-15, D-52, D-57)

PII is detected and replaced by redaction markers **before** anything is persisted or emitted. It runs in the same single redaction engine as secrets (`src/sentinel/redaction.py`), so it covers every sink:
- evidence (redacted before hashing and writing);
- findings, results, manifests and every report format;
- the run and admin audit logs;
- CLI output, including raw report bodies.

If a detector fails, `RedactionError` is raised: the artifact is held back and the check is `ERROR` (`redaction_failed`).

Scanner processes only ever write to their per-check workspace, which is removed after the check, or to the container's in-memory `/tmp`. Scanner output is held in memory and redacted before storage. Gitleaks' matched secret is classified in memory and then discarded; it is never written anywhere.

**Detection is format matching only. It is not identity verification.** A match means a value *looks like* an identifier of that class. It never means the number exists, is valid, or belongs to anyone. Sentinel never contacts any service to check a value.

## In-scope classes and format rules

| Class | Rule (marker name) | Format rule | Structural check |
|---|---|---|---|
| Email address | `pii_email` | `local@domain.tld`: local part up to 64 characters, TLD 2–24 letters | — |
| Phone number | `pii_phone` | E.164 `+<country><6–14 digits>` (optional separators); NANP `(NXX) NXX-XXXX` with separators; Bangladesh mobile `01[3-9]XXXXXXXX`; UK spaced `0XXX XXX XXXX` | — |
| Postal-address line | `pii_postal_address` | House number followed by 1–4 capitalised words and an English street type (Street, Road, Avenue, Lane, Drive, …) | — |
| IPv4 | `pii_ipv4` | Dotted quad, each octet 0–255 | — |
| IPv6 | `pii_ipv6` | Full or compressed form | Must parse as an IPv6 address (rejects times and MAC addresses) |
| Payment card | `pii_payment_card` | 13–19 digits starting 3–6, optional spaces or hyphens | **Luhn** checksum |
| Bangladesh NID | `pii_bd_nid` | 17 digits starting with a birth year 1900–2099; or 10 or 13 digits **after an NID label** (`NID`, `National ID`, …) | Length and year range |
| Indian Aadhaar | `pii_aadhaar` | 12 digits, first digit 2–9, optional grouping `XXXX XXXX XXXX` | **Verhoeff** checksum |
| US SSN | `pii_us_ssn` | `AAA-GG-SSSS` (dashed) | Area not 000, 666 or 9xx; group not 00; serial not 0000 |
| UK National Insurance number | `pii_uk_nino` | Two prefix letters, six digits, suffix A–D, optional spaces | Disallowed first and second letters, and the reserved prefixes BG, GB, KN, NK, NT, TN, ZZ |

Every numeric rule requires a token boundary: no letter, digit, `_` or `-` immediately before or after. This keeps hashes, key IDs, UUIDs and redaction markers from ever being matched. It is covered by `tests/test_pii_identifiers_untouched.py`: 4,000 rounds of random identifiers, none redacted.

## Fixtures and measured results

| Measure | Result |
|---|---|
| Synthetic corpus | `tests/pii_corpus.py`: 60 generated, format-valid, fictitious instances per class (600 in total) |
| Detection on the corpus | 600 of 600 detected; every class 60/60 |
| End to end (`tests/test_m2_pii.py`) | The corpus is injected through a scanner's findings, file paths and evidence, then through the audit log. Afterwards every file under the state directory and all CLI output are searched: **0 raw instances**, covering the run and json/sarif/md/html reports, `runs show`, `evidence verify` and `fix-plan` |
| False positives on a clean corpus | 18,000 look-alike lines: versions, SHA-256 hashes, UUIDs, ISO timestamps, prices, ports, `file:line:col`, build and order numbers. **0 false positives in every class (0.0%)** |

The clean corpus doesn't represent every real repository. Real code will produce some false positives, for example IPv4-shaped version strings or test card numbers. A false positive only over-redacts; it never leaks.

## Limitations (also listed in every report under `redaction.pii.not_covered`)

- Personal names, dates of birth, and postal addresses without an English street type, or postcodes.
- Phone numbers in other national formats.
- Unformatted nine-digit SSNs.
- Unlabelled 10- or 13-digit Bangladesh NIDs, which can't be told apart from ordinary numbers.
- Other national identifiers, passports, driving licences, tax and bank account numbers.
- Biometric, health and location data.
- PII inside binary or encoded content (base64, compressed or encrypted data).
- Legitimate addresses such as `127.0.0.1` or documentation IPs are redacted too; this is deliberate over-redaction.
