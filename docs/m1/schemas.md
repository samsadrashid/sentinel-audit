# Versioned JSON Schemas (D-40)

Status: implemented in M1 Task 2. Scope: D-40 only. Signing-protocol (D-49) and `fix-plan` (D-50)
contracts are deferred to M1 Tasks 3 and 4.

## Contract set

`src/sentinel/schemas/` holds 19 JSON Schema 2020-12 documents: `common` (shared `$defs` only) and
18 artifact contracts:

`audit-config`, `policy`, `authorization-record`, `approval`, `decision`, `operator-public-key`,
`trust-store`, `nonce-ledger`, `applied-policy`, `run-key-metadata`, `log-entry`, `run-manifest`,
`manifest-signature`, `evidence-record`, `audit-result`, `sarif-profile`, `cli-output`,
`adapter-findings`.

Each file is named `<name>.schema.json`, declares
`"$schema": "https://json-schema.org/draft/2020-12/schema"` and
`"$id": "urn:sentinel:schema:<name>:v1"`. Shared shapes (hashes, nonces, key ids, run ids,
enums, limits, approval payloads, findings, summaries and so on) live once in
`common.schema.json#/$defs/...` and are referenced from the other files.

## Versioning and compatibility

* The contract version is the `:v1` suffix of `$id`. A breaking change adds a new `:v2` file. It does
  not edit `v1` in place.
* Artifact version gates are unchanged, so signed bytes stay identical:
  * The run manifest and the audit result carry `"schema_version": "1.0"`, enforced as `const`.
    `check_version` raises `SchemaError(code="unsupported_version")` for any other value.
  * Approval contexts must start with `sentinel/v1/`. Anything else is `unsupported_version`.
  * No new version fields were added to existing artifacts. Adding one would change canonical bytes
    and invalidate historical signatures.
* Compatibility evidence is in `tests/fixtures/schemas/historical/`:
  * `signed/` holds 20 artifacts from the pre-D-40 engine, with `SHA256SUMS` and public keys only.
  * `corpus/` holds 215 artifacts captured from the previous test suite.

  Tests check that all of them validate, that every signature still verifies, and that every hash
  is unchanged.
* Validation never mutates, copies or re-serialises the instance. Canonical bytes are untouched.

## Supported keyword subset

Allowed keywords:

* `$schema`, `$id`, `$ref`, `$defs`, `$comment`, `title`, `description`;
* `type`, `properties`, `required`, `additionalProperties`, `patternProperties`;
* `enum`, `const`, `pattern`, `minLength`, `maxLength`, `minimum`, `maximum`;
* `items`, `minItems`, `maxItems`, `uniqueItems`, `oneOf`.

Any other keyword stops loading, including misspellings, `format`, `anyOf`, `allOf`, `if`, `not` and
`$dynamicRef`. So does any malformed keyword value.

Semantics follow 2020-12, with these deliberate deviations and clarifications:

| Topic | Behaviour |
|---|---|
| Booleans | `true`/`false` are never `integer` or `number`. |
| `1.0` | Not an `integer`. This is stricter than 2020-12. Sentinel's canonical encoding has no floats. |
| `oneOf` | Exactly one branch must match. Zero or two or more matches fail. |
| `uniqueItems` | Uses JSON structural equality: `1` and `1.0` are equal, `1` and `true` are not, and object key order is ignored. |
| `additionalProperties` | Applies only to names matched by neither `properties` nor any `patternProperties` regex. |
| `$ref` siblings | Evaluated together with the `$ref` target (2020-12 applicator semantics). This is not draft-07 override. |
| Bounds | `minimum`/`maximum`/`minLength`/`maxLength`/`minItems`/`maxItems` are inclusive. Length counts code points. |

## Regex subset

Patterns must be fully anchored as `^...$` and 2–512 characters long. They are compiled with
`re.ASCII`, and the trailing `$` is replaced with `\Z`. This makes the match ECMA-262 compatible:
Python's `$` would also accept a trailing newline.

Supported:

* literal characters `[A-Za-z0-9 _:/@=,+~-]`;
* the escapes `\. \- \/ \\ \+ \* \? \( \) \[ \] \{ \} \| \^ \$ \: \_ \@`;
* character classes `[...]` of literals and same-kind ASCII ranges (`a-z`, `A-Z`, `0-9` and their
  sub-ranges);
* quantifiers `? * + {n} {n,} {n,m}`, with n ≤ m ≤ 1000;
* groups `(...)` and `(?:...)`;
* alternation, but only inside a group.

Refused at load, because these constructs differ between Python and ECMA-262 or aren't needed:

* `.`;
* the class escapes `\d \w \s \b \B`;
* the anchors `\A \Z \z`;
* the escapes `\x` and `\u`;
* back-references and lookaround;
* named, flagged and atomic groups;
* negated and nested classes;
* mixed-kind ranges;
* stacked or lazy quantifiers;
* a mid-pattern `^` or `$`;
* top-level alternation;
* repetition above 1000.

Both accepted and refused patterns are tested in `tests/test_schemas.py`.

## References

* Only two `$ref` forms are allowed:
  * `#/$defs/<name>` refers to the same file;
  * `<contract>.schema.json#/$defs/<name>` refers to another bundled contract.
* URLs, absolute URIs, `$id`-based lookups, anchors and JSON pointers deeper than one `$defs` level
  are refused. **No network or filesystem lookup is ever performed.** Contracts are read only from
  the installed package via `importlib.resources`.
* A reference to a missing file or a missing definition stops loading.
* Reference cycles of any length stop loading. Recursive data shapes aren't needed in v1.

## Limits

| Limit | Value | Effect |
|---|---|---|
| Schema file size | 512 KiB | refused at load |
| Schema nesting depth | 48 | refused at load |
| Instance depth | 64 | `SchemaError(code="schema_too_complex")` |
| Keyword evaluations per validation | 500,000 | `SchemaError(code="schema_too_complex")` |
| Regex repetition bound | 1000 | refused at load |

## Failure behaviour

| Failure | Error | CLI exit |
|---|---|---|
| Damaged, unknown-keyword or bad-reference schema | `SchemaDefinitionError`, raised at start-up before any command runs | 7 `schema_definition_invalid` |
| Input fails its contract | `SchemaError` (`schema_invalid`, `unsupported_version`, `schema_too_complex`) | 4 |
| Stored artifact fails on read (manifest, signature, result, log) | `IntegrityError` | integrity exit |
| Engine output fails its contract | `SchemaViolation`. Nothing is signed, persisted or printed. | 7 `schema_violation` |
| Adapter findings fail `adapter-findings` | The check becomes `ERROR` with reason `schema_invalid`. | — |

No schema failure can produce `PASS`.

Every input boundary runs in the approved order: **strict decoding → JSON Schema → existing domain
validation**, all before any trust decision, signature verification, persistence or printing. In
particular:

* A policy file is schema-checked before its approval is verified. No nonce is consumed and no
  applied-policy record is written for a schema-invalid policy.
* A run manifest is schema-checked before its signature is verified.
* A stored result is schema-checked before it is compared with the manifest.

Existing error classifications are kept through explicit mapping, not by reordering:

* `SchemaError` is a `ValidationError`, so the exit-code classes are unchanged.
* Stored artifacts map schema failures to `IntegrityError`.
* For approvals, `_map_approval_schema_error` restores the D-42/D-33 messages ("unknown approval
  action", "approval context does not match its action"). It reads only the two plain strings and
  keeps code `schema_invalid`.
* Business rules stay domain errors, because the contracts check shape only. For example, B3 is still
  `BlockedError("b3_prohibited")`.

`tests/test_schema_boundaries.py` contains tripwire tests (`test_order_*`). Each forces a schema
failure and fails if the domain parser, signature verification, trust decision or storage step is
reached.

The domain checks that the schema now always catches first stay in place as defence in depth. Two
examples are the D-42 unknown-action and context checks in `Approval.from_json`. Their mutants
(`eng-d42-*`) now target the explicit mapping.

## Raw CLI output

`_raw` carries only `sentinel report` bodies printed to stdout. It can carry JSON, so it has its own
contract, checked after redaction and before printing by `cli._check_raw_output`. The same check runs
before `--output` writes a file.

| Format | Check |
|---|---|
| `json` | strict decoding, then `audit-result` |
| `sarif` | strict decoding, then `sarif-profile` |
| `md`, `html` | **Documented exception: text, no JSON contract.** Refused if the body decodes as JSON. |
| anything else | refused |

Any other command that returns `_raw`, or a `_raw` value that is not `bytes`, is withheld with exit 7
and `schema_violation: output withheld`. These rules are tested in `test_raw_*`.

## Legacy Secure Enclave key-file form: removed (compatibility break)

The `handle_b64` key-metadata form, from the rejected handle-on-disk design (SE-H1 FAIL, superseded
by D-47), is **no longer accepted**. The operator approved its removal during the M1 Task 2 review.

* `key enrol` and `key rotate` accept only the public-only form, exactly
  `{key_id, algorithm, public_hex}`. The `operator-public-key` contract contains only that shape.
* A file containing `handle_b64` is refused with `SchemaError` code `legacy_key_format` (exit 4),
  before any schema, domain, approval or trust step. The handle value is never decoded, imported,
  stored or used. Nothing is written to `state/keys/secure-enclave/`, and the approval is not
  consumed.
* `admin.py` no longer imports or writes Secure Enclave key metadata. No production module outside
  the dormant `keys/secure_enclave.py` references the metadata format or its store, or builds a
  signer. `production_provider` still has no success path.
* The D-47 signing-device architecture is unchanged.

**Conversion.** Replace a legacy file with:

```json
{"key_id": "<key_id>", "algorithm": "ecdsa-p256-sha256", "public_hex": "<public_x963_hex>"}
```

Use the same `key_id` and `algorithm` values as the legacy file, and take `public_hex` from its
`public_x963_hex`. Drop `handle_b64`, `backend` and `created_at`. Delete any leftover files under
`state/keys/secure-enclave/`: Sentinel never reads them.

**Unaffected:** trust stores, enrolled public keys, approvals, decisions and the historical signed
artifacts. None of them contain a handle; `tests/test_legacy_se_keyfile.py` checks this.

Because the contract set is new in Task 2 and has never been released, `operator-public-key:v1` was
narrowed in place rather than versioned.

## Distribution

Schemas ship as package data in `sentinel/schemas/`. `tests/test_schema_distribution.py`:

* builds the wheel and sdist offline with `uv build --offline`;
* checks that all 19 schemas are in both artifacts, byte-identical to the source tree;
* checks that the historical fixtures and this document are in the sdist;
* installs the wheel with `--no-deps` into a temporary target;
* calls `ensure_loaded()` from an isolated (`-I`) interpreter, outside the source tree.

## Official JSON Schema Test Suite: pending approval

Nothing has been downloaded or installed. The suite needs separate operator approval. Proposed
process:

1. **Source.** Use `https://github.com/json-schema-org/JSON-Schema-Test-Suite`, pinned to one full
   40-character commit SHA chosen at approval time (the latest commit on `main`). The operator
   approves the SHA in chat, and it is recorded in the decision register. No floating ref is used.
2. **Fetch.** Download the GitHub archive for that exact SHA, as a test-only dev artifact, into an
   isolated directory. It is not a runtime dependency and is not shipped in the wheel.
3. **Integrity.** Record the archive's SHA-256 next to the commit SHA. Later fetches must match both,
   or the run fails.
4. **Licence.** Read `COPYING` at that commit and confirm the MIT licence text. Add an entry to
   `THIRD_PARTY_NOTICES` and `licenses/`, then run `scripts/license_audit.py check --strict`.
5. **Use.** Run only the `tests/draft2020-12/` files for the supported keywords. Record each case
   whose result differs because of a documented deviation (unknown keywords refused, `1.0` not an
   integer, remote refs refused, regex subset) as an expected deviation, with a reason. Every other
   case must pass.
