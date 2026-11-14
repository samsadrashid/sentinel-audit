"""D-40: versioned JSON Schema contracts and the restricted validator.

Covers load-time refusal (unknown keywords, bad regexes, bad references, cycles), validation semantics
(booleans vs numbers, exact-one oneOf, structural uniqueItems, patternProperties + additionalProperties,
$ref siblings, bounds), resource limits, no-mutation, version gates, and compatibility with historical
artifacts and their signatures.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from sentinel import approvals, canonical, schema
from sentinel.crypto.signing import ED25519, PublicKey
from sentinel.schema import SchemaDefinitionError, SchemaError, SchemaViolation

ROOT = Path(__file__).parent / "fixtures/schemas"
HIST = ROOT / "historical"
SIGNED = HIST / "signed"
DRAFT = schema.DRAFT


def contract(name: str, body: dict[str, Any]) -> bytes:
    return json.dumps({"$schema": DRAFT, "$id": f"urn:sentinel:schema:{name}:v1", **body}).encode()


def load(**files: dict[str, Any]) -> Any:
    return schema.load_contracts(
        {f"{k.replace('_', '-')}.schema.json": contract(k.replace("_", "-"), v) for k, v in files.items()}
    )


def errors(loaded: Any, instance: Any, name: str = "t") -> str | None:
    ctx = schema._Ctx(loaded)
    return schema._errors(ctx, instance, loaded.contracts[name], name, "$", 0)


# ── bundled set ────────────────────────────────────────────────────────────
EXPECTED = {
    "common",
    "audit-config",
    "policy",
    "authorization-record",
    "approval",
    "decision",
    "operator-public-key",
    "trust-store",
    "nonce-ledger",
    "applied-policy",
    "run-key-metadata",
    "log-entry",
    "run-manifest",
    "manifest-signature",
    "evidence-record",
    "audit-result",
    "sarif-profile",
    "cli-output",
    "adapter-findings",
    # D-49 signing protocol v1 (engine side)
    "recovery-approval",
    "sign-request",
    "sign-response",
    "pending-request",
    # D-50
    "fix-plan",
}


def test_bundled_contract_set_is_complete_and_versioned():
    assert set(schema.contract_names()) == EXPECTED
    for name in EXPECTED:
        doc = schema.ensure_loaded().contracts[name]
        assert doc["$id"] == f"urn:sentinel:schema:{name}:v1" and doc["$schema"] == DRAFT


def test_shared_definitions_are_reused_not_duplicated():
    contracts = schema.ensure_loaded().contracts
    raw = {n: json.dumps(contracts[n]) for n in EXPECTED}
    assert sum("common.schema.json#/$defs/" in r for n, r in raw.items() if n != "common") >= 15
    defined = [d for n in EXPECTED if n != "cli-output" for d in contracts[n].get("$defs", {})]
    for d in ("hex64", "key_id", "approval_payload", "finding", "check_result", "host_report"):
        assert defined.count(d) == 1 and d in contracts["common"]["$defs"], d


# ── load-time refusal (Sentinel must not start) ────────────────────────────
@pytest.mark.parametrize(
    "body,msg",
    [
        ({"type": "object", "requried": ["a"]}, "unsupported keyword"),
        ({"type": "string", "format": "email"}, "unsupported keyword"),
        ({"if": {"type": "string"}}, "unsupported keyword"),
        ({"unevaluatedProperties": False}, "unsupported keyword"),
        ({"$dynamicRef": "#x"}, "unsupported keyword"),
        ({"type": "strng"}, "invalid type"),
        ({"type": ["string", "string"]}, "invalid type"),
        ({"required": ["a", "a"]}, "unique strings"),
        ({"enum": []}, "non-empty"),
        ({"minLength": -1}, "non-negative"),
        ({"minLength": True}, "non-negative"),
        ({"minItems": 3, "maxItems": 2}, "minItems > maxItems"),
        ({"oneOf": []}, "non-empty"),
        ({"uniqueItems": 1}, "boolean"),
        ({"$ref": "https://example.com/s.json"}, "only local"),
        ({"$ref": "#/properties/x"}, "only local"),
        ({"$ref": "../other.schema.json#/$defs/x"}, "only local"),
        ({"$ref": "#/$defs/missing"}, "unresolved reference"),
        ({"$ref": "nope.schema.json#/$defs/x"}, "unresolved reference"),
    ],
)
def test_invalid_schema_definitions_are_refused(body, msg):
    with pytest.raises(SchemaDefinitionError, match=msg):
        load(t=body)


def test_reference_cycles_are_refused():
    with pytest.raises(SchemaDefinitionError, match="reference cycle"):
        load(t={"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"items": {"$ref": "#/$defs/a"}}}})
    with pytest.raises(SchemaDefinitionError, match="reference cycle"):
        load(t={"$defs": {"a": {"properties": {"x": {"$ref": "#/$defs/a"}}}}})


def test_cross_file_local_references_resolve():
    loaded = load(lib={"$defs": {"n": {"type": "integer"}}}, t={"$ref": "lib.schema.json#/$defs/n"})
    assert errors(loaded, 3) is None and errors(loaded, "3") is not None


def test_file_naming_id_and_draft_are_enforced():
    with pytest.raises(SchemaDefinitionError, match=r"\$id"):
        schema.load_contracts({"t.schema.json": json.dumps({"$schema": DRAFT, "$id": "urn:x"}).encode()})
    with pytest.raises(SchemaDefinitionError, match=r"\$schema"):
        schema.load_contracts({"t.schema.json": json.dumps({"$id": "urn:sentinel:schema:t:v1"}).encode()})
    with pytest.raises(SchemaDefinitionError, match="file name"):
        schema.load_contracts({"T.json": b"{}"})
    with pytest.raises(SchemaDefinitionError, match="duplicate key"):
        schema.load_contracts(
            {
                "t.schema.json": b'{"$schema":"'
                + DRAFT.encode()
                + b'","$id":"urn:sentinel:schema:t:v1","type":"x","type":"y"}'
            }
        )
    with pytest.raises(SchemaDefinitionError, match="too large"):
        schema.load_contracts({"t.schema.json": b" " * (schema.MAX_SCHEMA_FILE_BYTES + 1)})


def test_damaged_bundled_schema_prevents_every_command(monkeypatch, capsys):
    from sentinel import cli

    real = schema._bundled_files()
    bad = dict(real)
    bad["policy.schema.json"] = real["policy.schema.json"].replace(b'"properties"', b'"propertees"', 1)
    monkeypatch.setattr(schema, "_STATE", None)
    monkeypatch.setattr(schema, "_bundled_files", lambda: bad)
    for argv in (["--json", "version"], ["--json", "status"], ["--json", "audit", "--config", "x"]):
        assert cli.main(argv) == cli.EXIT_INTERNAL
        assert json.loads(capsys.readouterr().out)["error"] == "schema_definition_invalid"
    monkeypatch.setattr(schema, "_STATE", None)


# ── regex subset ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "pattern",
    [
        "^[0-9a-f]{64}$",
        "^(?:ed25519|p256):[0-9a-f]{32}$",
        "^[A-Za-z0-9+/]*={0,2}$",
        "^sentinel/v1/approval/(?:review\\.verify_no_evidence|suppress)$",
        "^a(b|c)?d+$",
        "^[a-z_:/@.-]{1,10}$",
    ],
)
def test_supported_patterns(pattern):
    schema.check_pattern(pattern)


@pytest.mark.parametrize(
    "pattern,reason",
    [
        ("[a-z]+", "anchored"),
        ("^[a-z]+", "anchored"),
        ("^a|b$", "top-level alternation"),
        ("^a.b$", "unsupported construct"),
        ("^\\d+$", "unsupported escape"),
        ("^\\w+$", "unsupported escape"),
        ("^\\s$", "unsupported escape"),
        ("^\\bword$", "unsupported escape"),
        ("^\\u0041$", "unsupported escape"),
        ("^\\x41$", "unsupported escape"),
        ("^(a)\\1$", "unsupported escape"),
        ("^(?=a)a$", "only (?:...)"),
        ("^(?!a)b$", "only (?:...)"),
        ("^(?<=a)b$", "only (?:...)"),
        ("^(?P<n>a)$", "only (?:...)"),
        ("^(?i)a$", "only (?:...)"),
        ("^[^a]$", "negated"),
        ("^[a-Z]$", "unsupported range"),
        ("^[0-z]$", "unsupported range"),
        ("^[[a]]$", "nested"),
        ("^[]$", "empty"),
        ("^a**$", "stacked"),
        ("^a+?$", "stacked"),
        ("^*a$", "dangling"),
        ("^a{2,1}$", "repetition bounds"),
        ("^a{1,5000}$", "repetition bounds"),
        ("^a{x}$", "bad repetition"),
        ("^(a$", "unbalanced"),
        ("^a)$", "unbalanced"),
        ("^a\\$", "anchored"),
        ("^a$b$", "unsupported construct"),
        ("^é$", "unsupported construct"),
    ],
)
def test_unsupported_patterns_refused(pattern, reason):
    with pytest.raises(SchemaDefinitionError, match=reason):
        schema.check_pattern(pattern)


def test_pattern_semantics_match_ecma_anchors():
    p = schema.check_pattern("^abc$")
    assert p.match("abc") and not p.match("abc\n") and not p.match("xabc") and not p.match("abcd")
    ascii_only = schema.check_pattern("^[a-z]+$")
    assert not ascii_only.match("é")


# ── validation semantics ───────────────────────────────────────────────────
def test_booleans_are_not_numbers_and_floats_are_not_integers():
    loaded = load(t={"$defs": {"i": {"type": "integer"}, "n": {"type": "number"}}, "type": "object"})
    i = loaded.contracts["t"]["$defs"]["i"]
    n = loaded.contracts["t"]["$defs"]["n"]
    ctx = schema._Ctx(loaded)
    assert schema._errors(ctx, 1, i, "t", "$", 0) is None
    assert schema._errors(ctx, True, i, "t", "$", 0) is not None
    assert schema._errors(ctx, 1.0, i, "t", "$", 0) is not None  # stricter than 2020-12 (documented)
    assert schema._errors(ctx, 1.5, n, "t", "$", 0) is None
    assert schema._errors(ctx, False, n, "t", "$", 0) is not None
    loaded = load(t={"enum": [1, "a"]})
    assert errors(loaded, True) is not None  # true is not 1
    loaded = load(t={"const": False})
    assert errors(loaded, 0) is not None and errors(loaded, False) is None


def test_one_of_requires_exactly_one():
    loaded = load(t={"oneOf": [{"type": "integer"}, {"minimum": 0}]})
    assert errors(loaded, -1) is None  # integer only
    assert "matched 2" in (errors(loaded, 5) or "")  # both
    assert errors(loaded, "x") is None  # strings satisfy minimum vacuously: exactly one
    assert "matched 0" in (errors(loaded, -1.5) or "")  # neither
    loaded = load(t={"oneOf": [{"type": "string"}, {"type": "null"}]})
    assert errors(loaded, None) is None and errors(loaded, 1) is not None


def test_unique_items_uses_json_structural_equality():
    loaded = load(t={"type": "array", "uniqueItems": True})
    assert errors(loaded, [1, True]) is None  # bool is not a number
    assert errors(loaded, [1, 1.0]) is not None  # 1 == 1.0 in JSON
    assert errors(loaded, [{"a": 1, "b": 2}, {"b": 2, "a": 1}]) is not None  # object key order ignored
    assert errors(loaded, [[1, 2], [2, 1]]) is None  # array order matters
    assert errors(loaded, [0, False, None, "0"]) is None


def test_pattern_properties_with_additional_properties():
    loaded = load(
        t={
            "type": "object",
            "properties": {"fixed": {"type": "string"}},
            "patternProperties": {"^x_[a-z]+$": {"type": "integer"}},
            "additionalProperties": False,
        }
    )
    assert errors(loaded, {"fixed": "a", "x_one": 1}) is None
    assert errors(loaded, {"x_one": "not int"}) is not None
    assert "unexpected or invalid property 'other'" in (errors(loaded, {"other": 1}) or "")
    loaded = load(
        t={
            "type": "object",
            "patternProperties": {"^a$": {"type": "integer"}},
            "additionalProperties": {"type": "string"},
        }
    )
    assert errors(loaded, {"a": 1, "b": "s"}) is None and errors(loaded, {"b": 2}) is not None


def test_ref_siblings_apply_together():
    loaded = load(t={"$defs": {"s": {"type": "string"}}, "$ref": "#/$defs/s", "maxLength": 3})
    assert errors(loaded, "abc") is None
    assert errors(loaded, "abcd") is not None  # sibling applies
    assert errors(loaded, 7) is not None  # referenced applies


@pytest.mark.parametrize(
    "sch,ok,bad",
    [
        ({"type": "integer", "minimum": 0, "maximum": 7}, [0, 7], [-1, 8]),
        ({"type": "string", "minLength": 2, "maxLength": 3}, ["ab", "abc", "éé"], ["a", "abcd"]),
        ({"type": "array", "minItems": 1, "maxItems": 2}, [[1], [1, 2]], [[], [1, 2, 3]]),
    ],
)
def test_numeric_and_collection_boundaries(sch, ok, bad):
    loaded = load(t=sch)
    for v in ok:
        assert errors(loaded, v) is None, v
    for v in bad:
        assert errors(loaded, v) is not None, v


def test_boolean_schemas():
    loaded = load(t={"type": "object", "properties": {"any": True, "never": False}})
    assert errors(loaded, {"any": [1, {"x": None}]}) is None
    assert errors(loaded, {"never": 1}) is not None


def test_validation_is_bounded():
    deep: Any = 0
    for _ in range(schema.MAX_DEPTH + 5):
        deep = [deep]
    loaded = load(t={"type": "array", "items": True})
    loaded2 = load(
        lib={
            "$defs": {
                "a": {"type": "array", "items": {"$ref": "#/$defs/b"}},
                "b": {"type": "array", "items": True},
            }
        },
        t={"$ref": "lib.schema.json#/$defs/a"},
    )
    assert errors(loaded, deep) is None  # `true` does not descend
    big = [[0] * 1000 for _ in range(600)]
    nested = load(t={"type": "array", "items": {"type": "array", "items": {"type": "integer"}}})
    with pytest.raises(SchemaError) as e:
        errors(nested, big)
    assert e.value.code == "schema_too_complex"
    assert errors(loaded2, [[1]]) is None


def test_validation_never_mutates_input():
    data = json.loads((SIGNED / "run/reports/report.json").read_text())
    before = copy.deepcopy(data)
    schema.validate(data, "audit-result")
    assert data == before and canonical.encode(data) == canonical.encode(before)

    def freeze(v: Any) -> Any:
        if isinstance(v, dict):
            return MappingProxyType({k: freeze(x) for k, x in v.items()})
        if isinstance(v, list):
            return tuple(freeze(x) for x in v)
        return v

    # read-only views: any write attempt would raise
    small = load(t={"type": "object", "properties": {"a": {"type": "integer"}}})
    assert schema._errors(schema._Ctx(small), freeze({"a": 1}), {"properties": {}}, "t", "$", 0) is None


def test_non_json_values_are_rejected():
    loaded = load(t={"enum": [1]})
    with pytest.raises(SchemaError):
        errors(loaded, object())


# ── version gates ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("v", ["2.0", "1", "1.0.0", 1])
def test_unsupported_result_and_manifest_versions(v):
    for f, name in (("run/reports/report.json", "audit-result"), ("run/manifest.json", "run-manifest")):
        data = json.loads((SIGNED / f).read_text())
        data["schema_version"] = v
        with pytest.raises(SchemaError) as e:
            schema.check_version(data)
        assert e.value.code == "unsupported_version"
        with pytest.raises(SchemaError):
            schema.validate(data, name)


def test_unsupported_approval_context_version():
    data = json.loads((SIGNED / "policy.approval.json").read_text())
    data["payload"]["context"] = "sentinel/v2/approval/policy.change"
    with pytest.raises(SchemaError) as e:
        approvals.Approval.from_json(data)
    assert e.value.code == "unsupported_version"


# ── historical compatibility and cryptographic integrity ───────────────────
def _sums() -> dict[str, str]:
    out = {}
    for line in (SIGNED / "SHA256SUMS").read_text().splitlines():
        h, name = line.split("  ", 1)
        out[name] = h
    return out


def test_historical_signed_set_is_byte_identical():
    for name, h in _sums().items():
        assert hashlib.sha256((SIGNED / name).read_bytes()).hexdigest() == h, name


SIGNED_MAP = [
    ("trust.json", "trust-store"),
    ("policy.json", "policy"),
    ("policy.approval.json", "approval"),
    ("record.json", "authorization-record"),
    ("record.approval.json", "approval"),
    ("nonces.json", "nonce-ledger"),
    ("run/manifest.json", "run-manifest"),
    ("run/manifest.sig.json", "manifest-signature"),
    ("run/reports/report.json", "audit-result"),
    ("run/reports/report.sarif", "sarif-profile"),
]


@pytest.mark.parametrize("name,contract_name", SIGNED_MAP)
def test_historical_signed_artifacts_validate_without_changing_bytes(name, contract_name):
    raw = (SIGNED / name).read_bytes()
    data = canonical.decode_strict(raw)
    enc_before = canonical.encode(data)
    schema.validate(data, contract_name)
    assert canonical.encode(data) == enc_before
    assert (SIGNED / name).read_bytes() == raw


def test_historical_signatures_still_verify_after_validation():
    keys = json.loads((SIGNED / "keys.json").read_text())
    op = PublicKey.from_raw(bytes.fromhex(keys["operator_public_hex"]), ED25519)
    files = [
        "policy.approval.json",
        "record.approval.json",
        *(f"decisions/{p.name}" for p in (SIGNED / "decisions").iterdir()),
        *(f"decisions-revocations/{p.name}" for p in (SIGNED / "decisions-revocations").iterdir()),
    ]
    for f in files:
        raw = canonical.decode_strict((SIGNED / f).read_bytes())
        ap_json = raw["approval"] if "approval" in raw else raw
        schema.validate(raw, "decision" if f.startswith("decisions/") else "approval")
        ap = approvals.Approval.from_json(ap_json)
        assert op.verify(ap.signature, ap.payload_bytes), f
        assert ap.payload_bytes == canonical.encode(ap_json["payload"])
    # policy approval binds the policy file's raw bytes
    pol_ap = approvals.load_approval_file(SIGNED / "policy.approval.json")
    assert pol_ap.payload["subject"]["sha256"] == canonical.sha256_hex((SIGNED / "policy.json").read_bytes())
    # the run manifest signature verifies over the unchanged manifest bytes
    run_pub = PublicKey.from_raw(bytes.fromhex(keys["run_public_hex"]), ED25519)
    body = (SIGNED / "run/manifest.json").read_bytes()
    sig = json.loads((SIGNED / "run/manifest.sig.json").read_text())
    assert run_pub.verify(base64.b64decode(sig["signature"]), b"sentinel/v1/run/manifest\n" + body)
    manifest = canonical.decode_strict(body)
    report = canonical.decode_strict((SIGNED / "run/reports/report.json").read_bytes())
    assert canonical.digest(report) == manifest["result_sha256"]


def test_historical_log_and_evidence_validate():
    for line in (SIGNED / "run/audit-log.jsonl").read_text().splitlines():
        schema.validate(json.loads(line), "log-entry")
    for p in (SIGNED / "run/evidence").glob("*.meta.json"):
        schema.validate(json.loads(p.read_text()), "evidence-record")


def _corpus() -> list[tuple[str, Path]]:
    return [(d.name, f) for d in sorted((HIST / "corpus").iterdir()) for f in sorted(d.iterdir())]


@pytest.mark.parametrize("name,path", _corpus(), ids=lambda x: x if isinstance(x, str) else x.name)
def test_historical_corpus_validates(name, path):
    schema.validate(json.loads(path.read_text()), name)


def test_real_run_with_redaction_markers_validates(tmp_path, trust, ledger):
    from .test_redaction import PW, HostileAdapter, _audit

    out = _audit(tmp_path, trust, ledger, HostileAdapter())
    result = json.loads((out.run_dir / "reports/report.json").read_text())
    assert "[REDACTED:" in json.dumps(result) and PW not in json.dumps(result)
    schema.validate(result, "audit-result")


# ── invalid fixtures and malformed input ───────────────────────────────────
def test_invalid_fixtures_are_rejected():
    for d in (ROOT / "invalid").iterdir():
        for f in d.iterdir():
            with pytest.raises(SchemaError):
                schema.validate(json.loads(f.read_text()), d.name)


def _mutated(name: str, contract_name: str) -> dict[str, Any]:
    return canonical.decode_strict((SIGNED / name).read_bytes())


@pytest.mark.parametrize("name,contract_name", SIGNED_MAP)
def test_unknown_field_missing_field_and_wrong_type_rejected(name, contract_name):
    data = _mutated(name, contract_name)
    with pytest.raises(SchemaError):
        schema.validate({**data, "unexpected_field": 1}, contract_name)
    if contract_name != "policy":  # every policy key is optional
        k = sorted(data)[0]
        with pytest.raises(SchemaError):
            schema.validate({x: v for x, v in data.items() if x != k}, contract_name)
    k = next(iter(sorted(data)))
    with pytest.raises(SchemaError):
        schema.validate(
            {**data, k: {"wrong": [object.__name__]}} if not isinstance(data[k], dict) else {**data, k: 7},
            contract_name,
        )


@pytest.mark.parametrize("bad", [[], "x", 1, None, True])
def test_non_object_roots_rejected(bad):
    for c in ("approval", "trust-store", "run-manifest", "audit-config", "policy"):
        with pytest.raises(SchemaError):
            schema.validate(bad, c)


def test_duplicate_keys_rejected_before_schema():
    from sentinel.errors import ValidationError

    with pytest.raises(ValidationError):
        canonical.decode_strict(b'{"keys":[],"keys":[]}')


def test_unicode_and_redaction_markers_in_text_fields():
    data = canonical.decode_strict((SIGNED / "run/reports/report.json").read_bytes())
    data["findings"][0]["title"] = "Ünïcødé ✓ [REDACTED:github_token:0123456789ab] 测试"
    schema.validate(data, "audit-result")
    data["findings"][0]["fingerprint"] = "É" * 64  # pattern-restricted field refuses non-ASCII
    with pytest.raises(SchemaError):
        schema.validate(data, "audit-result")


def test_optional_and_nullable_fields():
    data = canonical.decode_strict((SIGNED / "run/reports/report.json").read_bytes())
    f = data["findings"][0]
    for review in (None, {"payload_hash": "a" * 64, "key_id": "ed25519:" + "0" * 32, "rationale": "x"}):
        schema.validate({**data, "findings": [{**f, "review": review}]}, "audit-result")
    with pytest.raises(SchemaError):
        schema.validate({**data, "findings": [{**f, "review": "yes"}]}, "audit-result")
    no_redaction = {k: v for k, v in data.items() if k != "redaction"}
    schema.validate(no_redaction, "audit-result")  # redaction block is optional


def test_output_violation_is_a_distinct_internal_error():
    with pytest.raises(SchemaViolation):
        schema.check_output({"keys": "nope"}, "trust-store")
    with pytest.raises(SchemaDefinitionError):
        schema.check_output({}, "no-such-contract")
    with pytest.raises(SchemaDefinitionError):
        schema.validate({}, "cli-output", "no_such_def")


def test_instance_depth_limit_is_enforced_independently_of_the_step_budget():
    """An acyclic chain of 40 definitions descends 80 schema levels for a 40-deep array."""
    n = 40
    defs = {f"d{i}": {"type": "array", "items": {"$ref": f"#/$defs/d{i + 1}"}} for i in range(n)}
    defs[f"d{n}"] = {"type": "integer"}
    loaded = load(t={"$defs": defs, "$ref": "#/$defs/d0"})
    inst: Any = 1
    for _ in range(n):
        inst = [inst]
    with pytest.raises(SchemaError) as e:
        errors(loaded, inst)
    assert e.value.code == "schema_too_complex" and "nesting deeper" in str(e.value)
    shallow: Any = 1
    for _ in range(20):
        shallow = [shallow]
    loaded20 = load(
        t={
            "$defs": {**{f"d{i}": defs[f"d{i}"] for i in range(20)}, "d20": {"type": "integer"}},
            "$ref": "#/$defs/d0",
        }
    )
    assert errors(loaded20, shallow) is None
