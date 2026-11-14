"""Versioned JSON Schema contracts (D-40) and Sentinel's restricted validator.

The schemas in ``sentinel/schemas/`` are standard JSON Schema 2020-12 documents that use only a small,
explicit keyword subset, so external tools can consume them. This module validates against them with
deliberately *stricter* rules than the specification:

* **Load-time checks (fail closed at start-up).** Every schema file is parsed strictly and walked once.
  Any keyword outside ``ALLOWED_KEYWORDS`` (including misspellings and ``format``), any malformed keyword
  value, any regex outside the supported subset, any ``$ref`` that is not a local reference to an
  existing ``$defs`` entry, and any reference cycle raise ``SchemaDefinitionError``. The CLI calls
  ``ensure_loaded()`` before running any command, so a damaged schema set prevents Sentinel from starting.
* **References are local only.** ``$ref`` is ``#/$defs/<name>`` (same file) or
  ``<contract>.schema.json#/$defs/<name>`` (another bundled contract). URLs, absolute URIs, JSON-pointer
  paths deeper than one ``$defs`` level and anchors are refused. Nothing is ever fetched.
* **Bounded validation.** Instances deeper than ``MAX_DEPTH`` or needing more than ``MAX_STEPS`` keyword
  evaluations are rejected (``schema_too_complex``).
* **No mutation.** Validation only reads the already-decoded instance; it never copies, normalises or
  re-serialises it, so canonical bytes and signatures are untouched.
* **Booleans are not numbers.** ``integer`` accepts Python ``int`` but never ``bool``; ``number`` accepts
  ``int``/``float`` but never ``bool``. A float with zero fraction (``1.0``) is **not** an integer here
  (stricter than 2020-12; Sentinel's canonical encoding has no floats).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from typing import Any

from .errors import SentinelError, ValidationError

DRAFT = "https://json-schema.org/draft/2020-12/schema"
MAX_DEPTH = 64
MAX_STEPS = 500_000
MAX_SCHEMA_DEPTH = 48
MAX_SCHEMA_FILE_BYTES = 512 * 1024
MAX_REPETITION = 1000

ALLOWED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "$comment",
        "title",
        "description",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "patternProperties",
        "enum",
        "const",
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "oneOf",
    }
)
TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})
_CONTRACT_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_DEF_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_REF = re.compile(r"^(?:([a-z][a-z0-9-]{0,63})\.schema\.json)?#/\$defs/([A-Za-z][A-Za-z0-9_]{0,63})$")


class SchemaDefinitionError(SentinelError):
    """A bundled schema is invalid. Sentinel must not start."""


class SchemaError(ValidationError):
    """An instance failed a schema (input boundary). ``code`` is a stable machine reason."""

    def __init__(self, message: str, code: str = "schema_invalid") -> None:
        super().__init__(message)
        self.code = code


class SchemaViolation(SentinelError):
    """Engine-produced output failed its contract. Nothing may be signed, persisted or printed."""


# ── regex subset ──────────────────────────────────────────────────────────
# Supported: literals [A-Za-z0-9 _:/@=,+~-]; escaped punctuation \. \- \/ \\ \+ \* \? \( \) \[ \] \{ \}
# \| \^ \$ \: \_ \@ ; character classes [...] of those literals and same-kind ASCII ranges (a-z, A-Z, 0-9
# and their sub-ranges), no negation; quantifiers ? * + {n} {n,} {n,m} (n<=m<=1000), never stacked or lazy;
# groups (...) and (?:...); alternation | only inside a group. The whole pattern must be ^...$.
# Refused (Python/ECMA-262 ambiguities or unneeded power): '.', \d \w \s \b \B \A \Z \z, \x \u escapes,
# back-references, lookaround, named/flagged groups, negated classes, nested classes, '^'/'$' mid-pattern.
_LITERAL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _:/@=,+~-")
_ESCAPABLE = set(".-/\\+*?()[]{}|^$:_@")
_CLASS_LITERAL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_:/@+.=~ ")


def _range_ok(a: str, b: str) -> bool:
    for lo, hi in (("a", "z"), ("A", "Z"), ("0", "9")):
        if lo <= a <= hi and lo <= b <= hi:
            return a <= b
    return False


def check_pattern(pattern: str) -> re.Pattern[str]:
    """Validate ``pattern`` against the supported subset and compile it. Raises SchemaDefinitionError."""
    if not isinstance(pattern, str) or len(pattern) < 2 or len(pattern) > 512:
        raise SchemaDefinitionError(f"pattern must be a 2-512 character string: {pattern!r}")
    if not pattern.startswith("^") or not pattern.endswith("$") or pattern.endswith("\\$"):
        raise SchemaDefinitionError(f"pattern must be anchored as ^...$: {pattern!r}")
    body = pattern[1:-1]
    i, depth, prev_quantifiable, top_alt = 0, 0, False, False
    while i < len(body):
        c = body[i]
        if c == "\\":
            if i + 1 >= len(body) or body[i + 1] not in _ESCAPABLE:
                raise SchemaDefinitionError(f"unsupported escape in pattern {pattern!r}")
            i, prev_quantifiable = i + 2, True
        elif c == "[":
            j = i + 1
            if j < len(body) and body[j] == "^":
                raise SchemaDefinitionError(f"negated character class not supported: {pattern!r}")
            members = 0
            while j < len(body) and body[j] != "]":
                ch = body[j]
                if ch == "\\":
                    if j + 1 >= len(body) or body[j + 1] not in {"-", "]", "\\", "."}:
                        raise SchemaDefinitionError(f"unsupported class escape in {pattern!r}")
                    j += 2
                elif ch == "[":
                    raise SchemaDefinitionError(f"nested character class in {pattern!r}")
                elif j + 2 < len(body) and body[j + 1] == "-" and body[j + 2] != "]":
                    if not _range_ok(ch, body[j + 2]):
                        raise SchemaDefinitionError(f"unsupported range {ch}-{body[j + 2]} in {pattern!r}")
                    j += 3
                elif ch in _CLASS_LITERAL or ch == "-":
                    j += 1
                else:
                    raise SchemaDefinitionError(f"unsupported class member {ch!r} in {pattern!r}")
                members += 1
            if j >= len(body) or members == 0:
                raise SchemaDefinitionError(f"unterminated or empty character class in {pattern!r}")
            i, prev_quantifiable = j + 1, True
        elif c == "(":
            if body.startswith("(?", i):
                if not body.startswith("(?:", i):
                    raise SchemaDefinitionError(f"only (?:...) groups are supported: {pattern!r}")
                i += 3
            else:
                i += 1
            depth, prev_quantifiable = depth + 1, False
        elif c == ")":
            if depth == 0:
                raise SchemaDefinitionError(f"unbalanced ')' in {pattern!r}")
            depth, i, prev_quantifiable = depth - 1, i + 1, True
        elif c == "|":
            if depth == 0:
                top_alt = True
            i, prev_quantifiable = i + 1, False
        elif c in "?*+":
            if not prev_quantifiable:
                raise SchemaDefinitionError(f"stacked, lazy or dangling quantifier in {pattern!r}")
            i, prev_quantifiable = i + 1, False
        elif c == "{":
            m = re.match(r"\{([0-9]{1,4})(,([0-9]{0,4}))?\}", body[i:])
            if not m or not prev_quantifiable:
                raise SchemaDefinitionError(f"bad repetition in {pattern!r}")
            lo = int(m.group(1))
            hi = int(m.group(3)) if m.group(3) else (lo if m.group(2) is None else MAX_REPETITION)
            if lo > hi or hi > MAX_REPETITION:
                raise SchemaDefinitionError(f"repetition bounds out of range in {pattern!r}")
            i, prev_quantifiable = i + m.end(), False
        elif c in _LITERAL:
            i, prev_quantifiable = i + 1, True
        else:
            raise SchemaDefinitionError(f"unsupported construct {c!r} in pattern {pattern!r}")
    if depth != 0:
        raise SchemaDefinitionError(f"unbalanced '(' in {pattern!r}")
    if top_alt:
        raise SchemaDefinitionError(f"top-level alternation is ambiguous with anchors; group it: {pattern!r}")
    # '$' in Python also matches before a trailing newline; \Z does not (ECMA-262 '$' semantics).
    return re.compile(r"(?:" + body + r")\Z", re.ASCII)


# ── loading ───────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class _Loaded:
    contracts: Mapping[str, Mapping[str, Any]]
    patterns: Mapping[str, re.Pattern[str]]


_STATE: _Loaded | None = None


def _strict_json(raw: bytes) -> Any:
    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise SchemaDefinitionError(f"duplicate key {k!r} in schema")
            out[k] = v
        return out

    return json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)


def _nonneg_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _check_schema(node: Any, where: str, depth: int, patterns: dict[str, re.Pattern[str]]) -> list[str]:
    """Validate one schema node; return the $ref strings it contains (recursively)."""
    if depth > MAX_SCHEMA_DEPTH:
        raise SchemaDefinitionError(f"{where}: schema nesting too deep")
    if isinstance(node, bool):
        return []
    if not isinstance(node, dict):
        raise SchemaDefinitionError(f"{where}: schema must be an object or boolean")
    unknown = set(node) - ALLOWED_KEYWORDS
    if unknown:
        raise SchemaDefinitionError(f"{where}: unsupported keyword(s) {sorted(unknown)}")
    refs: list[str] = []
    for k, v in node.items():
        at = f"{where}/{k}"
        if k in ("title", "description", "$comment", "$schema", "$id"):
            if not isinstance(v, str):
                raise SchemaDefinitionError(f"{at}: must be a string")
        elif k == "$ref":
            if not isinstance(v, str) or not _REF.match(v):
                raise SchemaDefinitionError(f"{at}: only local '#/$defs/x' or 'name.schema.json#/$defs/x'")
            refs.append(v)
        elif k == "$defs":
            if not isinstance(v, dict) or not all(_DEF_NAME.match(n) for n in v):
                raise SchemaDefinitionError(f"{at}: $defs must map valid names to schemas")
            for n, sub in v.items():
                refs += _check_schema(sub, f"{at}/{n}", depth + 1, patterns)
        elif k == "type":
            ts = v if isinstance(v, list) else [v]
            if not ts or not all(isinstance(t, str) and t in TYPES for t in ts) or len(set(ts)) != len(ts):
                raise SchemaDefinitionError(f"{at}: invalid type")
        elif k == "properties":
            if not isinstance(v, dict):
                raise SchemaDefinitionError(f"{at}: must be an object")
            for n, sub in v.items():
                refs += _check_schema(sub, f"{at}/{n}", depth + 1, patterns)
        elif k == "patternProperties":
            if not isinstance(v, dict):
                raise SchemaDefinitionError(f"{at}: must be an object")
            for p, sub in v.items():
                patterns[p] = check_pattern(p)
                refs += _check_schema(sub, f"{at}/{p}", depth + 1, patterns)
        elif k in ("additionalProperties", "items"):
            refs += _check_schema(v, at, depth + 1, patterns)
        elif k == "required":
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v) or len(set(v)) != len(v):
                raise SchemaDefinitionError(f"{at}: must be a list of unique strings")
        elif k == "enum":
            if not isinstance(v, list) or not v:
                raise SchemaDefinitionError(f"{at}: must be a non-empty list")
        elif k == "pattern":
            patterns[v] = check_pattern(v)
        elif k in ("minLength", "maxLength", "minItems", "maxItems"):
            if not _nonneg_int(v):
                raise SchemaDefinitionError(f"{at}: must be a non-negative integer")
        elif k in ("minimum", "maximum"):
            if isinstance(v, bool) or not isinstance(v, int | float):
                raise SchemaDefinitionError(f"{at}: must be a number")
        elif k == "uniqueItems":
            if not isinstance(v, bool):
                raise SchemaDefinitionError(f"{at}: must be a boolean")
        elif k == "oneOf":
            if not isinstance(v, list) or not v:
                raise SchemaDefinitionError(f"{at}: must be a non-empty list")
            for n, sub in enumerate(v):
                refs += _check_schema(sub, f"{at}/{n}", depth + 1, patterns)
        # const: any JSON value
    for lo, hi in (("minLength", "maxLength"), ("minItems", "maxItems"), ("minimum", "maximum")):
        if lo in node and hi in node and node[lo] > node[hi]:
            raise SchemaDefinitionError(f"{where}: {lo} > {hi}")
    return refs


def _resolve(ref: str, current: str) -> tuple[str, str]:
    m = _REF.match(ref)
    assert m is not None  # checked at load
    return (m.group(1) or current), m.group(2)


def load_contracts(files: Mapping[str, bytes]) -> _Loaded:
    """Load and check a complete contract set. ``files`` maps 'name.schema.json' to bytes."""
    contracts: dict[str, dict[str, Any]] = {}
    patterns: dict[str, re.Pattern[str]] = {}
    refs_by_def: dict[tuple[str, str], list[str]] = {}
    root_refs: dict[str, list[str]] = {}
    for fname, raw in sorted(files.items()):
        if not fname.endswith(".schema.json") or not _CONTRACT_NAME.match(fname[: -len(".schema.json")]):
            raise SchemaDefinitionError(f"unexpected schema file name {fname!r}")
        name = fname[: -len(".schema.json")]
        if len(raw) > MAX_SCHEMA_FILE_BYTES:
            raise SchemaDefinitionError(f"{fname}: too large")
        try:
            doc = _strict_json(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise SchemaDefinitionError(f"{fname}: not valid JSON ({exc})") from exc
        if not isinstance(doc, dict):
            raise SchemaDefinitionError(f"{fname}: root must be an object")
        if doc.get("$schema") != DRAFT:
            raise SchemaDefinitionError(f"{fname}: $schema must be {DRAFT}")
        if doc.get("$id") != f"urn:sentinel:schema:{name}:v1":
            raise SchemaDefinitionError(f"{fname}: $id must be urn:sentinel:schema:{name}:v1")
        defs = doc.get("$defs", {})
        for d, sub in defs.items():
            refs_by_def[(name, d)] = _check_schema(sub, f"{fname}#/$defs/{d}", 0, patterns)
        root = {k: v for k, v in doc.items() if k != "$defs"}
        root_refs[name] = _check_schema(root, fname, 0, patterns)
        contracts[name] = doc
    # every reference must exist
    for (name, _d), refs in list(refs_by_def.items()) + [((n, ""), r) for n, r in root_refs.items()]:
        for ref in refs:
            tf, td = _resolve(ref, name)
            if tf not in contracts or td not in contracts[tf].get("$defs", {}):
                raise SchemaDefinitionError(f"{name}: unresolved reference {ref!r}")
    # no reference cycles (no recursive schemas in v1)
    graph = {k: [_resolve(r, k[0]) for r in v] for k, v in refs_by_def.items()}
    state: dict[tuple[str, str], int] = {}

    def visit(node: tuple[str, str], stack: list[tuple[str, str]]) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            raise SchemaDefinitionError(
                f"reference cycle: {' -> '.join(f'{a}#{b}' for a, b in stack + [node])}"
            )
        state[node] = 1
        for nxt in graph.get(node, []):
            visit(nxt, stack + [node])
        state[node] = 2

    for node in graph:
        visit(node, [])
    return _Loaded(contracts, patterns)


def _bundled_files() -> dict[str, bytes]:
    pkg = resources.files("sentinel") / "schemas"
    return {p.name: p.read_bytes() for p in pkg.iterdir() if p.name.endswith(".schema.json")}


def ensure_loaded() -> _Loaded:
    """Load the bundled contracts once. Raises SchemaDefinitionError if any is invalid."""
    global _STATE
    if _STATE is None:
        files = _bundled_files()
        if not files:
            raise SchemaDefinitionError("no bundled schema contracts found")
        _STATE = load_contracts(files)
    return _STATE


def contract_names() -> list[str]:
    return sorted(ensure_loaded().contracts)


# ── validation ────────────────────────────────────────────────────────────
def _json_key(v: Any) -> Any:
    """Structural-equality key (JSON semantics: bool is not a number; 1 == 1.0; object order ignored)."""
    if isinstance(v, bool):
        return ("bool", v)
    if isinstance(v, int | float):
        return ("num", v)
    if isinstance(v, str):
        return ("str", v)
    if v is None:
        return ("null",)
    if isinstance(v, list):
        return ("arr", tuple(_json_key(x) for x in v))
    if isinstance(v, dict):
        return ("obj", tuple(sorted((k, _json_key(x)) for k, x in v.items())))
    raise SchemaError(f"not a JSON value: {type(v).__name__}")


def _type_ok(v: Any, t: str) -> bool:
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "string":
        return isinstance(v, str)
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, int | float) and not isinstance(v, bool)
    if t == "boolean":
        return isinstance(v, bool)
    return v is None  # "null"


class _Ctx:
    def __init__(self, loaded: _Loaded) -> None:
        self.loaded = loaded
        self.steps = 0

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise SchemaError("instance too complex to validate", "schema_too_complex")


def _errors(ctx: _Ctx, v: Any, s: Any, file: str, path: str, depth: int) -> str | None:
    """Return the first error message, or None. Never mutates ``v``."""
    ctx.tick()
    if depth > MAX_DEPTH:
        raise SchemaError(f"{path}: nesting deeper than {MAX_DEPTH}", "schema_too_complex")
    if s is True:
        return None
    if s is False:
        return f"{path}: no value is allowed here"
    if "$ref" in s:
        tf, td = _resolve(s["$ref"], file)
        err = _errors(ctx, v, ctx.loaded.contracts[tf]["$defs"][td], tf, path, depth + 1)
        if err:
            return err
        # 2020-12: sibling keywords apply in addition to $ref (fall through)
    if "type" in s:
        ts = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if not any(_type_ok(v, t) for t in ts):
            return f"{path}: expected {'/'.join(ts)}, got {type(v).__name__}"
    if "const" in s and _json_key(v) != _json_key(s["const"]):
        return f"{path}: must equal {s['const']!r}"
    if "enum" in s and _json_key(v) not in {_json_key(e) for e in s["enum"]}:
        return f"{path}: not one of the allowed values"
    if isinstance(v, str):
        if "minLength" in s and len(v) < s["minLength"]:
            return f"{path}: shorter than {s['minLength']}"
        if "maxLength" in s and len(v) > s["maxLength"]:
            return f"{path}: longer than {s['maxLength']}"
        if "pattern" in s and not ctx.loaded.patterns[s["pattern"]].match(v):
            return f"{path}: does not match the required pattern"
    if isinstance(v, int | float) and not isinstance(v, bool):
        if "minimum" in s and v < s["minimum"]:
            return f"{path}: below minimum {s['minimum']}"
        if "maximum" in s and v > s["maximum"]:
            return f"{path}: above maximum {s['maximum']}"
    if isinstance(v, list):
        if "minItems" in s and len(v) < s["minItems"]:
            return f"{path}: fewer than {s['minItems']} items"
        if "maxItems" in s and len(v) > s["maxItems"]:
            return f"{path}: more than {s['maxItems']} items"
        if s.get("uniqueItems") and len({_json_key(x) for x in v}) != len(v):
            return f"{path}: items are not unique"
        if "items" in s:
            for n, x in enumerate(v):
                err = _errors(ctx, x, s["items"], file, f"{path}[{n}]", depth + 1)
                if err:
                    return err
    if isinstance(v, dict):
        for r in s.get("required", []):
            if r not in v:
                return f"{path}: missing required property {r!r}"
        props = s.get("properties", {})
        pprops = s.get("patternProperties", {})
        for k, x in v.items():
            matched = False
            if k in props:
                matched = True
                err = _errors(ctx, x, props[k], file, f"{path}.{k}", depth + 1)
                if err:
                    return err
            for p, sub in pprops.items():
                if ctx.loaded.patterns[p].match(k):
                    matched = True
                    err = _errors(ctx, x, sub, file, f"{path}.{k}", depth + 1)
                    if err:
                        return err
            if not matched and "additionalProperties" in s:
                err = _errors(ctx, x, s["additionalProperties"], file, f"{path}.{k}", depth + 1)
                if err:
                    return (
                        f"{path}: unexpected or invalid property {k!r}"
                        if s["additionalProperties"] is False
                        else err
                    )
    if "oneOf" in s:
        ok = sum(1 for sub in s["oneOf"] if _errors(ctx, v, sub, file, path, depth + 1) is None)
        if ok != 1:
            return f"{path}: must match exactly one alternative (matched {ok})"
    return None


def _target(contract: str, definition: str | None) -> tuple[str, Any]:
    loaded = ensure_loaded()
    if contract not in loaded.contracts:
        raise SchemaDefinitionError(f"unknown contract {contract!r}")
    doc = loaded.contracts[contract]
    if definition is None:
        return contract, doc
    defs = doc.get("$defs", {})
    if definition not in defs:
        raise SchemaDefinitionError(f"unknown definition {contract}#/$defs/{definition}")
    return contract, defs[definition]


def validate(instance: Any, contract: str, definition: str | None = None) -> None:
    """Input boundary: raise SchemaError (fail closed) if ``instance`` violates the contract."""
    file, s = _target(contract, definition)
    loaded = ensure_loaded()
    err = _errors(_Ctx(loaded), instance, s, file, "$", 0)
    if err:
        raise SchemaError(f"{contract}{'#' + definition if definition else ''}: {err}")


def check_output(instance: Any, contract: str, definition: str | None = None) -> None:
    """Output boundary: raise SchemaViolation before anything is signed, persisted or printed."""
    try:
        validate(instance, contract, definition)
    except SchemaError as exc:
        raise SchemaViolation(f"engine output violates its contract: {exc}") from exc


def check_version(data: Any, field: str = "schema_version", supported: Sequence[str] = ("1.0",)) -> None:
    """Explicit version gate: an unknown version is 'unsupported_version', not a generic schema error."""
    if isinstance(data, dict) and field in data and data[field] not in supported:
        raise SchemaError(f"unsupported {field} {data[field]!r}", "unsupported_version")
