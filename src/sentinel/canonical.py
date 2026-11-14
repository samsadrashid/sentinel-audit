"""Deterministic canonical encoding (§11.3 'Canonical encoding').

Sorted keys, NFC-normalised UTF-8 strings, no insignificant whitespace, no floats, no NaN.
The same value always encodes to the same bytes, so signatures and fingerprints are stable.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from .errors import ValidationError

JSONValue = Any


def _normalise(value: JSONValue, depth: int = 0) -> JSONValue:
    if depth > 64:
        raise ValidationError("canonical: nesting too deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2**63:
            raise ValidationError("canonical: integer out of range")
        return value
    if isinstance(value, float):
        raise ValidationError("canonical: floats are not allowed in signed or fingerprinted data")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_normalise(v, depth + 1) for v in value]
    if isinstance(value, dict):
        out: dict[str, JSONValue] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValidationError("canonical: object keys must be strings")
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise ValidationError("canonical: duplicate key after normalisation")
            out[nk] = _normalise(v, depth + 1)
        return out
    raise ValidationError(f"canonical: unsupported type {type(value).__name__}")


def encode(value: JSONValue) -> bytes:
    """Return the canonical byte encoding of a JSON-compatible value."""
    return json.dumps(
        _normalise(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: JSONValue) -> str:
    return sha256_hex(encode(value))


def decode_strict(raw: bytes, max_bytes: int = 4 * 1024 * 1024) -> JSONValue:
    """Parse untrusted JSON with size limit and duplicate-key rejection."""
    if len(raw) > max_bytes:
        raise ValidationError("json input too large")

    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k, v in pairs:
            if k in d:
                raise ValidationError(f"duplicate JSON key: {k!r}")
            d[k] = v
        return d

    def no_const(c: str) -> Any:
        raise ValidationError(f"invalid JSON constant {c}")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes, parse_constant=no_const)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JSON: {exc}") from exc
