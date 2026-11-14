"""Deterministic, local-only secret redaction (§6.4, §13.4, D-05, D-31).

Every secret-like value is replaced by a marker `[REDACTED:<rule>:<fingerprint>]`. The fingerprint is
the first 12 hex characters of HMAC-SHA256 over the value, keyed with a per-installation key that never
leaves the state directory. It lets an operator see that two redactions are the same value without the
marker revealing it (a plain hash of a short password could be brute-forced). Assignment keys, header
names and URL schemes stay visible as diagnostic context; only the value is replaced.

Redaction runs on bytes, so invalid UTF-8 can't make it skip content. It is idempotent: markers never
match a rule. It fails closed (`RedactionError`) on oversized input, a missing key, or any internal
error; callers must then hold the content back (§6.4: check `ERROR`, reason `redaction_failed`).

Nothing here sends content anywhere. Detection is pattern-based and incomplete: see
docs/m1/redaction.md for the known blind spots and false positives.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import SentinelError, ValidationError
from .paths import ensure_private_dir, state_dir

MAX_REDACT_BYTES = 64 * 1024 * 1024  # equals the scanner output cap
MAX_CUSTOM_PATTERNS = 32
MAX_CUSTOM_PATTERN_LEN = 512
MARKER_PREFIX = b"[REDACTED:"
_NOT_MARKER = rb"(?!\[REDACTED:)"
#: An existing marker. Rules are applied only to the text between markers, so redaction is idempotent and a
#: marker's own text (for example `private_key:`) can never be matched again.
MARKER_RE = re.compile(rb"\[REDACTED:[a-z0-9_]{1,60}:[0-9a-f]{12}\]")
_SCHEMES = rb"(?:bearer|basic|token|digest|negotiate|ntlm|apikey)"
_NOT_PLACEHOLDER = rb"(?!(?:null|none|true|false|undefined|\*+|x{3,})(?![A-Za-z0-9]))"
_VALUE_END = rb"\s\"'`,;&<>{}\[\]()\\"

_ASSIGN_NAMES = (
    rb"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    rb"client[_-]?secret|credentials?|auth[_-]?token|session[_-]?(?:key|token)|signing[_-]?key|"
    rb"encryption[_-]?key|master[_-]?key|account[_-]?key|sas[_-]?token|bearer)"
)
_ENV_NAMES = (
    rb"(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?|"
    rb"DSN|DATABASE_URL|CONNECTION_STRING|AUTH)"
)


class RedactionError(SentinelError):
    """Redaction could not complete. The content must be held back (fail closed)."""


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[bytes]
    #: Group holding the secret value; 0 means the whole match.
    group: int = 0
    #: Optional structural check on the matched value (checksums, reserved ranges). Format only:
    #: a passing check never means a real person or identity exists (D-57).
    check: Callable[[bytes], bool] | None = None


def _r(
    name: str, pattern: bytes, group: int = 0, flags: int = 0, check: Callable[[bytes], bool] | None = None
) -> Rule:
    return Rule(name, re.compile(pattern, flags), group, check)


# ── PII format checks (AC-15, D-52, D-57) ──────────────────────────────────
def _digits(v: bytes) -> str:
    return re.sub(rb"[^0-9]", b"", v).decode()


def luhn_ok(v: bytes) -> bool:
    d = _digits(v)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(v: bytes) -> bool:
    d = _digits(v)
    if len(d) != 12:
        return False
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def ssn_ok(v: bytes) -> bool:
    d = _digits(v)
    area, group, serial = d[:3], d[3:5], d[5:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


_NINO_BAD_PREFIX = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


def nino_ok(v: bytes) -> bool:
    return v[:2].decode().upper() not in _NINO_BAD_PREFIX


def ipv6_ok(v: bytes) -> bool:
    import ipaddress

    text = v.decode("ascii", "replace")
    if text.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def bd_nid_ok(v: bytes) -> bool:
    d = _digits(v)
    if len(d) == 17:  # birth year + 13-digit legacy number
        return 1900 <= int(d[:4]) <= 2099
    return len(d) in (10, 13)


#: Built-in rules, applied in this order (specific formats before generic assignments).
BUILTIN_RULES: tuple[Rule, ...] = (
    _r(
        "private_key",
        rb"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----.*?"
        rb"(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|\Z)",
        flags=re.DOTALL,
    ),
    _r("aws_access_key_id", rb"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}(?![A-Z0-9])"),
    _r(
        "github_token", rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})"
    ),
    _r("gitlab_token", rb"(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_\-]{20,}"),
    _r("slack_token", rb"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9\-]{10,}"),
    _r("stripe_key", rb"(?<![A-Za-z0-9])(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    _r("google_api_key", rb"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}"),
    _r("anthropic_key", rb"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}"),
    _r("openai_key", rb"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"),
    _r("npm_token", rb"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}"),
    _r("jwt", rb"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    _r("azure_account_key", rb"(?i)(AccountKey\s*=\s*)([A-Za-z0-9+/]{40,}={0,2})", 2),
    _r("azure_sas_signature", rb"(?i)([?&]sig=)([A-Za-z0-9%+/=]{20,})", 2),
    _r(
        "sensitive_env",
        rb"(?m)^[ \t]*(?:export[ \t]+)?([A-Z0-9_]{0,60}"
        + _ENV_NAMES
        + rb"[A-Z0-9_]{0,30}[ \t]*=[ \t]*)"
        + _NOT_MARKER
        + rb"([^\r\n]+)",
        2,
    ),
    _r(
        "authorization_header",
        rb"(?i)((?:proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?"
        rb"(?:"
        + _SCHEMES
        + rb"[ \t]+)?)"
        + _NOT_MARKER
        + rb"(?!"
        + _SCHEMES
        + rb"(?:[ \t]|$))"
        + rb"([^\s\"',;]{4,})",
        2,
    ),
    _r(
        "connection_string_password",
        rb"([A-Za-z][A-Za-z0-9+.\-]{1,20}://[^:/\s@\"']{0,256}:)"
        + _NOT_MARKER
        + rb"([^@\s/\"']{1,256})(?=@)",
        2,
    ),
    _r(
        "credential_assignment",
        rb"(?i)([A-Za-z0-9_.\-]{0,40}" + _ASSIGN_NAMES + rb"[A-Za-z0-9_.\-]{0,40}[\"'\\]{0,2}[ \t]*[:=][ \t]*"
        rb"[\"'\\]{0,2})" + _NOT_MARKER + _NOT_PLACEHOLDER + rb"([^" + _VALUE_END + rb"]{3,512})",
        2,
    ),
)
#: PII rules (AC-15, D-57). Applied after the secret rules; detection is by format only and is never an
#: identity check. Classes not listed here are not detected (see `PII_NOT_COVERED`).
PII_RULES: tuple[Rule, ...] = (
    _r(
        "pii_email",
        rb"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*"
        rb"\.[A-Za-z]{2,24}(?![A-Za-z0-9\-])",
    ),
    _r(
        "pii_payment_card",
        rb"(?<![0-9A-Za-z_\\-])[3-6][0-9](?:[ \-]?[0-9]){11,17}(?![0-9A-Za-z_\\-])",
        check=luhn_ok,
    ),
    _r(
        "pii_aadhaar",
        rb"(?<![0-9A-Za-z_\\-])[2-9][0-9]{3}[ \-]?[0-9]{4}[ \-]?[0-9]{4}(?![0-9A-Za-z_\\-])",
        check=verhoeff_ok,
    ),
    _r("pii_us_ssn", rb"(?<![0-9A-Za-z_\\-])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9A-Za-z_\\-])", check=ssn_ok),
    _r(
        "pii_uk_nino",
        rb"(?<![A-Za-z0-9])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
        rb" ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D](?![A-Za-z0-9])",
        check=nino_ok,
    ),
    _r(
        "pii_bd_nid",
        rb"(?i)((?:\bNID\b|national[ _\-]?id(?:entity)?(?:[ _\-]?(?:no|number|card))?)[\s:#=.\-]{0,6})"
        rb"((?<![0-9A-Za-z_\\-])(?:[0-9]{17}|[0-9]{13}|[0-9]{10})(?![0-9A-Za-z_\\-]))",
        2,
        check=bd_nid_ok,
    ),
    _r("pii_bd_nid", rb"(?<![0-9A-Za-z_\\-])(?:19|20)[0-9]{15}(?![0-9A-Za-z_\\-])", check=bd_nid_ok),
    _r("pii_phone", rb"(?<![0-9A-Za-z+])\+[1-9](?:[ .\-]?[0-9]){6,14}(?![0-9A-Za-z_\\-])"),
    _r(
        "pii_phone",
        rb"(?<![0-9A-Za-z_\\-])\(?[2-9][0-9]{2}\)?[ .\-][0-9]{3}[ .\-][0-9]{4}(?![0-9A-Za-z_\\-])",
    ),
    _r("pii_phone", rb"(?<![0-9A-Za-z_\\-])01[3-9][0-9]{8}(?![0-9A-Za-z_\\-])"),
    _r("pii_phone", rb"(?<![0-9A-Za-z_\\-])0[1-9][0-9]{2,3} [0-9]{3} ?[0-9]{3,4}(?![0-9A-Za-z_\\-])"),
    _r(
        "pii_ipv4",
        rb"(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9]|\.[0-9])",
    ),
    _r(
        "pii_ipv6",
        rb"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])",
        check=ipv6_ok,
    ),
    _r(
        "pii_postal_address",
        rb"(?<![A-Za-z0-9])[0-9]{1,5}[A-Za-z]?,? +(?:[A-Z][a-z]+ +){1,4}"
        rb"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Place|Pl|Terrace|Close|Crescent)"
        rb"\b\.?",
    ),
)
PII_CLASSES = (
    "email address",
    "phone number (E.164, NANP, Bangladesh mobile, UK spaced)",
    "postal-address line (English street-type lines)",
    "IPv4 address",
    "IPv6 address",
    "payment-card number (Luhn-valid, IIN 3-6)",
    "Bangladesh NID (17-digit with birth year; 10/13-digit with an NID label)",
    "Indian Aadhaar (Verhoeff-valid)",
    "US SSN (dashed, valid ranges)",
    "UK National Insurance number",
)
PII_NOT_COVERED = (
    "personal names",
    "dates of birth",
    "postal addresses without an English street type, and postcodes",
    "phone numbers in other national formats",
    "unformatted 9-digit SSNs",
    "unlabelled 10- or 13-digit Bangladesh NIDs",
    "other national identifiers, passports, driving licences, tax and bank account numbers",
    "biometric, health and location data",
    "PII inside binary or encoded content",
)
BUILTIN_RULES = BUILTIN_RULES + PII_RULES
BUILTIN_NAMES = frozenset(r.name for r in BUILTIN_RULES)
_CUSTOM_NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def compile_custom(patterns: Iterable[Any]) -> tuple[Rule, ...]:
    """Validate operator-approved custom patterns: [{"name": str, "regex": str}]. The whole match is
    redacted. Patterns that match the empty string, fail to compile or collide with a built-in are refused."""
    out: list[Rule] = []
    items = list(patterns)
    if len(items) > MAX_CUSTOM_PATTERNS:
        raise ValidationError(f"at most {MAX_CUSTOM_PATTERNS} custom redaction patterns")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"name", "regex"}:
            raise ValidationError("custom redaction pattern must have exactly name and regex")
        name, regex = item["name"], item["regex"]
        if not isinstance(name, str) or not _CUSTOM_NAME.match(name) or name in BUILTIN_NAMES or name in seen:
            raise ValidationError(f"invalid or duplicate custom redaction pattern name {name!r}")
        if not isinstance(regex, str) or not regex or len(regex) > MAX_CUSTOM_PATTERN_LEN:
            raise ValidationError(
                f"custom redaction pattern {name}: regex must be 1-{MAX_CUSTOM_PATTERN_LEN} chars"
            )
        try:
            pat = re.compile(regex.encode())
        except re.error as exc:
            raise ValidationError(f"custom redaction pattern {name}: {exc}") from exc
        if pat.search(b"") is not None or pat.search(b"x") is not None and pat.fullmatch(b"") is not None:
            raise ValidationError(f"custom redaction pattern {name} matches empty input")
        seen.add(name)
        out.append(Rule(f"custom_{name}", pat, 0))
    return tuple(out)


def redaction_key_path() -> Path:
    return state_dir() / "keys" / "redaction.key"


def load_or_create_key() -> bytes:
    """Per-installation HMAC key (32 random bytes, 0600). Fails closed if it can't be read or created."""
    p = redaction_key_path()
    try:
        if p.exists():
            if p.is_symlink():
                raise RedactionError("redaction key path is a symlink")
            key = p.read_bytes()
        else:
            ensure_private_dir(p.parent)
            key = secrets.token_bytes(32)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
    except FileExistsError:
        key = p.read_bytes()
    except OSError as exc:
        raise RedactionError(f"redaction key unavailable: {exc}") from exc
    if len(key) != 32:
        raise RedactionError("redaction key is malformed")
    return key


@dataclass
class Redactor:
    key: bytes
    custom: tuple[Rule, ...] = ()
    rules: tuple[Rule, ...] = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) != 32:
            raise RedactionError("redaction key must be 32 bytes")
        self.rules = BUILTIN_RULES + self.custom

    @classmethod
    def default(cls, custom: Iterable[Any] = ()) -> Redactor:
        return cls(load_or_create_key(), compile_custom(custom))

    @classmethod
    def for_output(cls) -> Redactor:
        """For CLI and agent-facing output: the installation key if it exists, otherwise a throwaway key
        (markers then differ between invocations, but nothing is written and nothing leaks)."""
        p = redaction_key_path()
        if p.is_file() and not p.is_symlink():
            return cls(load_or_create_key())
        return cls(secrets.token_bytes(32))

    def fingerprint(self, value: bytes) -> str:
        return hmac.new(self.key, value, hashlib.sha256).hexdigest()[:12]

    def redact_bytes(self, data: bytes) -> tuple[bytes, dict[str, int]]:
        """Return (redacted bytes, {rule: count}). Raises RedactionError; never returns partial output."""
        if not isinstance(data, (bytes, bytearray)):
            raise RedactionError("redaction input must be bytes")
        if len(data) > MAX_REDACT_BYTES:
            raise RedactionError(f"input larger than {MAX_REDACT_BYTES} bytes")
        counts: dict[str, int] = {}
        out = bytes(data)
        try:
            for rule in self.rules:
                out = self._apply(rule, out, counts)
        except RedactionError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure means the content can't be released
            raise RedactionError(f"redaction failed: {type(exc).__name__}") from exc
        return out, counts

    def _apply(self, rule: Rule, data: bytes, counts: dict[str, int]) -> bytes:
        parts: list[bytes] = []
        pos = 0
        for mk in MARKER_RE.finditer(data):
            parts.append(rule.pattern.sub(lambda m: self._replace(m, rule, counts), data[pos : mk.start()]))
            parts.append(mk.group(0))
            pos = mk.end()
        parts.append(rule.pattern.sub(lambda m: self._replace(m, rule, counts), data[pos:]))
        return b"".join(parts)

    def _replace(self, m: re.Match[bytes], rule: Rule, counts: dict[str, int]) -> bytes:
        value = m.group(rule.group)
        if not value or value.startswith(MARKER_PREFIX):
            return m.group(0)
        if rule.check is not None and not rule.check(value):
            return m.group(0)
        counts[rule.name] = counts.get(rule.name, 0) + 1
        marker = MARKER_PREFIX + rule.name.encode() + b":" + self.fingerprint(value).encode() + b"]"
        if rule.group == 0:
            return marker
        start, end = m.start(rule.group) - m.start(0), m.end(rule.group) - m.start(0)
        whole = m.group(0)
        return whole[:start] + marker + whole[end:]

    def redact_text(self, text: str) -> tuple[str, dict[str, int]]:
        raw = text.encode("utf-8", "surrogatepass")
        out, counts = self.redact_bytes(raw)
        return out.decode("utf-8", "surrogatepass"), counts

    def redact_obj(self, obj: Any, counts: dict[str, int] | None = None) -> Any:
        """Redact every string (values and keys) in a JSON-like structure."""
        counts = {} if counts is None else counts
        if isinstance(obj, str):
            red, c = self.redact_text(obj)
            for k, v in c.items():
                counts[k] = counts.get(k, 0) + v
            return red
        if isinstance(obj, dict):
            return {self.redact_obj(k, counts): self.redact_obj(v, counts) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_obj(v, counts) for v in obj]
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        raise RedactionError(f"cannot redact value of type {type(obj).__name__}")

    def contains_secret(self, obj: Any) -> bool:
        counts: dict[str, int] = {}
        self.redact_obj(obj, counts)
        return bool(counts)


def summary(counts: dict[str, int]) -> dict[str, Any]:
    return {
        "engine": "sentinel-redaction/1",
        "rules": sorted(counts),
        "counts": dict(sorted(counts.items())),
        "total": sum(counts.values()),
    }
