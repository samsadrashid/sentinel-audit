"""Secret classification (AC-16, D-31, D-52 item 6): `live`, `test` or `unknown`, by fixed local rules.

There is **no network validation**: nothing is ever sent anywhere to check a secret. Rules apply in
this order, and the first match wins:

1. **Documented test credentials, exact or by provider test format** → `test`. These are values
   providers publish as non-functional (for example AWS's documentation key `AKIAIOSFODNN7EXAMPLE`),
   or formats the provider defines as test-mode only (Stripe `sk_test_`, `pk_test_`, `rk_test_`).
2. **A provider live-credential format** → `live`. A value in a live format is **never** labelled
   `test` because of a marker word, its file path or its surroundings. A real key pasted into a test
   file is still a real key.
3. **A documented test marker inside the value itself** (`EXAMPLE`, `example`, `dummy`, `fake`,
   `placeholder`, `test`, `sample`, `xxxx`, all-same characters) → `test`.
4. Anything else → `unknown`, the default.

The classifier sees the value in memory only. Adapters discard the value immediately after
classification, and it is never stored.
"""

from __future__ import annotations

import re

LIVE, TEST, UNKNOWN = "live", "test", "unknown"

#: Provider-published, non-functional documentation credentials (exact values).
DOCUMENTED_TEST_VALUES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AKIAI44QH8DHBEXAMPLE",
        "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    }
)
#: Formats a provider defines as test-mode only.
TEST_FORMATS = (re.compile(r"^(?:sk|pk|rk)_test_[A-Za-z0-9]{16,}$"),)
#: Provider live-credential formats.
LIVE_FORMATS = (
    re.compile(r"^(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}$"),
    re.compile(r"^gh[pousr]_[A-Za-z0-9]{36,255}$"),
    re.compile(r"^github_pat_[A-Za-z0-9_]{22,255}$"),
    re.compile(r"^glpat-[A-Za-z0-9_\-]{20,}$"),
    re.compile(r"^xox[abposr]-[A-Za-z0-9\-]{10,}$"),
    re.compile(r"^(?:sk|pk|rk)_live_[A-Za-z0-9]{16,}$"),
    re.compile(r"^AIza[0-9A-Za-z_\-]{35}$"),
    re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,}$"),
    re.compile(r"^sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}$"),
    re.compile(r"^npm_[A-Za-z0-9]{36}$"),
    re.compile(r"^-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY"),
)
TEST_MARKERS = re.compile(r"(?i)(?:example|dummy|fake|placeholder|sample|test|xxxx)")
SAME_CHAR = re.compile(r"^(.)\1{7,}$")


def classify(value: str) -> str:
    """Deterministic label for one secret value. Pure: no I/O, no network, no randomness."""
    v = value.strip()
    if not v:
        return UNKNOWN
    if v in DOCUMENTED_TEST_VALUES or any(p.match(v) for p in TEST_FORMATS):
        return TEST
    if any(p.match(v) for p in LIVE_FORMATS):
        return LIVE
    if TEST_MARKERS.search(v) or SAME_CHAR.match(v):
        return TEST
    return UNKNOWN
