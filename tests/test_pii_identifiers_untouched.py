"""PII detectors must never fire inside engine identifiers (hashes, key IDs, UUIDs, markers)."""

from __future__ import annotations

import secrets
import uuid

from sentinel.redaction import Redactor

R = Redactor(b"k" * 32)


def test_random_identifiers_are_never_redacted():
    for _ in range(4000):
        for value in (
            secrets.token_hex(32),
            "p256:" + secrets.token_hex(16),
            "ed25519:" + secrets.token_hex(16),
            str(uuid.uuid4()),
            "sha256:" + secrets.token_hex(32),
        ):
            out, counts = R.redact_text(value)
            assert out == value and not counts, value
