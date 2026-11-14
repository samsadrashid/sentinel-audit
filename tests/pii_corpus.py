"""Synthetic PII corpus for AC-15 (D-57). Every value is generated, format-valid and fictitious; none
identifies a person. A clean look-alike corpus measures false positives."""

from __future__ import annotations

from sentinel.redaction import _VERHOEFF_D, _VERHOEFF_P

N = 60  # at least 50 instances per class (AC-15)


def _luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        cand = prefix + d
        total = 0
        for i, ch in enumerate(reversed(cand)):
            n = int(ch)
            if i % 2:
                n = n * 2 - 9 if n > 4 else n * 2
            total += n
        if total % 10 == 0:
            return cand
    raise AssertionError


_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _verhoeff_complete(prefix: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(prefix)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return prefix + str(_VERHOEFF_INV[c])


def corpus() -> dict[str, list[str]]:
    r = range(N)
    return {
        "pii_email": [f"person{i}.name@example{i % 7}.org" for i in r],
        "pii_phone": [f"+88017{i:08d}" for i in r[: N // 3]]
        + [f"(415) 555-{1000 + i:04d}" for i in r[: N // 3]]
        + [f"0171{i:07d}" for i in r[: N // 3]],
        "pii_postal_address": [
            f"{i + 1} {['Baker', 'Station', 'Mill Hill', 'Oak'][i % 4]} Street" for i in r
        ],
        "pii_ipv4": [f"10.{i}.{(i * 3) % 250}.{(i * 7) % 250 + 1}" for i in r],
        "pii_ipv6": [f"2001:db8:{i:x}::{(i * 13) % 65535:x}" for i in r],
        "pii_payment_card": [
            " ".join(_luhn_complete(f"4{i:014d}")[k : k + 4] for k in range(0, 16, 4)) for i in r
        ],
        "pii_aadhaar": [
            " ".join(_verhoeff_complete(f"{2 + i % 8}{i:010d}")[k : k + 4] for k in range(0, 12, 4))
            for i in r
        ],
        "pii_us_ssn": [f"{100 + i:03d}-{10 + i % 80:02d}-{1000 + i:04d}" for i in r],
        "pii_uk_nino": [
            f"{['AB', 'CE', 'HJ', 'PR'][i % 4]} {i % 100:02d} {(i * 3) % 100:02d} "
            f"{(i * 7) % 100:02d} {'ABCD'[i % 4]}"
            for i in r
        ],
        "pii_bd_nid": [f"19{80 + i % 20}{i:013d}" for i in r[: N // 2]]
        + [f"NID: 54{i:08d}" for i in r[: N // 2]],
    }


def raw_values(c: dict[str, list[str]]) -> list[str]:
    """The sensitive part of each instance (labels such as 'NID:' are context, not PII)."""
    out = []
    for cls, vals in c.items():
        for v in vals:
            out.append(v.split(": ", 1)[1] if cls == "pii_bd_nid" and ": " in v else v)
    return out


def clean_corpus() -> list[str]:
    """Look-alike text with no PII: versions, hashes, UUIDs, dates, times, prices, ports, line numbers."""
    import hashlib
    import uuid

    lines = []
    for i in range(2000):
        lines += [
            f"version {i % 30}.{i % 17}.{i % 11}",
            f"sha256:{hashlib.sha256(str(i).encode()).hexdigest()}",
            str(uuid.UUID(int=i * 7919 + 1)),
            f"2026-{1 + i % 12:02d}-{1 + i % 28:02d}T{i % 24:02d}:{i % 60:02d}:{i % 60:02d}Z",
            f"price {i}.{i % 100:02d} USD, qty {i % 1000}",
            f"listening on localhost:{1024 + i}",
            f"src/module_{i}.py:{i % 500}:{i % 80}",
            f"build {i:010d} took {i % 900} ms",
            f"order-{i:06d} items={i % 9}",
        ]
    return lines
