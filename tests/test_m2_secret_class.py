"""AC-16: deterministic secret classification without network validation (D-31)."""

from __future__ import annotations

import socket

import pytest

from sentinel.secret_class import DOCUMENTED_TEST_VALUES, LIVE, TEST, UNKNOWN, classify

LIVE_FORMAT = [
    "AKIA" + "Z7Q4HN2KV9PLM3XT",
    "ASIA" + "QWERTYUIOPASDFGH",
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "github_pat_" + "A" * 22 + "_" + "b" * 59,
    "glpat-" + "x1Y2z3W4v5U6t7S8r9Q0",
    "xoxb-123456789012-abcdefghijkl",
    "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
    "sk-ant-" + "api03-abcdefghijklmnopqrstuvwx",
    "sk-proj-" + "abcdefghijklmnopqrstuvwx",
    "npm_" + "a" * 18 + "B" * 18,
    "-----BEGIN RSA PRIVATE KEY-----",
]
#: Live formats that also contain a marker word: still live (AC-16's failure condition).
LIVE_FORMAT_WITH_MARKERS = [
    "AKIA" + "TESTTESTTESTTEST",
    "ghp_" + "test" * 9,
    "sk_live_" + "exampleexampleexample1",
    "xoxb-test-fake-dummy-123",
    "glpat-" + "sample" * 4,
]
DOCUMENTED_TEST = [
    *sorted(DOCUMENTED_TEST_VALUES),
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_" + "TYooMQauvdEDq54NiTphI7jx",
    "my-example-password",
    "dummy-token-value",
    "FAKE_SECRET_123",
    "placeholder",
    "xxxxxxxxxxxx",
    "aaaaaaaaaaaaaaaa",
]
UNKNOWN_VALUES = [
    "Zr9#kq2!LmP0",
    "hunter2-but-longer",
    "c29tZSBiYXNlNjQ=",
    "8f14e45fceea167a5a36dedd4bea2543",
]


@pytest.mark.parametrize("v", LIVE_FORMAT + LIVE_FORMAT_WITH_MARKERS)
def test_live_formats_are_never_labelled_test(v):
    assert classify(v) == LIVE


@pytest.mark.parametrize("v", DOCUMENTED_TEST)
def test_every_documented_test_marker_is_labelled_test(v):
    assert classify(v) == TEST


@pytest.mark.parametrize("v", [*UNKNOWN_VALUES, "", "   "])
def test_everything_else_defaults_to_unknown(v):
    assert classify(v) == UNKNOWN


def test_labels_are_identical_across_two_runs():
    corpus = LIVE_FORMAT + LIVE_FORMAT_WITH_MARKERS + DOCUMENTED_TEST + UNKNOWN_VALUES
    assert [classify(v) for v in corpus] == [classify(v) for v in corpus]


def test_classification_never_touches_the_network(monkeypatch):
    def no_network(*a, **k):  # type: ignore[no-untyped-def]
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    for v in LIVE_FORMAT + DOCUMENTED_TEST + UNKNOWN_VALUES:
        classify(v)
