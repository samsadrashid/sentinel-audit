"""MANUAL Secure Enclave hardware tests H1-H11 (docs/m1/se-hardware-tests.md).

Run by the owner, at the Mac, in an interactive Terminal:

    .venv/bin/python native/macos/se-helper/manual_hardware_tests.py <helper-path> <sha256-from-build.sh>

Uses a throwaway SENTINEL_HOME; it never touches real Sentinel state. Each test says what to do at the
prompt. Results are written to <throwaway-home>/hardware-results.json and printed at the end.
Never run this from CI, an agent or a background job.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

if not (sys.stdin.isatty() and sys.stdout.isatty()):
    sys.exit("refusing: must be run by a person in an interactive terminal")

HOME = Path(tempfile.mkdtemp(prefix="sentinel-hw-"))
os.environ["SENTINEL_HOME"] = str(HOME)

from sentinel import approvals, canonical  # noqa: E402
from sentinel.domain.enums import ApprovalAction as A  # noqa: E402
from sentinel.errors import BlockedError, CapabilityUnavailable  # noqa: E402
from sentinel.keys.operator import TrustStore  # noqa: E402
from sentinel.keys.secure_enclave import (  # noqa: E402
    KeyMetadataStore,
    NativeHelperBackend,
    SecureEnclaveProvider,
    register_key,
    revoke_key,
    sign_payload,
)

results: dict[str, Any] = {}


def record(tid: str, passed: bool, detail: str) -> None:
    results[tid] = {"passed": passed, "detail": detail}
    print(f"  -> {tid}: {'PASS' if passed else 'FAIL'} ({detail})\n")


def ask(msg: str) -> str:
    return input(f"{msg} ").strip().lower()


def blocked_code(fn: Any) -> str:
    try:
        fn()
    except (BlockedError, CapabilityUnavailable) as e:
        return getattr(e, "code", type(e).__name__)
    return "NO_ERROR"


def payload(key_id: str, action: A = A.SUPPRESS, subject: Any = None, revision: str = "commit:hwtest") -> Any:
    return approvals.build_payload(
        action=action,
        subject=subject or {"type": "finding", "fingerprint": "e" * 64},
        revision=revision,
        scope={},
        issued_at=int(time.time()),
        lifetime=600,
        key_id=key_id,
        rationale="manual hardware test",
    )


def show(text: str) -> None:
    print("\n----- payload to approve -----\n" + text + "\n------------------------------")


def main() -> None:
    helper, pin = Path(sys.argv[1]), sys.argv[2]
    backend = NativeHelperBackend(helper, pin)
    now = lambda: int(time.time())  # noqa: E731

    print("H1: status")
    record("H1", backend.status() is True, "helper reports secure_enclave")

    print("H2: create and enrol (no prompt expected)")
    meta = backend.create(now())
    trust, store = TrustStore(HOME / "trust.json"), KeyMetadataStore(HOME / "meta")
    register_key(meta, trust, store, operator="owner", expires_at=now() + 86400)
    record("H2", store.load(meta.key_id) == meta, f"key {meta.key_id} enrolled; id recomputed by Sentinel")

    prov = SecureEnclaveProvider(meta, trust, backend, now=now)
    ledger = approvals.NonceLedger(HOME / "ledger.json")

    print(
        "H3 + H4: a system prompt will appear. Compare its SHA-256 with the one printed below, then APPROVE."
    )
    p = payload(meta.key_id)
    try:
        ap = sign_payload(prov, p, show)
        approvals.verify(
            ap,
            approvals.Expectation(A.SUPPRESS, p["subject"], p["revision"]),
            trust,
            ledger,
            now(),
            consume=True,
        )
        record("H3", True, "hardware signature verified by approvals.verify")
    except (BlockedError, CapabilityUnavailable) as e:
        record("H3", False, f"{type(e).__name__}: {e}")
    same = ask(f"H4: did the prompt show exactly {canonical.digest(p)}? [y/n]") == "y"
    record("H4", same, "operator compared prompt hash with terminal hash")

    print("H5: a prompt will appear. CANCEL it.")
    c = blocked_code(lambda: sign_payload(prov, payload(meta.key_id), show))
    record("H5", c == "presence_cancelled", c)

    print("H6: a prompt will appear. DO NOTHING for 15 seconds.")
    t0 = time.time()
    resp = backend.sign(meta.handle, canonical.encode(payload(meta.key_id)), "", 10)
    record("H6", resp.get("error") == "timeout", f"{resp.get('error')} after {time.time() - t0:.0f}s")

    print("H7: TWO prompts should appear, one after the other. APPROVE both.")
    ask("Press Enter to start, then count the prompts you see.")
    a1 = blocked_code(lambda: sign_payload(prov, payload(meta.key_id), show))
    a2 = blocked_code(lambda: sign_payload(prov, payload(meta.key_id), show))
    two = ask("H7: did you see two separate prompts? [y/n]") == "y"
    record("H7", two and a1 == a2 == "NO_ERROR", f"signatures: {a1}, {a2}")

    print("H8: non-interactive refusal (no prompt should appear)")
    ni = SecureEnclaveProvider(meta, trust, backend, now=now, interactive=lambda: False)
    c = blocked_code(lambda: ni.sign_with_presence(b"x", "x"))
    saw = ask("H8: did any prompt appear? [y/n]") == "y"
    record(
        "H8a", c == "CapabilityUnavailable" and not saw, f"{c}; second half (SSH session) is manual, see doc"
    )

    print("H11: substituted payload. A prompt will appear with a DIFFERENT hash than the terminal shows.")
    print("     Approve it anyway, to prove Sentinel rejects the result.")

    class Tamper:
        genuine_hardware = True

        def sign(self, handle: bytes, message: bytes, reason: str, timeout_s: int) -> dict[str, Any]:
            return backend.sign(
                handle, message.replace(b"manual hardware test", b"manual hardware TEST"), reason, timeout_s
            )

    tp = SecureEnclaveProvider(meta, trust, Tamper(), now=now)
    c = blocked_code(lambda: sign_payload(tp, payload(meta.key_id), show))
    record("H11", c == "payload_mismatch", c)

    print(
        "H9: revoke the key through key.revoke (one prompt: APPROVE), then try to sign (no prompt expected)"
    )
    rv = payload(
        meta.key_id,
        A.KEY_REVOKE,
        {"type": "operator_key", "key_id": meta.key_id},
        f"trust:{trust.fingerprint()}",
    )
    try:
        revoke_key(sign_payload(prov, rv, show), meta.key_id, trust, ledger, now())
        c = blocked_code(lambda: sign_payload(prov, payload(meta.key_id), show))
        record("H9", c == "revoked_key", c)
    except (BlockedError, CapabilityUnavailable) as e:
        record("H9", False, f"revocation failed: {e}")

    (HOME / "handle-for-H10.b64").write_bytes(base64.b64encode(meta.handle))
    print(f"H10 is manual: copy {HOME}/handle-for-H10.b64 to another Mac or user account (see doc).")
    out = HOME / "hardware-results.json"
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    print(f"\nResults: {out}")


if __name__ == "__main__":
    main()
