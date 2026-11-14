"""MobSF 4.6.4 driver (D-72). It runs *inside* the pinned MobSF image, never on the host.

It is passed as one `python3 -I -c` argument. The artifact arrives on stdin, MobSF's own static-analysis
API views handle it in-process through Django's RequestFactory (no server, no URL routing, no socket and
no network; the container has `--network=none` anyway), and one JSON document leaves on stdout.
Everything MobSF writes goes to the container's tmpfs, which disappears with the container.

The output is MobSF's scorecard (its consolidated appsec summary), reduced to the fields Sentinel uses.
MobSF's own logging goes to stderr: file descriptor 1 is reserved for the result.
"""

import io
import json
import logging
import os
import secrets
import sys
from typing import Any

MOBSF_ROOT = "/home/mobsf/Mobile-Security-Framework-MobSF"
BUNDLED_JADX = "/home/mobsf/.MobSF/tools/jadx/jadx-1.5.6"
SECTIONS = ("high", "warning", "hotspot")
MAX_FINDINGS = 2000


def emit(fd: int, doc: dict) -> None:  # type: ignore[type-arg]
    os.write(fd, json.dumps(doc, sort_keys=True, separators=(",", ":")).encode())


def main() -> int:
    max_in, kind = int(sys.argv[1]), sys.argv[2]
    out = os.dup(1)
    os.dup2(2, 1)  # anything MobSF prints goes to stderr
    if kind not in ("apk", "aab", "ipa"):
        emit(out, {"tool": "mobsf", "error": "bad_kind"})
        return 2
    data = sys.stdin.buffer.read(max_in + 1)
    if not data or len(data) > max_in:
        emit(out, {"tool": "mobsf", "error": "bad_size"})
        return 2
    home = "/work/mobsf-home"
    os.makedirs(home + "/tools/jadx", mode=0o700, exist_ok=True)
    # Use the JADX the image ships (read-only). Otherwise MobSF tries to download it, which fails
    # with no network and silently skips decompilation.
    os.symlink(BUNDLED_JADX, home + "/tools/jadx/" + os.path.basename(BUNDLED_JADX))
    key = secrets.token_hex(32)  # never used for a request: there is no server and no URL routing
    os.environ.update(
        {
            "MOBSF_HOME_DIR": home,
            "MOBSF_API_KEY": key,
            "MOBSF_ASYNC_ANALYSIS": "0",
            "MOBSF_DEBUG": "0",
            "MOBSF_JADX_BINARY": BUNDLED_JADX + "/bin/jadx",
            "MOBSF_DOMAIN_MALWARE_SCAN": "0",  # a network lookup; there is no network
            "DJANGO_SETTINGS_MODULE": "mobsf.MobSF.settings",
        }
    )
    sys.path.insert(0, MOBSF_ROOT)
    import django  # type: ignore[import-not-found]

    django.setup()
    logging.disable(logging.CRITICAL)
    from django.contrib.auth.models import AnonymousUser  # type: ignore[import-not-found]
    from django.core.management import call_command  # type: ignore[import-not-found]
    from django.test import RequestFactory  # type: ignore[import-not-found]

    # Only the static-analysis API views are imported. MobSF's URL table would also load the dynamic
    # analyzer (mitmproxy, Frida, ADB), which Sentinel never uses: less code runs.
    from mobsf.MobSF.views.api import api_static_analysis as api  # type: ignore[import-not-found]

    # The image ships no StaticAnalyzer migrations (its entrypoint generates them); the root is
    # read-only here, so create the tables directly.
    call_command("migrate", verbosity=0, interactive=False, run_syncdb=True)
    rf = RequestFactory()

    def post(view: Any, payload: dict[str, Any]) -> Any:
        req = rf.post("/api/v1/", payload)
        req.user = AnonymousUser()
        return view(req)

    upload = io.BytesIO(data)
    upload.name = f"target.{kind}"
    r = post(api.api_upload, {"file": upload})
    if r.status_code != 200:
        emit(out, {"tool": "mobsf", "error": f"upload_{r.status_code}"})
        return 3
    md5 = json.loads(r.content)["hash"]
    r = post(api.api_scan, {"hash": md5})
    if r.status_code != 200:
        emit(out, {"tool": "mobsf", "error": f"scan_{r.status_code}"})
        return 3
    r = post(api.api_scorecard, {"hash": md5})
    if r.status_code != 200:
        emit(out, {"tool": "mobsf", "error": f"scorecard_{r.status_code}"})
        return 3
    card = json.loads(r.content)
    # MobSF carries on when a stage fails (decompiler, binary analysis, ...) and records it only in
    # the scan log. Every such failure is reported, so the host never accepts a partial analysis.
    from mobsf.MobSF.utils import get_scan_logs  # type: ignore[import-not-found]

    stage_errors = [
        str(e.get("status", ""))[:200]
        for e in get_scan_logs(md5)
        if isinstance(e, dict) and e.get("exception")
    ][:50]
    findings: list[dict[str, str]] = []
    for sec in SECTIONS:
        for item in card.get(sec) or []:
            if isinstance(item, dict) and len(findings) < MAX_FINDINGS:
                findings.append(
                    {
                        "level": sec,
                        "section": str(item.get("section", ""))[:100],
                        "title": str(item.get("title", ""))[:300],
                        "description": str(item.get("description", ""))[:500],
                    }
                )
    score = card.get("security_score")
    emit(
        out,
        {
            "tool": "mobsf",
            "findings": findings,
            "security_score": score if isinstance(score, int) else None,
            "truncated": len(findings) >= MAX_FINDINGS,
            "stage_errors": stage_errors,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
