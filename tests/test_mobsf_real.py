"""Real MobSF 4.6.4 execution in the share-free Podman machine (D-72).

Runs only when the approved pins include `mobsf` and the share-free machine is running with the pinned
image. Otherwise every test is SKIPPED with the precondition reason; a skip is never a pass.
"""

from __future__ import annotations

import json

import pytest

from sentinel import mobsf
from sentinel.adapters.mobsf import MobsfAdapter
from sentinel.domain.enums import CheckStatus
from sentinel.isolation import b2 as b2iso

from .test_b2 import MANIFEST, axml_doc, zbytes
from .test_m2_real_scanners import PINS

RUNNER = (
    b2iso.B2Runner(PINS.podman, PINS.mobsf, b2iso.MOBSF_PROFILE)
    if PINS is not None and PINS.podman and PINS.mobsf
    else None
)
WHY = "no mobsf pin" if RUNNER is None else RUNNER.precondition()
pytestmark = pytest.mark.skipif(
    WHY is not None, reason=f"MobSF share-free runner not usable: {WHY} (not a pass)"
)


def test_mobsf_container_self_test_observations():
    p = RUNNER.probe()  # type: ignore[union-attr]
    assert p.available, p.reason
    assert p.observations == {**b2iso.EXPECTED, "uid": "9901"}


def test_real_mobsf_scan_of_an_apk_end_to_end(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "app.apk").write_bytes(zbytes([("AndroidManifest.xml", axml_doc(MANIFEST))]))
    a = MobsfAdapter()
    plan = a.plan(t)
    res = a.execute(plan[0], t, 900, 8 << 20, runner=RUNNER)
    assert res.status in (CheckStatus.FAIL, CheckStatus.PASS), (res.status, res.reason)
    assert res.isolation == "mobsf-podman-share-free" and res.binary_sha256 == mobsf.program()[1]
    doc = json.loads(res.raw_output)[0]
    assert doc["tool"] == "mobsf" and "error" not in doc
    # The fixture manifest is debuggable and allows backups: MobSF must report it.
    assert any(f["severity"] == "high" and f["file"] == "app.apk" for f in res.findings), res.findings


def test_mobsf_container_cannot_reach_the_network_or_the_host():
    probe = r"""
import json, os, socket
r = {}
try:
    socket.create_connection(("1.1.1.1", 443), timeout=2); r["net"] = "allowed"
except OSError:
    r["net"] = "denied"
r["host"] = [p for p in ("/Users", "/private", "/var/folders", "/mnt/host") if os.path.exists(p)]
SHARE = ("virtiofs", "9p", "nfs", "cifs")
r["mounts"] = [l.split()[1] for l in open("/proc/mounts") if l.split()[2] in SHARE]
print(json.dumps(r))
"""
    run = RUNNER.run(probe, [], b"", timeout_s=120, max_output=10_000).run  # type: ignore[union-attr]
    assert run.returncode == 0
    assert json.loads(run.stdout) == {"net": "denied", "host": [], "mounts": []}
