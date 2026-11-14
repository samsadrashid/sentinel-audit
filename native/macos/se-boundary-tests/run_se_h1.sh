#!/bin/sh
# SE-H1 and the Design A creation probe. TEST ONLY: disposable directory, throwaway key, no Sentinel
# state, no operator key. Needs the operator at the Mac for up to two authentication prompts.
# Usage: run_se_h1.sh <evidence-output.json>
set -eu
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/../../.." && pwd)"
outjson="${1:?usage: run_se_h1.sh <evidence.json>}"
T="$(mktemp -d /tmp/sentinel-se-h1.XXXXXX)"; chmod 700 "$T"
cleanup() { rm -rf "$T"; echo "cleanup: removed $T"; }
trap cleanup EXIT INT TERM
echo "== building genuine helper, attacker and probe in $T"
sh "$repo/native/macos/se-helper/build.sh" "$T/helper" > "$T/helper.sha256"
xcrun swiftc -O -target "$(uname -m)-apple-macosx14.0" -o "$T/attacker" "$here/attacker.swift"
xcrun swiftc -O -target "$(uname -m)-apple-macosx14.0" -o "$T/dp_probe" "$here/dp_probe.swift"
codesign --force --sign - --timestamp=none "$T/attacker" "$T/dp_probe" 2>/dev/null
# Disposable home for everything that runs from here on (no Sentinel or user state is read).
export HOME="$T/home" SENTINEL_HOME="$T/home/sentinel"; mkdir -p "$SENTINEL_HOME"
echo "== creating THROWAWAY key with the genuine helper (no prompt expected)"
"$T/helper" create > "$T/create.json"
/usr/bin/python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));open(sys.argv[2],"w").write(d["handle_b64"])' "$T/create.json" "$T/handle.b64"
echo
echo ">>> PROMPT 1: a dialog with ATTACKER text ('...ATTACKER TEXT, SE-H1') will appear."
echo ">>> Authenticate with Touch ID or password to let the test complete. Then note exactly what it said."
"$T/attacker" "$T/handle.b64" custom > "$T/attack_custom.json" || true
cat "$T/attack_custom.json"
printf "Describe prompt 1 exactly (title, text, any app name/icon shown): "; read -r P1
echo
echo ">>> PROMPT 2: the attacker signs WITHOUT supplying its own dialog (system default text)."
"$T/attacker" "$T/handle.b64" default > "$T/attack_default.json" || true
cat "$T/attack_default.json"
printf "Describe prompt 2 exactly (title, text, any app name/icon shown): "; read -r P2
echo
echo "== Design A probe: unentitled ad-hoc binary creating an access-group Secure Enclave key"
"$T/dp_probe" "SE01TEST.org.sentinel.se01" "se01-probe-$$" > "$T/dp_probe.json" || true
cat "$T/dp_probe.json"
"$repo/.venv/bin/python" -I - "$T" "$outjson" "$P1" "$P2" <<'PY'
import base64, json, platform, subprocess, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
T, outp, p1, p2 = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
def sh(*c):
    r = subprocess.run(list(c), capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()
create = json.loads((T / "create.json").read_text())
def verify(name):
    d = json.loads((T / name).read_text())
    if d.get("signed"):
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(create["public_x963_hex"]))
        try:
            pub.verify(base64.b64decode(d["signature_der_b64"]), base64.b64decode(d["message_b64"]), ec.ECDSA(hashes.SHA256()))
            d["verifies_against_throwaway_public_key"] = True
        except Exception as e:
            d["verifies_against_throwaway_public_key"] = f"no: {e}"
        d["same_public_key_as_helper_created"] = d.get("public_x963_hex") == create["public_x963_hex"]
    return d
ev = {
    "test": "SE-H1 (+ Design A creation probe)",
    "macos": sh("sw_vers"),
    "hardware": {"model": sh("sysctl", "-n", "hw.model"), "cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "arch": platform.machine()},
    "xcode": sh("xcrun", "swiftc", "--version"),
    "genuine_helper": {"sha256": (T / "helper.sha256").read_text().strip(), "codesign": sh("codesign", "-dv", str(T / "helper")), "entitlements": sh("codesign", "-d", "--entitlements", "-", str(T / "helper"))},
    "attacker": {"codesign": sh("codesign", "-dv", str(T / "attacker")), "entitlements": sh("codesign", "-d", "--entitlements", "-", str(T / "attacker"))},
    "key": {"created_by": "genuine helper `create` (SecAccessControl: privateKeyUsage+userPresence, WhenUnlockedThisDeviceOnly)", "public_x963_hex": create["public_x963_hex"], "handle_bytes": len(base64.b64decode(create["handle_b64"]))},
    "api_calls_attacker": ["SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:authenticationContext:)", "LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: <attacker text>) [custom mode]", "PrivateKey.signature(for:)"],
    "attack_custom_reason": verify("attack_custom.json"),
    "attack_default_prompt": verify("attack_default.json"),
    "operator_observed_prompt_1": p1,
    "operator_observed_prompt_2": p2,
    "design_a_probe_unentitled": json.loads((T / "dp_probe.json").read_text() or "{}"),
    "cleanup": "disposable directory deleted on exit; the throwaway key existed only as a handle in that directory (no keychain item was created by the helper)",
}
Path(outp).write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
print("evidence written:", outp)
PY
