"""Completion of M4 (mobile), M5 (OS configuration snapshots) and M8 (supply chain, binary metadata).

Every check has a vulnerable and a clean synthetic fixture. Binaries are synthetic headers built here;
nothing is executed, decompressed or extracted. Real-sandbox runs of every analyzer are in
test_native_analyzers.py (parametrized over native_registry.ALL, which includes binmeta).
"""

# ruff: noqa: E501
from __future__ import annotations

import importlib
import json
import struct
import sys
import zipfile
from pathlib import Path

import pytest

from sentinel.adapters import native_registry
from sentinel.adapters.native import ANALYZERS_DIR, builtin_native_allowlist

sys.path.insert(0, str(ANALYZERS_DIR))
android = importlib.import_module("android")
ios = importlib.import_module("ios")
oscfg = importlib.import_module("oscfg")
supplychain = importlib.import_module("supplychain")
binmeta = importlib.import_module("binmeta")


def w(root: Path, rel: str, data: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def rules(mod, root: Path) -> set[str]:  # type: ignore[no-untyped-def]
    return {f["rule"] for f in mod.analyze(root)}


def check(mod, tmp_path, vuln: dict[str, str | bytes], clean: dict[str, str | bytes], rule: str) -> None:  # type: ignore[no-untyped-def]
    v, c = tmp_path / "v", tmp_path / "c"
    for rel, data in vuln.items():
        w(v, rel, data)
    for rel, data in clean.items():
        w(c, rel, data)
    assert rule in rules(mod, v), f"{rule} not detected"
    assert rule not in rules(mod, c), f"{rule} false positive"


NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def manifest(app_attrs: str = 'android:allowBackup="false"', body: str = "") -> str:
    return f'<?xml version="1.0"?><manifest {NS} package="x"><application {app_attrs}>{body}</application></manifest>'


DEEP_HTTP = '<activity android:name=".Link" android:exported="true" android:permission="p"><intent-filter{av}><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="https" android:host="example.invalid"/></intent-filter></activity>'
DEEP_CUSTOM = '<activity android:name=".Cb" android:exported="true" android:permission="p"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="myapp"/></intent-filter></activity>'

ANDROID_CASES = [
    (
        "deeplink-unverified",
        {"AndroidManifest.xml": manifest(body=DEEP_HTTP.format(av=""))},
        {"AndroidManifest.xml": manifest(body=DEEP_HTTP.format(av=' android:autoVerify="true"'))},
    ),
    (
        "deeplink-custom-scheme",
        {"AndroidManifest.xml": manifest(body=DEEP_CUSTOM)},
        {"AndroidManifest.xml": manifest(body=DEEP_HTTP.format(av=' android:autoVerify="true"'))},
    ),
    (
        "legacy-external-storage",
        {
            "AndroidManifest.xml": manifest(
                'android:allowBackup="false" android:requestLegacyExternalStorage="true"'
            )
        },
        {"AndroidManifest.xml": manifest()},
    ),
    (
        "gradle-dynamic-dependency",
        {"app/build.gradle": "dependencies {\n implementation 'com.squareup.okhttp3:okhttp:4.+'\n}\n"},
        {"app/build.gradle": "dependencies {\n implementation 'com.squareup.okhttp3:okhttp:4.12.0'\n}\n"},
    ),
    (
        "gradle-release-debug-signing",
        {"app/build.gradle": "android { buildTypes { release { signingConfig signingConfigs.debug } } }\n"},
        {"app/build.gradle": "android { buildTypes { release { signingConfig signingConfigs.release } } }\n"},
    ),
    (
        "webview-mixed-content",
        {"A.kt": "s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW)\n"},
        {"A.kt": "s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW)\n"},
    ),
    (
        "webview-universal-file-access",
        {"A.java": "s.setAllowUniversalAccessFromFileURLs(true);\n"},
        {"A.java": "s.setAllowUniversalAccessFromFileURLs(false);\n"},
    ),
    (
        "webview-ssl-error-ignored",
        {
            "A.java": "public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.proceed(); }\n"
        },
        {
            "A.java": "public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) { h.cancel(); }\n"
        },
    ),
    (
        "hardcoded-crypto-key",
        {"K.java": 'Key k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");\n'},
        {"K.java": "Key k = keyStore.getKey(alias, null);\n"},
    ),
    (
        "securerandom-seeded",
        {"R.java": "SecureRandom r = new SecureRandom(); r.setSeed(42);\n"},
        {"R.java": "SecureRandom r = new SecureRandom();\n"},
    ),
    (
        "external-storage",
        {"S.java": "File f = Environment.getExternalStorageDirectory();\n"},
        {"S.java": "File f = context.getFilesDir();\n"},
    ),
]


@pytest.mark.parametrize("rule, vuln, clean", ANDROID_CASES, ids=[c[0] for c in ANDROID_CASES])
def test_android_checks(tmp_path, rule, vuln, clean):
    check(android, tmp_path, vuln, clean, rule)


def plist(d: dict) -> bytes:
    import plistlib

    return plistlib.dumps(d)


IOS_CASES = [
    (
        "ats-web-content-loads",
        {"Info.plist": plist({"NSAppTransportSecurity": {"NSAllowsArbitraryLoadsInWebContent": True}})},
        {"Info.plist": plist({"NSAppTransportSecurity": {}})},
    ),
    (
        "background-modes",
        {"Info.plist": plist({"UIBackgroundModes": ["location", "audio"]})},
        {"Info.plist": plist({"CFBundleName": "x"})},
    ),
    (
        "file-sharing-enabled",
        {"Info.plist": plist({"UIFileSharingEnabled": True})},
        {"Info.plist": plist({"UIFileSharingEnabled": False})},
    ),
    (
        "data-protection-none",
        {"App.entitlements": plist({"com.apple.developer.default-data-protection": "NSFileProtectionNone"})},
        {
            "App.entitlements": plist(
                {"com.apple.developer.default-data-protection": "NSFileProtectionComplete"}
            )
        },
    ),
    (
        "keychain-wildcard-group",
        {"App.entitlements": plist({"keychain-access-groups": ["$(AppIdentifierPrefix)*"]})},
        {"App.entitlements": plist({"keychain-access-groups": ["$(AppIdentifierPrefix)com.example.app"]})},
    ),
    (
        "file-protection-none",
        {"S.swift": "try data.write(to: url, options: .noFileProtection)\n"},
        {"S.swift": "try data.write(to: url, options: .completeFileProtection)\n"},
    ),
    (
        "insecure-transport-url",
        {"N.swift": 'let u = URL(string: "http://api.example.invalid/v1")\n'},
        {
            "N.swift": 'let u = URL(string: "https://api.example.invalid/v1")\nlet l = URL(string: "http://localhost:8080")\n'
        },
    ),
    (
        "pod-unpinned",
        {"Podfile": "target 'App' do\n  pod 'Alamofire'\nend\n"},
        {"Podfile": "target 'App' do\n  pod 'Alamofire', '~> 5.9'\nend\n"},
    ),
    (
        "pod-git-unpinned",
        {"Podfile": "pod 'Lib', :git => 'https://example.invalid/lib.git'\n"},
        {"Podfile": "pod 'Lib', :git => 'https://example.invalid/lib.git', :tag => '1.2.0'\n"},
    ),
    (
        "pod-insecure-source",
        {"Podfile": "source 'http://specs.example.invalid/'\n"},
        {"Podfile": "source 'https://cdn.cocoapods.org/'\n"},
    ),
    (
        "spm-branch-dependency",
        {"Package.swift": '.package(url: "https://example.invalid/a.git", branch: "main")\n'},
        {"Package.swift": '.package(url: "https://example.invalid/a.git", from: "1.2.0")\n'},
    ),
    (
        "spm-insecure-url",
        {"Package.swift": '.package(url: "http://example.invalid/a.git", from: "1.0.0")\n'},
        {"Package.swift": '.package(url: "https://example.invalid/a.git", from: "1.0.0")\n'},
    ),
]


@pytest.mark.parametrize("rule, vuln, clean", IOS_CASES, ids=[c[0] for c in IOS_CASES])
def test_ios_checks(tmp_path, rule, vuln, clean):
    check(ios, tmp_path, vuln, clean, rule)


REG = "Windows Registry Editor Version 5.00\r\n\r\n"
OS_CASES = [
    (
        "win-firewall-disabled",
        {
            "fw.reg": REG
            + '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile]\r\n"EnableFirewall"=dword:00000000\r\n'
        },
        {
            "fw.reg": REG
            + '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile]\r\n"EnableFirewall"=dword:00000001\r\n'
        },
    ),
    (
        "win-secure-boot-off",
        {
            "sb.reg": REG
            + '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State]\r\n"UEFISecureBootEnabled"=dword:00000000\r\n'
        },
        {
            "sb.reg": REG
            + '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State]\r\n"UEFISecureBootEnabled"=dword:00000001\r\n'
        },
    ),
    (
        "win-wdigest-plaintext",
        {"w.reg": REG + '"UseLogonCredential"=dword:00000001\r\n'},
        {"w.reg": REG + '"UseLogonCredential"=dword:00000000\r\n'},
    ),
    (
        "win-lsa-not-protected",
        {"l.reg": REG + '"RunAsPPL"=dword:00000000\r\n'},
        {"l.reg": REG + '"RunAsPPL"=dword:00000001\r\n'},
    ),
    (
        "win-run-key-persistence",
        {
            "r.reg": REG
            + '[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"Updater"="C:\\\\Users\\\\Public\\\\u.exe"\r\n'
        },
        {"r.reg": REG + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n\r\n"},
    ),
    (
        "macos-filevault-off",
        {"fdesetup-status.txt": "FileVault is Off.\n"},
        {"fdesetup-status.txt": "FileVault is On.\n"},
    ),
    (
        "macos-sip-disabled",
        {"csrutil-status.txt": "System Integrity Protection status: disabled.\n"},
        {"csrutil-status.txt": "System Integrity Protection status: enabled.\n"},
    ),
    (
        "macos-gatekeeper-disabled",
        {"spctl-status.txt": "assessments disabled\n"},
        {"spctl-status.txt": "assessments enabled\n"},
    ),
    (
        "macos-firewall-off",
        {"Library/Preferences/com.apple.alf.plist": plist({"globalstate": 0})},
        {"Library/Preferences/com.apple.alf.plist": plist({"globalstate": 1})},
    ),
    (
        "linux-secure-boot-off",
        {"mokutil-sb-state.txt": "SecureBoot disabled\n"},
        {"mokutil-sb-state.txt": "SecureBoot enabled\n"},
    ),
    ("linux-ufw-disabled", {"etc/ufw/ufw.conf": "ENABLED=no\n"}, {"etc/ufw/ufw.conf": "ENABLED=yes\n"}),
    (
        "linux-selinux-disabled",
        {"etc/selinux/config": "SELINUX=disabled\n"},
        {"etc/selinux/config": "SELINUX=enforcing\n"},
    ),
    (
        "linux-selinux-disabled-boot",
        {"etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet selinux=0"\n'},
        {"etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n'},
    ),
    (
        "linux-cpu-mitigations-off",
        {"etc/default/grub": 'GRUB_CMDLINE_LINUX_DEFAULT="mitigations=off"\n'},
        {"etc/default/grub": 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n'},
    ),
    (
        "pam-permit-auth",
        {"etc/pam.d/sshd": "auth sufficient pam_permit.so\n"},
        {"etc/pam.d/sshd": "auth required pam_unix.so\n"},
    ),
    (
        "pam-nullok",
        {"etc/pam.d/common-auth": "auth [success=1 default=ignore] pam_unix.so nullok\n"},
        {"etc/pam.d/common-auth": "auth [success=1 default=ignore] pam_unix.so\n"},
    ),
    (
        "cron-writable-path",
        {"etc/crontab": "* * * * * root /tmp/job.sh\n"},
        {"etc/crontab": "* * * * * root /usr/local/bin/job.sh\n"},
    ),
    (
        "boot-persistence",
        {"var/spool/cron/crontab": "@reboot /usr/local/bin/agent\n"},
        {"var/spool/cron/crontab": "0 3 * * * /usr/local/bin/agent\n"},
    ),
    (
        "password-no-expiry",
        {"etc/login.defs": "PASS_MAX_DAYS 99999\n"},
        {"etc/login.defs": "PASS_MAX_DAYS 90\n"},
    ),
]


@pytest.mark.parametrize("rule, vuln, clean", OS_CASES, ids=[c[0] for c in OS_CASES])
def test_os_snapshot_checks(tmp_path, rule, vuln, clean):
    check(oscfg, tmp_path, vuln, clean, rule)


def test_os_snapshot_files_make_the_analyzer_applicable(tmp_path):
    w(tmp_path, "fdesetup-status.txt", "FileVault is On.\n")
    assert native_registry.OsConfigAdapter("x").plan(tmp_path)


def test_malformed_firewall_plist_is_unparseable(tmp_path):
    w(tmp_path, "Library/Preferences/com.apple.alf.plist", b"<plist")
    assert ("input-unparseable", "Library/Preferences/com.apple.alf.plist") in {
        (f["rule"], f["file"]) for f in oscfg.analyze(tmp_path)
    }


# ── M8 supply chain ───────────────────────────────────────────────────────
SC_CASES = [
    (
        "npm-no-lockfile",
        {"package.json": json.dumps({"name": "a", "dependencies": {"left-pad": "1.3.0"}})},
        {
            "package.json": json.dumps({"name": "a", "dependencies": {"left-pad": "1.3.0"}}),
            "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {}}),
        },
    ),
    (
        "sbom-component-unversioned",
        {
            "bom.json": json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [{"name": "a", "purl": "pkg:npm/a"}],
                }
            )
        },
        {
            "bom.json": json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [
                        {
                            "name": "a",
                            "version": "1.0.0",
                            "purl": "pkg:npm/a@1.0.0",
                            "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                        }
                    ],
                }
            )
        },
    ),
    (
        "sbom-invalid-purl",
        {
            "x.cdx.json": json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [{"name": "a", "version": "1", "purl": "npm:a"}],
                }
            )
        },
        {
            "x.cdx.json": json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {
                            "name": "a",
                            "version": "1",
                            "purl": "pkg:npm/a@1",
                            "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                        }
                    ],
                }
            )
        },
    ),
    (
        "sbom-empty",
        {"sbom.json": json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})},
        {
            "sbom.json": json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [
                        {"name": "a", "version": "1", "hashes": [{"alg": "SHA-256", "content": "0" * 64}]}
                    ],
                }
            )
        },
    ),
    (
        "sbom-invalid",
        {"x.spdx.json": json.dumps({"spdxVersion": "SPDX-2.3", "packages": []})},
        {
            "x.spdx.json": json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "packages": [{"name": "a", "SPDXID": "SPDXRef-a", "versionInfo": "1"}],
                }
            )
        },
    ),
    (
        "sbom-unknown-format",
        {"bom.json": json.dumps({"hello": "world"})},
        {
            "bom.json": json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [
                        {"name": "a", "version": "1", "hashes": [{"alg": "SHA-256", "content": "0" * 64}]}
                    ],
                }
            )
        },
    ),
]


@pytest.mark.parametrize("rule, vuln, clean", SC_CASES, ids=[c[0] for c in SC_CASES])
def test_supply_chain_completion_checks(tmp_path, rule, vuln, clean):
    check(supplychain, tmp_path, vuln, clean, rule)


def test_malformed_sbom_is_unparseable(tmp_path):
    w(tmp_path, "bom.json", "{not json")
    assert "input-unparseable" in rules(supplychain, tmp_path)


# ── M8 binary structural metadata ───────────────────────────────────────────
def pe_bytes(dllchars: int = 0x0140 | 0x4000, signed: bool = True, wx: bool = False) -> bytes:
    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<H", buf, opt + 70, dllchars)
    struct.pack_into("<I", buf, opt + 108, 16)
    if signed:
        struct.pack_into("<II", buf, opt + 112 + 32, 0x400, 0x100)
    chars = 0x60000020 | (0x80000000 if wx else 0)
    struct.pack_into("<8s6I2HI", buf, opt + 240, b".text", 0x1000, 0x1000, 0x200, 0x400, 0, 0, 0, 0, chars)
    return bytes(buf)


def msi_bytes(signed: bool) -> bytes:
    hdr = bytearray(512)
    hdr[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", hdr, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", hdr, 0x28, 0, 1, 1, 0, 4096, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    difat = [0] + [0xFFFFFFFF] * 108
    struct.pack_into("<109I", hdr, 0x4C, *difat)
    fat = struct.pack("<128I", 0xFFFFFFFD, 0xFFFFFFFE, *([0xFFFFFFFF] * 126))
    d = bytearray(512)

    def entry(i: int, name: str, typ: int) -> None:
        raw = (name + "\0").encode("utf-16-le")
        d[i * 128 : i * 128 + len(raw)] = raw
        struct.pack_into("<HB", d, i * 128 + 64, len(raw), typ)

    entry(0, "Root Entry", 5)
    entry(1, "\x05SummaryInformation", 2)
    if signed:
        entry(2, "\x05DigitalSignature", 2)
    return bytes(hdr) + fat + bytes(d)


def msix_bytes(tmp: Path, *, signed: bool = True, traversal: bool = False, bomb: bool = False) -> bytes:
    p = tmp / "pkg.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AppxManifest.xml", "<Package/>")
        z.writestr("AppxBlockMap.xml", "<BlockMap/>")
        if signed:
            z.writestr("AppxSignature.p7x", b"sig")
        if traversal:
            z.writestr(zipfile.ZipInfo("../../evil.dll"), b"x")
        if bomb:
            z.writestr("big.bin", b"\0" * (2 << 20))
    return p.read_bytes()


BIN_CASES = [
    ("pe-no-aslr", {"a.exe": pe_bytes(dllchars=0x0100 | 0x4000)}, {"a.exe": pe_bytes()}),
    ("pe-no-dep", {"a.dll": pe_bytes(dllchars=0x0040 | 0x4000)}, {"a.dll": pe_bytes()}),
    ("pe-no-cfg", {"a.exe": pe_bytes(dllchars=0x0140)}, {"a.exe": pe_bytes()}),
    ("pe-unsigned", {"a.exe": pe_bytes(signed=False)}, {"a.exe": pe_bytes()}),
    ("pe-wx-section", {"a.sys": pe_bytes(wx=True)}, {"a.sys": pe_bytes()}),
    ("msi-unsigned", {"setup.msi": msi_bytes(False)}, {"setup.msi": msi_bytes(True)}),
]


@pytest.mark.parametrize("rule, vuln, clean", BIN_CASES, ids=[c[0] for c in BIN_CASES])
def test_binary_metadata_checks(tmp_path, rule, vuln, clean):
    check(binmeta, tmp_path, vuln, clean, rule)


def test_signed_artifacts_are_reported_as_present_not_verified(tmp_path):
    w(tmp_path, "a.exe", pe_bytes())
    w(tmp_path, "s.msi", msi_bytes(True))
    out = {f["rule"]: f for f in binmeta.analyze(tmp_path)}
    assert (
        out["pe-signature-present"]["severity"] == "informational"
        and "not verified" in out["pe-signature-present"]["message"]
    )
    assert "not verified" in out["msi-signature-present"]["message"]


@pytest.mark.parametrize(
    "kw, rule",
    [
        ({"signed": False}, "msix-unsigned"),
        ({"traversal": True}, "package-path-traversal"),
        ({"bomb": True}, "package-compression-bomb"),
    ],
)
def test_msix_central_directory_checks(tmp_path, kw, rule):
    w(tmp_path / "v", "app.msix", msix_bytes(tmp_path, **kw))
    w(tmp_path / "c", "app.msix", msix_bytes(tmp_path))
    assert rule in rules(binmeta, tmp_path / "v") and rule not in rules(binmeta, tmp_path / "c")


def test_msix_contents_are_never_extracted(tmp_path, monkeypatch):
    w(tmp_path, "app.msix", msix_bytes(tmp_path, traversal=True))
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda *a, **k: pytest.fail("entry opened"))
    monkeypatch.setattr(zipfile.ZipFile, "extract", lambda *a, **k: pytest.fail("entry extracted"))
    monkeypatch.setattr(zipfile.ZipFile, "extractall", lambda *a, **k: pytest.fail("entries extracted"))
    binmeta.analyze(tmp_path)
    assert not (tmp_path.parent / "evil.dll").exists()


@pytest.mark.parametrize(
    "name, data",
    [
        ("a.exe", b"MZ" + b"\0" * 10),
        ("a.exe", b"not a pe at all"),
        ("b.dll", pe_bytes()[:0x90]),
        ("c.msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 20),
        ("d.msi", bytes.fromhex("D0CF11E0A1B11AE1") + b"\0" * 504),
        ("e.msix", b"PK\x03\x04garbage"),
    ],
)
def test_malformed_binaries_are_unparseable_not_fatal(tmp_path, name, data):
    w(tmp_path, name, data)
    w(tmp_path, "ok.exe", pe_bytes())
    out = binmeta.analyze(tmp_path)
    assert ("input-unparseable", name) in {(f["rule"], f["file"]) for f in out}
    assert any(f["file"] == "ok.exe" for f in out)  # other files still analysed


def test_msi_directory_cycle_is_bounded(tmp_path):
    data = bytearray(msi_bytes(False))
    struct.pack_into("<I", data, 512 + 4, 1)  # FAT[1] -> 1: the directory chain loops forever
    w(tmp_path, "loop.msi", bytes(data))
    # Run in a child process with a deadline: an unbounded walk must fail this test, not hang the suite.
    import subprocess

    r = subprocess.run(
        [sys.executable, "-I", str(ANALYZERS_DIR / "binmeta.py"), str(tmp_path)],
        capture_output=True,
        timeout=30,
    )
    assert r.returncode == 0
    out = json.loads(r.stdout)["findings"]
    assert ("input-unparseable", "loop.msi") in {(f["rule"], f["file"]) for f in out}


def test_msix_symlink_entry_is_reported(tmp_path):
    p = tmp_path / "s.msix"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AppxSignature.p7x", b"s")
        z.writestr("AppxBlockMap.xml", "<b/>")
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        z.writestr(info, "/etc/passwd")
    assert "package-symlink-entry" in rules(binmeta, tmp_path)


def test_msix_entry_count_limit_stops_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(binmeta, "MAX_ZIP_ENTRIES", 3)
    w(tmp_path, "big.msix", msix_bytes(tmp_path, traversal=True))
    out = rules(binmeta, tmp_path)
    assert "package-entry-limit" in out and "package-path-traversal" not in out  # nothing past the limit


def test_binmeta_is_registered_allowlisted_and_planned_only_for_binaries(tmp_path):
    assert "binmeta" in builtin_native_allowlist()
    a = native_registry.BinaryMetadataAdapter("x")
    w(tmp_path / "none", "a.txt", "x")
    assert a.plan(tmp_path / "none") == []
    w(tmp_path / "yes", "a.exe", pe_bytes())
    assert a.plan(tmp_path / "yes")


def test_mobsf_without_its_share_free_runner_is_not_run(tmp_path, monkeypatch):
    """D-72: MobSF runs only in the share-free machine. Without that runner it is NOT_RUN, no process."""
    import subprocess

    from sentinel import cli
    from sentinel.adapters.mobsf import MobsfAdapter
    from sentinel.domain.enums import CheckStatus

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("no process without the runner"))
    a = MobsfAdapter()
    w(tmp_path / "web", "index.html", "<p/>")
    assert a.plan(tmp_path / "web") == []
    w(tmp_path / "src", "AndroidManifest.xml", manifest())
    assert a.plan(tmp_path / "src") == []  # source trees never go to MobSF (D-72)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.apk").write_bytes(b"PK")
    plan = a.plan(tmp_path / "app")
    for runner in (None, object()):
        res = a.execute(plan[0], tmp_path / "app", 10, 1 << 20, runner=runner)
        assert res.status == CheckStatus.NOT_RUN and res.reason == "host_isolation_unavailable"
    assert any(isinstance(x, MobsfAdapter) for x in cli.default_adapters(cli.policy.default_policy()))
