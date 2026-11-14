"""Android static analyzer (M4). Reads AndroidManifest.xml, network security configs, Gradle files and
Java/Kotlin sources. Never builds, installs or runs anything (no APK handling: B2 stays disabled)."""

from __future__ import annotations

import os  # noqa: E402
import re
import sys  # noqa: E402
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import UnsafeXML, finding, line_of, main, parse_xml, read_text, walk

A = "{http://schemas.android.com/apk/res/android}"
DANGEROUS = {
    "android.permission.READ_SMS": "high",
    "android.permission.SEND_SMS": "high",
    "android.permission.RECEIVE_SMS": "high",
    "android.permission.READ_CALL_LOG": "high",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.ACCESS_FINE_LOCATION": "medium",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "high",
    "android.permission.RECORD_AUDIO": "medium",
    "android.permission.CAMERA": "low",
    "android.permission.READ_EXTERNAL_STORAGE": "low",
    "android.permission.WRITE_EXTERNAL_STORAGE": "medium",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "high",
    "android.permission.REQUEST_INSTALL_PACKAGES": "high",
    "android.permission.SYSTEM_ALERT_WINDOW": "medium",
    "android.permission.QUERY_ALL_PACKAGES": "medium",
}
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")


def _true(v: str | None) -> bool:
    return (v or "").strip().lower() == "true"


def manifest(p: Path, rel: str, out: list[dict[str, Any]]) -> None:
    text = read_text(p)
    try:
        root = parse_xml(p)
    except UnsafeXML as exc:
        out.append(finding("manifest-unsafe-xml", rel, 1, str(exc), "medium"))
        return
    except Exception:  # noqa: BLE001 - malformed manifest is reported, not fatal
        out.append(finding("manifest-unparseable", rel, 1, "AndroidManifest.xml could not be parsed", "low"))
        return
    app = root.find("application")
    if app is not None:
        if _true(app.get(A + "debuggable")):
            out.append(
                finding(
                    "debuggable",
                    rel,
                    line_of(text, "debuggable"),
                    'android:debuggable="true" in the manifest',
                    "high",
                )
            )
        if _true(app.get(A + "allowBackup")) or app.get(A + "allowBackup") is None:
            out.append(
                finding(
                    "allow-backup",
                    rel,
                    line_of(text, "<application"),
                    "App data may be backed up (allowBackup not set to false)",
                    "low",
                )
            )
        if _true(app.get(A + "requestLegacyExternalStorage")):
            out.append(
                finding(
                    "legacy-external-storage",
                    rel,
                    line_of(text, "requestLegacyExternalStorage"),
                    "requestLegacyExternalStorage opts out of scoped storage",
                    "low",
                )
            )
        if _true(app.get(A + "usesCleartextTraffic")):
            out.append(
                finding(
                    "cleartext-traffic",
                    rel,
                    line_of(text, "usesCleartextTraffic"),
                    'usesCleartextTraffic="true" permits unencrypted HTTP',
                    "medium",
                )
            )
        for tag in COMPONENTS:
            for c in app.iter(tag):
                name = c.get(A + "name") or "?"
                exported = c.get(A + "exported")
                has_filter = c.find("intent-filter") is not None
                is_exported = _true(exported) or (exported is None and has_filter)
                if (
                    is_exported
                    and not c.get(A + "permission")
                    and not (tag == "activity" and has_filter and _launcher(c))
                ):
                    sev = "high" if tag in ("provider", "service", "receiver") else "medium"
                    out.append(
                        finding(
                            f"exported-{tag}-unprotected",
                            rel,
                            line_of(text, name),
                            f"Exported {tag} {name} has no android:permission",
                            sev,
                        )
                    )
                for f in c.findall("intent-filter"):
                    deeplink(f, name, text, rel, out)
                if tag == "provider" and _true(c.get(A + "grantUriPermissions")):
                    out.append(
                        finding(
                            "provider-grant-uri",
                            rel,
                            line_of(text, name),
                            f"Provider {name} grants URI permissions",
                            "low",
                        )
                    )
    sdk = root.find("uses-sdk")
    if sdk is not None:
        try:
            if int(sdk.get(A + "minSdkVersion") or "99") < 23:
                out.append(
                    finding(
                        "min-sdk-low",
                        rel,
                        line_of(text, "minSdkVersion"),
                        "minSdkVersion below 23 (no runtime permissions, weak TLS defaults)",
                        "low",
                    )
                )
        except ValueError:
            pass
    for perm in root.iter("uses-permission"):
        name = perm.get(A + "name") or ""
        if name in DANGEROUS:
            out.append(
                finding("dangerous-permission", rel, line_of(text, name), f"Requests {name}", DANGEROUS[name])
            )


def deeplink(f: Any, name: str, text: str, rel: str, out: list[dict[str, Any]]) -> None:
    """Deep links: BROWSABLE VIEW filters. http(s) links need autoVerify; custom schemes are hijackable."""
    actions = {a.get(A + "name") for a in f.findall("action")}
    cats = {c.get(A + "name") for c in f.findall("category")}
    if "android.intent.action.VIEW" not in actions or "android.intent.category.BROWSABLE" not in cats:
        return
    schemes = {d.get(A + "scheme") for d in f.findall("data") if d.get(A + "scheme")}
    if schemes & {"http", "https"} and not _true(f.get(A + "autoVerify")):
        out.append(
            finding(
                "deeplink-unverified",
                rel,
                line_of(text, name),
                f"{name}: web deep link without autoVerify",
                "medium",
            )
        )
    for s in sorted(schemes - {"http", "https"}):
        out.append(
            finding(
                "deeplink-custom-scheme",
                rel,
                line_of(text, f'scheme="{s}"'),
                f"{name}: custom scheme {s} can be claimed by other apps; validate input",
                "low",
            )
        )


def _launcher(c: Any) -> bool:
    for f in c.iter("intent-filter"):
        cats = {x.get(A + "name") for x in f.iter("category")}
        if "android.intent.category.LAUNCHER" in cats:
            return True
    return False


def network_config(p: Path, rel: str, out: list[dict[str, Any]]) -> None:
    text = read_text(p)
    try:
        root = parse_xml(p)
    except Exception:  # noqa: BLE001
        return
    if root.tag != "network-security-config":
        return
    for el in root.iter():
        if el.tag in ("base-config", "domain-config") and _true(el.get("cleartextTrafficPermitted")):
            out.append(
                finding(
                    "nsc-cleartext",
                    rel,
                    line_of(text, "cleartextTrafficPermitted"),
                    f"{el.tag} permits cleartext traffic",
                    "medium",
                )
            )
        if el.tag == "certificates" and el.get("src") == "user":
            out.append(
                finding(
                    "nsc-user-certs",
                    rel,
                    line_of(text, 'src="user"'),
                    "User-installed CAs are trusted (TLS interception)",
                    "medium",
                )
            )
        if el.tag == "debug-overrides":
            continue


GRADLE = [
    (
        re.compile(r"\bdebuggable\s*(?:=\s*)?true\b"),
        "gradle-debuggable",
        "A build type sets debuggable true",
        "medium",
    ),
    (
        re.compile(r"\bminifyEnabled\s*(?:=\s*)?false\b"),
        "gradle-no-minify",
        "Code shrinking/obfuscation is disabled",
        "informational",
    ),
    (
        re.compile(
            r"""(?:implementation|api|compile|runtimeOnly)\s*\(?\s*['"][^'"\n]+:(?:[^'"\n]*\+|latest\.[a-z]+)['"]"""
        ),
        "gradle-dynamic-dependency",
        "Dependency with a dynamic version (+ or latest.*): builds are not reproducible",
        "medium",
    ),
    (
        re.compile(
            r"release\s*\{[^}]*signingConfig\s*(?:=\s*)?signingConfigs\.(?:getByName\(\s*\"debug\"\s*\)|debug)"
        ),
        "gradle-release-debug-signing",
        "Release build signed with the debug key",
        "high",
    ),
    (
        re.compile(r"\bmaven\s*\{\s*url\s*[= ]\s*['\"]http://"),
        "gradle-insecure-repo",
        "Dependency repository over plain HTTP",
        "high",
    ),
]
SOURCE = [
    (
        re.compile(r"MODE_WORLD_(?:READABLE|WRITEABLE)"),
        "world-accessible-file",
        "World-readable or world-writable file mode",
        "high",
    ),
    (
        re.compile(r"\.setJavaScriptEnabled\(\s*true\s*\)"),
        "webview-javascript",
        "WebView JavaScript enabled",
        "low",
    ),
    (
        re.compile(r"\.addJavascriptInterface\("),
        "webview-js-interface",
        "WebView exposes a JavaScript interface",
        "medium",
    ),
    (
        re.compile(r"\.setAllowFileAccess\(\s*true\s*\)"),
        "webview-file-access",
        "WebView file access enabled",
        "medium",
    ),
    (
        re.compile(r"setMixedContentMode\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW"),
        "webview-mixed-content",
        "WebView loads HTTP content into HTTPS pages",
        "medium",
    ),
    (
        re.compile(r"\.setAllowUniversalAccessFromFileURLs\(\s*true\s*\)"),
        "webview-universal-file-access",
        "WebView file URLs may read any origin",
        "high",
    ),
    (
        re.compile(r"onReceivedSslError[\s\S]{0,300}?\.proceed\(\s*\)"),
        "webview-ssl-error-ignored",
        "WebView proceeds despite TLS errors",
        "critical",
    ),
    (
        re.compile(r"SecretKeySpec\(\s*\"[^\"]{8,}\"\s*\.(?:getBytes|toByteArray)"),
        "hardcoded-crypto-key",
        "Hard-coded symmetric key",
        "high",
    ),
    (
        re.compile(r"new\s+SecureRandom\([^)]+\)|\.setSeed\("),
        "securerandom-seeded",
        "SecureRandom with a fixed seed is predictable",
        "medium",
    ),
    (
        re.compile(r"getExternalStorageDirectory\(|getExternalStoragePublicDirectory\("),
        "external-storage",
        "Data written to shared external storage",
        "low",
    ),
    (
        re.compile(r"Cipher\.getInstance\(\s*\"(?:DES|DESede|RC4|AES/ECB)[^\"]*\""),
        "weak-cipher",
        "Weak cipher or ECB mode",
        "high",
    ),
    (
        re.compile(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\""),
        "weak-hash",
        "MD5 or SHA-1 digest",
        "low",
    ),
    (
        re.compile(
            r"(?:X509TrustManager|HostnameVerifier)[\s\S]{0,400}?(?:return\s+true|checkServerTrusted\([^)]*\)\s*\{\s*\})"
        ),
        "tls-trust-all",
        "Custom TLS trust or hostname check that accepts everything",
        "critical",
    ),
    (
        re.compile(
            r"getSharedPreferences\([^)]*\)[\s\S]{0,200}?\.put(?:String)?\(\s*\"(?:password|token|secret|api_?key)\"",
            re.I,
        ),
        "secret-in-shared-prefs",
        "Credential written to SharedPreferences in plain text",
        "medium",
    ),
]


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in walk(root):
        rel = str(p.relative_to(root))
        if p.name == "AndroidManifest.xml":
            manifest(p, rel, out)
        elif (
            p.suffix == ".xml"
            and "xml" in p.parent.name
            and b"network-security-config" in p.read_bytes()[:65536]
        ):
            network_config(p, rel, out)
        elif p.name in ("build.gradle", "build.gradle.kts"):
            text = read_text(p)
            for rx, rule, msg, sev in GRADLE:
                for m in rx.finditer(text):
                    out.append(finding(rule, rel, text.count("\n", 0, m.start()) + 1, msg, sev))
        elif p.suffix in (".java", ".kt"):
            text = read_text(p)
            for rx, rule, msg, sev in SOURCE:
                for m in rx.finditer(text):
                    out.append(finding(rule, rel, text.count("\n", 0, m.start()) + 1, msg, sev))
    return out


if __name__ == "__main__":
    raise SystemExit(main("android", analyze))
