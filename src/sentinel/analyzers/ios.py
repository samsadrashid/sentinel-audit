"""iOS static analyzer (M4). Reads Info.plist, entitlements, privacy manifests and Swift/Objective-C
sources. Never builds, signs, installs or runs anything (no IPA handling: B2 stays disabled)."""

from __future__ import annotations

import os  # noqa: E402
import plistlib
import re
import sys  # noqa: E402
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import finding, line_of, main, read_text, unparseable, walk

#: APIs/frameworks that need a usage-description key in Info.plist.
USAGE_KEYS = {
    "AVCaptureDevice": "NSCameraUsageDescription",
    "CLLocationManager": "NSLocationWhenInUseUsageDescription",
    "CNContactStore": "NSContactsUsageDescription",
    "PHPhotoLibrary": "NSPhotoLibraryUsageDescription",
    "AVAudioSession": "NSMicrophoneUsageDescription",
    "HKHealthStore": "NSHealthShareUsageDescription",
    "LAContext": "NSFaceIDUsageDescription",
}
SOURCE = [
    (
        re.compile(r"kSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b"),
        "keychain-always-accessible",
        "Keychain item accessible while the device is locked",
        "high",
    ),
    (
        re.compile(
            r"UserDefaults\.standard\.set\([^)]*,\s*forKey:\s*\"(?:password|token|secret|api_?key)\"", re.I
        ),
        "secret-in-userdefaults",
        "Credential stored in UserDefaults",
        "medium",
    ),
    (
        re.compile(r"\bCC_MD5\b|\bInsecure\.MD5\b|\bCC_SHA1\b|\bInsecure\.SHA1\b"),
        "weak-hash",
        "MD5 or SHA-1 digest",
        "low",
    ),
    (re.compile(r"kCCAlgorithmDES\b|kCCOptionECBMode\b"), "weak-cipher", "DES or ECB mode", "high"),
    (
        re.compile(
            r"(?:serverTrust|didReceive\s+challenge)[\s\S]{0,400}?\.useCredential\b[\s\S]{0,120}?URLCredential\(trust:"
        ),
        "tls-trust-all",
        "URLSession challenge handler accepts any server trust",
        "high",
    ),
    (re.compile(r"\bUIWebView\b"), "uiwebview", "Deprecated UIWebView", "low"),
    (
        re.compile(r"\.noFileProtection\b|NSFileProtectionNone\b|FileProtectionType\.none\b"),
        "file-protection-none",
        "File written without data protection",
        "medium",
    ),
    (
        re.compile(r"URL\(string:\s*\"http://(?!localhost|127\.0\.0\.1)"),
        "insecure-transport-url",
        "Plain HTTP URL in source",
        "low",
    ),
    (
        re.compile(r"NSLog\([^)]*(?:password|token|secret)", re.I),
        "secret-logged",
        "Credential written to the system log",
        "medium",
    ),
]


def plist(p: Path) -> dict[str, Any] | None:
    try:
        data = plistlib.loads(p.read_bytes()[: 4 * 1024 * 1024])
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def podfile(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    """CocoaPods dependency pinning and sources."""
    for n, ln in enumerate(text.splitlines(), 1):
        s = ln.split("#", 1)[0].strip()
        if re.match(r"source\s+['\"]http://", s):
            out.append(finding("pod-insecure-source", rel, n, "CocoaPods source over plain HTTP", "high"))
        m = re.match(r"pod\s+['\"]([^'\"]+)['\"](.*)$", s)
        if not m:
            continue
        rest = m.group(2)
        if ":git" in rest and not re.search(r":(?:tag|commit)\s*=>", rest):
            out.append(
                finding(
                    "pod-git-unpinned", rel, n, f"Pod {m.group(1)} from git without a tag or commit", "medium"
                )
            )
        elif ":git" not in rest and ":path" not in rest and not re.search(r"['\"][~>=<\d]", rest):
            out.append(finding("pod-unpinned", rel, n, f"Pod {m.group(1)} has no version requirement", "low"))


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    info: dict[str, Any] = {}
    sources: list[tuple[str, str]] = []
    privacy_manifest = False
    for p in walk(root):
        rel = str(p.relative_to(root))
        if p.name == "Info.plist":
            d = plist(p)
            if d is None:
                out.append(unparseable(rel, "Info.plist"))
                continue
            info.update(d)
            text = read_text(p)
            ats = d.get("NSAppTransportSecurity") or {}
            if isinstance(ats, dict):
                if ats.get("NSAllowsArbitraryLoads") is True:
                    out.append(
                        finding(
                            "ats-arbitrary-loads",
                            rel,
                            line_of(text, "NSAllowsArbitraryLoads"),
                            "App Transport Security disabled (NSAllowsArbitraryLoads)",
                            "high",
                        )
                    )
                for dom, cfg in (ats.get("NSExceptionDomains") or {}).items():
                    if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                        out.append(
                            finding(
                                "ats-insecure-domain",
                                rel,
                                line_of(text, dom),
                                f"Insecure HTTP allowed for {dom}",
                                "medium",
                            )
                        )
                    if isinstance(cfg, dict) and cfg.get("NSExceptionMinimumTLSVersion") in (
                        "TLSv1.0",
                        "TLSv1.1",
                    ):
                        out.append(
                            finding(
                                "ats-old-tls",
                                rel,
                                line_of(text, dom),
                                f"TLS below 1.2 allowed for {dom}",
                                "medium",
                            )
                        )
            if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
                out.append(
                    finding(
                        "ats-web-content-loads",
                        rel,
                        line_of(text, "NSAllowsArbitraryLoadsInWebContent"),
                        "ATS disabled for web views",
                        "medium",
                    )
                )
            modes = d.get("UIBackgroundModes")
            if isinstance(modes, list) and modes:
                out.append(
                    finding(
                        "background-modes",
                        rel,
                        line_of(text, "UIBackgroundModes"),
                        "Background capabilities: " + ", ".join(sorted(str(m) for m in modes))[:300],
                        "informational",
                    )
                )
            if d.get("UIFileSharingEnabled") is True:
                out.append(
                    finding(
                        "file-sharing-enabled",
                        rel,
                        line_of(text, "UIFileSharingEnabled"),
                        "Documents folder is exposed through Finder/iTunes file sharing",
                        "low",
                    )
                )
            for scheme in d.get("CFBundleURLTypes") or []:
                for s in (scheme or {}).get("CFBundleURLSchemes") or []:
                    out.append(
                        finding(
                            "custom-url-scheme",
                            rel,
                            line_of(text, str(s)),
                            f"Custom URL scheme {s}: validate every incoming URL",
                            "informational",
                        )
                    )
        elif p.suffix == ".entitlements":
            parsed = plist(p)
            if parsed is None:
                out.append(unparseable(rel, "entitlements plist"))
            d = parsed or {}
            text = read_text(p)
            if d.get("get-task-allow") is True:
                out.append(
                    finding(
                        "get-task-allow",
                        rel,
                        line_of(text, "get-task-allow"),
                        "get-task-allow enabled (debuggable build)",
                        "high",
                    )
                )
            if d.get("com.apple.developer.default-data-protection") == "NSFileProtectionNone":
                out.append(
                    finding(
                        "data-protection-none",
                        rel,
                        line_of(text, "default-data-protection"),
                        "Default file data protection is NSFileProtectionNone",
                        "high",
                    )
                )
            groups = d.get("keychain-access-groups")
            if isinstance(groups, list) and any(str(g).endswith("*") for g in groups):
                out.append(
                    finding(
                        "keychain-wildcard-group",
                        rel,
                        line_of(text, "keychain-access-groups"),
                        "Wildcard keychain access group",
                        "medium",
                    )
                )
            if d.get("com.apple.security.cs.disable-library-validation") is True:
                out.append(
                    finding(
                        "disable-library-validation",
                        rel,
                        line_of(text, "disable-library-validation"),
                        "Library validation disabled",
                        "high",
                    )
                )
            if d.get("com.apple.security.cs.allow-unsigned-executable-memory") is True:
                out.append(
                    finding(
                        "unsigned-exec-memory",
                        rel,
                        line_of(text, "allow-unsigned-executable-memory"),
                        "Unsigned executable memory allowed",
                        "medium",
                    )
                )
        elif p.name == "Podfile":
            podfile(rel, read_text(p), out)
        elif p.name == "Package.swift":
            text = read_text(p)
            for m in re.finditer(r"\.package\([^)]*\bbranch:\s*\"", text):
                out.append(
                    finding(
                        "spm-branch-dependency",
                        rel,
                        text.count("\n", 0, m.start()) + 1,
                        "Swift package pinned to a branch, not a version",
                        "medium",
                    )
                )
            for m in re.finditer(r"\.package\(\s*url:\s*\"http://", text):
                out.append(
                    finding(
                        "spm-insecure-url",
                        rel,
                        text.count("\n", 0, m.start()) + 1,
                        "Swift package fetched over plain HTTP",
                        "high",
                    )
                )
        elif p.name == "PrivacyInfo.xcprivacy":
            privacy_manifest = True
        elif p.suffix in (".swift", ".m", ".mm"):
            text = read_text(p)
            sources.append((rel, text))
            for rx, rule, msg, sev in SOURCE:
                for m in rx.finditer(text):
                    out.append(finding(rule, rel, text.count("\n", 0, m.start()) + 1, msg, sev))
    for rel, text in sources:
        for api, key in USAGE_KEYS.items():
            if api in text and key not in info and info:
                out.append(
                    finding(
                        "missing-usage-description",
                        rel,
                        line_of(text, api),
                        f"{api} used but {key} is missing from Info.plist",
                        "medium",
                    )
                )
    if sources and not privacy_manifest:
        out.append(
            finding(
                "missing-privacy-manifest",
                sources[0][0],
                0,
                "No PrivacyInfo.xcprivacy privacy manifest found",
                "low",
            )
        )
    return out


if __name__ == "__main__":
    raise SystemExit(main("ios", analyze))
