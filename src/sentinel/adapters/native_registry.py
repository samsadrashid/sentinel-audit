"""The native analyzers and when they apply (M4, M5, M6/D10, M7/D11, M8).

Domain labels are descriptive, provisional and not product-specification domain IDs
(D-59 covers only D01, D02, D08 and D14).
"""

from __future__ import annotations

from pathlib import Path

from .native import NativeAnalyzerAdapter


def _has(root: Path, *names: str, suffixes: tuple[str, ...] = ()) -> bool:
    from ..analyzers_probe import any_file

    return any_file(root, set(names), suffixes)


class AndroidAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "android", "android.py", "mobile-android", "mobile.android"

    def applies(self, root: Path) -> bool:
        return _has(root, "AndroidManifest.xml", "build.gradle", "build.gradle.kts")


class IosAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "ios", "ios.py", "mobile-ios", "mobile.ios"

    def applies(self, root: Path) -> bool:
        return _has(
            root, "Info.plist", "Podfile", "Package.swift", suffixes=(".entitlements", ".xcodeproj", ".swift")
        )


class OsConfigAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "oscfg", "oscfg.py", "os-config", "os.config"

    def applies(self, root: Path) -> bool:
        return _has(
            root,
            "sshd_config",
            "sudoers",
            "passwd",
            "shadow",
            "sysctl.conf",
            "ufw.conf",
            "grub",
            "login.defs",
            "crontab",
            "rc.local",
            "com.apple.alf.plist",
            "fdesetup-status.txt",
            "csrutil-status.txt",
            "spctl-status.txt",
            "mokutil-sb-state.txt",
            suffixes=(".service", ".reg"),
        )


class SupplyChainAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "supplychain", "supplychain.py", "supply-chain", "supply.chain"

    def applies(self, root: Path) -> bool:
        return True


class ExtensionsAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "extensions", "extensions.py", "extensions", "extensions.manifest"

    def applies(self, root: Path) -> bool:
        return _has(root, "manifest.json", "package.json")


class AgentsAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "agents", "agents.py", "ai-agents", "agents.config"

    def applies(self, root: Path) -> bool:
        return True  # instruction files and agent settings can sit anywhere in a tree


BINARY_SUFFIXES = (
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".ocx",
    ".msi",
    ".msix",
    ".appx",
    ".msixbundle",
    ".appxbundle",
)


class BinaryMetadataAdapter(NativeAnalyzerAdapter):
    name, script, domain, check_id = "binmeta", "binmeta.py", "binaries", "binaries.metadata"

    def applies(self, root: Path) -> bool:
        return _has(
            root,
            suffixes=BINARY_SUFFIXES,
        )


ALL: tuple[type[NativeAnalyzerAdapter], ...] = (
    AndroidAdapter,
    IosAdapter,
    OsConfigAdapter,
    SupplyChainAdapter,
    ExtensionsAdapter,
    AgentsAdapter,
    BinaryMetadataAdapter,
)


def native_adapters(allowlist: dict[str, str]) -> list[NativeAnalyzerAdapter]:
    return [cls(allowlist.get(cls.name)) for cls in ALL]
