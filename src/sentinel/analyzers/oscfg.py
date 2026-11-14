"""Operating-system configuration analyzer (M5). Analyses a read-only configuration snapshot directory
(for example a copy of /etc, launchd plists, or Windows .reg exports) for macOS, Linux and Windows.
It never reads the live host outside the scoped target, never changes anything and runs no commands.
Live-host assessment (asset kind `host`) stays NOT_RUN until host isolation and authorisation exist."""

from __future__ import annotations

import os  # noqa: E402
import plistlib
import re
import stat
import sys  # noqa: E402
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import finding, line_of, main, read_text, unparseable, walk


def _lines(text: str) -> list[tuple[int, str]]:
    return [
        (i + 1, ln.strip())
        for i, ln in enumerate(text.splitlines())
        if ln.strip() and not ln.strip().startswith("#")
    ]


def sshd(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    rules = {
        ("permitrootlogin", "yes"): ("ssh-root-login", "SSH permits root login", "high"),
        ("passwordauthentication", "yes"): (
            "ssh-password-auth",
            "SSH password authentication enabled",
            "medium",
        ),
        ("permitemptypasswords", "yes"): ("ssh-empty-passwords", "SSH permits empty passwords", "critical"),
        ("x11forwarding", "yes"): ("ssh-x11-forwarding", "SSH X11 forwarding enabled", "low"),
        ("protocol", "1"): ("ssh-protocol-1", "SSH protocol 1 enabled", "critical"),
        ("permituserenvironment", "yes"): (
            "ssh-user-environment",
            "SSH PermitUserEnvironment enabled",
            "medium",
        ),
    }
    for n, ln in _lines(text):
        parts = ln.split(None, 1)
        if len(parts) == 2:
            key = (parts[0].lower(), parts[1].strip().lower())
            if key in rules:
                rule, msg, sev = rules[key]
                out.append(finding(rule, rel, n, msg, sev))


def sudoers(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in _lines(text):
        if re.search(r"NOPASSWD\s*:\s*ALL\b", ln):
            out.append(finding("sudo-nopasswd-all", rel, n, "Passwordless sudo for all commands", "high"))
        if re.match(r"^ALL\s+ALL\s*=", ln):
            out.append(finding("sudo-all-users", rel, n, "Every user may run sudo", "critical"))
        if re.search(r"!authenticate\b", ln):
            out.append(finding("sudo-no-authenticate", rel, n, "sudo authentication disabled", "high"))


def passwd(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in _lines(text):
        f = ln.split(":")
        if len(f) >= 4 and f[2] == "0" and f[0] != "root":
            out.append(finding("uid0-non-root", rel, n, f"Account {f[0]!r} has UID 0", "critical"))
        if len(f) >= 2 and f[1] == "":
            out.append(
                finding(
                    "passwd-empty-password",
                    rel,
                    n,
                    f"Account {f[0]!r} has an empty password field",
                    "critical",
                )
            )


def shadow(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in _lines(text):
        f = ln.split(":")
        if len(f) >= 2 and f[1] == "":
            out.append(
                finding("shadow-empty-password", rel, n, f"Account {f[0]!r} has no password", "critical")
            )


SYSCTL = {
    "kernel.randomize_va_space": ("0", "sysctl-aslr-disabled", "ASLR disabled", "high"),
    "net.ipv4.ip_forward": ("1", "sysctl-ip-forward", "IPv4 forwarding enabled", "low"),
    "net.ipv4.conf.all.accept_redirects": ("1", "sysctl-icmp-redirects", "ICMP redirects accepted", "low"),
    "fs.suid_dumpable": ("2", "sysctl-suid-dumpable", "Core dumps of setuid programs enabled", "medium"),
    "kernel.kptr_restrict": ("0", "sysctl-kptr-exposed", "Kernel pointers exposed", "low"),
}


def sysctl(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    for n, ln in _lines(text):
        if "=" in ln:
            k, v = (x.strip() for x in ln.split("=", 1))
            if k in SYSCTL and v == SYSCTL[k][0]:
                _, rule, msg, sev = SYSCTL[k]
                out.append(finding(rule, rel, n, msg, sev))


def systemd(rel: str, text: str, out: list[dict[str, Any]]) -> None:
    if "[Service]" not in text:
        return
    keys = {ln.split("=", 1)[0].strip() for _, ln in _lines(text) if "=" in ln}
    if "User" not in keys and "DynamicUser" not in keys:
        out.append(
            finding(
                "systemd-runs-as-root", rel, 1, "Service runs as root (no User= or DynamicUser=)", "medium"
            )
        )
    if "NoNewPrivileges" not in keys:
        out.append(finding("systemd-no-new-privileges-missing", rel, 1, "NoNewPrivileges= not set", "low"))


#: Locations any local user can write; a launch job running from them can be hijacked.
WORLD_WRITABLE = ("/tmp/", "/private/tmp/", "/Users/Shared/", "/var/tmp/")  # noqa: S108


def launchd(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    try:
        d = plistlib.loads(path.read_bytes()[: 1 << 20])
    except Exception:  # noqa: BLE001
        out.append(unparseable(rel, "launchd plist"))
        return
    if not isinstance(d, dict):
        out.append(unparseable(rel, "launchd plist"))
        return
    args = d.get("ProgramArguments") or ([d["Program"]] if d.get("Program") else [])
    if args and isinstance(args[0], str) and args[0].startswith(WORLD_WRITABLE):
        out.append(
            finding(
                "launchd-writable-program-path",
                rel,
                1,
                f"Launch job runs a program from a world-writable location: {args[0]}",
                "high",
            )
        )
    if d.get("UserName") in (None, "root") and "LaunchDaemons" in rel and args:
        out.append(finding("launchd-daemon-as-root", rel, 1, "Launch daemon runs as root", "informational"))


REG = [
    (
        re.compile(r'"EnableLUA"=dword:00000000', re.I),
        "win-uac-disabled",
        "User Account Control disabled",
        "high",
    ),
    (
        re.compile(r'"LmCompatibilityLevel"=dword:0000000[0-2]', re.I),
        "win-weak-ntlm",
        "LM/NTLMv1 authentication allowed",
        "high",
    ),
    (re.compile(r'"SMB1"=dword:00000001', re.I), "win-smb1-enabled", "SMBv1 enabled", "high"),
    (
        re.compile(r'"DisableAntiSpyware"=dword:00000001', re.I),
        "win-defender-disabled",
        "Microsoft Defender disabled by policy",
        "high",
    ),
    (
        re.compile(r'"fDenyTSConnections"=dword:00000000', re.I),
        "win-rdp-enabled",
        "Remote Desktop enabled",
        "low",
    ),
    (
        re.compile(r'"UserAuthentication"=dword:00000000', re.I),
        "win-rdp-no-nla",
        "RDP without Network Level Authentication",
        "medium",
    ),
    (
        re.compile(r'"EnableFirewall"=dword:00000000', re.I),
        "win-firewall-disabled",
        "Windows Firewall profile disabled",
        "high",
    ),
    (
        re.compile(r'"UEFISecureBootEnabled"=dword:00000000', re.I),
        "win-secure-boot-off",
        "UEFI Secure Boot reported off",
        "medium",
    ),
    (
        re.compile(r'"UseLogonCredential"=dword:00000001', re.I),
        "win-wdigest-plaintext",
        "WDigest keeps plaintext credentials in memory",
        "high",
    ),
    (
        re.compile(r'"RunAsPPL"=dword:00000000', re.I),
        "win-lsa-not-protected",
        "LSA protection (RunAsPPL) disabled",
        "medium",
    ),
    (
        re.compile(r"\\CurrentVersion\\Run(?:Once)?\]\s*\n(?:\s*\n)*\s*\"[^\"]+\"=", re.I),
        "win-run-key-persistence",
        "Autostart entries under a Run/RunOnce key (review each)",
        "informational",
    ),
    (
        re.compile(r'"AutoAdminLogon"="1"', re.I),
        "win-auto-logon",
        "Automatic administrator logon configured",
        "high",
    ),
]


def regfile(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    raw = path.read_bytes()[: 4 * 1024 * 1024]
    text = (
        raw.decode("utf-16", "replace")
        if raw.startswith((b"\xff\xfe", b"\xfe\xff"))
        else raw.decode("utf-8", "replace")
    )
    head = text.lstrip("\ufeff").lstrip()[:64]
    if "\ufffd" in text or not head.startswith(("Windows Registry Editor Version 5.00", "REGEDIT4")):
        out.append(unparseable(rel, "registry export"))
        return
    for rx, rule, msg, sev in REG:
        for m in rx.finditer(text):
            out.append(finding(rule, rel, text.count("\n", 0, m.start()) + 1, msg, sev))


def modes(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    st = path.lstat()
    if st.st_mode & stat.S_IWOTH:
        out.append(finding("world-writable-file", rel, 0, "File is world-writable", "medium"))
    if st.st_mode & stat.S_ISUID:
        out.append(finding("setuid-file", rel, 0, "File has the setuid bit", "medium"))
    if rel.endswith(("shadow", "sudoers")) and st.st_mode & (stat.S_IROTH | stat.S_IWOTH):
        out.append(finding("sensitive-file-readable", rel, 0, "Sensitive file readable by others", "high"))


#: Text snapshots of status commands, captured by the operator (documented in docs/user/limitations.md).
STATUS_FILES = {
    "fdesetup-status.txt": (
        re.compile(r"FileVault is Off", re.I),
        "macos-filevault-off",
        "FileVault disk encryption off",
        "high",
    ),
    "csrutil-status.txt": (
        re.compile(r"System Integrity Protection status:\s*disabled", re.I),
        "macos-sip-disabled",
        "System Integrity Protection disabled",
        "high",
    ),
    "spctl-status.txt": (
        re.compile(r"assessments disabled", re.I),
        "macos-gatekeeper-disabled",
        "Gatekeeper assessments disabled",
        "high",
    ),
    "mokutil-sb-state.txt": (
        re.compile(r"SecureBoot disabled", re.I),
        "linux-secure-boot-off",
        "UEFI Secure Boot disabled",
        "medium",
    ),
}
KERNEL_FLAGS = [
    (
        re.compile(r"\bselinux=0\b"),
        "linux-selinux-disabled-boot",
        "SELinux disabled on the kernel command line",
        "high",
    ),
    (
        re.compile(r"\bapparmor=0\b"),
        "linux-apparmor-disabled-boot",
        "AppArmor disabled on the kernel command line",
        "high",
    ),
    (
        re.compile(r"\bmitigations=off\b"),
        "linux-cpu-mitigations-off",
        "CPU vulnerability mitigations disabled",
        "medium",
    ),
]


def linux_misc(rel: str, name: str, text: str, out: list[dict[str, Any]]) -> None:
    if name == "ufw.conf" and re.search(r"^\s*ENABLED\s*=\s*no\b", text, re.M | re.I):
        out.append(
            finding("linux-ufw-disabled", rel, line_of(text, "ENABLED"), "ufw firewall disabled", "medium")
        )
    elif name == "config" and "selinux" in rel and re.search(r"^\s*SELINUX\s*=\s*disabled\b", text, re.M):
        out.append(
            finding("linux-selinux-disabled", rel, line_of(text, "SELINUX="), "SELinux disabled", "high")
        )
    elif name == "grub":
        for n, ln in _lines(text):
            if ln.startswith("GRUB_CMDLINE_LINUX"):
                for rx, rule, msg, sev in KERNEL_FLAGS:
                    if rx.search(ln):
                        out.append(finding(rule, rel, n, msg, sev))
    elif "pam.d" in rel:
        for n, ln in _lines(text):
            if re.match(r"auth\s+\S+\s+pam_permit\.so", ln):
                out.append(
                    finding(
                        "pam-permit-auth",
                        rel,
                        n,
                        "pam_permit.so in the auth stack accepts anyone",
                        "critical",
                    )
                )
            elif re.match(r"auth\s.*pam_unix\.so.*\bnullok\b", ln):
                out.append(finding("pam-nullok", rel, n, "pam_unix nullok allows empty passwords", "medium"))
    elif name in ("crontab", "rc.local") or "cron." in rel or "/cron.d/" in "/" + rel:
        for n, ln in _lines(text):
            if any(w in ln for w in WORLD_WRITABLE):
                out.append(
                    finding(
                        "cron-writable-path", rel, n, "Scheduled job runs from a world-writable path", "high"
                    )
                )
            elif name == "rc.local" or ln.startswith("@reboot"):
                out.append(finding("boot-persistence", rel, n, "Runs at boot (review)", "informational"))
    elif name == "login.defs":
        m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", text, re.M)
        if m and int(m.group(1)) > 365:
            out.append(
                finding(
                    "password-no-expiry",
                    rel,
                    line_of(text, "PASS_MAX_DAYS"),
                    "Passwords effectively never expire",
                    "low",
                )
            )


def macos_firewall(rel: str, path: Path, out: list[dict[str, Any]]) -> None:
    try:
        d = plistlib.loads(path.read_bytes()[: 1 << 20])
    except Exception:  # noqa: BLE001
        out.append(unparseable(rel, "application firewall plist"))
        return
    if isinstance(d, dict) and d.get("globalstate") == 0:
        out.append(finding("macos-firewall-off", rel, 1, "macOS application firewall off", "medium"))


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in walk(root):
        rel = str(p.relative_to(root))
        name = p.name
        modes(rel, p, out)
        if name == "sshd_config" or (p.parent.name == "sshd_config.d" and name.endswith(".conf")):
            sshd(rel, read_text(p), out)
        elif name == "sudoers" or p.parent.name == "sudoers.d":
            sudoers(rel, read_text(p), out)
        elif name == "passwd":
            passwd(rel, read_text(p), out)
        elif name == "shadow":
            shadow(rel, read_text(p), out)
        elif name == "sysctl.conf" or (p.parent.name == "sysctl.d" and name.endswith(".conf")):
            sysctl(rel, read_text(p), out)
        elif name.endswith(".service"):
            systemd(rel, read_text(p), out)
        elif name.endswith(".plist") and ("LaunchDaemons" in rel or "LaunchAgents" in rel):
            launchd(rel, p, out)
        elif name.endswith(".reg"):
            regfile(rel, p, out)
        elif name == "com.apple.alf.plist":
            macos_firewall(rel, p, out)
        elif name in STATUS_FILES:
            rx, rule, msg, sev = STATUS_FILES[name]
            text = read_text(p)
            m = rx.search(text)
            if m:
                out.append(finding(rule, rel, text.count("\n", 0, m.start()) + 1, msg, sev))
        elif (
            name in ("ufw.conf", "grub", "crontab", "rc.local", "login.defs")
            or (name == "config" and "selinux" in rel)
            or "pam.d" in rel
            or "cron." in rel
        ):
            linux_misc(rel, name, read_text(p), out)
    return out


if __name__ == "__main__":
    raise SystemExit(main("oscfg", analyze))
