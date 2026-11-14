"""Extension analyzer (M6, roadmap D10). Static and offline: browser-extension manifests and VS Code
extension manifests. Reads JSON only; never installs, loads or runs an extension, never fetches an
update URL."""

from __future__ import annotations

import json
import os  # noqa: E402
import sys  # noqa: E402
from pathlib import Path
from typing import Any

# `python -I` doesn't put the script directory on sys.path; add only this directory (read-only).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _common import finding, line_of, main, read_text, walk

BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "file:///*"}
HIGH_PERMS = {"debugger", "nativeMessaging", "proxy", "management", "webRequestBlocking"}
MEDIUM_PERMS = {"cookies", "history", "clipboardRead", "downloads", "tabs", "webRequest", "scripting"}


def _strings(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def browser(rel: str, text: str, d: dict[str, Any], out: list[dict[str, Any]]) -> None:
    perms = set(_strings(d.get("permissions"))) | set(_strings(d.get("optional_permissions")))
    hosts = set(_strings(d.get("host_permissions"))) | (perms & BROAD_HOSTS)
    for cs in d.get("content_scripts") or []:
        if isinstance(cs, dict):
            hosts |= set(_strings(cs.get("matches")))
    for h in sorted(hosts & BROAD_HOSTS):
        out.append(
            finding(
                "ext.broad_host_access",
                rel,
                line_of(text, h),
                f"extension can access all sites ({h})",
                "high",
            )
        )
    for p in sorted(perms & HIGH_PERMS):
        out.append(
            finding("ext.sensitive_permission", rel, line_of(text, p), f"high-risk permission {p}", "high")
        )
    for p in sorted(perms & MEDIUM_PERMS):
        out.append(
            finding("ext.sensitive_permission", rel, line_of(text, p), f"sensitive permission {p}", "medium")
        )
    csp = d.get("content_security_policy")
    csp_text = json.dumps(csp) if not isinstance(csp, str) else csp
    if csp is not None and ("unsafe-eval" in csp_text or "http:" in csp_text):
        out.append(
            finding(
                "ext.weak_csp",
                rel,
                line_of(text, "content_security_policy"),
                "CSP allows eval or http",
                "high",
            )
        )
    ec = d.get("externally_connectable")
    if isinstance(ec, dict) and set(_strings(ec.get("matches"))) & (BROAD_HOSTS | {"*"}):
        out.append(
            finding(
                "ext.open_messaging",
                rel,
                line_of(text, "externally_connectable"),
                "any website can message the extension",
                "high",
            )
        )
    for war in d.get("web_accessible_resources") or []:
        if isinstance(war, dict) and set(_strings(war.get("matches"))) & BROAD_HOSTS:
            out.append(
                finding(
                    "ext.web_accessible_all",
                    rel,
                    line_of(text, "web_accessible_resources"),
                    "resources exposed to every website (fingerprinting and clickjacking)",
                    "medium",
                )
            )
            break
    upd = d.get("update_url")
    if isinstance(upd, str) and not upd.startswith("https://"):
        out.append(
            finding(
                "ext.insecure_update", rel, line_of(text, "update_url"), "update URL is not HTTPS", "medium"
            )
        )
    if d.get("manifest_version") == 2:
        out.append(
            finding(
                "ext.manifest_v2", rel, line_of(text, "manifest_version"), "Manifest V2 is deprecated", "low"
            )
        )


def vscode(rel: str, text: str, d: dict[str, Any], out: list[dict[str, Any]]) -> None:
    if "*" in _strings(d.get("activationEvents")):
        out.append(
            finding(
                "ide.activate_always",
                rel,
                line_of(text, "activationEvents"),
                "activates on every start",
                "medium",
            )
        )
    caps = d.get("capabilities")
    utw = caps.get("untrustedWorkspaces") if isinstance(caps, dict) else None
    if isinstance(utw, dict) and utw.get("supported") is True and d.get("main"):
        out.append(
            finding(
                "ide.untrusted_workspace",
                rel,
                line_of(text, "untrustedWorkspaces"),
                "runs code in untrusted workspaces",
                "medium",
            )
        )
    for section in ("dependencies", "optionalDependencies"):
        deps = d.get(section)
        if isinstance(deps, dict):
            for dep, spec in sorted(deps.items()):
                v = str(spec)
                if v in ("*", "latest", "") or v.startswith(("git", "http:", "https:", "github:", "file:")):
                    out.append(
                        finding(
                            "ide.dependency_unpinned",
                            rel,
                            line_of(text, f'"{dep}"'),
                            f"dependency {dep} is not pinned to a registry version ({v[:60]})",
                            "medium",
                        )
                    )
    scripts = d.get("scripts")
    if isinstance(scripts, dict):
        for k in ("preinstall", "install", "postinstall"):
            if k in scripts:
                out.append(
                    finding(
                        "ide.install_script", rel, line_of(text, k), f"{k} script runs at install", "medium"
                    )
                )


def analyze(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in walk(root):
        if p.name not in ("manifest.json", "package.json"):
            continue
        rel = str(p.relative_to(root))
        text = read_text(p)
        try:
            d = json.loads(text)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        if p.name == "manifest.json" and "manifest_version" in d:
            browser(rel, text, d, out)
        elif p.name == "package.json" and isinstance(d.get("engines"), dict) and "vscode" in d["engines"]:
            vscode(rel, text, d, out)
    return out


if __name__ == "__main__":
    raise SystemExit(main("extensions", analyze))
