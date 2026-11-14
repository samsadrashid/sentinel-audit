"""Report renderers: canonical JSON, SARIF 2.1.0, Markdown and HTML (D-17).

All renderers take the same canonical result object. Untrusted strings (scanner output, file names)
are escaped for each format. No renderer reports a target as "secure".
"""

from __future__ import annotations

import html
import json
from typing import Any

from .. import canonical

SEV_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
DISCLAIMER = (
    "This report lists what Sentinel checked and found. It is not a statement that the target is "
    "secure. Checks that did not run are listed explicitly."
)


def to_json(result: dict[str, Any]) -> bytes:
    return canonical.encode(result)


def to_sarif(result: dict[str, Any]) -> bytes:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in result["findings"]:
        rules.setdefault(f["rule"], {"id": f["rule"], "shortDescription": {"text": f["title"][:200]}})
        results.append(
            {
                "ruleId": f["rule"],
                "level": SEV_TO_SARIF.get(f["severity"], "warning"),
                "message": {"text": f["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["location"]["file"]},
                            "region": {"startLine": max(1, int(f["location"]["line"]))},
                        }
                    }
                ],
                "partialFingerprints": {"sentinel/v1": f["fingerprint"]},
                **(
                    {
                        "suppressions": [
                            {
                                "kind": "external",
                                "status": "accepted",
                                "justification": f["suppression"]["rationale"],
                            }
                        ]
                    }
                    if f.get("suppression")
                    else {}
                ),
                "properties": {
                    "severity": f["severity"],
                    "confidence": f["confidence"],
                    "state": f["state"],
                    "origin": f["origin"],
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": result["sentinel_version"],
                        "rules": [rules[k] for k in sorted(rules)],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": result["overall"] in ("PASS", "FAIL"),
                        "properties": {"audit_state": result["state"], "overall": result["overall"]},
                    }
                ],
                # AC-06: SARIF property bags (SARIF 2.1.0 section 3.8) carry coverage, the checks that
                # did not finish and the run's limitations, so a SARIF consumer sees what wasn't covered.
                "properties": {
                    "checks": result["checks"],
                    "checks_not_finished": result.get("checks_not_finished", []),
                    "disclaimer": DISCLAIMER,
                    "limitations": result.get("integrity_note", ""),
                    **(
                        {"domain_coverage": result["domain_coverage"]}
                        if result.get("domain_coverage") is not None
                        else {}
                    ),
                },
            }
        ],
    }
    from ..schema import check_output

    check_output(sarif, "sarif-profile")  # D-40: before the export is written
    return json.dumps(sarif, indent=2, sort_keys=True).encode()


def _md_escape(s: str) -> str:
    return "".join("\\" + c if c in "\\`*_{}[]()#+-.!|<>" else c for c in s.replace("\n", " "))


def to_markdown(result: dict[str, Any]) -> bytes:
    lines = [
        f"# Sentinel audit {result['audit_id']}",
        "",
        f"**Overall:** {result['overall']}  ",
        f"**State:** {result['state']}  ",
        f"**Mode / level:** {result['mode']} / {result['level']}  ",
        f"**Target revision:** {_md_escape(str(result['target']['revision']))}  ",
        f"**Data boundary:** {_md_escape(result['disclosure']['statement'])}",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Checks",
        "",
        "| Check | Status | Reason |",
        "|---|---|---|",
    ]
    for c in result["checks"]:
        lines.append(f"| {_md_escape(c['check_id'])} | {c['status']} | {_md_escape(c.get('reason', ''))} |")
    s = result["summary"]
    lines += [
        "",
        "## Findings",
        "",
        f"Total {s['total']}; verified {s['verified']}; human-verified without deterministic evidence "
        f"{s['human_verified_no_deterministic_evidence']} (reported separately, never counted as verified).",
        "",
        "| Severity | Confidence | State | Rule | Title | Location |",
        "|---|---|---|---|---|---|",
    ]
    for f in result["findings"]:
        loc = f"{f['location']['file']}:{f['location']['line']}"
        lines.append(
            f"| {f['severity']} | {f['confidence']} | {f['state']} | {_md_escape(f['rule'])} | "
            f"{_md_escape(f['title'])} | {_md_escape(loc)} |"
        )
    hv = [f for f in result["findings"] if f["state"] == "HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE"]
    lines += ["", "## Human-verified without deterministic evidence", ""]
    lines += [
        f"- {_md_escape(f['rule'])} {_md_escape(f['fingerprint'][:16])}: "
        f"{_md_escape(str((f.get('review') or {}).get('rationale', '')))}"
        for f in hv
    ] or ["None."]
    ex = [f for f in result["findings"] if f.get("suppression")]
    lines += ["", "## Exclusions (suppressed and accepted risk)", ""]
    lines += [
        f"- {f['suppression']['type']}: {f['severity']} {_md_escape(f['rule'])} "
        f"{_md_escape(f['fingerprint'][:16])}, expires {int(f['suppression']['expires_at'])}: "
        f"{_md_escape(str(f['suppression']['rationale']))}"
        for f in ex
    ] or ["None."]
    rej = result.get("decisions", {}).get("rejected", [])
    if rej:
        lines += ["", f"{len(rej)} recorded decision(s) were not applied (invalid, expired or revoked)."]
    lines += ["", "## Domain coverage", ""]
    lines += [
        f"- {d} {_md_escape(str(c.get('name', '')))}: **{_md_escape(str(c['status']))}**"
        + "".join(
            f"; {_md_escape(r['adapter'])} {r['status']}"
            + (f" ({_md_escape(r['reason'])})" if r["reason"] else "")
            for r in c.get("required_checks", [])
        )
        for d, c in sorted((result.get("domain_coverage") or {}).items())
    ] or ["Not reported."]
    lines += ["", "## Integrity", "", _md_escape(result["integrity_note"]), ""]
    return "\n".join(lines).encode()


def _html_sections(result: dict[str, Any]) -> str:
    e = html.escape
    hv = "".join(
        f"<li>{e(f['rule'])} {e(f['fingerprint'][:16])}: "
        f"{e(str((f.get('review') or {}).get('rationale', '')))}</li>"
        for f in result["findings"]
        if f["state"] == "HUMAN_VERIFIED_NO_DETERMINISTIC_EVIDENCE"
    )
    ex = "".join(
        f"<li>{e(f['suppression']['type'])}: {e(f['severity'])} {e(f['rule'])} {e(f['fingerprint'][:16])}, "
        f"expires {int(f['suppression']['expires_at'])}: {e(str(f['suppression']['rationale']))}</li>"
        for f in result["findings"]
        if f.get("suppression")
    )
    cov = "".join(
        f"<li>{e(d)} {e(str(c.get('name', '')))}: <b>{e(str(c['status']))}</b>"
        + "".join(
            f"; {e(r['adapter'])} {e(r['status'])}" + (f" ({e(r['reason'])})" if r["reason"] else "")
            for r in c.get("required_checks", [])
        )
        + "</li>"
        for d, c in sorted((result.get("domain_coverage") or {}).items())
    )
    return (
        f"<h2>Domain coverage</h2><ul>{cov or '<li>Not reported.</li>'}</ul>"
        f"<h2>Human-verified without deterministic evidence</h2><ul>{hv or '<li>None.</li>'}</ul>"
        f"<h2>Exclusions (suppressed and accepted risk)</h2><ul>{ex or '<li>None.</li>'}</ul>"
    )


def to_html(result: dict[str, Any]) -> bytes:
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(c['check_id'])}</td><td>{e(c['status'])}</td><td>{e(c.get('reason', ''))}</td></tr>"
        for c in result["checks"]
    )
    frows = "".join(
        f"<tr><td>{e(f['severity'])}</td><td>{e(f['confidence'])}</td><td>{e(f['state'])}</td>"
        f"<td>{e(f['rule'])}</td><td>{e(f['title'])}</td>"
        f"<td>{e(f['location']['file'])}:{int(f['location']['line'])}</td></tr>"
        for f in result["findings"]
    )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Sentinel audit {e(result["audit_id"])}</title>
<style>body{{font-family:system-ui;margin:2rem;max-width:70rem}}td,th{{border:1px solid #999;padding:4px}}
table{{border-collapse:collapse}}</style></head><body>
<h1>Sentinel audit {e(result["audit_id"])}</h1>
<p><strong>Overall:</strong> {e(result["overall"])} &middot; <strong>State:</strong> {e(result["state"])}
&middot; <strong>Mode/level:</strong> {e(result["mode"])}/{e(result["level"])}</p>
<p><strong>Data boundary:</strong> {e(result["disclosure"]["statement"])}</p>
<p><em>{e(DISCLAIMER)}</em></p>
<h2>Checks</h2><table><tr><th>Check</th><th>Status</th><th>Reason</th></tr>{rows}</table>
<h2>Findings</h2><table><tr><th>Severity</th><th>Confidence</th><th>State</th><th>Rule</th><th>Title</th><th>Location</th></tr>
{frows}</table>{_html_sections(result)}<h2>Integrity</h2><p>{e(result["integrity_note"])}</p></body></html>"""
    return doc.encode()


RENDERERS = {"json": to_json, "sarif": to_sarif, "md": to_markdown, "html": to_html}
