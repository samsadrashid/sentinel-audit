"""Render every Mermaid block in docs/architecture/discovery.md with an ALREADY-INSTALLED Mermaid build
in headless Microsoft Edge (no downloads, name resolution blocked, local files only).

Usage: python3 scripts/docs/render_mermaid.py <repo-root> <work-dir>
<work-dir> must contain mermaid.min.js copied from a local installation; the manifest records its SHA-256.
Outputs <work-dir>/out/dNN.{svg,png} and manifest.json. Status RENDER_OK or RENDER_ERROR per diagram.
"""

import hashlib
import html
import json
import pathlib
import re
import subprocess
import sys

root, S = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
EDGE = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
blocks = re.findall(r"```mermaid\n(.*?)```", (root / "docs/architecture/discovery.md").read_text(), re.S)
man = {
    "renderer": "mermaid 11.11.0 (Goodnotes bundle) in headless Microsoft Edge",
    "mermaid_sha256": hashlib.sha256((S / "mermaid.min.js").read_bytes()).hexdigest(),
    "diagrams": [],
}
for i, b in enumerate(blocks, 1):
    page = S / f"d{i:02d}.html"
    page.write_text(f"""<!doctype html><html><head><meta charset="utf-8">
<script src="mermaid.min.js"></script></head>
<body style="background:#fff;margin:16px"><pre class="mermaid">{html.escape(b)}</pre>
<div id="status">pending</div>
<script>mermaid.initialize({{startOnLoad:false, securityLevel:'strict', theme:'default'}});
mermaid.run({{querySelector:'.mermaid'}}).then(()=>{{document.getElementById('status').textContent='RENDER_OK';}})
.catch(e=>{{document.getElementById('status').textContent='RENDER_ERROR: '+e;}});</script></body></html>""")
    common = [
        EDGE,
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--disable-extensions",
        f"--user-data-dir={S}/profile",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--proxy-server=127.0.0.1:9",
        "--allow-file-access-from-files",
        "--virtual-time-budget=8000",
        "--window-size=1400,1800",
    ]
    dom = subprocess.run(
        common + ["--dump-dom", page.as_uri()], capture_output=True, text=True, timeout=90
    ).stdout
    status = re.search(r'<div id="status">(.*?)</div>', dom, re.S)
    svg = re.search(r"<svg.*?</svg>", dom, re.S)
    png = S / "out" / f"d{i:02d}.png"
    subprocess.run(common + [f"--screenshot={png}", page.as_uri()], capture_output=True, timeout=90)
    if svg:
        (S / "out" / f"d{i:02d}.svg").write_text(svg.group(0))
    man["diagrams"].append(
        {
            "n": i,
            "type": b.split()[0],
            "input_sha256": hashlib.sha256(b.encode()).hexdigest(),
            "status": html.unescape(status.group(1)) if status else "NO_STATUS",
            "svg_bytes": len(svg.group(0)) if svg else 0,
            "png": png.exists(),
        }
    )
    print(
        i, man["diagrams"][-1]["type"], man["diagrams"][-1]["status"][:120], man["diagrams"][-1]["svg_bytes"]
    )
(S / "out" / "manifest.json").write_text(json.dumps(man, indent=2))
