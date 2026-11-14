"""Structural checks for Sentinel architecture docs (no rendering)."""

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
disc = (root / "docs/architecture/discovery.md").read_text()
plan = (root / "docs/architecture-discovery-plan.md").read_text()
docs = {
    p: p.read_text()
    for p in [
        root / "docs/architecture/discovery.md",
        root / "docs/architecture/review.md",
        root / "docs/architecture-discovery-plan.md",
    ]
    + sorted((root / "docs/architecture").glob("*.md"))
}
fail = 0
CORE = {"discovery.md", "review.md", "architecture-discovery-plan.md"}


def bad(msg):
    global fail
    fail += 1
    print("FAIL", msg)


# 1 decision register completeness
reg = re.findall(r"^\| (D-\d\d) \|", plan, re.M)
want = (
    [f"D-{i:02d}" for i in range(1, 39)]
    + ["D-45", "D-46", "D-47"]
    + [f"D-{i:02d}" for i in range(39, 45)]
    + [
        "D-48",
        "D-49",
        "D-50",
        "D-51",
        "D-52",
        "D-53",
        "D-54",
        "D-55",
        "D-56",
        "D-57",
        "D-58",
        "D-59",
        "D-60",
        "D-61",
        "D-62",
        "D-63",
        "D-64",
        "D-65",
        "D-66",
        "D-67",
        "D-68",
        "D-69",
        "D-70",
        "D-71",
        "D-72",
        "D-73",
        "D-74",
    ]
)
reserved = {f"D-{i:02d}" for i in range(39, 45)} if "| D-39–D-44 |" in plan else set()
print("reserved:", sorted(reserved))
print(
    "decision register rows:",
    len(reg),
    "missing:",
    sorted(set(want) - set(reg)),
    "dupes:",
    sorted({d for d in reg if reg.count(d) > 1}),
)
if reg != want:
    bad("decision register not exactly D-01..D-38 in order")
# 2 references resolve
defs = {
    "D": set(want) | reserved,
    "R": {f"R-{i:02d}" for i in range(1, 18)},
    "T": {f"T{i}" for i in range(1, 18)},
    "AC": {f"AC-{i:02d}" for i in range(1, 19)},
    "O": {f"O-{i:02d}" for i in range(1, 11)},
}
for p, t in docs.items():
    for kind, pat in (
        ("D", r"\bD-\d\d\b"),
        ("R", r"\bR-\d\d\b"),
        ("T", r"(?<![-\w])T\d{1,2}\b"),
        ("AC", r"\bAC-\d\d\b"),
        ("O", r"\bO-\d\d\b"),
    ):
        if kind == "AC" and p.name not in CORE:
            continue  # proposal docs may cite proposed ACs
        for ref in sorted(set(re.findall(pat, t))):
            if ref not in defs[kind]:
                bad(f"{p.name}: unknown reference {ref}")
heads = set(re.findall(r"^#{2,4} (\d+(?:\.\d+)*)\.? ", disc, re.M))
for ref in sorted(set(re.findall(r"§(\d+(?:\.\d+)*)", disc))):
    if ref not in heads:
        bad(f"discovery.md: § reference {ref} has no heading")
print("section headings:", len(heads))
# 3 mermaid structure
blocks = re.findall(r"```mermaid\n(.*?)```", disc, re.S)
print("mermaid blocks:", len(blocks))
for i, b in enumerate(blocks, 1):
    lines = [ln.strip() for ln in b.strip().splitlines() if ln.strip()]
    kind = lines[0].split()[0]
    if kind not in {"flowchart", "stateDiagram-v2", "sequenceDiagram"}:
        bad(f"diagram {i}: unknown type {kind}")
    opens = sum(1 for ln in lines if ln.startswith(("subgraph", "alt ", "loop ", "opt ", "par ")))
    ends = sum(1 for ln in lines if ln == "end")
    if opens != ends:
        bad(f"diagram {i}: {opens} blocks opened, {ends} closed")
    if b.count('"') % 2:
        bad(f"diagram {i}: unbalanced quotes")
    for ln in lines:
        if ln.startswith("note ") and ";" in ln:
            bad(f"diagram {i}: ';' in a note splits it into statements")
    if kind == "sequenceDiagram":
        parts = set(re.findall(r"participant (\w+)", b))
        used = set(
            re.findall(r"^\s*(\w+)-[->]+>?(\w+)", b, re.M)
            and [x for pr in re.findall(r"^\s*(\w+)-+>>?(\w+)", b, re.M) for x in pr]
        )
        if used - parts:
            bad(f"diagram {i}: undeclared participants {used - parts}")
    if kind == "stateDiagram-v2":
        targets = {re.findall(r"-->\s*(\[\*\]|\w+)", ln)[0] for ln in lines if "-->" in ln}
        sources = {re.findall(r"^(\[\*\]|\w+)", ln)[0] for ln in lines if "-->" in ln}
        dead = {s for s in targets - sources if s != "[*]"}
        if dead:
            bad(f"diagram {i}: states with no outgoing transition {sorted(dead)}")
    print(f"  diagram {i}: {kind}, {len(lines)} lines, blocks {opens}/{ends}")
print("RESULT:", "PASS" if not fail else f"{fail} failure(s)")
sys.exit(1 if fail else 0)
