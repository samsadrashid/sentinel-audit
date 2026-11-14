"""Release integrity (M10): verify the installed package against its wheel RECORD; build SHA256SUMS.

`sentinel self-check` re-hashes every file the installed distribution's RECORD lists with a hash and
compares. Outcomes, fail-closed:

* `verified` — every hashed RECORD entry is present and matches, and every module of the imported
  `sentinel` package is covered by RECORD.
* `mismatch` / `missing` — integrity failure (exit 5).
* `mismatch` also when a regular (non-editable) install contains a file RECORD doesn't list
  (`unexpected_file`, V-7): a planted module or data file is tampering, not a development install.
* `unverifiable` — not installed, a PEP 610 editable install, the imported package isn't the one the
  distribution installed, or no hashed entries. This is never reported as verified (exit 2).

This checks that the installed bytes match what the installer recorded. It is not a signature: RECORD
sits beside the files it describes, so it detects corruption and casual tampering, not a determined
local attacker.

Release signing (D-74): the signing device signs a `release.publish` approval over the exact `SHA256SUMS`
bytes and the artifact list, and `verify_release` checks it against the files. Production signing stays
disabled until the signing-device ceremony, so no real release signature exists yet.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
from importlib import metadata
from pathlib import Path
from typing import Any

DIST = "sentinel-audit"


def _record_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return "sha256=" + base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode()


def self_check(dist_name: str = DIST, package_dir: Path | None = None) -> dict[str, Any]:
    try:
        dist = metadata.distribution(dist_name)
    except metadata.PackageNotFoundError:
        return {
            "status": "unverifiable",
            "reason": "distribution_not_installed",
            "checked": 0,
            "problems": [],
        }
    # RECORD is parsed directly: `Distribution.files` silently drops entries whose file no longer exists
    # (Python 3.12+), which would hide deleted files.
    try:
        record = dist.read_text("RECORD")
    except OSError:
        record = None
    if not record:
        return {
            "distribution": dist_name,
            "version": dist.version,
            "status": "unverifiable",
            "reason": "no_record",
            "checked": 0,
            "problems": [],
        }
    rows = [r for r in csv.reader(record.splitlines()) if r]
    if package_dir is None:
        package_dir = Path(__file__).resolve().parent
    entries = [(r[0], r[1] if len(r) > 1 else "") for r in rows]
    covered = {Path(str(dist.locate_file(name))).resolve() for name, _ in entries}
    hashed = [(name, h) for name, h in entries if h.startswith("sha256=")]
    problems: list[dict[str, str]] = []
    for name, h in hashed:
        p = Path(str(dist.locate_file(name)))
        if not p.is_file():
            problems.append({"file": name, "problem": "missing"})
        elif _record_hash(p) != h:
            problems.append({"file": name, "problem": "mismatch"})
    base = {"distribution": dist_name, "version": dist.version, "checked": len(hashed)}
    pkg = package_dir.resolve()
    present = sorted(
        p.resolve()
        for p in pkg.rglob("*")
        if (p.is_file() or p.is_symlink()) and "__pycache__" not in p.relative_to(pkg).parts
    )
    uncovered = [str(p.relative_to(pkg)) for p in present if p not in covered]
    if problems:  # a RECORD entry that doesn't match is a mismatch in every install kind
        status = "missing" if {p["problem"] for p in problems} == {"missing"} else "mismatch"
        return {**base, "status": status, "reason": "record_mismatch", "problems": problems[:200]}
    if _editable(dist):
        return {
            **base,
            "status": "unverifiable",
            "reason": "editable_install",
            "problems": [{"file": u, "problem": "not_in_record"} for u in uncovered[:200]],
        }
    if not any(pkg in c.parents for c in covered):
        # The imported package isn't the one this distribution installed (e.g. run from a source tree).
        return {**base, "status": "unverifiable", "reason": "package_not_from_distribution", "problems": []}
    # V-7: in a regular install every file in the package must be in RECORD. An extra file is tampering.
    if uncovered:
        return {
            **base,
            "status": "mismatch",
            "reason": "unexpected_files",
            "problems": [{"file": u, "problem": "unexpected_file"} for u in uncovered[:200]],
        }
    if not hashed:
        return {**base, "status": "unverifiable", "reason": "no_hashed_record", "problems": []}
    return {**base, "status": "verified", "reason": "record_matches", "problems": []}


def _editable(dist: metadata.Distribution) -> bool:
    """PEP 610: an editable install records `dir_info.editable` in direct_url.json."""
    try:
        raw = dist.read_text("direct_url.json")
        info = json.loads(raw) if raw else {}
    except (OSError, ValueError):
        return False
    d = info.get("dir_info") if isinstance(info, dict) else None
    return isinstance(d, dict) and d.get("editable") is True


SUMS_NAME = "SHA256SUMS"
#: The signed `release.publish` approval, published next to `SHA256SUMS` (D-74). Not itself an artifact.
APPROVAL_NAME = "SHA256SUMS.approval.json"
RELEASE_ACTION = "release.publish"
MAX_ARTIFACTS = 16
MAX_SUMS_BYTES = 64 * 1024
MAX_APPROVAL_BYTES = 64 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]{0,63}")
_WHEEL = re.compile(r"sentinel_audit-([0-9][0-9A-Za-z.+]{0,63})-py3-none-any\.whl")


def sha256sums(directory: Path) -> bytes:
    """Deterministic `SHA256SUMS` body for the regular files directly inside `directory`."""
    lines = []
    for p in sorted(directory.iterdir()):
        # Dotfiles (e.g. the .gitignore `uv build` writes into dist/) are not release artifacts, and
        # neither are the manifest itself or its signed approval.
        if (
            p.is_symlink()
            or not p.is_file()
            or p.name in (SUMS_NAME, APPROVAL_NAME)
            or p.name.startswith(".")
        ):
            continue
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{h}  {p.name}\n")
    if not lines:
        raise ValueError("no release files")
    return "".join(lines).encode()


def parse_sums(body: bytes) -> list[dict[str, str]]:
    """Strict `SHA256SUMS`: `<64 lowercase hex>  <name>\\n` lines, names sorted, unique and plain."""
    from .errors import ValidationError

    if not body or len(body) > MAX_SUMS_BYTES or not body.endswith(b"\n"):
        raise ValidationError("SHA256SUMS is empty, too large or not newline-terminated")
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValidationError("SHA256SUMS is not ASCII") from exc
    out: list[dict[str, str]] = []
    for line in text[:-1].split("\n"):
        digest, sep, name = line.partition("  ")
        if not sep or not re.fullmatch(r"[0-9a-f]{64}", digest) or not _NAME.fullmatch(name):
            raise ValidationError(f"SHA256SUMS line is malformed: {line[:120]!r}")
        out.append({"name": name, "sha256": digest})
    names = [a["name"] for a in out]
    if names != sorted(set(names)) or not 1 <= len(out) <= MAX_ARTIFACTS:
        raise ValidationError(f"SHA256SUMS names must be sorted, unique and 1-{MAX_ARTIFACTS} in number")
    if APPROVAL_NAME in names or SUMS_NAME in names:
        raise ValidationError("SHA256SUMS must not list itself or its approval")
    return out


def render_sums(artifacts: list[dict[str, str]]) -> bytes:
    return "".join(f"{a['sha256']}  {a['name']}\n" for a in artifacts).encode()


def _read_limited(path: Path, limit: int, what: str) -> bytes:
    from .errors import ValidationError

    if path.is_symlink() or not path.is_file():
        raise ValidationError(f"{what} must be a regular file: {path.name}")
    data = path.read_bytes()
    if len(data) > limit:
        raise ValidationError(f"{what} exceeds {limit} bytes")
    return data


def wheel_version(artifacts: list[dict[str, str]]) -> str:
    """The release version, from its one Sentinel wheel. Any sdist must carry the same version."""
    from .errors import BlockedError

    versions = [m.group(1) for a in artifacts if (m := _WHEEL.fullmatch(a["name"]))]
    if len(versions) != 1:
        raise BlockedError("a release must contain exactly one sentinel_audit wheel", "release_wheel")
    v = versions[0]
    for a in artifacts:
        if a["name"].startswith("sentinel_audit-") and a["name"].endswith(".tar.gz"):
            if a["name"] != f"sentinel_audit-{v}.tar.gz":
                raise BlockedError("the sdist and the wheel name different versions", "version_mismatch")
    return v


def release_parts(dist: Path, commit: str) -> tuple[dict[str, str], str, dict[str, Any]]:
    """Subject, revision and scope of a `release.publish` payload, recomputed from the files in `dist`.
    `SHA256SUMS` must already describe exactly those files; nothing caller-supplied is trusted."""
    from .errors import BlockedError, ValidationError

    if not _COMMIT.fullmatch(commit):
        raise ValidationError("--commit must be a full 40-character lowercase git commit hash")
    sums = _read_limited(dist / SUMS_NAME, MAX_SUMS_BYTES, SUMS_NAME)
    if sums != sha256sums(dist):
        raise BlockedError("SHA256SUMS does not match the files in the directory", "sums_mismatch")
    artifacts = parse_sums(sums)
    version = wheel_version(artifacts)
    subject = {"type": "release", "name": DIST, "version": version, "commit": commit}
    return subject, f"sums:{hashlib.sha256(sums).hexdigest()}", {"artifacts": artifacts}


def _content_problem(dist: Path, payload: dict[str, Any]) -> tuple[str, str] | None:
    """Why the files in `dist` are not what `payload` signed, or None if they are."""
    sums_path = dist / SUMS_NAME
    if not sums_path.is_file() or sums_path.is_symlink():
        return "sums_missing", "SHA256SUMS is missing"
    sums = sums_path.read_bytes()[: MAX_SUMS_BYTES + 1]
    if payload["revision"] != f"sums:{hashlib.sha256(sums).hexdigest()}":
        return "sums_mismatch", "SHA256SUMS is not the one that was signed"
    if payload["scope"] != {"artifacts": parse_sums(sums)}:
        return "artifacts_mismatch", "the signed artifact list differs from SHA256SUMS"
    try:
        actual = sha256sums(dist)
    except ValueError:
        return "artifact_missing", "no release files"
    if actual != sums:
        have = {a["name"]: a["sha256"] for a in parse_sums(actual)}
        for a in payload["scope"]["artifacts"]:
            if a["name"] not in have:
                return "artifact_missing", f"{a['name']} is missing"
            if have[a["name"]] != a["sha256"]:
                return "artifact_mismatch", f"{a['name']} does not match its signed hash"
        extra = sorted(set(have) - {a["name"] for a in payload["scope"]["artifacts"]})
        return "artifact_unexpected", f"{extra[0]} is not part of the signed release"
    if payload["subject"].get("version") != wheel_version(payload["scope"]["artifacts"]):
        return "version_mismatch", "the signed version is not the wheel's version"
    return None


def verify_release(dist: Path, approval_raw: Any, public: Any, trusted: Any = None) -> dict[str, Any]:
    """D-74: verify a signed `release.publish` approval against the files in `dist`. Fail-closed.

    `public` is the signer's `PublicKey`. `trusted`, when given, is its trust-store `OperatorKey`: then the
    D-45 role, permission and status are checked too. Key expiry is judged at the payload's `issued_at`,
    and an expired signing window does not invalidate a signature made inside it (the signing device
    refuses to sign outside the window)."""
    from . import canonical
    from .approvals import Approval
    from .crypto.signing import P256
    from .errors import BlockedError, IntegrityError
    from .keys.operator import OPERATOR_ROLE

    ap = Approval.from_json(approval_raw)  # schema, exact field set, action/context pairing, nonce form
    p = ap.payload
    if p["action"] != RELEASE_ACTION:
        raise BlockedError(f"not a release approval: {p['action']!r}", "wrong_action")
    if public.algorithm != P256 or p["key_id"] != public.key_id:
        raise BlockedError("the approval is signed by a different key", "key_mismatch")
    if trusted is not None:
        if trusted.public.public_raw != public.public_raw or trusted.role != OPERATOR_ROLE:
            raise BlockedError("release approvals need an operator-role key (D-45, D-74)", "wrong_key_role")
        if RELEASE_ACTION not in trusted.permitted_actions:
            raise BlockedError("release.publish is not permitted for this key", "action_not_permitted")
        if trusted.status != "active":
            raise BlockedError(f"the signing key is {trusted.status}", "revoked_key")
        if p["issued_at"] >= trusted.expires_at:
            raise BlockedError("the signing key had expired when this was issued", "expired_key")
    if not ap.signature or len(ap.signature) > 128 or not public.verify(ap.signature, canonical.encode(p)):
        raise BlockedError("the release signature does not verify", "bad_signature")
    problem = _content_problem(dist, p)
    if problem is not None:
        raise IntegrityError(f"{problem[0]}: {problem[1]}")
    return {
        "status": "verified",
        "name": p["subject"]["name"],
        "version": p["subject"]["version"],
        "commit": p["subject"]["commit"],
        "key_id": p["key_id"],
        "issued_at": p["issued_at"],
        "artifacts": [a["name"] for a in p["scope"]["artifacts"]],
        "role_checked": trusted is not None,
    }


def load_approval_file(path: Path) -> Any:
    from . import canonical

    return canonical.decode_strict(_read_limited(path, MAX_APPROVAL_BYTES, "release approval"))
