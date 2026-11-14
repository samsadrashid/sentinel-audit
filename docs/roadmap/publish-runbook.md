# Publishing Sentinel: what remains, in order (2026-11-13)

Everything that can be built and verified in software on this Mac is done (see
`sentinel-final-release-report.md` §10 and §11). **Sentinel is not published, and can't be yet.** A
release must be signed (D-20, D-24), signing needs the hardware ceremony, and three owner decisions are
open. This runbook lists each remaining step, who does it, and what proves it's done.

## A. Owner decisions (needed before the steps that use them)

| # | Decision | Why it's open | Options |
|---|---|---|---|
| A1 | **Commit and remote.** *Done 2026-11-13: first commit `fe1763f`; private GitHub repository `samsadrashid/sentinel`.* Authorise the first commit, and name the remote repository | CLAUDE.md rule 4: no commit, push, remote or Git-index change without the owner | Authorise a local commit of the current tree (the index holds 3 older staged files); then name a remote |
| A2 | **How a release is signed.** *Decided 2026-11-14: D-74, option (a).* The signing device signs a one-time `release.publish` approval over the exact `SHA256SUMS` bytes and the artifact list; `sentinel release verify` checks it. Implemented in the engine and the signer and tested in software | — | — |
| A3 | **Where it's published** (for example a Git hosting release, or PyPI). *Chosen 2026-11-13: GitHub. Making the repository public, and any release, still need approval at the time* | Publishing is outward-facing and needs explicit approval at the time | — |

## B. Signing-device hardware (owner, physical)

1. Provision the SD (design §7): FileVault, SIP, firewall, no sharing or iCloud Keychain, a standard
   `signer` account, network off during signing. **SD-T01.**
2. Bring the signer source to the SD as a git bundle; review the complete signer tree there (final
   review §4, about 2,100 lines); build with `native/macos/sentinel-signer/build.sh`. Record the commit,
   tree hash (`sentinel-signer release tree-hash`) and binary hash on paper.
3. Run **SD-T01 to SD-T55** (QR tests SD-T05 and SD-T06 deferred) and record every result. **SD-T35**
   decides whether FIDO2 recovery works through AuthenticationServices; if not, OD-4 (libfido2 review).
4. Run the **first-enrolment ceremony** (`native/macos/sentinel-signer/README.md`), including the
   trust-store audit MATCH, the test approval and the first checkpoint.
5. Record an **activation decision** in `docs/architecture-discovery-plan.md`. Only then may production
   signing be enabled (final review §6).

## C. Release (after A and B)

1. On the DM, with the Mac unlocked: `uv run pytest -q` (full suite, exit 0), then
   `uv run python scripts/m10/release_check.py <out>` (exit 0) and `shasum -a 256 -c SHA256SUMS`.
2. Sign the release on the SD (D-74, `docs/user/operator-approvals.md` "Signing a release"):
   `approval prepare release-publish --dist <out>/dist --commit <sha>`, `approval request`; on the SD,
   compare every displayed hash with the remote CI build of the same commit, then approve; back on the DM,
   `approval receive`, then `release attach`. Check with `release verify <out>/dist --key pub-<key_id>.json`.
3. Remote CI: the workflows in `.github/workflows` must pass on GitHub for the release commit. They first
   passed on `73791ae` (2026-11-13), after four runs fixed five defects (report §13). Hosted runners skip
   the real-scanner, Podman and MobSF tests, so the DM full suite (step 1) stays required.
4. Publish to the target chosen in **A3**, with the signature, the SBOM and `THIRD_PARTY_NOTICES`. Claim
   **macOS only**: Linux and Windows are untested (B-4).

## D. Optional, independent

- Linux and Windows hosts, to lift the macOS-only limit (B-4).
- MobSF 4.6.5 when published (replaces the D-72 risk acceptance), and a real-APK fixture to exercise its
  code-analysis stage (a download, needing approval).
