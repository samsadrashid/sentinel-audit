# Operator keys and approvals

Every trust-anchor change (authorising a record, policy changes, reviews, accepted risks,
suppressions, key rotation and revocation) needs a **pre-signed approval** over the exact canonical
payload (§11.3, D-33). Sentinel only verifies approvals; it never creates an operator signature.

## Roles and permitted actions (D-45)

`key list` shows each key's role and permitted actions; both are part of the trust-store fingerprint.

| Role | Key | May sign |
|---|---|---|
| `operator` | ECDSA P-256 in the dedicated signing device's Secure Enclave (D-47) | `authorize_record`, `revoke_record`, `review.verify_no_evidence`, `review.accept_risk`, `suppress`, `policy.change`, `key.rotate`, `key.revoke`, and `release.publish` (D-74) |
| `recovery` | FIDO2 ES256 credential, RP ID `sentinel-recovery.invalid` | only `key.rotate` enrolling a replacement **operator** key, and `key.revoke` of another key |

Operator and recovery keys are ECDSA P-256 only; Ed25519 operator keys are refused (D-47). An action outside a key's permitted actions is `BLOCKED` (`action_not_permitted`). A recovery
assertion is never accepted as an operator signature, and an operator signature never as a recovery
assertion (`wrong_key_role`). A key can't revoke itself, and the last active operator key can't be
revoked.

## Workflow with the signing device (protocol v1)

1. Prepare the unsigned payload: `sentinel approval prepare KIND ... --output payload.json`.
2. Write the sign request to the transfer volume:
   `sentinel approval request --payload payload.json --volume /Volumes/SENTINEL-XFER`.
3. Take the volume to the signing device, review and approve there.
4. Bring the volume back: `sentinel approval receive --volume /Volumes/SENTINEL-XFER`. Each response is
   verified against **this engine's own pending payload** with the enrolled key; valid approvals are
   stored under the state directory, and the request and response files are removed from the volume.
5. Use the approval file with the consuming command (for example `key revoke --approval ...`). It is
   verified again, in full, at that point.

**First enrolment.** The trust store is empty, so the signing device's key isn't trusted yet. Pass its
public-key file with the request: `sentinel approval request --payload enrol.json --enrol-key pub-<id>.json
--volume …`. Only the key's own self-signed `key.rotate` into the empty trust store is accepted; the
response is checked against that key, and `sentinel key enrol` then verifies the approval again, in full.
The signing-device side of the ceremony is in `native/macos/sentinel-signer/README.md`.

Recovery assertions are checked exactly per `signing-protocol-final-review.md` §1.3 (client-data key
set, type, challenge, origin, crossOrigin, rpIdHash, UP and UV set, AT and ED clear, 37-byte
authenticator data, credential ID, OD-3 counter policy, signature). A counter rollback marks the
recovery key `suspect`; a suspect key is refused until it is resolved on the signing device.

## Signing a release (D-74)

A release is signed on the signing device like any other approval, as the one-time action
`release.publish` (1-hour signing window, operator keys only; a recovery key never signs a release).

1. Build the release: `uv run python scripts/m10/release_check.py OUT` (it writes `OUT/dist/` with the
   wheel, sdist, SBOM and `SHA256SUMS`).
2. Prepare the payload from those files:
   `sentinel approval prepare release-publish --key-id ID --lifetime 3600 --rationale "release X.Y.Z"
   --dist OUT/dist --commit <40-hex commit> --output release.json`. The subject, the `SHA256SUMS`
   digest and the artifact list are all recomputed from the files; `SHA256SUMS` must describe exactly
   what is in the directory.
3. `approval request` and take the volume to the signing device. It recomputes the `SHA256SUMS` digest
   from the listed artifacts itself and shows the version, the commit and every artifact hash.
   **Compare every hash with an independent reproducible build (remote CI), never with figures from the
   development Mac**, then approve.
4. `approval receive`, then `sentinel release attach --approval <received file> --dist OUT/dist`. This
   verifies the approval against the files and the trust store and writes `SHA256SUMS.approval.json`.
5. Anyone can then check the release with `sentinel release verify OUT/dist --key pub-<key_id>.json`,
   where the key file is the release key they obtained independently (a key file shipped inside the
   release proves nothing on its own). Without `--key`, the engine trust store supplies the key and its
   D-45 role, permission and status are checked too.

`release verify` fails closed if any artifact, `SHA256SUMS`, the signed artifact list, the version,
the key or the signature doesn't match. The signing window bounds when the device may sign, not how
long the signature stays valid.

## Legacy key files

The handle-on-disk Secure Enclave key-metadata format is refused (`legacy_key_format`). Convert it
to `{key_id, algorithm, public_hex}`; see `docs/m1/schemas.md`.

## Production status

**Production operator signing is disabled.** No release has been signed (D-74 needs the ceremony first). The signing device, its Secure Enclave
implementation and the FIDO2 ceremonies are a separate milestone (D-49), and the hardware tests
SD-T01 to SD-T55 are outstanding. The M1 engine-side checks are tested with software test keys only.
