# Changelog

All notable changes to this module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-16

### Breaking

- **Module import path** changed to `github.com/smarter-contracts/pulse-protocol-go/ipfs/v2`
  (required by Go's major-version module convention). Update all import paths accordingly.

- **`MarshalRevokeEC`, `UnmarshalRevokeEC`, `MarshalRevokePQ`, `UnmarshalRevokePQ` removed from
  the public API.** These functions are now unexported (`marshalRevokeEC` etc.) and called
  internally by the new `MarshalRevoke` / `UnmarshalRevoke` dispatchers. Callers should use
  the new polymorphic functions instead.

- **`DecodedConsentBlock`** — `V2EC` field type changed from `*types.ConsentStructure` to
  `*types.PulseECEncryptionResult`; `V2PQ` changed from `*types.ConsentStructureMulti` to
  `*types.PulsePQEncryptionResult`.

- **`DecodedRevokeBlock`** — `V2EC` and `V2PQ` field types both changed to
  `*types.PulseRevokePayload`. The `GrantRef` field (previously `RevokeStructure.Grant` /
  `RevokeStructureMulti.Grant`) is now at `PulseRevokePayload.GrantRef`.

### Added

- **`MarshalConsent(p *PulseConsentPayload) ([]byte, error)`** — polymorphic consent
  serialiser. Dispatches to `MarshalConsentEC` (EC path) or `MarshalConsentPQ` (PQ path)
  based on `p.IsMultiKey()`.

- **`MarshalRevoke(p *PulseRevokePayload) ([]byte, error)`** — polymorphic revoke serialiser.
  Dispatches to the EC or PQ encoding based on `p.IsMultiKey()`.

- **`UnmarshalConsent(block []byte) (*PulseConsentPayload, error)`** — polymorphic consent
  deserialiser. Decodes EC or PQ CBOR and returns a unified `PulseConsentPayload`.

- **`UnmarshalRevoke(block []byte) (*PulseRevokePayload, error)`** — polymorphic revoke
  deserialiser. Decodes EC or PQ CBOR and returns a unified `PulseRevokePayload`.

- **`OptString(n ipld.Node, key string) (string, error)`** — IPLD node helper for optional
  string fields. Returns `("", nil)` when the key is absent (rather than an error), enabling
  clean handling of fields that are omitted from older records.

### Changed

- **`MarshalFeedPermission`** now emits an optional `"gx"` field (DAG-CBOR key in canonical
  sort order) when `FeedPermissionPayload.GrantorXpub` is non-empty, giving 16 map entries
  instead of 15. **`UnmarshalFeedPermission`** decodes it back into the `GrantorXpub` field
  (absent from older records decodes as `""`).

## [1.2.0] - 2026-05-14

### Added

- `MarshalFeedRevocation` / `UnmarshalFeedRevocation`: DAG-CBOR encode/decode for
  `feedrevocation.FeedRevocationPayload`. Produces an 8-field map
  `{"t":"feed-revocation","v":1,"en":<bytes>,"iat":<int>,"nk1":<bytes>,"nk2":<bytes>,"rid":<str>,"gcid":<str>}`
  with keys in DAG-CBOR canonical order.

### Changed

- `ipfs/go.mod`: minimum required version of `pulse-protocol-go/types` updated to `v1.2.0`
  (required for the `feedrevocation.FeedRevocationPayload` type).

## [1.1.0] - 2026-05-06

### Added

- `MarshalNotaryBlock` / `UnmarshalNotaryBlock`: DAG-CBOR encode/decode for `types.NotaryBlock`.
  Produces a 6-field map `{"t":"notary","v":1,"ts":<int>,"ip":<str>,"ua":<str>,"loc":<str>}`
  with keys in DAG-CBOR canonical order. Mirrors `pulse-protocol-go/ipfs.MarshalNotaryBlock` in Go
  and the TypeScript equivalent in `@pulse-protocol/ipfs`.
- `MarshalFeedPermission` / `UnmarshalFeedPermission`: DAG-CBOR encode/decode for
  `feedpermission.FeedPermissionPayload`. Produces a 15-field map with keys in canonical order.
  Includes `encodeStringSlice` helper for the `pm` (permissions) and `dc` (data categories) list fields.
- `MustStringList`: IPLD node helper — looks up a key and returns its value as `[]string`.
  Returns an error if the key is absent or the value is not an IPLD list of strings.

### Changed

- `ipfs/go.mod`: minimum required version of `pulse-protocol-go/types` is `v1.1.0` (updated from
  `v1.0.0` at tagging time, after `types/v1.1.0` is published).

## [1.0.1] - 2026-04-09

### Security

- Updated `github.com/ipld/go-ipld-prime` from v0.21.0 to v0.22.0
  - Fixes [CVE-2026-35480](https://github.com/advisories/GHSA-378j-3jfj-8r9f): DAG-CBOR decoder unbounded memory allocation from CBOR headers (medium)

## [1.0.0] - Initial release
