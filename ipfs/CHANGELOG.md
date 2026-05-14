# Changelog

All notable changes to this module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
