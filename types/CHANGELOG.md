# Changelog

All notable changes to this module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-05-14

### Added

- `types/payloads/feedrevocation` package: new `FeedRevocationPayload` struct representing the
  unencrypted revocation payload for Feed Permission consents. Contains 6 data fields: `GrantCID`
  (IPFS CID of the original grant, binding the revocation to a specific consent), `RevokerId`
  (DID or WebID of the revoking party), `IssuedAt` (Unix timestamp in seconds), `EncryptedNotary`
  (AES-256-GCM sealed `NotaryBlock`), `NotaryKey1` (grantee's compressed secp256k1 purpose-4
  public key), and `NotaryKey2` (Mid-Tier notary compressed public key).
- `feedrevocation.Type` constant (`"feed-revocation"`) — the CBOR type discriminator for this payload.

### Changed

- `consent_structures.go`: added godoc to the `MarshalJSON` and `UnmarshalJSON` methods on
  `ConsentStructure`, `RevokeStructure`, and `ConsentStructureMulti`. No struct or tag changes —
  fully backwards compatible.

## [1.1.0] - 2026-05-06

### Added

- `types/payloads/feedpermission` package: new `FeedPermissionPayload` struct representing the
  unencrypted consent payload for feed permission grants. Contains 13 data fields (consent number,
  wallet and party identifiers, feed type, pod container path, permissions, data categories,
  issued/expiry timestamps, and encrypted notary material with its two public keys).
- `feedpermission.Type` constant (`"feed-permission"`) — the CBOR type discriminator for this payload.

### Changed

- `NotaryBlock`: updated doc comment to describe ECDH encryption scheme (purpose-2 grantor key ×
  Mid-Tier notary key). Added field-level doc comments for `Timestamp`, `IPAddress`, `UserAgent`,
  and `Location`. No struct or tag changes — fully backwards compatible.

## [1.0.0] - Initial release
