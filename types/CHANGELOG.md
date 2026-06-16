# Changelog

All notable changes to this module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-16

### Breaking

- **Module import path** changed to `github.com/smarter-contracts/pulse-protocol-go/types/v2`
  (required by Go's major-version module convention). Update all import paths accordingly.

- **Removed `ConsentStructure`, `ConsentStructureMulti`, `RevokeStructure`, `RevokeStructureMulti`.**
  These were thin wrappers / type aliases over the underlying encryption result types.
  Replace with `PulseECEncryptionResult`, `PulsePQEncryptionResult`, and the new
  `PulseRevokePayload` (see *Added* below).

- **`ConsentStore` interface** — `StoreRevocation` and `GetRevocation` now use
  `*PulseRevokePayload` instead of the removed `*RevokeStructure`.

- **`ConsentStoreMulti` interface** — `StoreRevocation` and `GetRevocation` now use
  `*PulseRevokePayload` instead of the removed `*RevokeStructureMulti`.

### Added

- **`PulseConsentPayload`** — polymorphic consent content type for grant requests.
  Carries `SealedData`, `Key1`, `Key2` (EC path) or `Keys []PulsePQEncryptionKey` (PQ path).
  `IsMultiKey()` returns `true` when the PQ path is populated.

- **`PulseRevokePayload`** — polymorphic revoke content type for revocation requests.
  Carries `SealedData`, `Key1`, `Key2` (EC path) or `Keys` (PQ path), plus `GrantRef` (the
  CID of the original grant being revoked). `IsMultiKey()` returns `true` for the PQ path.

- **`FeedPermissionPayload.GrantorXpub`** (`cbor:"gx,omitempty"`) — optional BIP-32
  extended public key of the grantor at `m/4410704'/{slot}`. When present in an inbound
  consent, the recipient stores it to enable per-consent key derivation without a separate
  xpub round-trip.

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
