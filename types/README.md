# pulse-protocol-go/types

Wire-format types for the Pulse Permissions Protocol. This module defines the structs, interfaces, and enumerations shared across the other `pulse-protocol-go` modules and their consumers. It has no dependency on `crypto` or `ipfs` — it is safe to import without pulling in cryptographic or IPLD dependencies.

```
go get github.com/smarter-contracts/pulse-protocol-go/types/v2
```

## Key types

### Encryption results

| Type | Description |
|---|---|
| `PulseECEncryptionResult` | AES-256-GCM ciphertext + two 33-byte compressed secp256k1 keys (Key1: ephemeral grantor, Key2: recipient) |
| `PulsePQEncryptionResult` | AES-256-GCM ciphertext + one or more ML-KEM-768 encapsulated keys |
| `PulsePQEncryptionKey` | A single ML-KEM-768 recipient slot: encapsulated key + 33-byte public key |

### Polymorphic request payloads

These types replaced the earlier type-specific structs (`ConsentStructure` etc.) in v2.

| Type | Description |
|---|---|
| `PulseConsentPayload` | Polymorphic consent content — EC (Key1/Key2) or PQ (Keys). `IsMultiKey()` distinguishes the two. |
| `PulseRevokePayload` | Polymorphic revoke content — EC or PQ, plus `GrantRef` (CID of the original grant) |
| `PulseGrantRequest` | V3 API request body for `PUT /api/v3/grant` |
| `PulseRevokeRequest` | V3 API request body for `DELETE /api/v3/grant` |

### Payload sub-packages

| Package | Type | Description |
|---|---|---|
| `payloads/feedpermission` | `FeedPermissionPayload` | Decrypted consent payload: consent number, feed type, pod path, permissions, data categories, timestamps, notary material, optional `GrantorXpub` |
| `payloads/feedrevocation` | `FeedRevocationPayload` | Decrypted revoke payload: original grant CID, revoker identity, timestamp, notary material |

`FeedPermissionPayload.GrantorXpub` (`cbor:"gx,omitempty"`) carries the grantor's BIP-32 xpub at `m/4410704'/{slot}`. When present in an inbound consent, the recipient stores it to enable future per-consent key derivation without a separate xpub round-trip.

### Ancillary types

| Type | Description |
|---|---|
| `NotaryBlock` | Consent metadata (timestamp, IP, user agent, location) encrypted for the mid-tier notary |

### Storage interfaces

| Interface | Description |
|---|---|
| `ConsentStore` | Persist/retrieve EC consent and revoke records; suitable for a Solid pod or relational database |
| `ConsentStoreMulti` | Same as `ConsentStore` but for PQ (multi-key) records |

Both interfaces share the same method surface: `StoreConsent`, `GetConsent`, `ListConsents`, `StoreRevocation`, `GetRevocation`. `ErrConsentNotFound` is returned when a lookup finds no matching record.

## V1 compatibility

The `v1/` sub-package retains the original wire types (`ConsentStructure`, `RevokeStructure`, `ConsentStructureMulti`, `RevokeStructureMulti`) used before v2. The `ipfs` module's `DecodeConsent` and `DecodeRevoke` functions use these to decode older records found on IPFS.
