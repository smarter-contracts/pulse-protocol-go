# pulse-protocol-go/ipfs

DAG-CBOR serialisation and CIDv1 computation for the Pulse Permissions Protocol. This module encodes and decodes all Pulse record types — consent grants, revocations, feed permission payloads, notary blocks — using the [IPLD](https://ipld.io/) DAG-CBOR codec with canonical (sorted) key ordering.

```
go get github.com/smarter-contracts/pulse-protocol-go/ipfs/v2
```

## Serialisation

### Polymorphic consent and revoke records

These are the primary entry points for encoding records destined for IPFS.

```go
// Serialise a grant record — dispatches to EC or PQ based on p.IsMultiKey().
cbor, err := ipfs.MarshalConsent(p)   // *types.PulseConsentPayload → []byte

// Serialise a revoke record — dispatches to EC or PQ based on p.IsMultiKey().
cbor, err := ipfs.MarshalRevoke(p)    // *types.PulseRevokePayload → []byte

// Deserialise a grant record — returns a unified PulseConsentPayload.
p, err := ipfs.UnmarshalConsent(cbor) // []byte → *types.PulseConsentPayload

// Deserialise a revoke record — returns a unified PulseRevokePayload.
p, err := ipfs.UnmarshalRevoke(cbor)  // []byte → *types.PulseRevokePayload
```

### Type-specific encoders

| Function | Wire format |
|---|---|
| `MarshalConsentEC` / `UnmarshalConsentEC` | `{"t":"ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>}` |
| `MarshalConsentPQ` / `UnmarshalConsentPQ` | `{"t":"pq","v":1,"sd":<bytes>,"keys":[...]}` |
| `MarshalFeedPermission` / `UnmarshalFeedPermission` | 15-field map (16 when `GrantorXpub` is present) |
| `MarshalFeedRevocation` / `UnmarshalFeedRevocation` | 8-field map |
| `MarshalNotaryBlock` / `UnmarshalNotaryBlock` | `{"t":"notary","v":1,"ts":<int>,"ip":<str>,"ua":<str>,"loc":<str>}` |

The EC and PQ revoke encoders (`marshalRevokeEC`, `marshalRevokePQ`) are internal. Use `MarshalRevoke` instead.

### V1 compatibility

`MarshalV1ConsentEC`, `UnmarshalV1ConsentEC`, `MarshalV1RevokePQ` etc. handle the original wire format used before v2 of the `types` module. These are used internally by `DecodeConsent` and `DecodeRevoke` to decode older records retrieved from IPFS.

## Multi-version decode

When reading a record from IPFS whose version is unknown, use the decode helpers. They detect the type automatically and return a discriminated union:

```go
decoded, err := ipfs.DecodeConsent(cbor)
switch decoded.Kind {
case ipfs.RecordKindV2EC:
    // decoded.V2EC is *types.PulseECEncryptionResult
case ipfs.RecordKindV2PQ:
    // decoded.V2PQ is *types.PulsePQEncryptionResult
case ipfs.RecordKindV1EC:
    // decoded.V1EC is *v1.ConsentStructure
case ipfs.RecordKindV1PQ:
    // decoded.V1PQ is *v1.ConsentStructureMulti
}

decoded, err := ipfs.DecodeRevoke(cbor)
switch decoded.Kind {
case ipfs.RecordKindV2EC:
    // decoded.V2EC is *types.PulseRevokePayload (Key1/Key2 populated)
case ipfs.RecordKindV2PQ:
    // decoded.V2PQ is *types.PulseRevokePayload (Keys populated)
}
```

## CID computation

```go
// Compute the IPFS CIDv1 of arbitrary DAG-CBOR bytes.
// This is the canonical content address used as the consent identifier.
cid, err := ipfs.ComputeCID(cborBytes)
```

CIDs are computed using SHA2-256 and encoded as base32 (CIDv1 / `dag-cbor` multicodec), matching the CIDs produced by a standard IPFS node and by the `@pulse-protocol/ipfs` TypeScript package.

## IPLD node helpers

```go
// Look up a required bytes value.
b, err := ipfs.MustBytes(node, "sd")

// Look up a required int value.
n, err := ipfs.MustInt(node, "cn")

// Look up a required string value.
s, err := ipfs.MustString(node, "ft")

// Look up an optional string value — returns ("", nil) when absent.
s, err := ipfs.OptString(node, "gx")

// Look up a required string list value.
ss, err := ipfs.MustStringList(node, "pm")
```
