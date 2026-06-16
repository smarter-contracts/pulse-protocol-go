# pulse-protocol-go/registry

The `OtherPartyRegistry` interface and an in-memory reference implementation for the Pulse Permissions Protocol. A registry maps human-readable counterparty identifiers (DIDs, Ethereum addresses, WebIDs) to the stable `uint32` slot numbers used in Pulse HD wallet derivation paths, and tracks per-(slot, chainId) consent sequence numbers.

```
go get github.com/smarter-contracts/pulse-protocol-go/registry
```

## Interface

```go
type OtherPartyRegistry interface {
    // Returns the slot for identifier, allocating one if it has not been seen before.
    // The slot is a non-hardened BIP-32 child index (< 0x80000000).
    LookupOrCreate(identifier string) (uint32, error)

    // Returns the slot for identifier; returns ErrNotFound if not registered.
    Lookup(identifier string) (uint32, error)

    // Returns the next consent sequence number for (otherPartyNo, chainId)
    // and increments the counter. Sequence numbers start at 1.
    NextConsentNumber(otherPartyNo uint32, chainId uint32) (uint32, error)
}
```

Slots must be stable — once assigned, a slot must never change for a given identifier. This stability is a hard requirement of the HD derivation scheme: the slot is embedded in the BIP-32 path `m/4410704'/{slot}/{chain}/{consent}/{purpose}`, and any change would produce different keys for historical records.

All implementations must be safe for concurrent use.

## MemoryRegistry

`MemoryRegistry` is a thread-safe in-memory implementation suitable for testing and development. It does not persist state across restarts.

```go
reg := registry.NewMemoryRegistry()

slot, err := reg.LookupOrCreate("did:key:zAlice...")   // allocates slot 0
slot, err  = reg.LookupOrCreate("did:key:zAlice...")   // returns 0 (idempotent)
slot, err  = reg.LookupOrCreate("did:key:zBob...")     // allocates slot 1

no, err := reg.NextConsentNumber(0, 1) // returns 1 for Alice on chain 1
no, err  = reg.NextConsentNumber(0, 1) // returns 2
no, err  = reg.NextConsentNumber(1, 1) // returns 1 for Bob on chain 1 (independent)
```

## Relationship to `consent.CounterpartyDirectory`

The `consent` module defines a higher-level `CounterpartyDirectory` interface that operates on string party keys (DIDs) rather than pre-resolved `uint32` slots, and adds `StoreXpub` / `GetXpub` for the BIP-32 extended public key exchange flow. Production implementations typically embed or delegate to an `OtherPartyRegistry` for the slot allocation and sequence tracking parts.
