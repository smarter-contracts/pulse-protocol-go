# pulse-protocol-go/consent

The consent engine library for grantee-side Pulse Protocol implementations. It wires together the `crypto`, `ipfs`, and `types` modules into a complete consent lifecycle: ingesting inbound grants, applying a review policy, approving or rejecting after human review, counter-signing and submitting to mid-tier, processing lifecycle callbacks, revoking, and catch-up synchronisation.

```
go get github.com/smarter-contracts/pulse-protocol-go/consent
```

## Quick start

```go
engine := consent.NewConsentEngine(
    wallet,     // crypto.WalletStore — provides the BIP-32 master key
    cpDir,      // consent.CounterpartyDirectory — maps DIDs to HD path slots
    store,      // consent.ConsentStore — persists ConsentRecords
    mtClient,   // consent.MidTierClient — submits to mid-tier over HTTP
    consent.WithReviewer(myReviewer),      // optional: default is accept-all
    consent.WithEventHandler(myHandler),   // optional: default is no-op
)
```

## Operations

### Ingest an inbound consent

Called by the HTTP handler that receives sealed consents from Pulse+ users or other Pulse services.

```go
resp, err := engine.HandleInboundConsent(ctx, consent.InboundConsentRequest{
    PartyKey:   "did:key:zAlice...",
    ChainID:    1,
    ConsentNo:  42,
    SealedData: req.SealedData,
    Key1:       req.Key1,
    Key2:       req.Key2,
    Signatures: req.Signatures,
})
// resp.Decision is "accept", "reject", or "defer"
```

If `ConsentReviewer.Review` returns `defer`, the record is stored at `pending-review` and nothing is submitted to mid-tier until `ApproveConsent` is called.

If the inbound `FeedPermissionPayload` carries a `GrantorXpub`, `HandleInboundConsent` automatically stores it via `CounterpartyDirectory.StoreXpub`.

### Manual approval / rejection

```go
err := engine.ApproveConsent(ctx, consentID)   // pending-review → pending; submits to mid-tier
err := engine.RejectConsent(ctx, consentID)    // pending-review → rejected
```

### Revoke an active consent

```go
err := engine.RevokeConsent(ctx, consentID, callbackURL)
```

Encrypts and signs the revocation payload and submits it to mid-tier. If the `ipfs_live` callback was never received (so `ConsentRecord.CID` is empty), falls back to `ConsentRecord.ID`, which is derived from the same DAG-CBOR bytes and is a safe equivalent.

### Handle a lifecycle callback from mid-tier

```go
err := engine.HandleTransactionCallback(ctx, consent.CallbackRequest{
    ConsentID: "bafk...",
    Type:      consent.TransactionTypeGrant,
    Status:    consent.TransactionStatusConfirmed,
    CID:       "bafk...",
})
```

Updates the stored record's status. Fires `EventHandler.OnTransactionUpdate` for every stage and `EventHandler.OnConsentRevoked` once when a revoke reaches `Confirmed`.

### Check consent status

```go
result, err := engine.CheckConsent(ctx, partyKey, feedType)
// result.Status: "active", "expired", "not-found"
// result.Payload: *feedpermission.FeedPermissionPayload (non-nil when active)
```

Expiry is evaluated at call time; `expired` is never written to the store.

### Catch-up synchronisation

```go
err := engine.Synchronize(ctx)
```

Queries mid-tier for all consent events since the last known cursor, processes them in order, and advances the cursor atomically. Call this periodically (e.g. every 60 s) to recover from missed callbacks.

### Xpub exchange

```go
// By pre-known slot number:
resp, err := engine.HandleXpubRequest(ctx, slot)

// By counterparty DID — resolves or assigns a slot automatically:
resp, err := engine.HandleXpubRequestByDID(ctx, "did:key:zBob...")
// resp.Xpub is the xpub at m/4410704'/{slot}
```

## Interfaces to implement

### `CounterpartyDirectory`

Maps party keys (DIDs, WebIDs) to stable HD path indices and xpubs.

```go
type CounterpartyDirectory interface {
    GetOrAssignIndex(partyKey string) (int, error)
    GetXpub(partyKey string) (string, bool, error)
    StoreXpub(partyKey, xpub string) error
    NextConsentNo(partyKey string, chainId int) (int, error)
}
```

`NextConsentNo` is called when this party is acting as grantor and needs to allocate the next consent sequence number. Sequence numbers start at 1.

### `ConsentStore`

Persists `ConsentRecord` values and the opaque sync cursor.

```go
type ConsentStore interface {
    Get(id string) (*ConsentRecord, error)
    Set(record *ConsentRecord) error
    FindActive(partyKey, feedType string) ([]*ConsentRecord, error)
    GetSyncCursor() (string, error)
    SetSyncCursor(cursor string) error
}
```

### `MidTierClient`

Network boundary to the mid-tier service. Use `midtierclient.New(baseURL)` for the concrete HTTP implementation (see below), or implement the interface for testing.

```go
type MidTierClient interface {
    SubmitGrant(ctx, record ConsentRecord, callbackURL string, metadata map[string]any) error
    SubmitRevoke(ctx, record RevokeRecord, callbackURL string, metadata map[string]any) error
    GetConsentsSince(ctx, xpub, cursor string) ([]ConsentEvent, error)
}
```

### Optional: `ConsentReviewer`

```go
type ConsentReviewer interface {
    Review(ctx, payload *feedpermission.FeedPermissionPayload) (ReviewDecision, error)
    // ReviewDecision: "accept" | "reject" | "defer"
}
```

### Optional: `EventHandler`

```go
type EventHandler interface {
    OnTransactionUpdate(ctx, event TransactionUpdateEvent) error
    OnConsentRevoked(ctx, event ConsentRevokedEvent) error
}
```

## `midtierclient` sub-package

A ready-made HTTP implementation of `MidTierClient`:

```go
import "github.com/smarter-contracts/pulse-protocol-go/consent/midtierclient"

mtClient := midtierclient.New("http://midtier:3020")
```

Implements:
- `GET /api/v3/consents-by-key/{xpub}?since={cursor}`
- `PUT /api/v3/grant`
- `DELETE /api/v3/grant`

Non-2xx responses include up to 1 KiB of the response body in the error string.

## Consent lifecycle

```
HandleInboundConsent
        │
        ├─ accept ──► SubmitGrant ──► mid-tier ──► callbacks
        │                                 │
        │                     pending → ipfs_live → confirmed → active
        │
        ├─ defer  ──► pending-review
        │                 │
        │          ApproveConsent ──► SubmitGrant (same path as accept)
        │          RejectConsent  ──► rejected (terminal)
        │
        └─ reject ──► rejected (terminal)

RevokeConsent ──► SubmitRevoke ──► mid-tier ──► rev_confirmed → revoked (terminal)
```
