# Changelog

All notable changes to this module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-16

### Breaking

- **`CounterpartyDirectory` interface** — new required method:
  ```go
  NextConsentNo(partyKey string, chainId int) (int, error)
  ```
  Atomically returns and increments the consent sequence number for a counterparty on a
  given chain. Sequence numbers start at 1; 0 is the "unset" sentinel. Implementations that
  previously satisfied this interface must add this method.

- **`RevokeRecord` fields restructured** — `SealedBytes []byte` is replaced by three separate
  fields matching the EC encryption output: `SealedData []byte`, `Key1 []byte`, `Key2 []byte`.
  This aligns `RevokeRecord` with the `PulseRevokePayload` wire format and removes the implicit
  marshalling that previously combined these into a single field.

### Added

- **`ConsentEngine.HandleXpubRequestByDID(ctx, requestorDID string) (XpubResponse, error)`**
  — resolves or assigns a counterparty slot for the given DID via `CounterpartyDirectory`,
  then delegates to `HandleXpubRequest`. Callers no longer need to resolve the slot themselves
  before requesting an xpub.

### Fixed

- **`RevokeConsent`**: falls back to `record.ID` as `GrantRef` when `record.CID` is empty.
  `record.CID` is populated by the `ipfs_live` callback from mid-tier; if that callback was
  never received (e.g. the service restarted before it arrived), `record.CID` is empty.
  Both values are derived from the same DAG-CBOR bytes, so `record.ID` is a safe substitute.

- **`midtierclient`**: non-2xx responses now include up to 1 KiB of the response body in the
  returned error string. Previously the body was discarded, making transport-level rejections
  from mid-tier opaque.

### Changed

- **`HandleInboundConsent`** now calls `CounterpartyDirectory.StoreXpub` when the inbound
  `FeedPermissionPayload.GrantorXpub` field is non-empty. This caches the grantor's xpub
  automatically on first contact, enabling future reverse grants without a separate xpub
  round-trip.

## [0.1.1] - 2026-05-14

### Changed

- `consent/go.mod`: corrected dependency version pins to match the versions the consent code
  actually requires outside the Go workspace:
  - `github.com/smarter-contracts/pulse-protocol-go/crypto` updated to `v2.0.0` — the
    `WalletStore` interface, which all consent engine functions depend on, was introduced in v2.0.0
  - `github.com/smarter-contracts/pulse-protocol-go/ipfs` updated to `v1.2.0` — required for
    `MarshalFeedRevocation` used in `RevokeConsent`
  - `github.com/smarter-contracts/pulse-protocol-go/types` updated to `v1.2.0` — required for
    `feedrevocation.FeedRevocationPayload` used in `RevokeConsent`

## [0.1.0] - 2026-05-13

### Added

Initial release of the `pulse-consent-core` library.

- **`ConsentEngine`** — central struct wiring together all consent operations.
  Constructed via `NewConsentEngine(wallet, cpDir, store, midTierClient, ...opts)`.

- **`HandleInboundConsent`** — decrypts an inbound consent request (ECDH open),
  unmarshals the `FeedPermissionPayload`, evaluates expiry, invokes `ConsentReviewer.Review`,
  stores the record with the appropriate status, and submits to mid-tier if accepted.
  `ConsentRecord.ID` is the IPFS CIDv1 of the sealed bytes, computed client-side before submission.

- **`ApproveConsent` / `RejectConsent`** — transitions a `pending-review` record to `pending`
  (submit to mid-tier) or `rejected` after a deferred human review decision.

- **`RevokeConsent`** — encrypts and signs a revocation payload (ECDH), submits to mid-tier,
  and stores the record at `pending-revoke` status.

- **`HandleTransactionCallback`** — processes grant and revoke lifecycle events from mid-tier:
  `grant_ipfs_live`, `grant_submitted`, `grant_confirmed`, `grant_rejected`, `grant_delayed`,
  `revoke_ipfs_live`, `revoke_confirmed`. Fires typed domain events via `EventHandler`.

- **`CheckConsent`** — pure read with expiry evaluation at call time; returns `active`,
  `expired`, or `not_found` without mutating store state.

- **`Synchronize`** — catch-up replay against mid-tier using `GetConsentsSince`. Derives the
  root xpub at `m/CMP'` (via `DeriveOtherPartyXpub(wallet, 0)`) for address-based lookup.
  Advances the cursor atomically after each event so restarts are safe.

- **`HandleXpubRequest`** — derives and returns the xpub at `m/CMP'/{otherPartyId}` for
  counterparty key exchange.

- **`MidTierClient` interface** — `GetConsentsSince(ctx, xpub, cursor)`,
  `SubmitGrant(ctx, record, callbackURL, metadata)`,
  `SubmitRevoke(ctx, record, callbackURL, metadata)`.

- **`ConsentStore` interface** — `Get(id)`, `Set(record)`, `FindActive(partyKey, feedType)`,
  `GetSyncCursor()`, `SetSyncCursor(cursor)`. Implement to plug in any persistence layer.

- **`CounterpartyDirectory` interface** — `GetOrAssignIndex(partyKey)`, `GetXpub(partyKey)`,
  `StoreXpub(partyKey, xpub)`. Maps party keys to stable HD path indices.

- **`ConsentReviewer` interface** — `Review(ctx, payload)` returning `accept`, `reject`, or
  `defer`. Default implementation accepts all.

- **`EventHandler` interface** — `Handle(ctx, event)` for domain events emitted by the engine.
  Default implementation is a no-op.

- **Option functions**: `WithReviewer`, `WithEventHandler`, `WithContractAddress`.

- **`consent/midtierclient` sub-package** — concrete HTTP implementation of `MidTierClient`.
  `midtierclient.New(baseURL)` returns a client wired to the mid-tier service.
  - `GET /api/v3/consents-by-key/{xpub}?since={cursor}` → `[]ConsentEvent`
  - `PUT /api/v3/grant` with base64-encoded `SealedBytes`
  - `DELETE /api/v3/grant` with base64-encoded `SealedBytes` and hex-encoded `Signature`

### Dependencies

- `github.com/smarter-contracts/pulse-protocol-go/crypto v1.1.0`
- `github.com/smarter-contracts/pulse-protocol-go/ipfs v1.1.0`
- `github.com/smarter-contracts/pulse-protocol-go/types v1.1.0`
- `github.com/jamesradley/go-bip32 v1.0.1`
