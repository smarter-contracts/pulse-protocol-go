package consent

import (
	"context"

	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// CounterpartyDirectory manages the mapping between counterparty identifiers
// (DIDs, WebIDs, or future multi-party concat keys) and their assigned
// HD path indices and public keys.
//
// partyKey is chosen over a more specific name (e.g. webId) so the interface
// remains valid for future multi-party consents where the key will be a
// concatenation of participant identifiers.
type CounterpartyDirectory interface {
	// GetOrAssignIndex returns the HD path index for partyKey, assigning one
	// if the counterparty has not been seen before.
	GetOrAssignIndex(partyKey string) (int, error)

	// GetXpub returns the stored xpub for partyKey. The boolean is false if
	// no xpub has been stored yet for this counterparty.
	GetXpub(partyKey string) (string, bool, error)

	// StoreXpub persists the counterparty's xpub for future use.
	StoreXpub(partyKey, xpub string) error
}

// ConsentStore persists ConsentRecords and the opaque sync cursor.
type ConsentStore interface {
	// Get returns the record with the given ID, or an error if not found.
	Get(id string) (*ConsentRecord, error)

	// Set creates or replaces the record. Implementations must be idempotent.
	Set(record *ConsentRecord) error

	// FindActive returns all records for partyKey+feedType whose status is Active
	// and whose expiry (if set) has not passed.
	FindActive(partyKey, feedType string) ([]*ConsentRecord, error)

	// GetSyncCursor returns the opaque cursor from the last successful Synchronize
	// call. Returns "" if no sync has been completed yet.
	GetSyncCursor() (string, error)

	// SetSyncCursor persists the cursor atomically with any batch writes performed
	// in the same Synchronize pass.
	SetSyncCursor(cursor string) error
}

// ConsentReviewer is an optional hook called for every inbound consent before it
// is accepted. The default (no reviewer provided) is accept-all.
type ConsentReviewer interface {
	// Review inspects the decrypted payload and returns a decision. Defer causes
	// the record to be stored as pending-review; the app later calls
	// ApproveConsent or RejectConsent.
	Review(ctx context.Context, payload *feedpermission.FeedPermissionPayload) (ReviewDecision, error)
}

// EventHandler is an optional hook that receives lifecycle events. The default
// (no handler provided) is a no-op.
type EventHandler interface {
	// OnTransactionUpdate fires at each mid-tier stage for both Grant and Revoke
	// transactions: Pending → IPFSLive → Submitted → Confirmed/Failed.
	OnTransactionUpdate(ctx context.Context, event TransactionUpdateEvent) error

	// OnConsentRevoked fires once for all registered parties when a Revoke
	// transaction reaches Confirmed. Semantically distinct from
	// OnTransactionUpdate: "the consent is dead, act accordingly."
	OnConsentRevoked(ctx context.Context, event ConsentRevokedEvent) error
}

// MidTierClient is the network boundary to the mid-tier service. Applications
// provide a concrete implementation; the library calls it during grant, revoke,
// and synchronisation flows.
type MidTierClient interface {
	// SubmitGrant submits a sealed consent record for IPFS publication and
	// on-chain registration. callbackURL receives progress updates; metadata
	// is returned verbatim in each callback.
	SubmitGrant(ctx context.Context, record ConsentRecord, callbackURL string, metadata map[string]any) error

	// SubmitRevoke submits a sealed revocation record. callbackURL receives
	// rev_* progress updates; metadata is returned verbatim in each callback.
	SubmitRevoke(ctx context.Context, record RevokeRecord, callbackURL string, metadata map[string]any) error

	// GetConsentsSince returns an ordered list of consent events (by
	// blockNumber:txIndex) for the signing addresses derived from xpub,
	// starting after cursor. An empty cursor requests a full history.
	GetConsentsSince(ctx context.Context, xpub, cursor string) ([]ConsentEvent, error)
}
