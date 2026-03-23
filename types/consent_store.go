package types

import (
	"context"
	"time"
)

// ConsentStore defines the storage abstraction for consent and revocation records.
// Implementations may back this with a Solid pod, a relational database, or an
// in-memory store for testing.
type ConsentStore interface {
	// StoreConsent persists an encrypted consent record under the given CID.
	// The operation is idempotent — storing the same CID twice is not an error.
	StoreConsent(ctx context.Context, cid string, record *ConsentStructure) error

	// GetConsent retrieves an encrypted consent record by CID.
	// Returns ErrConsentNotFound if no record exists for the given CID.
	GetConsent(ctx context.Context, cid string) (*ConsentStructure, error)

	// ListConsents returns a filtered list of consent summaries.
	ListConsents(ctx context.Context, filter ConsentFilter) ([]ConsentSummary, error)

	// StoreRevocation persists an encrypted revocation record.
	// grantCID is the CID of the original consent; revokeCID is the CID of the
	// revocation record itself.
	StoreRevocation(ctx context.Context, grantCID, revokeCID string, record *RevokeStructure) error

	// GetRevocation retrieves an encrypted revocation record by its CID.
	// Returns ErrConsentNotFound if no record exists for the given CID.
	GetRevocation(ctx context.Context, revokeCID string) (*RevokeStructure, error)
}

// ConsentStoreMulti is the storage abstraction for multi-party (PQ) consent records.
// It mirrors ConsentStore but operates on the multi-party encrypted structures.
type ConsentStoreMulti interface {
	StoreConsent(ctx context.Context, cid string, record *ConsentStructureMulti) error
	GetConsent(ctx context.Context, cid string) (*ConsentStructureMulti, error)
	ListConsents(ctx context.Context, filter ConsentFilter) ([]ConsentSummary, error)
	StoreRevocation(ctx context.Context, grantCID, revokeCID string, record *RevokeStructureMulti) error
	GetRevocation(ctx context.Context, revokeCID string) (*RevokeStructureMulti, error)
}

// ConsentFilter controls which consent records are returned by ListConsents.
type ConsentFilter struct {
	// Status filters by consent lifecycle status (e.g. "pending", "confirmed",
	// "rev_confirmed"). Empty string matches all statuses.
	Status string

	// Limit caps the number of results. Zero means no limit.
	Limit int

	// Offset skips the first N results (for pagination).
	Offset int
}

// ConsentSummary is a lightweight representation of a consent record for list views.
type ConsentSummary struct {
	CID       string
	GrantCID  string    // Non-empty for revocation summaries
	Status    string
	CreatedAt time.Time
}

// ErrConsentNotFound is returned when a requested consent or revocation record
// does not exist in the store.
type ErrConsentNotFound struct {
	CID string
}

func (e *ErrConsentNotFound) Error() string {
	return "consent not found: " + e.CID
}
