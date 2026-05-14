package consent

import (
	"context"
	"fmt"
	"time"
)

// CheckConsent returns the current status of any active consent for the given
// partyKey and feedType. It is a pure read — no crypto, no network calls.
//
// Status semantics:
//   - Active: a non-expired active consent exists; Payload is populated.
//   - Expired: the most recent active record's ExpiresAt has passed; Payload is nil.
//   - NotFound: no active record exists for this partyKey+feedType pair.
//
// Revoked and rejected records are not returned by FindActive, so those states
// do not appear here; callers that need full history should query the store directly.
func (e *ConsentEngine) CheckConsent(_ context.Context, partyKey, feedType string) (ConsentCheckResult, error) {
	records, err := e.store.FindActive(partyKey, feedType)
	if err != nil {
		return ConsentCheckResult{}, fmt.Errorf("consent: CheckConsent FindActive: %w", err)
	}
	if len(records) == 0 {
		return ConsentCheckResult{Status: ConsentStatusNotFound}, nil
	}

	record := records[0]

	if record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt) {
		return ConsentCheckResult{
			Status:    ConsentStatusExpired,
			ExpiresAt: record.ExpiresAt,
		}, nil
	}

	return ConsentCheckResult{
		Status:    ConsentStatusActive,
		Payload:   record.Payload,
		ExpiresAt: record.ExpiresAt,
	}, nil
}
