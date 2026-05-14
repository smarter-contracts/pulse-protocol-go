package consent

import (
	"context"
	"fmt"
	"time"
)

// HandleTransactionCallback processes a mid-tier progress update and advances
// the ConsentRecord through the state machine.
//
// Mid-tier sends the raw status string in the callback; grant and revoke stages
// use distinct prefixes (rev_) so both can be in flight concurrently against the
// same record without ambiguity.
//
// Grant path (status: pending → ipfs_live → submitted → confirmed | rejected | delayed):
//   - ipfs_live: record.CID updated, OnTransactionUpdate fired.
//   - submitted/pending: OnTransactionUpdate fired, no status change.
//   - confirmed: record.Status → active, OnTransactionUpdate fired.
//   - rejected/delayed: OnTransactionUpdate fired, no status change (app retries or abandons).
//
// Revoke path (status: rev_pending → rev_ipfs_live → rev_submitted → rev_confirmed):
//   - rev_ipfs_live: record.RevokeCID updated, OnTransactionUpdate fired.
//   - rev_submitted/rev_pending: OnTransactionUpdate fired, no status change.
//   - rev_confirmed: record.Status → revoked, OnTransactionUpdate fired, OnConsentRevoked fired.
//
// The primary ConsentStatus is not checked as a prerequisite — grant and revoke
// can be in flight simultaneously, so the status may be anything from pending to
// active when revoke callbacks arrive.
func (e *ConsentEngine) HandleTransactionCallback(ctx context.Context, req CallbackRequest) error {
	record, err := e.store.Get(req.ConsentID)
	if err != nil {
		return fmt.Errorf("consent: HandleTransactionCallback Get: %w", err)
	}
	if record == nil {
		return fmt.Errorf("consent: HandleTransactionCallback: consent %q not found", req.ConsentID)
	}

	// Refuse callbacks against already-terminal records.
	if record.Status == ConsentStatusRevoked || record.Status == ConsentStatusRejected {
		return fmt.Errorf("consent: HandleTransactionCallback: record %q is already in terminal state %q", req.ConsentID, record.Status)
	}

	switch req.Status {
	case TransactionStatusIPFSLive:
		record.CID = req.CID

	case TransactionStatusRevIPFSLive:
		record.RevokeCID = req.CID

	case TransactionStatusConfirmed:
		record.Status = ConsentStatusActive

	case TransactionStatusRevConfirmed:
		record.Status = ConsentStatusRevoked

	case TransactionStatusPending,
		TransactionStatusSubmitted,
		TransactionStatusRejected,
		TransactionStatusDelayed,
		TransactionStatusRevPending,
		TransactionStatusRevSubmitted:
		// No record-state change; event fired below.

	default:
		return fmt.Errorf("consent: HandleTransactionCallback: unrecognised status %q", req.Status)
	}

	record.UpdatedAt = time.Now().UTC()
	if err := e.store.Set(record); err != nil {
		return fmt.Errorf("consent: HandleTransactionCallback Set: %w", err)
	}

	if err := e.config.handler.OnTransactionUpdate(ctx, TransactionUpdateEvent{
		ConsentID: record.ID,
		Type:      req.Type,
		Status:    req.Status,
		CID:       req.CID,
	}); err != nil {
		return fmt.Errorf("consent: OnTransactionUpdate: %w", err)
	}

	if req.Status == TransactionStatusRevConfirmed {
		if err := e.config.handler.OnConsentRevoked(ctx, ConsentRevokedEvent{
			ConsentID: record.ID,
			PartyKey:  record.PartyKey,
			CID:       record.RevokeCID,
		}); err != nil {
			return fmt.Errorf("consent: OnConsentRevoked: %w", err)
		}
	}

	return nil
}
