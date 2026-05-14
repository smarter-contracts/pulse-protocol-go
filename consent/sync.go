package consent

import (
	"context"
	"fmt"

	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto/v2"
)

// Synchronize fetches consent events from mid-tier since the last saved cursor
// and replays them through the same state machine as HandleTransactionCallback.
//
// The root xpub at m/4410704'/0 is derived from the wallet and passed to
// MidTierClient.GetConsentsSince so mid-tier can resolve the set of signing
// addresses owned by this engine. An empty cursor requests the full history.
//
// Each event is processed in order. After each event the sync cursor is
// advanced to event.Cursor, so a restart after a partial run resumes from
// the last successfully processed event rather than replaying from the top.
//
// Events for unknown consent IDs (consents created before this engine started
// tracking them) and events for already-terminal records are skipped silently;
// the cursor still advances past them.
func (e *ConsentEngine) Synchronize(ctx context.Context) error {
	xpub, err := ppcrypto.DeriveOtherPartyXpub(e.wallet, 0)
	if err != nil {
		return fmt.Errorf("consent: Synchronize: derive root xpub: %w", err)
	}

	cursor, err := e.store.GetSyncCursor()
	if err != nil {
		return fmt.Errorf("consent: Synchronize GetSyncCursor: %w", err)
	}

	events, err := e.mt.GetConsentsSince(ctx, xpub, cursor)
	if err != nil {
		return fmt.Errorf("consent: Synchronize GetConsentsSince: %w", err)
	}

	for _, event := range events {
		if err := e.applySyncEvent(ctx, event); err != nil {
			return err
		}
	}

	return nil
}

// applySyncEvent processes a single ConsentEvent from a Synchronize pass.
// Unknown and terminal records are skipped so that a single bad event cannot
// stall the entire sync. The cursor is advanced regardless of whether the
// event was applied.
func (e *ConsentEngine) applySyncEvent(ctx context.Context, event ConsentEvent) error {
	record, err := e.store.Get(event.ConsentID)
	if err != nil {
		return fmt.Errorf("consent: Synchronize Get %q: %w", event.ConsentID, err)
	}

	skip := record == nil ||
		record.Status == ConsentStatusRevoked ||
		record.Status == ConsentStatusRejected

	if !skip {
		if err := e.HandleTransactionCallback(ctx, CallbackRequest{
			ConsentID: event.ConsentID,
			Type:      event.Type,
			Status:    event.Status,
			CID:       event.CID,
		}); err != nil {
			return err
		}
	}

	if event.Cursor != "" {
		if err := e.store.SetSyncCursor(event.Cursor); err != nil {
			return fmt.Errorf("consent: Synchronize SetSyncCursor: %w", err)
		}
	}

	return nil
}
