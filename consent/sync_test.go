package consent

import (
	"context"
	"errors"
	"testing"
)

// ── Synchronize ───────────────────────────────────────────────────────────────

func TestSynchronize_EmptyEvents_NoStateChanges(t *testing.T) {
	store := &stubConsentStore{}
	mt := &stubMidTierClient{} // sinceEvents nil → empty

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)

	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.lastSet != nil {
		t.Error("no records should be written for an empty event list")
	}
}

func TestSynchronize_PassesXpubAndCursorToGetConsentsSince(t *testing.T) {
	store := &stubConsentStore{}
	store.setCursor("prior-cursor")
	mt := &stubMidTierClient{}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)
	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mt.capturedXpub == "" {
		t.Error("GetConsentsSince was not called with an xpub")
	}
	if mt.capturedCursor != "prior-cursor" {
		t.Errorf("cursor: got %q, want %q", mt.capturedCursor, "prior-cursor")
	}
}

func TestSynchronize_EventApplied_RecordUpdated(t *testing.T) {
	const cid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{
		sinceEvents: []ConsentEvent{
			{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusIPFSLive, CID: cid, Cursor: "cur-1"},
		},
	}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)
	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated := store.records["c1"]
	if updated.CID != cid {
		t.Errorf("CID: got %q, want %q", updated.CID, cid)
	}
}

func TestSynchronize_CursorAdvancedAfterEachEvent(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{
		sinceEvents: []ConsentEvent{
			{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusIPFSLive, CID: "cid-1", Cursor: "cur-1"},
			{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusSubmitted, Cursor: "cur-2"},
		},
	}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)
	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, _ := store.GetSyncCursor()
	if got != "cur-2" {
		t.Errorf("final cursor: got %q, want %q", got, "cur-2")
	}
}

func TestSynchronize_UnknownConsentID_SkippedCursorAdvanced(t *testing.T) {
	// An event for a consent we don't hold must not abort the sync.
	store := &stubConsentStore{}
	mt := &stubMidTierClient{
		sinceEvents: []ConsentEvent{
			{ConsentID: "unknown", Type: TransactionTypeGrant, Status: TransactionStatusConfirmed, Cursor: "cur-x"},
		},
	}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)
	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error for unknown consent: %v", err)
	}

	got, _ := store.GetSyncCursor()
	if got != "cur-x" {
		t.Errorf("cursor should advance past unknown event: got %q, want %q", got, "cur-x")
	}
}

func TestSynchronize_TerminalRecord_SkippedCursorAdvanced(t *testing.T) {
	// An event arriving for an already-revoked record must not abort the sync.
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusRevoked}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{
		sinceEvents: []ConsentEvent{
			{ConsentID: "c1", Type: TransactionTypeRevoke, Status: TransactionStatusRevIPFSLive, CID: "cid-rev", Cursor: "cur-t"},
		},
	}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)
	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error for terminal record: %v", err)
	}

	got, _ := store.GetSyncCursor()
	if got != "cur-t" {
		t.Errorf("cursor should advance past terminal event: got %q, want %q", got, "cur-t")
	}
}

func TestSynchronize_ConfirmedEvent_RecordBecomesActive(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{
		sinceEvents: []ConsentEvent{
			{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusConfirmed, Cursor: "cur-c"},
		},
	}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, mt)
	if err := engine.Synchronize(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.records["c1"].Status != ConsentStatusActive {
		t.Errorf("Status: got %q, want %q", store.records["c1"].Status, ConsentStatusActive)
	}
}

func TestSynchronize_WalletError_Propagates(t *testing.T) {
	walletErr := errors.New("key unavailable")
	engine := NewConsentEngine(
		&stubWalletStore{err: walletErr},
		&stubCounterpartyDirectory{},
		&stubConsentStore{},
		&stubMidTierClient{},
	)

	err := engine.Synchronize(context.Background())
	if !errors.Is(err, walletErr) {
		t.Fatalf("expected walletErr, got %v", err)
	}
}

func TestSynchronize_GetConsentsSinceError_Propagates(t *testing.T) {
	networkErr := errors.New("connection refused")
	mt := &stubMidTierClient{sinceErr: networkErr}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, &stubConsentStore{}, mt)

	err := engine.Synchronize(context.Background())
	if !errors.Is(err, networkErr) {
		t.Fatalf("expected networkErr, got %v", err)
	}
}
