package consent

import (
	"context"
	"testing"
)

// ── HandleTransactionCallback ─────────────────────────────────────────────────

func TestHandleTransactionCallback_GrantIPFSLive_UpdatesCIDAndFiresEvent(t *testing.T) {
	record := &ConsentRecord{ID: "c1", PartyKey: "did:web:bank.example", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	handler := &stubEventHandler{onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e }}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusIPFSLive, CID: "Qmfoo"}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusPending {
		t.Errorf("status: got %q, want pending", store.lastSet.Status)
	}
	if store.lastSet.CID != "Qmfoo" {
		t.Errorf("CID: got %q, want Qmfoo", store.lastSet.CID)
	}
	if gotUpdate.Status != TransactionStatusIPFSLive {
		t.Errorf("event status: got %q, want ipfs_live", gotUpdate.Status)
	}
	if gotUpdate.CID != "Qmfoo" {
		t.Errorf("event CID: got %q, want Qmfoo", gotUpdate.CID)
	}
}

func TestHandleTransactionCallback_GrantSubmitted_FiresEvent(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	handler := &stubEventHandler{onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e }}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusSubmitted}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusPending {
		t.Errorf("status: got %q, want pending", store.lastSet.Status)
	}
	if gotUpdate.Status != TransactionStatusSubmitted {
		t.Errorf("event status: got %q, want submitted", gotUpdate.Status)
	}
}

func TestHandleTransactionCallback_GrantConfirmed_SetsActiveAndFiresEvent(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	var revokeFired bool
	handler := &stubEventHandler{
		onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e },
		onRevoke: func(_ ConsentRevokedEvent) { revokeFired = true },
	}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusConfirmed, CID: "QmActive"}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusActive {
		t.Errorf("status: got %q, want active", store.lastSet.Status)
	}
	if gotUpdate.Status != TransactionStatusConfirmed {
		t.Errorf("event status: got %q, want confirmed", gotUpdate.Status)
	}
	if gotUpdate.Type != TransactionTypeGrant {
		t.Errorf("event type: got %q, want grant", gotUpdate.Type)
	}
	if revokeFired {
		t.Error("OnConsentRevoked must NOT fire for a grant callback")
	}
}

func TestHandleTransactionCallback_GrantRejected_FiresEventStatusUnchanged(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	handler := &stubEventHandler{onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e }}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusRejected}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusPending {
		t.Errorf("status: got %q, want pending (unchanged on rejection)", store.lastSet.Status)
	}
	if gotUpdate.Status != TransactionStatusRejected {
		t.Errorf("event status: got %q, want rejected", gotUpdate.Status)
	}
}

func TestHandleTransactionCallback_GrantDelayed_FiresEvent(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	handler := &stubEventHandler{onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e }}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeGrant, Status: TransactionStatusDelayed}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotUpdate.Status != TransactionStatusDelayed {
		t.Errorf("event status: got %q, want delayed", gotUpdate.Status)
	}
}

func TestHandleTransactionCallback_RevokePendingWhileGrantPending_Allowed(t *testing.T) {
	// Grant and revoke can overlap: a rev_pending callback may arrive before the
	// grant has confirmed. The primary status must not block the revoke callbacks.
	record := &ConsentRecord{ID: "c1", PartyKey: "did:web:bank.example", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	handler := &stubEventHandler{onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e }}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeRevoke, Status: TransactionStatusRevPending}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusPending {
		t.Errorf("status: got %q, want pending (grant still in flight)", store.lastSet.Status)
	}
	if gotUpdate.Status != TransactionStatusRevPending {
		t.Errorf("event status: got %q, want rev_pending", gotUpdate.Status)
	}
}

func TestHandleTransactionCallback_RevokeIPFSLive_UpdatesRevokeCID(t *testing.T) {
	record := &ConsentRecord{ID: "c1", PartyKey: "did:web:bank.example", Status: ConsentStatusActive}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var revokeFired bool
	handler := &stubEventHandler{onRevoke: func(_ ConsentRevokedEvent) { revokeFired = true }}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeRevoke, Status: TransactionStatusRevIPFSLive, CID: "QmRev"}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusActive {
		t.Errorf("status: got %q, want active (revoke not yet confirmed)", store.lastSet.Status)
	}
	if store.lastSet.RevokeCID != "QmRev" {
		t.Errorf("RevokeCID: got %q, want QmRev", store.lastSet.RevokeCID)
	}
	if revokeFired {
		t.Error("OnConsentRevoked must NOT fire until rev_confirmed")
	}
}

func TestHandleTransactionCallback_RevokeConfirmed_SetsRevokedAndFiresBothEvents(t *testing.T) {
	const partyKey = "did:web:bank.example"
	record := &ConsentRecord{ID: "c1", PartyKey: partyKey, Status: ConsentStatusActive, RevokeCID: "QmRevoked"}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}

	var gotUpdate TransactionUpdateEvent
	var gotRevoke ConsentRevokedEvent
	handler := &stubEventHandler{
		onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e },
		onRevoke: func(e ConsentRevokedEvent) { gotRevoke = e },
	}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{},
		WithEventHandler(handler),
	)

	req := CallbackRequest{ConsentID: "c1", Type: TransactionTypeRevoke, Status: TransactionStatusRevConfirmed}
	if err := engine.HandleTransactionCallback(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusRevoked {
		t.Errorf("status: got %q, want revoked", store.lastSet.Status)
	}
	if gotUpdate.Type != TransactionTypeRevoke || gotUpdate.Status != TransactionStatusRevConfirmed {
		t.Errorf("OnTransactionUpdate: got type=%q status=%q, want revoke/rev_confirmed",
			gotUpdate.Type, gotUpdate.Status)
	}
	if gotRevoke.ConsentID != "c1" {
		t.Errorf("OnConsentRevoked ConsentID: got %q, want c1", gotRevoke.ConsentID)
	}
	if gotRevoke.PartyKey != partyKey {
		t.Errorf("OnConsentRevoked PartyKey: got %q, want %q", gotRevoke.PartyKey, partyKey)
	}
	if gotRevoke.CID != "QmRevoked" {
		t.Errorf("OnConsentRevoked CID: got %q, want QmRevoked", gotRevoke.CID)
	}
}

func TestHandleTransactionCallback_ConsentNotFound_Errors(t *testing.T) {
	store := &stubConsentStore{records: map[string]*ConsentRecord{}}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	err := engine.HandleTransactionCallback(context.Background(),
		CallbackRequest{ConsentID: "missing", Type: TransactionTypeGrant, Status: TransactionStatusPending})
	if err == nil {
		t.Fatal("expected error for missing consent, got nil")
	}
}

func TestHandleTransactionCallback_AlreadyRevoked_Errors(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusRevoked}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	err := engine.HandleTransactionCallback(context.Background(),
		CallbackRequest{ConsentID: "c1", Type: TransactionTypeRevoke, Status: TransactionStatusRevConfirmed})
	if err == nil {
		t.Fatal("expected error: callback on already-revoked record")
	}
}

func TestHandleTransactionCallback_UnrecognisedStatus_Errors(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	err := engine.HandleTransactionCallback(context.Background(),
		CallbackRequest{ConsentID: "c1", Type: TransactionTypeGrant, Status: "bogus"})
	if err == nil {
		t.Fatal("expected error for unrecognised status")
	}
}
