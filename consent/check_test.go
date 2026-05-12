package consent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// ── CheckConsent ──────────────────────────────────────────────────────────────

func TestCheckConsent_ActiveRecord_ReturnsActiveWithPayload(t *testing.T) {
	payload := &feedpermission.FeedPermissionPayload{
		FeedType: "open-banking",
	}
	record := &ConsentRecord{
		ID:       "c1",
		PartyKey: "did:web:bank.example",
		FeedType: "open-banking",
		Status:   ConsentStatusActive,
		Payload:  payload,
	}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	store.activeRecords = []*ConsentRecord{record}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	result, err := engine.CheckConsent(context.Background(), "did:web:bank.example", "open-banking")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != ConsentStatusActive {
		t.Errorf("Status: got %q, want %q", result.Status, ConsentStatusActive)
	}
	if result.Payload == nil {
		t.Fatal("Payload should not be nil for active consent")
	}
}

func TestCheckConsent_NotFound_ReturnsNotFound(t *testing.T) {
	store := &stubConsentStore{}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	result, err := engine.CheckConsent(context.Background(), "did:web:unknown.example", "open-banking")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != ConsentStatusNotFound {
		t.Errorf("Status: got %q, want %q", result.Status, ConsentStatusNotFound)
	}
	if result.Payload != nil {
		t.Error("Payload should be nil when not found")
	}
}

func TestCheckConsent_ExpiredRecord_ReturnsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	record := &ConsentRecord{
		ID:        "c1",
		Status:    ConsentStatusActive,
		FeedType:  "open-banking",
		ExpiresAt: &past,
		Payload:   &feedpermission.FeedPermissionPayload{},
	}
	store := &stubConsentStore{}
	store.activeRecords = []*ConsentRecord{record}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	result, err := engine.CheckConsent(context.Background(), "did:web:bank.example", "open-banking")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != ConsentStatusExpired {
		t.Errorf("Status: got %q, want %q", result.Status, ConsentStatusExpired)
	}
	if result.Payload != nil {
		t.Error("Payload should be nil for expired consent")
	}
}

func TestCheckConsent_FutureExpiry_ReturnsActive(t *testing.T) {
	future := time.Now().Add(time.Hour)
	record := &ConsentRecord{
		ID:        "c1",
		Status:    ConsentStatusActive,
		FeedType:  "open-banking",
		ExpiresAt: &future,
		Payload:   &feedpermission.FeedPermissionPayload{FeedType: "open-banking"},
	}
	store := &stubConsentStore{}
	store.activeRecords = []*ConsentRecord{record}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	result, err := engine.CheckConsent(context.Background(), "did:web:bank.example", "open-banking")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != ConsentStatusActive {
		t.Errorf("Status: got %q, want %q", result.Status, ConsentStatusActive)
	}
	if result.ExpiresAt == nil || !result.ExpiresAt.Equal(future) {
		t.Errorf("ExpiresAt: got %v, want %v", result.ExpiresAt, future)
	}
}

func TestCheckConsent_NoExpiry_ReturnsActive(t *testing.T) {
	record := &ConsentRecord{
		ID:       "c1",
		Status:   ConsentStatusActive,
		FeedType: "open-banking",
		Payload:  &feedpermission.FeedPermissionPayload{},
		// ExpiresAt nil → no expiry
	}
	store := &stubConsentStore{}
	store.activeRecords = []*ConsentRecord{record}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	result, err := engine.CheckConsent(context.Background(), "did:web:bank.example", "open-banking")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != ConsentStatusActive {
		t.Errorf("Status: got %q, want %q", result.Status, ConsentStatusActive)
	}
	if result.ExpiresAt != nil {
		t.Errorf("ExpiresAt should be nil, got %v", result.ExpiresAt)
	}
}

func TestCheckConsent_StoreError_Propagates(t *testing.T) {
	storeErr := errors.New("database unavailable")
	store := &stubConsentStore{findActiveErr: storeErr}

	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	_, err := engine.CheckConsent(context.Background(), "did:web:bank.example", "open-banking")
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected storeErr, got %v", err)
	}
}
