package consent

import (
	"context"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

func TestDefaultConfig_ReviewerIsAcceptAll(t *testing.T) {
	cfg := defaultConfig()
	decision, err := cfg.reviewer.Review(context.Background(), &feedpermission.FeedPermissionPayload{})
	if err != nil {
		t.Fatalf("acceptAllReviewer.Review returned error: %v", err)
	}
	if decision != ReviewDecisionAccept {
		t.Fatalf("expected Accept, got %q", decision)
	}
}

func TestDefaultConfig_HandlerIsNoop(t *testing.T) {
	cfg := defaultConfig()
	ctx := context.Background()

	if err := cfg.handler.OnTransactionUpdate(ctx, TransactionUpdateEvent{}); err != nil {
		t.Fatalf("noopEventHandler.OnTransactionUpdate returned error: %v", err)
	}
	if err := cfg.handler.OnConsentRevoked(ctx, ConsentRevokedEvent{}); err != nil {
		t.Fatalf("noopEventHandler.OnConsentRevoked returned error: %v", err)
	}
}

func TestWithReviewer_OverridesDefault(t *testing.T) {
	called := false
	stub := &stubReviewer{decision: ReviewDecisionDefer, onReview: func() { called = true }}

	cfg := defaultConfig()
	WithReviewer(stub)(cfg)

	decision, err := cfg.reviewer.Review(context.Background(), &feedpermission.FeedPermissionPayload{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("stub reviewer was not called")
	}
	if decision != ReviewDecisionDefer {
		t.Fatalf("expected Defer, got %q", decision)
	}
}

func TestWithEventHandler_OverridesDefault(t *testing.T) {
	var gotUpdate TransactionUpdateEvent
	var gotRevoke ConsentRevokedEvent

	stub := &stubEventHandler{
		onUpdate: func(e TransactionUpdateEvent) { gotUpdate = e },
		onRevoke: func(e ConsentRevokedEvent) { gotRevoke = e },
	}

	cfg := defaultConfig()
	WithEventHandler(stub)(cfg)

	ctx := context.Background()
	wantUpdate := TransactionUpdateEvent{ConsentID: "c1", Status: TransactionStatusConfirmed}
	wantRevoke := ConsentRevokedEvent{ConsentID: "c2", PartyKey: "did:web:example"}

	_ = cfg.handler.OnTransactionUpdate(ctx, wantUpdate)
	_ = cfg.handler.OnConsentRevoked(ctx, wantRevoke)

	if gotUpdate != wantUpdate {
		t.Errorf("OnTransactionUpdate: got %+v, want %+v", gotUpdate, wantUpdate)
	}
	if gotRevoke != wantRevoke {
		t.Errorf("OnConsentRevoked: got %+v, want %+v", gotRevoke, wantRevoke)
	}
}

// ── test doubles ─────────────────────────────────────────────────────────────

type stubReviewer struct {
	decision ReviewDecision
	onReview func()
}

func (s *stubReviewer) Review(_ context.Context, _ *feedpermission.FeedPermissionPayload) (ReviewDecision, error) {
	if s.onReview != nil {
		s.onReview()
	}
	return s.decision, nil
}

type stubEventHandler struct {
	onUpdate func(TransactionUpdateEvent)
	onRevoke func(ConsentRevokedEvent)
}

func (s *stubEventHandler) OnTransactionUpdate(_ context.Context, e TransactionUpdateEvent) error {
	if s.onUpdate != nil {
		s.onUpdate(e)
	}
	return nil
}

func (s *stubEventHandler) OnConsentRevoked(_ context.Context, e ConsentRevokedEvent) error {
	if s.onRevoke != nil {
		s.onRevoke(e)
	}
	return nil
}
