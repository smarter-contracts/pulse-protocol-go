package consent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	bip32 "github.com/jamesradley/go-bip32"
	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto/v2"
)

// ── CounterpartyDirectory.NextConsentNo ──────────────────────────────────────

func TestStubCounterpartyDirectory_NextConsentNo_StartsAtZero(t *testing.T) {
	dir := &stubCounterpartyDirectory{}
	n, err := dir.NextConsentNo("did:key:zBOB", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("want 0, got %d", n)
	}
}

func TestStubCounterpartyDirectory_NextConsentNo_Increments(t *testing.T) {
	dir := &stubCounterpartyDirectory{}
	for want := 0; want < 5; want++ {
		got, err := dir.NextConsentNo("did:key:zBOB", 1)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", want, err)
		}
		if got != want {
			t.Fatalf("call %d: want %d, got %d", want, want, got)
		}
	}
}

func TestStubCounterpartyDirectory_NextConsentNo_IndependentPerPartyAndChain(t *testing.T) {
	dir := &stubCounterpartyDirectory{}
	// Advance alice/chain-1 twice
	dir.NextConsentNo("did:key:zALICE", 1) //nolint:errcheck
	dir.NextConsentNo("did:key:zALICE", 1) //nolint:errcheck
	// bob/chain-1 and alice/chain-2 start fresh
	bobN, _ := dir.NextConsentNo("did:key:zBOB", 1)
	aliceChain2N, _ := dir.NextConsentNo("did:key:zALICE", 2)
	if bobN != 0 {
		t.Fatalf("bob chain-1: want 0, got %d", bobN)
	}
	if aliceChain2N != 0 {
		t.Fatalf("alice chain-2: want 0, got %d", aliceChain2N)
	}
	// alice/chain-1 should be at 2
	aliceNext, _ := dir.NextConsentNo("did:key:zALICE", 1)
	if aliceNext != 2 {
		t.Fatalf("alice chain-1: want 2, got %d", aliceNext)
	}
}

// ── NewConsentEngine ──────────────────────────────────────────────────────────

func TestNewConsentEngine_RequiredDependencies(t *testing.T) {
	wallet := &stubWalletStore{}
	cpDir := &stubCounterpartyDirectory{}
	store := &stubConsentStore{}
	mt := &stubMidTierClient{}

	engine := NewConsentEngine(wallet, cpDir, store, mt)
	if engine == nil {
		t.Fatal("expected non-nil ConsentEngine")
	}
}

func TestNewConsentEngine_DefaultsApplied(t *testing.T) {
	engine := NewConsentEngine(
		&stubWalletStore{},
		&stubCounterpartyDirectory{},
		&stubConsentStore{},
		&stubMidTierClient{},
	)

	// Default reviewer must be accept-all.
	decision, err := engine.config.reviewer.Review(context.Background(), nil)
	if err != nil {
		t.Fatalf("default reviewer error: %v", err)
	}
	if decision != ReviewDecisionAccept {
		t.Fatalf("expected Accept, got %q", decision)
	}
}

func TestNewConsentEngine_WithReviewerOption(t *testing.T) {
	stub := &stubReviewer{decision: ReviewDecisionDefer}
	engine := NewConsentEngine(
		&stubWalletStore{},
		&stubCounterpartyDirectory{},
		&stubConsentStore{},
		&stubMidTierClient{},
		WithReviewer(stub),
	)
	if engine.config.reviewer != stub {
		t.Fatal("WithReviewer option was not applied")
	}
}

func TestNewConsentEngine_WithEventHandlerOption(t *testing.T) {
	stub := &stubEventHandler{}
	engine := NewConsentEngine(
		&stubWalletStore{},
		&stubCounterpartyDirectory{},
		&stubConsentStore{},
		&stubMidTierClient{},
		WithEventHandler(stub),
	)
	if engine.config.handler != stub {
		t.Fatal("WithEventHandler option was not applied")
	}
}

// ── HandleXpubRequest ─────────────────────────────────────────────────────────

func TestHandleXpubRequest_ReturnsXpubFromWalletStore(t *testing.T) {
	const otherpartyId = 3
	wallet := makeTestWallet(t)

	engine := NewConsentEngine(wallet, &stubCounterpartyDirectory{}, &stubConsentStore{}, &stubMidTierClient{})

	resp, err := engine.HandleXpubRequest(context.Background(), otherpartyId)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantXpub, err := ppcrypto.DeriveOtherPartyXpub(wallet, uint32(otherpartyId))
	if err != nil {
		t.Fatalf("DeriveOtherPartyXpub: %v", err)
	}
	if resp.Xpub != wantXpub {
		t.Errorf("Xpub: got %q, want %q", resp.Xpub, wantXpub)
	}
	if resp.OtherpartyId != otherpartyId {
		t.Errorf("OtherpartyId: got %d, want %d", resp.OtherpartyId, otherpartyId)
	}
}

func TestHandleXpubRequest_PropagatesWalletStoreError(t *testing.T) {
	walletErr := errors.New("key derivation failed")
	engine := NewConsentEngine(
		&stubWalletStore{err: walletErr},
		&stubCounterpartyDirectory{},
		&stubConsentStore{},
		&stubMidTierClient{},
	)

	_, err := engine.HandleXpubRequest(context.Background(), 1)
	if !errors.Is(err, walletErr) {
		t.Fatalf("expected walletErr, got %v", err)
	}
}

func TestHandleXpubRequest_DifferentIdsDifferentXpubs(t *testing.T) {
	// Different otherpartyId values must produce different xpubs — the HD path
	// index is the distinguishing factor.
	wallet := makeTestWallet(t)
	engine := NewConsentEngine(wallet, &stubCounterpartyDirectory{}, &stubConsentStore{}, &stubMidTierClient{})

	resp1, err := engine.HandleXpubRequest(context.Background(), 1)
	if err != nil {
		t.Fatalf("request for id=1 failed: %v", err)
	}
	resp2, err := engine.HandleXpubRequest(context.Background(), 2)
	if err != nil {
		t.Fatalf("request for id=2 failed: %v", err)
	}
	if resp1.Xpub == resp2.Xpub {
		t.Error("different IDs must produce different xpubs")
	}
}

// ── HandleXpubRequestByDID ────────────────────────────────────────────────────

func TestHandleXpubRequestByDID_AssignsSlotAndReturnsXpub(t *testing.T) {
	wallet := makeTestWallet(t)
	cpDir := &stubCounterpartyDirectory{}
	engine := NewConsentEngine(wallet, cpDir, &stubConsentStore{}, &stubMidTierClient{})

	resp, err := engine.HandleXpubRequestByDID(context.Background(), "did:key:zALICE")
	if err != nil {
		t.Fatalf("HandleXpubRequestByDID: %v", err)
	}
	// stubCounterpartyDirectory.GetOrAssignIndex always returns 1.
	wantXpub, err := ppcrypto.DeriveOtherPartyXpub(wallet, 1)
	if err != nil {
		t.Fatalf("DeriveOtherPartyXpub: %v", err)
	}
	if resp.Xpub != wantXpub {
		t.Errorf("xpub mismatch: got %q want %q", resp.Xpub, wantXpub)
	}
	if resp.OtherpartyId != 1 {
		t.Errorf("OtherpartyId: got %d want 1", resp.OtherpartyId)
	}
}

func TestHandleXpubRequestByDID_DifferentDIDsDifferentSlots(t *testing.T) {
	wallet := makeTestWallet(t)
	cpDir := &sequentialCounterpartyDirectory{}
	engine := NewConsentEngine(wallet, cpDir, &stubConsentStore{}, &stubMidTierClient{})

	resp1, err := engine.HandleXpubRequestByDID(context.Background(), "did:key:zALICE")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	resp2, err := engine.HandleXpubRequestByDID(context.Background(), "did:key:zBOB")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	if resp1.Xpub == resp2.Xpub {
		t.Error("different DIDs must produce different xpubs")
	}
	if resp1.OtherpartyId == resp2.OtherpartyId {
		t.Error("different DIDs must get different slot numbers")
	}
}

// ── stub implementations ──────────────────────────────────────────────────────

// stubWalletStore is an in-memory WalletStore for use in consent package tests only.
type stubWalletStore struct {
	key *bip32.Key
	err error
}

func (s *stubWalletStore) GetMasterKey() (*bip32.Key, error) {
	return s.key, s.err
}

// makeTestWallet returns a deterministic wallet backed by BIP-32 Test Vector 1.
func makeTestWallet(t *testing.T) *stubWalletStore {
	t.Helper()
	seed := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return &stubWalletStore{key: key}
}

// makeTestXpub derives the extended public key at m/4410704'/{otherPartyId} from
// the test wallet. Used in revoke tests that need a valid grantor xpub.
func makeTestXpub(t *testing.T, otherPartyId uint32) string {
	t.Helper()
	wallet := makeTestWallet(t)
	xpub, err := ppcrypto.DeriveOtherPartyXpub(wallet, otherPartyId)
	if err != nil {
		t.Fatalf("DeriveOtherPartyXpub(%d): %v", otherPartyId, err)
	}
	return xpub
}

type storeXpubCall struct {
	partyKey string
	xpub     string
}

type stubCounterpartyDirectory struct {
	xpub           string         // if non-empty, returned by GetXpub (found=true)
	counters       map[string]int // key: "partyKey:chainId", value: next consent number
	storeXpubCalls []storeXpubCall
	storeXpubErr   error
	mu             sync.Mutex
}

func (s *stubCounterpartyDirectory) GetOrAssignIndex(_ string) (int, error) { return 1, nil }
func (s *stubCounterpartyDirectory) GetXpub(_ string) (string, bool, error) {
	if s.xpub == "" {
		return "", false, nil
	}
	return s.xpub, true, nil
}
func (s *stubCounterpartyDirectory) StoreXpub(partyKey, xpub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storeXpubCalls = append(s.storeXpubCalls, storeXpubCall{partyKey: partyKey, xpub: xpub})
	return s.storeXpubErr
}
func (s *stubCounterpartyDirectory) NextConsentNo(partyKey string, chainId int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counters == nil {
		s.counters = make(map[string]int)
	}
	key := fmt.Sprintf("%s:%d", partyKey, chainId)
	n := s.counters[key]
	s.counters[key] = n + 1
	return n, nil
}

// sequentialCounterpartyDirectory assigns incrementing slots per unique DID.
type sequentialCounterpartyDirectory struct {
	mu      sync.Mutex
	slots   map[string]int
	nextIdx int
}

func (d *sequentialCounterpartyDirectory) GetOrAssignIndex(did string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.slots == nil {
		d.slots = make(map[string]int)
	}
	if idx, ok := d.slots[did]; ok {
		return idx, nil
	}
	d.nextIdx++
	d.slots[did] = d.nextIdx
	return d.nextIdx, nil
}
func (d *sequentialCounterpartyDirectory) GetXpub(_ string) (string, bool, error) { return "", false, nil }
func (d *sequentialCounterpartyDirectory) StoreXpub(_, _ string) error            { return nil }
func (d *sequentialCounterpartyDirectory) NextConsentNo(_ string, _ int) (int, error) {
	return 0, nil
}

type stubConsentStore struct {
	records       map[string]*ConsentRecord // pre-seeded records for Get
	lastSet       *ConsentRecord            // most recent Set call
	activeRecords []*ConsentRecord          // returned by FindActive
	findActiveErr error                     // error returned by FindActive
	cursor        string                    // value returned by GetSyncCursor
}

// setCursor pre-seeds the sync cursor for test setup.
func (s *stubConsentStore) setCursor(c string) { s.cursor = c }

func (s *stubConsentStore) Get(id string) (*ConsentRecord, error) {
	if s.records == nil {
		return nil, nil
	}
	r, ok := s.records[id]
	if !ok {
		return nil, nil
	}
	return r, nil
}
func (s *stubConsentStore) Set(r *ConsentRecord) error {
	s.lastSet = r
	if s.records == nil {
		s.records = make(map[string]*ConsentRecord)
	}
	s.records[r.ID] = r
	return nil
}
func (s *stubConsentStore) FindActive(_, _ string) ([]*ConsentRecord, error) {
	return s.activeRecords, s.findActiveErr
}
func (s *stubConsentStore) GetSyncCursor() (string, error) { return s.cursor, nil }
func (s *stubConsentStore) SetSyncCursor(c string) error   { s.cursor = c; return nil }

type stubMidTierClient struct {
	submitGrantCalled  bool
	submitRevokeCalled bool
	lastGrantRecord    *ConsentRecord
	lastRevoke         *RevokeRecord
	// GetConsentsSince config
	sinceEvents    []ConsentEvent
	sinceErr       error
	capturedXpub   string
	capturedCursor string
}

func (s *stubMidTierClient) SubmitGrant(_ context.Context, r ConsentRecord, _ string, _ map[string]any) error {
	s.submitGrantCalled = true
	s.lastGrantRecord = &r
	return nil
}
func (s *stubMidTierClient) SubmitRevoke(_ context.Context, r RevokeRecord, _ string, _ map[string]any) error {
	s.submitRevokeCalled = true
	s.lastRevoke = &r
	return nil
}
func (s *stubMidTierClient) GetConsentsSince(_ context.Context, xpub, cursor string) ([]ConsentEvent, error) {
	s.capturedXpub = xpub
	s.capturedCursor = cursor
	return s.sinceEvents, s.sinceErr
}
