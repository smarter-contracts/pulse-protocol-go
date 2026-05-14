package consent

import (
	"context"
	"errors"
	"testing"
	"time"

	bip32 "github.com/jamesradley/go-bip32"
	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// testContractAddress is a fixed Ethereum-style address used across all inbound tests.
const testContractAddress = "0x0102030405060708090a0b0c0d0e0f1011121314"

// inboundTestSenderSeed is a fixed 16-byte seed for the sender (counterparty) wallet
// used in sealPayload — distinct from the engine wallet's BIP-32 Test Vector 1 seed.
var inboundTestSenderSeed = []byte{
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// ── helpers ───────────────────────────────────────────────────────────────────

// sealPayload encrypts payload to the engine wallet's consent structure key and
// returns an InboundConsentRequest suitable for HandleInboundConsent.
//
// The engine's cpDir stub always returns otherpartyId=1, so the engine decrypts
// using the key at m/4410704'/1/{chainId}/{consentNo}/3.  A fixed sender wallet
// (inboundTestSenderSeed) is used to keep tests deterministic.
func sealPayload(t *testing.T, payload *feedpermission.FeedPermissionPayload, engineWallet *stubWalletStore) InboundConsentRequest {
	t.Helper()

	cbor, err := ipfs.MarshalFeedPermission(payload)
	if err != nil {
		t.Fatalf("MarshalFeedPermission: %v", err)
	}

	// Derive the engine's consent structure encryption public key.
	// Path: m/4410704'/1/{chainId}/{consentNo}/3 (otherpartyId=1, chainId=1).
	engineXpub, err := ppcrypto.DeriveOtherPartyXpub(engineWallet, 1)
	if err != nil {
		t.Fatalf("DeriveOtherPartyXpub: %v", err)
	}
	engineParent, err := bip32.B58Deserialize(engineXpub)
	if err != nil {
		t.Fatalf("B58Deserialize: %v", err)
	}
	enginePub, err := ppcrypto.DerivePublicKeyFromParent(engineParent, 1, uint32(payload.ConsentNo), purposes.PulsePurposeEncryptConsentStructure)
	if err != nil {
		t.Fatalf("DerivePublicKeyFromParent: %v", err)
	}

	// Sender wallet uses a distinct fixed seed so encryption is deterministic but
	// produces a different key pair from the engine wallet.
	senderKey, err := bip32.NewMasterKey(inboundTestSenderSeed)
	if err != nil {
		t.Fatalf("NewMasterKey(sender): %v", err)
	}
	senderWallet := &stubWalletStore{key: senderKey}

	// Encrypt with purpose 3 (EncryptConsentStructure) from sender to engine.
	// otherPartyNo=1 is arbitrary — it only affects the sender's derivation path.
	consentReq, err := ppcrypto.EncryptSignConsentEC(senderWallet, cbor, 1, uint32(payload.ConsentNo), enginePub, testContractAddress, 1)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC: %v", err)
	}

	return InboundConsentRequest{
		PartyKey:   payload.CounterpartyDid,
		ChainID:    1,
		ConsentNo:  int(payload.ConsentNo),
		SealedData: consentReq.EncryptedData.SealedData,
		Key1:       consentReq.EncryptedData.Key1,
		Key2:       consentReq.EncryptedData.Key2,
	}
}

func validPayload() *feedpermission.FeedPermissionPayload {
	return &feedpermission.FeedPermissionPayload{
		ConsentNo:        1,
		WalletId:         "wlt_test",
		GrantorWebId:     "https://pod.example/alice#me",
		CounterpartyDid:  "did:web:bank.example",
		FeedType:         "open-banking",
		PodContainerPath: "pulse/feeds/open-banking/",
		Permissions:      []string{"read"},
		DataCategories:   []string{"transaction-history"},
		IssuedAt:         time.Now().Unix(),
		ExpiresAt:        0,
	}
}

// ── HandleInboundConsent ──────────────────────────────────────────────────────

func TestHandleInboundConsent_AcceptPath(t *testing.T) {
	engineWallet := makeTestWallet(t)
	payload := validPayload()

	store := &stubConsentStore{}
	mt := &stubMidTierClient{}
	engine := NewConsentEngine(engineWallet, &stubCounterpartyDirectory{}, store, mt, WithContractAddress(testContractAddress))
	req := sealPayload(t, payload, engineWallet)

	resp, err := engine.HandleInboundConsent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != ReviewDecisionAccept {
		t.Errorf("decision: got %q, want Accept", resp.Decision)
	}
	if resp.ConsentID == "" {
		t.Error("ConsentID should be non-empty")
	}

	// Record stored with pending status.
	if store.lastSet == nil {
		t.Fatal("ConsentStore.Set was not called")
	}
	if store.lastSet.Status != ConsentStatusPending {
		t.Errorf("stored status: got %q, want pending", store.lastSet.Status)
	}

	// Mid-tier was notified.
	if !mt.submitGrantCalled {
		t.Error("MidTierClient.SubmitGrant was not called on Accept")
	}
}

func TestHandleInboundConsent_RejectPath(t *testing.T) {
	engineWallet := makeTestWallet(t)
	payload := validPayload()

	store := &stubConsentStore{}
	mt := &stubMidTierClient{}
	engine := NewConsentEngine(
		engineWallet,
		&stubCounterpartyDirectory{},
		store, mt,
		WithContractAddress(testContractAddress),
		WithReviewer(&stubReviewer{decision: ReviewDecisionReject}),
	)
	req := sealPayload(t, payload, engineWallet)

	resp, err := engine.HandleInboundConsent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != ReviewDecisionReject {
		t.Errorf("decision: got %q, want Reject", resp.Decision)
	}
	if store.lastSet == nil {
		t.Fatal("ConsentStore.Set was not called")
	}
	if store.lastSet.Status != ConsentStatusRejected {
		t.Errorf("stored status: got %q, want rejected", store.lastSet.Status)
	}
	if mt.submitGrantCalled {
		t.Error("MidTierClient.SubmitGrant must NOT be called on Reject")
	}
}

func TestHandleInboundConsent_DeferPath(t *testing.T) {
	engineWallet := makeTestWallet(t)
	payload := validPayload()

	store := &stubConsentStore{}
	mt := &stubMidTierClient{}
	engine := NewConsentEngine(
		engineWallet,
		&stubCounterpartyDirectory{},
		store, mt,
		WithContractAddress(testContractAddress),
		WithReviewer(&stubReviewer{decision: ReviewDecisionDefer}),
	)
	req := sealPayload(t, payload, engineWallet)

	resp, err := engine.HandleInboundConsent(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != ReviewDecisionDefer {
		t.Errorf("decision: got %q, want Defer", resp.Decision)
	}
	if store.lastSet.Status != ConsentStatusPendingReview {
		t.Errorf("stored status: got %q, want pending-review", store.lastSet.Status)
	}
	if mt.submitGrantCalled {
		t.Error("MidTierClient.SubmitGrant must NOT be called on Defer")
	}
}

func TestHandleInboundConsent_ExpiredPayload_Errors(t *testing.T) {
	engineWallet := makeTestWallet(t)
	payload := validPayload()
	payload.ExpiresAt = time.Now().Add(-time.Hour).Unix() // expired

	engine := NewConsentEngine(
		engineWallet,
		&stubCounterpartyDirectory{},
		&stubConsentStore{}, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)
	req := sealPayload(t, payload, engineWallet)

	_, err := engine.HandleInboundConsent(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired payload, got nil")
	}
}

func TestHandleInboundConsent_InvalidSealedData_Errors(t *testing.T) {
	engineWallet := makeTestWallet(t)
	engine := NewConsentEngine(
		engineWallet,
		&stubCounterpartyDirectory{},
		&stubConsentStore{}, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)
	req := InboundConsentRequest{
		PartyKey:   "did:web:bank.example",
		ChainID:    1,
		ConsentNo:  1,
		SealedData: []byte("garbage"),
		Key1:       make([]byte, 33), // not a valid secp256k1 pubkey
		Key2:       make([]byte, 33),
	}

	_, err := engine.HandleInboundConsent(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid sealed data, got nil")
	}
}

func TestHandleInboundConsent_WalletStoreError_Propagates(t *testing.T) {
	walletErr := errors.New("key unavailable")
	engine := NewConsentEngine(
		&stubWalletStore{err: walletErr},
		&stubCounterpartyDirectory{},
		&stubConsentStore{}, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)
	req := InboundConsentRequest{PartyKey: "did:web:x", ChainID: 1, ConsentNo: 1}

	_, err := engine.HandleInboundConsent(context.Background(), req)
	if !errors.Is(err, walletErr) {
		t.Fatalf("expected walletErr, got %v", err)
	}
}

func TestHandleInboundConsent_StoredRecord_HasPayloadAndSealedBytes(t *testing.T) {
	engineWallet := makeTestWallet(t)
	payload := validPayload()

	store := &stubConsentStore{}
	engine := NewConsentEngine(
		engineWallet,
		&stubCounterpartyDirectory{},
		store, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)
	req := sealPayload(t, payload, engineWallet)
	_, _ = engine.HandleInboundConsent(context.Background(), req)

	if store.lastSet.Payload == nil {
		t.Error("stored record Payload should not be nil")
	}
	if store.lastSet.Payload.FeedType != payload.FeedType {
		t.Errorf("FeedType: got %q, want %q", store.lastSet.Payload.FeedType, payload.FeedType)
	}
	if len(store.lastSet.SealedBytes) == 0 {
		t.Error("stored record SealedBytes should not be empty")
	}
}

// ── ApproveConsent ────────────────────────────────────────────────────────────

func TestApproveConsent_PendingReview_SubmitsGrant(t *testing.T) {
	record := &ConsentRecord{
		ID:       "c1",
		Status:   ConsentStatusPendingReview,
		PartyKey: "did:web:bank.example",
		FeedType: "open-banking",
	}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{}

	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, mt)
	if err := engine.ApproveConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusPending {
		t.Errorf("status after approval: got %q, want pending", store.lastSet.Status)
	}
	if !mt.submitGrantCalled {
		t.Error("MidTierClient.SubmitGrant should be called on approval")
	}
}

func TestApproveConsent_NotFound_Errors(t *testing.T) {
	engine := NewConsentEngine(
		&stubWalletStore{}, &stubCounterpartyDirectory{},
		&stubConsentStore{records: map[string]*ConsentRecord{}},
		&stubMidTierClient{},
	)
	err := engine.ApproveConsent(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing consent ID")
	}
}

func TestApproveConsent_WrongStatus_Errors(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusActive}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	err := engine.ApproveConsent(context.Background(), "c1")
	if err == nil {
		t.Fatal("expected error: can only approve pending-review records")
	}
}

// ── RejectConsent ─────────────────────────────────────────────────────────────

func TestRejectConsent_PendingReview_SetsRejected(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPendingReview}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{}

	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, mt)
	if err := engine.RejectConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.lastSet.Status != ConsentStatusRejected {
		t.Errorf("status after rejection: got %q, want rejected", store.lastSet.Status)
	}
	if mt.submitGrantCalled {
		t.Error("MidTierClient.SubmitGrant must NOT be called on rejection")
	}
}

func TestRejectConsent_NotFound_Errors(t *testing.T) {
	engine := NewConsentEngine(
		&stubWalletStore{}, &stubCounterpartyDirectory{},
		&stubConsentStore{records: map[string]*ConsentRecord{}},
		&stubMidTierClient{},
	)
	if err := engine.RejectConsent(context.Background(), "missing"); err == nil {
		t.Fatal("expected error for missing consent ID")
	}
}

func TestRejectConsent_WrongStatus_Errors(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPending}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	engine := NewConsentEngine(&stubWalletStore{}, &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	if err := engine.RejectConsent(context.Background(), "c1"); err == nil {
		t.Fatal("expected error: can only reject pending-review records")
	}
}
