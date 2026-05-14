package consent

import (
	"context"
	"errors"
	"testing"

	bip32 "github.com/jamesradley/go-bip32"
	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// ── RevokeConsent ─────────────────────────────────────────────────────────────

const testRevokeGrantCID = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"

// makeRevokeTestRecord builds a ConsentRecord with a fully populated Payload
// (including a valid NotaryKey2) and returns the grantor xpub to store in the
// counterparty directory stub.
//
// The engine wallet is BIP-32 Test Vector 1 (seed 0x00..0x0f).  The grantor
// xpub is derived from the same wallet at otherPartyId=0 (because the stub
// always returns index 0).  The notary key is derived from the wallet at
// otherPartyId=1 to produce a distinct, realistic compressed public key.
func makeRevokeTestRecord(t *testing.T) (*ConsentRecord, string) {
	t.Helper()
	wallet := makeTestWallet(t)

	// Derive a mock mid-tier notary public key (purpose 4, chain 1, consent 1).
	notaryXpub, err := ppcrypto.DeriveOtherPartyXpub(wallet, 1)
	if err != nil {
		t.Fatalf("DeriveOtherPartyXpub(notary): %v", err)
	}
	notaryParent, err := bip32.B58Deserialize(notaryXpub)
	if err != nil {
		t.Fatalf("B58Deserialize(notary): %v", err)
	}
	notaryPub, err := ppcrypto.DerivePublicKeyFromParent(notaryParent, 1, 1, purposes.PulsePurposeEncryptRevokeNotaryBlock)
	if err != nil {
		t.Fatalf("DerivePublicKeyFromParent(notary): %v", err)
	}

	record := &ConsentRecord{
		ID:        "c1",
		PartyKey:  "did:web:bank.example",
		Status:    ConsentStatusActive,
		ConsentNo: 1,
		ChainID:   1,
		CID:       testRevokeGrantCID,
		Payload: &feedpermission.FeedPermissionPayload{
			CounterpartyDid: "did:web:grantee.example",
			NotaryKey2:      notaryPub.SerializeCompressed(),
		},
	}

	// Grantor xpub: cpDir stub returns index 0, so we use otherPartyId=0.
	grantorXpub := makeTestXpub(t, 0)
	return record, grantorXpub
}

func TestRevokeConsent_ActiveRecord_SubmitsRevoke(t *testing.T) {
	record, grantorXpub := makeRevokeTestRecord(t)
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, mt,
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mt.submitRevokeCalled {
		t.Fatal("MidTierClient.SubmitRevoke was not called")
	}
	if mt.lastRevoke.ConsentID != "c1" {
		t.Errorf("RevokeRecord.ConsentID: got %q, want c1", mt.lastRevoke.ConsentID)
	}
	if mt.lastRevoke.PartyKey != record.PartyKey {
		t.Errorf("RevokeRecord.PartyKey: got %q, want %q", mt.lastRevoke.PartyKey, record.PartyKey)
	}
	if mt.lastRevoke.GrantCID != testRevokeGrantCID {
		t.Errorf("RevokeRecord.GrantCID: got %q, want %q", mt.lastRevoke.GrantCID, testRevokeGrantCID)
	}
}

func TestRevokeConsent_PendingRecord_Allowed(t *testing.T) {
	record, grantorXpub := makeRevokeTestRecord(t)
	record.Status = ConsentStatusPending
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, mt,
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mt.submitRevokeCalled {
		t.Fatal("MidTierClient.SubmitRevoke was not called for pending record")
	}
}

func TestRevokeConsent_SealedBytesNonEmpty(t *testing.T) {
	// The RevokeRecord must carry SealedBytes (the encrypted revoke CBOR) so that
	// mid-tier can pin it to IPFS.
	record, grantorXpub := makeRevokeTestRecord(t)
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, mt,
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mt.lastRevoke.SealedBytes) == 0 {
		t.Error("RevokeRecord.SealedBytes should not be empty")
	}
}

func TestRevokeConsent_SignatureNonEmpty(t *testing.T) {
	record, grantorXpub := makeRevokeTestRecord(t)
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	mt := &stubMidTierClient{}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, mt,
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mt.lastRevoke.Signature) == 0 {
		t.Error("RevokeRecord.Signature should not be empty")
	}
}

func TestRevokeConsent_StatusUnchangedAfterCall(t *testing.T) {
	// RevokeConsent does not change the record status — the rev_confirmed callback
	// is responsible for driving the transition to ConsentStatusRevoked.
	record, grantorXpub := makeRevokeTestRecord(t)
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.lastSet != nil {
		t.Errorf("ConsentStore.Set should not be called by RevokeConsent, but got status %q", store.lastSet.Status)
	}
}

func TestRevokeConsent_MissingXpub_Errors(t *testing.T) {
	// Hard fail: the grantor's xpub must be present in the counterparty directory.
	record, _ := makeRevokeTestRecord(t)
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	cpDir := &stubCounterpartyDirectory{} // no xpub stored

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err == nil {
		t.Fatal("expected error when xpub is missing, got nil")
	}
}

func TestRevokeConsent_MissingPayload_Errors(t *testing.T) {
	// Hard fail: the record must have a decrypted Payload (for the notary key).
	record, grantorXpub := makeRevokeTestRecord(t)
	record.Payload = nil
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}

	engine := NewConsentEngine(makeTestWallet(t), cpDir, store, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)

	if err := engine.RevokeConsent(context.Background(), "c1"); err == nil {
		t.Fatal("expected error when payload is nil, got nil")
	}
}

func TestRevokeConsent_NotFound_Errors(t *testing.T) {
	store := &stubConsentStore{records: map[string]*ConsentRecord{}}
	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	if err := engine.RevokeConsent(context.Background(), "missing"); err == nil {
		t.Fatal("expected error for missing consent ID")
	}
}

func TestRevokeConsent_AlreadyRevoked_Errors(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusRevoked, CID: testRevokeGrantCID}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	if err := engine.RevokeConsent(context.Background(), "c1"); err == nil {
		t.Fatal("expected error: cannot revoke an already-revoked consent")
	}
}

func TestRevokeConsent_PendingReview_Errors(t *testing.T) {
	record := &ConsentRecord{ID: "c1", Status: ConsentStatusPendingReview, CID: testRevokeGrantCID}
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	engine := NewConsentEngine(makeTestWallet(t), &stubCounterpartyDirectory{}, store, &stubMidTierClient{})

	if err := engine.RevokeConsent(context.Background(), "c1"); err == nil {
		t.Fatal("expected error: pending-review consents should be rejected, not revoked")
	}
}

func TestRevokeConsent_WalletError_Propagates(t *testing.T) {
	walletErr := errors.New("key unavailable")
	record, grantorXpub := makeRevokeTestRecord(t)
	store := &stubConsentStore{records: map[string]*ConsentRecord{"c1": record}}
	cpDir := &stubCounterpartyDirectory{xpub: grantorXpub}
	engine := NewConsentEngine(&stubWalletStore{err: walletErr}, cpDir, store, &stubMidTierClient{},
		WithContractAddress(testContractAddress),
	)

	err := engine.RevokeConsent(context.Background(), "c1")
	if !errors.Is(err, walletErr) {
		t.Fatalf("expected walletErr, got %v", err)
	}
}
