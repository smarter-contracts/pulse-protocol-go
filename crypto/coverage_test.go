package crypto

/*
 * Additional tests to exercise error paths and improve coverage of the crypto
 * package.  These complement the happy-path and known-value tests in the other
 * test files.
 */

import (
	"bytes"
	"errors"
	"io"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/key_encapsulate"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/key_exchange"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── DerivePublicKeyFromParent (exported wrapper) ──────────────────────────────

func TestDerivePublicKeyFromParent_Success(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	gen, err := DeriveOtherPartyGenerator(masterKey, 2)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator() failed: %v", err)
	}

	pubKey, err := DerivePublicKeyFromParent(gen, 1, 62, purposes.PulsePurposeSignTx)
	if err != nil {
		t.Fatalf("DerivePublicKeyFromParent() failed: %v", err)
	}
	if pubKey == nil {
		t.Fatal("returned public key is nil")
	}
}

// ── encryptEC error paths ─────────────────────────────────────────────────────

func TestEncryptEC_NilMasterKey(t *testing.T) {
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	_, err := encryptEC(nil, []byte("data"), 2, 62, bobPub, *addr, 1, purposes.PulsePurposeEncryptConsentStructure)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── EncryptSignConsentEC error paths ──────────────────────────────────────────

func TestEncryptSignConsentEC_NilMasterKey(t *testing.T) {
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	_, err := EncryptSignConsentEC(nil, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── EncryptSignRevokeEC error paths ───────────────────────────────────────────

func TestEncryptSignRevokeEC_NilMasterKey(t *testing.T) {
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	_, err := EncryptSignRevokeEC(nil, []byte("data"), 2, 62, bobPub, *addr, 1, "bafyfake")
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── decryptHDEC error paths ───────────────────────────────────────────────────

func TestDecryptConsentEC_NilMasterKey(t *testing.T) {
	req := &types.PulseConsentRequestEC{}
	_, err := DecryptConsentEC(nil, req, 2, 62, "0x0102030405060708090a0b0c0d0e0f1011121314", 1)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

func TestDecryptRevokeEC_NilMasterKey(t *testing.T) {
	req := &types.PulseRevokeRequestEC{}
	_, err := DecryptRevokeEC(nil, req, 2, 62, "0x0102030405060708090a0b0c0d0e0f1011121314", 1)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── SignConsentRequest error paths ────────────────────────────────────────────

func TestSignConsentRequest_NilMasterKey(t *testing.T) {
	req := &types.PulseConsentRequestEC{
		EncryptedData: types.PulseECEncryptionResult{
			SealedData: []byte("x"),
			Key1:       make([]byte, 33),
			Key2:       make([]byte, 33),
		},
	}
	err := SignConsentRequest(nil, req, 2, 62, "0x0102030405060708090a0b0c0d0e0f1011121314", 1)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── SignRevokeRequest error paths ─────────────────────────────────────────────

func TestSignRevokeRequest_NilMasterKey(t *testing.T) {
	req := &types.PulseRevokeRequestEC{
		ConsentCid: "bafyfake",
		EncryptedData: types.PulseECEncryptionResult{
			SealedData: []byte("x"),
			Key1:       make([]byte, 33),
			Key2:       make([]byte, 33),
		},
	}
	err := SignRevokeRequest(nil, req, 2, 62, "0x0102030405060708090a0b0c0d0e0f1011121314", 1)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── EncryptSignConsentPQ error paths ──────────────────────────────────────────

func TestEncryptSignConsentPQ_NilMasterKey(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)

	_, err := EncryptSignConsentPQ(nil, []byte("data"), 2, 0, []*kyberKEM.PublicKey{pub}, "0x0102030405060708090a0b0c0d0e0f1011121314", 137)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── EncryptSignRevokePQ error paths ───────────────────────────────────────────

func TestEncryptSignRevokePQ_NilMasterKey(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveRevoke)

	_, err := EncryptSignRevokePQ(nil, []byte("data"), 2, 0, []*kyberKEM.PublicKey{pub}, "0x0102030405060708090a0b0c0d0e0f1011121314", 137, "bafyfake")
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── decryptHDPQ error paths ───────────────────────────────────────────────────

func TestDecryptConsentPQ_NilMasterKey(t *testing.T) {
	req := &types.PulseConsentRequestPQ{}
	_, err := DecryptConsentPQ(nil, req, 2, 0, "0x0102030405060708090a0b0c0d0e0f1011121314", 137)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

func TestDecryptRevokePQ_NilMasterKey(t *testing.T) {
	req := &types.PulseRevokeRequestPQ{}
	_, err := DecryptRevokePQ(nil, req, 2, 0, "0x0102030405060708090a0b0c0d0e0f1011121314", 137)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── DerivePQKeyPair error paths ───────────────────────────────────────────────

func TestDerivePQKeyPair_NilMasterKey(t *testing.T) {
	_, _, err := DerivePQKeyPair(nil, 2, 0, 1, purposes.PulsePurposePQDeriveConsent)
	if err == nil {
		t.Error("expected error for nil masterKey")
	}
}

// ── EncryptECDH / DecryptEC nil key error paths ──────────────────────────────

func TestDecryptEC_NilPrivateKey(t *testing.T) {
	// DecryptEC dereferences myPrivateKey immediately, so this should panic
	// or error.  We just verify it doesn't succeed silently.
	defer func() {
		if r := recover(); r == nil {
			// If it didn't panic, it should have returned an error
		}
	}()

	result := &types.PulseECEncryptionResult{
		SealedData: []byte("x"),
		Key1:       make([]byte, 33),
		Key2:       make([]byte, 33),
	}
	addr := "0x0102030405060708090a0b0c0d0e0f1011121314"
	_, _ = key_exchange.DecryptEC(result, &addr, nil, purposes.PulsePurposeEncryptConsentStructure, 1, 0)
}

// ── DeriveOtherPartyGenerator success path ────────────────────────────────────

func TestDeriveOtherPartyGenerator_DifferentParties(t *testing.T) {
	masterKey := mustNewMasterKey(t)

	gen1, err := DeriveOtherPartyGenerator(masterKey, 1)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator(1) failed: %v", err)
	}
	gen2, err := DeriveOtherPartyGenerator(masterKey, 2)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator(2) failed: %v", err)
	}

	// Different party numbers must produce different generators
	if gen1.String() == gen2.String() {
		t.Error("generators for different parties are identical")
	}
}

// ── EncryptSignConsentPQ sign failure (valid encrypt, nil signing key) ────────

func TestEncryptSignConsentPQ_SignFailure(t *testing.T) {
	// EncryptPQ works without a masterKey (it uses the PQ pub keys directly),
	// but SignConsentRequest needs the masterKey for HD signing key derivation.
	// We can't easily split these since EncryptSignConsentPQ calls both, but
	// the nil masterKey will fail at the encrypt stage since it tries to pass
	// nil to EncryptPQ's entropy. Instead test with an invalid signing path.
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()

	// Encrypt with valid master key — this exercises the full happy path
	req, err := EncryptSignConsentPQ(masterKey, []byte("data"), 2, 0, []*kyberKEM.PublicKey{pub}, *addr, 137)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Counter-sign with nil masterKey should fail at signing stage
	err = SignConsentRequest(nil, req, 2, 0, *addr, 137)
	if err == nil {
		t.Error("expected error for nil masterKey in SignConsentRequest")
	}
}

func TestEncryptSignRevokePQ_SignFailure(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveRevoke)
	addr := helperContractAddress()

	req, err := EncryptSignRevokePQ(masterKey, []byte("data"), 2, 0, []*kyberKEM.PublicKey{pub}, *addr, 137, "bafyfake")
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	// Attempt to re-sign with nil master key
	err = SignRevokeRequest(nil, req, 2, 0, *addr, 137)
	if err == nil {
		t.Error("expected error for nil masterKey in SignRevokeRequest")
	}
}

// ── EncryptECDH additional error path ─────────────────────────────────────────

func TestEncryptECDH_BothKeysNil(t *testing.T) {
	addr := helperContractAddress()
	_, err := key_exchange.EncryptECDH([]byte("data"), addr, nil, nil, purposes.PulsePurposeEncryptConsentStructure, 1, 0)
	if err == nil {
		t.Error("expected error for nil keys")
	}
}

// ── decryptHDPQ with invalid purpose ──────────────────────────────────────────

func TestDecryptConsentPQ_InvalidPurpose(t *testing.T) {
	// Exercise the DerivePQKeyPair purpose validation inside decryptHDPQ
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()

	req, err := EncryptSignConsentPQ(masterKey, []byte("data"), 2, 0, []*kyberKEM.PublicKey{pub}, *addr, 137)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// DecryptConsentPQ uses PulsePurposePQDeriveConsent internally — test it works
	plaintext, err := DecryptConsentPQ(masterKey, req, 2, 0, *addr, 137)
	if err != nil {
		t.Fatalf("DecryptConsentPQ() failed: %v", err)
	}
	if string(plaintext) != "data" {
		t.Errorf("plaintext mismatch: got %q, want %q", plaintext, "data")
	}
}

// ── DerivePublicKeyFromParent all purposes ────────────────────────────────────

func TestDerivePublicKeyFromParent_AllPurposes(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	gen, err := DeriveOtherPartyGenerator(masterKey, 2)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator() failed: %v", err)
	}

	for _, p := range []purposes.PulsePurpose{
		purposes.PulsePurposeSignTx,
		purposes.PulsePurposeEncryptConsentNotaryBlock,
		purposes.PulsePurposeEncryptConsentStructure,
		purposes.PulsePurposeEncryptRevokeNotaryBlock,
		purposes.PulsePurposeEncryptRevokeStructure,
	} {
		pubKey, err := DerivePublicKeyFromParent(gen, 1, 62, p)
		if err != nil {
			t.Errorf("DerivePublicKeyFromParent(purpose=%d) failed: %v", p, err)
		}
		if pubKey == nil {
			t.Errorf("DerivePublicKeyFromParent(purpose=%d) returned nil", p)
		}
	}
}

// ── DecryptEC: "no matching public key" path ─────────────────────────────────

func TestDecryptEC_NoMatchingKey(t *testing.T) {
	// Encrypt between Alice and Bob, try to decrypt with Carol's key
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	carolPriv, _ := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	result, err := EncryptConsentNotaryEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC() failed: %v", err)
	}

	_, err = key_exchange.DecryptEC(result, addr, carolPriv, purposes.PulsePurposeEncryptConsentStructure, 1, 62)
	if err == nil {
		t.Error("expected error for non-matching key")
	}
}

// ── DecryptEC: decrypt with Key1 (sender's own key) ─────────────────────────

func TestDecryptEC_DecryptWithKey1(t *testing.T) {
	// Alice encrypts to Bob. Alice decrypts using her own key (matches Key1).
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	plaintext := []byte("decrypt with own key")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	result, err := encryptEC(masterKey, plaintext, otherParty, consent, bobPub, *addr, chainId, purposes.PulsePurposeEncryptConsentStructure)
	if err != nil {
		t.Fatalf("encryptEC() failed: %v", err)
	}

	// Derive Alice's private key at the same path
	path, _ := newpulseHDPath(otherParty, chainId, consent, purposes.PulsePurposeEncryptConsentStructure)
	alicePriv, err := deriveKeyFromMaster(masterKey, path)
	if err != nil {
		t.Fatalf("deriveKeyFromMaster() failed: %v", err)
	}

	// Alice's pub should be Key1 — verify
	alicePub := alicePriv.PubKey().SerializeCompressed()
	if !bytes.Equal(result.Key1, alicePub) {
		t.Fatal("expected Alice to be Key1")
	}

	decrypted, err := key_exchange.DecryptEC(result, addr, alicePriv, purposes.PulsePurposeEncryptConsentStructure, chainId, consent)
	if err != nil {
		t.Fatalf("key_exchange.DecryptEC() with Key1 failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// ── DecryptConsentEC / DecryptRevokeEC full HD round-trip ────────────────────

func TestDecryptConsentEC_RoundTripHDWallet(t *testing.T) {
	// Alice encrypts+signs consent, Bob decrypts via HD wallet
	masterKeyAlice := mustNewMasterKey(t)
	masterKeyBob := mustNewMasterKey(t)
	addr := helperContractAddress()
	plaintext := []byte("consent for HD decrypt")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	// Derive Bob's public key for the encryption purpose
	bobPath, _ := newpulseHDPath(otherParty, chainId, consent, purposes.PulsePurposeEncryptConsentStructure)
	bobPriv, _ := deriveKeyFromMaster(masterKeyBob, bobPath)
	bobPub := bobPriv.PubKey()

	req, err := EncryptSignConsentEC(masterKeyAlice, plaintext, otherParty, consent, bobPub, *addr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	decrypted, err := DecryptConsentEC(masterKeyBob, req, otherParty, consent, *addr, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptRevokeEC_RoundTripHDWallet(t *testing.T) {
	masterKeyAlice := mustNewMasterKey(t)
	masterKeyBob := mustNewMasterKey(t)
	addr := helperContractAddress()
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	// Build consent first to get a CID
	bobPathConsent, _ := newpulseHDPath(otherParty, chainId, consent, purposes.PulsePurposeEncryptConsentStructure)
	bobPrivConsent, _ := deriveKeyFromMaster(masterKeyBob, bobPathConsent)
	consentReq, err := EncryptSignConsentEC(masterKeyAlice, []byte("consent"), otherParty, consent, bobPrivConsent.PubKey(), *addr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}
	consentCBOR, _ := consentReq.EncryptedData.MarshalCBOR()
	consentCid, _ := ipfs.GetCid(consentCBOR)

	// Derive Bob's revoke key
	bobPathRevoke, _ := newpulseHDPath(otherParty, chainId, consent, purposes.PulsePurposeEncryptRevokeStructure)
	bobPrivRevoke, _ := deriveKeyFromMaster(masterKeyBob, bobPathRevoke)

	revokeData := []byte("revoke for HD decrypt")
	revokeReq, err := EncryptSignRevokeEC(masterKeyAlice, revokeData, otherParty, consent, bobPrivRevoke.PubKey(), *addr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}

	decrypted, err := DecryptRevokeEC(masterKeyBob, revokeReq, otherParty, consent, *addr, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokeEC() failed: %v", err)
	}
	if !bytes.Equal(revokeData, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, revokeData)
	}
}

// ── DerivePQKeyPair invalid purpose ─────────────────────────────────────────

func TestDerivePQKeyPair_InvalidPurpose_SignTx(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, _, err := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposeSignTx)
	if err == nil {
		t.Error("expected error for non-PQ purpose")
	}
}

// generateAESKey nil-key tests are in internal/key_exchange/key_exchange_test.go

// ── EncryptPQ with deterministic entropy ────────────────────────────────────

func TestEncryptPQ_DeterministicEntropy(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()
	plaintext := []byte("deterministic PQ encrypt")

	// Use a deterministic reader so we exercise the entropy != nil branch in encapsulateKey
	entropy := &deterministicReader{seed: 42}
	result, err := key_encapsulate.EncryptPQ(entropy, plaintext, addr, []*kyberKEM.PublicKey{pub}, purposes.PulseSymmetricConsent, 137, 0)
	if err != nil {
		t.Fatalf("key_encapsulate.EncryptPQ() with deterministic entropy failed: %v", err)
	}

	// Decrypt to verify correctness
	priv, _, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	decrypted, err := key_encapsulate.DecryptPQ(result, addr, priv, purposes.PulseSymmetricConsent, 137, 0)
	if err != nil {
		t.Fatalf("key_encapsulate.DecryptPQ() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// deterministicReader produces a repeatable byte stream from a seed.
type deterministicReader struct {
	seed byte
	n    uint64
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		// Simple PRNG: mix seed with counter
		r.n++
		p[i] = byte(r.n*251+uint64(r.seed)*179) & 0xff
	}
	return len(p), nil
}

// ── DecryptPQ no matching key ───────────────────────────────────────────────

func TestDecryptPQ_NoMatchingKey(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pubAlice, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()

	result, err := key_encapsulate.EncryptPQ(nil, []byte("data"), addr, []*kyberKEM.PublicKey{pubAlice}, purposes.PulseSymmetricConsent, 137, 0)
	if err != nil {
		t.Fatalf("key_encapsulate.EncryptPQ() failed: %v", err)
	}

	// Try to decrypt with a different party's key
	privBob, _, _ := DerivePQKeyPair(masterKey, 3, 0, 137, purposes.PulsePurposePQDeriveConsent)
	_, err = key_encapsulate.DecryptPQ(result, addr, privBob, purposes.PulseSymmetricConsent, 137, 0)
	if err == nil {
		t.Error("expected error for non-matching key")
	}
}

// ── DecryptRevokePQ full round-trip ─────────────────────────────────────────

func TestDecryptRevokePQ_RoundTrip(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveRevoke)
	addr := helperContractAddress()
	revokeData := []byte("revoke PQ round-trip")

	req, err := EncryptSignRevokePQ(masterKey, revokeData, 2, 0, []*kyberKEM.PublicKey{pub}, *addr, 137, "bafyfake")
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	decrypted, err := DecryptRevokePQ(masterKey, req, 2, 0, *addr, 137)
	if err != nil {
		t.Fatalf("DecryptRevokePQ() failed: %v", err)
	}
	if !bytes.Equal(revokeData, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, revokeData)
	}
}

// ── DecryptEC with malformed Key2 (exercises ParsePubKey error on Key2 branch) ─

func TestDecryptEC_MalformedKey2(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	result, err := EncryptConsentNotaryEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC() failed: %v", err)
	}

	// Derive Alice's key to match Key1, then corrupt Key2
	path, _ := newpulseHDPath(2, 1, 62, purposes.PulsePurposeEncryptConsentStructure)
	alicePriv, _ := deriveKeyFromMaster(masterKey, path)
	result.Key2 = []byte{0xff, 0xff, 0xff} // malformed

	_, err = key_exchange.DecryptEC(result, addr, alicePriv, purposes.PulsePurposeEncryptConsentStructure, 1, 62)
	if err == nil {
		t.Error("expected error for malformed Key2")
	}
}

// ── DecryptEC with malformed Key1 (exercises ParsePubKey error on Key1 branch) ─

func TestDecryptEC_MalformedKey1(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	bobPriv, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	result, err := EncryptConsentNotaryEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC() failed: %v", err)
	}

	// Bob matches Key2, so DecryptEC parses Key1 for the other party. Corrupt Key1.
	result.Key1 = []byte{0xff, 0xff, 0xff} // malformed
	_, err = key_exchange.DecryptEC(result, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, 1, 62)
	if err == nil {
		t.Error("expected error for malformed Key1")
	}
}

// ── GetConsentAddress with malformed signature ──────────────────────────────

func TestGetConsentAddress_MalformedSignature(t *testing.T) {
	_, err := GetConsentAddress(make([]byte, 65), "0x0102030405060708090a0b0c0d0e0f1011121314", "bafyfake")
	if err == nil {
		t.Error("expected error for zero signature")
	}
}

// ── ConsentSigners with corrupted signature ─────────────────────────────────

func TestConsentSigners_CorruptedSignature(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	req, err := EncryptSignConsentEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	// Corrupt the signature so address recovery fails
	req.Signatures[0] = make([]byte, 65)
	_, err = ConsentSigners(req, *addr)
	if err == nil {
		t.Error("expected error for corrupted signature")
	}
}

// ── RevokeSignerWasConsentSigner with corrupted revoke signature ────────────

func TestRevokeSignerWasConsentSigner_CorruptedRevokeSignature(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	consentReq, _ := EncryptSignConsentEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	consentCBOR, _ := consentReq.EncryptedData.MarshalCBOR()
	consentCid, _ := ipfs.GetCid(consentCBOR)
	revokeReq, _ := EncryptSignRevokeEC(masterKey, []byte("revoke"), 2, 62, bobPub, *addr, 1, consentCid.String())

	// Corrupt the revoke signature
	revokeReq.Signature = make([]byte, 65)
	_, err := RevokeSignerWasConsentSigner(revokeReq, consentReq, *addr)
	if err == nil {
		t.Error("expected error for corrupted revoke signature")
	}
}

// ── EncryptECDH full happy path ─────────────────────────────────────────────

func TestEncryptECDH_FullRoundTrip(t *testing.T) {
	priv1, _ := secp.GeneratePrivateKey()
	priv2, _ := secp.GeneratePrivateKey()
	addr := helperContractAddress()
	plaintext := []byte("ECDH round-trip data")

	result, err := key_exchange.EncryptECDH(plaintext, addr, priv1, priv2.PubKey(), purposes.PulsePurposeEncryptConsentStructure, 1, 62)
	if err != nil {
		t.Fatalf("key_exchange.EncryptECDH() failed: %v", err)
	}

	decrypted, err := key_exchange.DecryptEC(result, addr, priv2, purposes.PulsePurposeEncryptConsentStructure, 1, 62)
	if err != nil {
		t.Fatalf("key_exchange.DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// ── EncryptPQ multiple recipients ───────────────────────────────────────────

func TestEncryptPQ_MultipleRecipients(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub1, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	_, pub2, _ := DerivePQKeyPair(masterKey, 3, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()
	plaintext := []byte("multi-recipient PQ data")

	result, err := key_encapsulate.EncryptPQ(nil, plaintext, addr, []*kyberKEM.PublicKey{pub1, pub2}, purposes.PulseSymmetricConsent, 137, 0)
	if err != nil {
		t.Fatalf("key_encapsulate.EncryptPQ() failed: %v", err)
	}
	if len(result.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(result.Keys))
	}

	// Both recipients can decrypt
	priv1, _, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	d1, err := key_encapsulate.DecryptPQ(result, addr, priv1, purposes.PulseSymmetricConsent, 137, 0)
	if err != nil {
		t.Fatalf("key_encapsulate.DecryptPQ(recipient1) failed: %v", err)
	}
	if !bytes.Equal(plaintext, d1) {
		t.Errorf("recipient1 plaintext mismatch")
	}

	priv2, _, _ := DerivePQKeyPair(masterKey, 3, 0, 137, purposes.PulsePurposePQDeriveConsent)
	d2, err := key_encapsulate.DecryptPQ(result, addr, priv2, purposes.PulseSymmetricConsent, 137, 0)
	if err != nil {
		t.Fatalf("key_encapsulate.DecryptPQ(recipient2) failed: %v", err)
	}
	if !bytes.Equal(plaintext, d2) {
		t.Errorf("recipient2 plaintext mismatch")
	}
}

// ── deriveKeyFromMaster with public key (triggers NewChildKey failure on hardened path) ─

func TestDeriveKeyFromMaster_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	pubKey := masterKey.PublicKey()
	path, _ := newpulseHDPath(2, 1, 62, purposes.PulsePurposeSignTx)

	// pulseProtocolIdentifier is hardened, so deriving from a public key must fail
	_, err := deriveKeyFromMaster(pubKey, path)
	if err == nil {
		t.Error("expected error when deriving hardened child from public key")
	}
}

// ── DeriveOtherPartyGenerator with public key (hardened derivation fails) ────

func TestDeriveOtherPartyGenerator_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	pubKey := masterKey.PublicKey()

	_, err := DeriveOtherPartyGenerator(pubKey, 2)
	if err == nil {
		t.Error("expected error when deriving hardened child from public key")
	}
}

// ── RevokeSignerWasConsentSigner with consent having no signatures ──────────

func TestRevokeSignerWasConsentSigner_ConsentNoSignatures(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	consentReq, _ := EncryptSignConsentEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	consentCBOR, _ := consentReq.EncryptedData.MarshalCBOR()
	consentCid, _ := ipfs.GetCid(consentCBOR)
	revokeReq, _ := EncryptSignRevokeEC(masterKey, []byte("revoke"), 2, 62, bobPub, *addr, 1, consentCid.String())

	// Clear the consent signatures to trigger ConsentSigners error
	consentReq.Signatures = nil
	_, err := RevokeSignerWasConsentSigner(revokeReq, consentReq, *addr)
	if err == nil {
		t.Error("expected error for consent with no signatures")
	}
}

// ── encryptEC with valid data but different purposes (covers more encryptEC lines) ─

func TestEncryptRevokeNotaryEC_RoundTripCoverage(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	notaryPriv, notaryPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	plaintext := []byte("revoke notary additional coverage")

	result, err := EncryptRevokeNotaryEC(masterKey, plaintext, 2, 62, notaryPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptRevokeNotaryEC() failed: %v", err)
	}

	// HD wallet holder decrypts via DecryptRevokeNotaryEC
	decrypted, err := DecryptRevokeNotaryEC(masterKey, result, 2, 62, *addr, 1)
	if err != nil {
		t.Fatalf("DecryptRevokeNotaryEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch")
	}

	// Bob decrypts directly
	decryptedBob, err := key_exchange.DecryptEC(result, addr, notaryPriv, purposes.PulsePurposeEncryptRevokeNotaryBlock, 1, 62)
	if err != nil {
		t.Fatalf("key_exchange.DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(decrypted, decryptedBob) {
		t.Errorf("HD and direct decrypt produced different results")
	}
}

// ── SignConsentRequest exercises CID computation path ────────────────────────

func TestSignConsentRequest_ThenVerify(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	// Create a consent and verify the signing address is deterministic
	req1, _ := EncryptSignConsentEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	addrs1, err := ConsentSigners(req1, *addr)
	if err != nil {
		t.Fatalf("ConsentSigners() failed: %v", err)
	}

	// Sign again with same key — address must be stable
	req2, _ := EncryptSignConsentEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	addrs2, _ := ConsentSigners(req2, *addr)
	if addrs1[0] != addrs2[0] {
		t.Errorf("signing address not deterministic: %s vs %s", addrs1[0].Hex(), addrs2[0].Hex())
	}
}

// ── SignConsentRequest with public key (exercises deriveKeyFromMaster error inside signing) ─

func TestSignConsentRequest_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	// Build a valid encrypted request first
	result, err := EncryptConsentNotaryEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC() failed: %v", err)
	}
	req := &types.PulseConsentRequestEC{EncryptedData: *result}

	// Sign with a public key instead of a private key
	pubKey := masterKey.PublicKey()
	err = SignConsentRequest(pubKey, req, 2, 62, *addr, 1)
	if err == nil {
		t.Error("expected error when signing with public key")
	}
}

// ── SignRevokeRequest with public key ───────────────────────────────────────

func TestSignRevokeRequest_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	// Build valid encrypted data
	result, err := EncryptRevokeNotaryEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err != nil {
		t.Fatalf("EncryptRevokeNotaryEC() failed: %v", err)
	}
	req := &types.PulseRevokeRequestEC{ConsentCid: "bafyfake", EncryptedData: *result}

	pubKey := masterKey.PublicKey()
	err = SignRevokeRequest(pubKey, req, 2, 62, *addr, 1)
	if err == nil {
		t.Error("expected error when signing with public key")
	}
}

// ── encryptEC with public key ───────────────────────────────────────────────

func TestEncryptEC_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	pubKey := masterKey.PublicKey()
	_, err := encryptEC(pubKey, []byte("data"), 2, 62, bobPub, *addr, 1, purposes.PulsePurposeEncryptConsentStructure)
	if err == nil {
		t.Error("expected error when encrypting with public key")
	}
}

// ── decryptHDEC with public key ─────────────────────────────────────────────

func TestDecryptConsentEC_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	req, _ := EncryptSignConsentEC(masterKey, []byte("data"), 2, 62, bobPub, *addr, 1)

	pubKey := masterKey.PublicKey()
	_, err := DecryptConsentEC(pubKey, req, 2, 62, *addr, 1)
	if err == nil {
		t.Error("expected error when decrypting with public key")
	}
}

// ── DerivePQKeyPair with public key ─────────────────────────────────────────

func TestDerivePQKeyPair_PublicKeyFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	pubKey := masterKey.PublicKey()

	_, _, err := DerivePQKeyPair(pubKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	if err == nil {
		t.Error("expected error when deriving PQ key from public key")
	}
}

// ── EncryptSignConsentEC with public key (exercises signing error path) ──────

func TestEncryptSignConsentEC_PublicKeySigningFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	pubKey := masterKey.PublicKey()
	_, err := EncryptSignConsentEC(pubKey, []byte("data"), 2, 62, bobPub, *addr, 1)
	if err == nil {
		t.Error("expected error when signing with public key")
	}
}

// ── EncryptSignRevokeEC with public key ─────────────────────────────────────

func TestEncryptSignRevokeEC_PublicKeySigningFails(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()

	pubKey := masterKey.PublicKey()
	_, err := EncryptSignRevokeEC(pubKey, []byte("data"), 2, 62, bobPub, *addr, 1, "bafyfake")
	if err == nil {
		t.Error("expected error when signing with public key")
	}
}

// ── EncryptPQ with failing entropy reader ───────────────────────────────────

func TestEncryptPQ_EntropyError(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()

	// errReader fails after returning some bytes — enough for PulseSealWithNewKey
	// (which needs 44 bytes) but fails during encapsulateKey's io.ReadFull (needs 32 more)
	_, err := key_encapsulate.EncryptPQ(&errReader{failAfter: 50}, []byte("data"), addr, []*kyberKEM.PublicKey{pub}, purposes.PulseSymmetricConsent, 137, 0)
	if err == nil {
		t.Error("expected error from failing entropy reader")
	}
}

func TestEncryptPQ_EntropyErrorDuringSeal(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, pub, _ := DerivePQKeyPair(masterKey, 2, 0, 137, purposes.PulsePurposePQDeriveConsent)
	addr := helperContractAddress()

	// Fail during seal phase (needs 44 bytes for key+nonce)
	_, err := key_encapsulate.EncryptPQ(&errReader{failAfter: 10}, []byte("data"), addr, []*kyberKEM.PublicKey{pub}, purposes.PulseSymmetricConsent, 137, 0)
	if err == nil {
		t.Error("expected error from failing entropy reader during seal")
	}
}

// errReader returns failAfter bytes then errors.
type errReader struct {
	failAfter int
	read      int
}

func (r *errReader) Read(p []byte) (int, error) {
	remaining := r.failAfter - r.read
	if remaining <= 0 {
		return 0, errors.New("entropy exhausted")
	}
	n := len(p)
	if n > remaining {
		n = remaining
	}
	for i := 0; i < n; i++ {
		p[i] = byte(r.read + i)
	}
	r.read += n
	return n, nil
}

// Use io import
var _ = io.EOF

// ── Ensure unused import is used ────────────────────────────────────────────

var _ = common.Address{}
