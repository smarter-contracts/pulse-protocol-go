package crypto

/*
 * Test pack for the Pulse Protocol HD wallet derivation functions (hdwallet.go).
 *
 * If you are implementing this in another language, replicate the "Known Values" tests
 * to ensure your derivation is compatible with the reference implementation.
 * All binary values are encoded as lowercase hex strings.
 *
 * ── Master key ──────────────────────────────────────────────────────────────────────
 *   Seed (BIP-32 Test Vector 1): 000102030405060708090a0b0c0d0e0f
 *   Master private key: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
 *   Master chain code:  873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
 *   Master public key:  0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
 *
 * ── Path under test ─────────────────────────────────────────────────────────────────
 *   otherParty=2, chain=1, consent=62, purpose=1 (PulsePurposeSignTx)
 *   Path string: m/4410704'/2/1/62/1
 *
 * ── Derived key known values ─────────────────────────────────────────────────────────
 *   Run `go test -v -run TestDeriveKeyFromMaster_KnownValues` to capture these values,
 *   then update the constants below.
 */

import (
	"bytes"
	"encoding/hex"
	"testing"

	bip32 "github.com/jamesradley/go-bip32"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── Known values ─────────────────────────────────────────────────────────────────────
// These constants are populated after running the known-values test with -v for the first
// time and capturing the logged output.  Leave empty to skip the hex assertion.
const (
	knownDerivedPrivKeyHex = "1f09c3843f3ab1fb85185838a72b1a2896c11ad6720bee6108904b6a25adeece"  // m/4410704'/2/1/62/1  private key
	knownDerivedPubKeyHex  = "02c1ad8b15196d38595afd2d96cbe92649c63729aebeecea0e2724a48bfce5f968" // m/4410704'/2/1/62/1  compressed public key
)

// ── Test fixtures ─────────────────────────────────────────────────────────────────────

// hdTestSeed is BIP-32 Test Vector 1.
var hdTestSeed = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
}

func mustNewMasterKey(t *testing.T) *bip32.Key {
	t.Helper()
	key, err := bip32.NewMasterKey(hdTestSeed)
	if err != nil {
		t.Fatalf("NewMasterKey() failed: %v", err)
	}
	return key
}

// mustNewOtherPartyKey generates a fresh random secp256k1 key pair representing a
// counterparty whose keys are outside our HD wallet.
func mustNewOtherPartyKey(t *testing.T) (*secp.PrivateKey, *secp.PublicKey) {
	t.Helper()
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() failed: %v", err)
	}
	return priv, priv.PubKey()
}

// ── NewPulseHDPath validation ─────────────────────────────────────────────────────────

func TestNewPulseHDPath_Validation(t *testing.T) {
	tests := []struct {
		name       string
		otherParty uint32
		chain      uint32
		consent    uint32
		purpose    purposes.PulsePurpose
		wantErr    bool
	}{
		// Valid paths — one for each HD wallet purpose
		{"valid purpose 1 (SignTx)", 2, 1, 62, purposes.PulsePurposeSignTx, false},
		{"valid purpose 2 (EncryptConsentNotaryBlock)", 2, 1, 62, purposes.PulsePurposeEncryptConsentNotaryBlock, false},
		{"valid purpose 3 (EncryptConsentStructure)", 2, 1, 62, purposes.PulsePurposeEncryptConsentStructure, false},
		{"valid purpose 4 (EncryptRevokeNotaryBlock)", 2, 1, 62, purposes.PulsePurposeEncryptRevokeNotaryBlock, false},
		{"valid purpose 5 (EncryptRevokeStructure)", 2, 1, 62, purposes.PulsePurposeEncryptRevokeStructure, false},
		// Valid symmetric purposes are also accepted
		{"valid purpose 6 (SymmetricConsent)", 2, 1, 0, purposes.PulseSymmetricConsent, false},
		{"valid purpose 7 (SymmetricRevoke)", 2, 1, 0, purposes.PulseSymmetricRevoke, false},
		{"valid purpose 8 (SymmetricUpdate)", 2, 1, 0, purposes.PulseSymmetricUpdate, false},
		{"valid purpose 255 (SymmetricKeyWrap)", 2, 1, 0, purposes.PulseSymmetricKeyWrap, false},
		// Boundary values
		{"otherParty=0", 0, 1, 0, purposes.PulsePurposeSignTx, false},
		{"otherParty=0x7fffffff (max normal)", 0x7fffffff, 1, 0, purposes.PulsePurposeSignTx, false},
		{"chain=0", 2, 0, 0, purposes.PulsePurposeSignTx, false},
		{"chain=0x7fffffff (max normal)", 2, 0x7fffffff, 0, purposes.PulsePurposeSignTx, false},
		{"consent=0", 2, 1, 0, purposes.PulsePurposeSignTx, false},
		{"consent=0x7fffffff (max normal)", 2, 1, 0x7fffffff, purposes.PulsePurposeSignTx, false},
		// Invalid: otherParty with hardening bit set
		{"otherParty hardened (0x80000000)", 0x80000000, 1, 0, purposes.PulsePurposeSignTx, true},
		{"otherParty hardened (max uint32)", 0xffffffff, 1, 0, purposes.PulsePurposeSignTx, true},
		// Invalid: chain with hardening bit set
		{"chain hardened (0x80000000)", 2, 0x80000000, 0, purposes.PulsePurposeSignTx, true},
		// Invalid: consent with hardening bit set
		{"consent hardened (0x80000000)", 2, 1, 0x80000000, purposes.PulsePurposeSignTx, true},
		// Valid PQ derive purposes
		{"valid purpose 9 (PQDeriveConsent)", 2, 1, 0, purposes.PulsePurposePQDeriveConsent, false},
		{"valid purpose 10 (PQDeriveRevoke)", 2, 1, 0, purposes.PulsePurposePQDeriveRevoke, false},
		// Invalid purposes
		{"purpose 0 (NoSymmetricPurpose)", 2, 1, 0, purposes.PulseNoSymmetricPurpose, true},
		{"purpose 11 (undefined)", 2, 1, 0, purposes.PulsePurpose(11), true},
		{"purpose 254 (undefined)", 2, 1, 0, purposes.PulsePurpose(254), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := NewPulseHDPath(tt.otherParty, tt.chain, tt.consent, tt.purpose)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if path == nil {
				t.Fatal("path is nil")
			}
			if path.OtherParty != tt.otherParty {
				t.Errorf("OtherParty: got %d, want %d", path.OtherParty, tt.otherParty)
			}
			if path.Chain != tt.chain {
				t.Errorf("Chain: got %d, want %d", path.Chain, tt.chain)
			}
			if path.Consent != tt.consent {
				t.Errorf("Consent: got %d, want %d", path.Consent, tt.consent)
			}
			if path.Purpose != tt.purpose {
				t.Errorf("Purpose: got %d, want %d", path.Purpose, tt.purpose)
			}
			if path.Protocol != PulseProtocolIdentifier {
				t.Errorf("Protocol: got 0x%x, want 0x%x", path.Protocol, PulseProtocolIdentifier)
			}
		})
	}
}

// ── PulseHDPath.String ────────────────────────────────────────────────────────────────

func TestPulseHDPath_String_KnownValues(t *testing.T) {
	// PulseProtocolIdentifier = 0x80434d50 ('CMP' hardened)
	// Display index = 0x80434d50 - 0x80000000 = 0x434d50 = 4410704
	tests := []struct {
		name     string
		path     PulseHDPath
		expected string
	}{
		{
			name: "basic path m/4410704'/2/1/62/1",
			path: PulseHDPath{
				Protocol:   PulseProtocolIdentifier,
				OtherParty: 2,
				Chain:      1,
				Consent:    62,
				Purpose:    purposes.PulsePurposeSignTx,
			},
			expected: "m/4410704'/2/1/62/1",
		},
		{
			name: "zero values (except protocol)",
			path: PulseHDPath{
				Protocol:   PulseProtocolIdentifier,
				OtherParty: 0,
				Chain:      0,
				Consent:    0,
				Purpose:    purposes.PulsePurposeSignTx,
			},
			expected: "m/4410704'/0/0/0/1",
		},
		{
			name: "purpose 5 (EncryptRevokeStructure)",
			path: PulseHDPath{
				Protocol:   PulseProtocolIdentifier,
				OtherParty: 100,
				Chain:      137,
				Consent:    999,
				Purpose:    purposes.PulsePurposeEncryptRevokeStructure,
			},
			expected: "m/4410704'/100/137/999/5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.path.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ── DeriveOtherPartyGenerator errors ─────────────────────────────────────────────────

func TestDeriveOtherPartyGenerator_Errors(t *testing.T) {
	masterKey := mustNewMasterKey(t)

	if _, err := DeriveOtherPartyGenerator(nil, 2); err == nil {
		t.Error("expected error for nil masterKey")
	}
	if _, err := DeriveOtherPartyGenerator(masterKey, 0x80000000); err == nil {
		t.Error("expected error for hardened otherParty index")
	}
	if _, err := DeriveOtherPartyGenerator(masterKey, 0xffffffff); err == nil {
		t.Error("expected error for max uint32 otherParty")
	}
}

func TestDeriveOtherPartyGenerator_ReturnValue(t *testing.T) {
	masterKey := mustNewMasterKey(t)

	gen, err := DeriveOtherPartyGenerator(masterKey, 2)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator() failed: %v", err)
	}
	if gen == nil {
		t.Fatal("returned key is nil")
	}
	// Must be a public (not private) key so it can safely be shared with counterparties
	// to allow them to derive our public keys without access to private key material.
	if gen.IsPrivate {
		t.Error("DeriveOtherPartyGenerator must return a public key, got private key")
	}
}

func TestDerivePublicKeyFromParent_ConsistencyWithPrivate(t *testing.T) {
	/*
	 * Derives the same key via two routes and confirms the results agree:
	 *
	 *   Route A (private path):
	 *     deriveKeyFromMaster(masterKey, path(otherParty=2, chain=1, consent=62, purpose=1))
	 *     → secp256k1 private key → .PubKey()
	 *
	 *   Route B (public path):
	 *     DeriveOtherPartyGenerator(masterKey, 2)          → extended public key at m/protocol'/2
	 *     derivePublicKeyFromParent(generator, 1, 62, 1)   → public key at m/protocol'/2/1/62/1
	 *
	 * Both routes must produce the same compressed public key.
	 */
	masterKey := mustNewMasterKey(t)
	const otherParty, chain, consent = uint32(2), uint32(1), uint32(62)
	p := purposes.PulsePurposeSignTx

	// Route A
	path, err := NewPulseHDPath(otherParty, chain, consent, p)
	if err != nil {
		t.Fatalf("NewPulseHDPath() failed: %v", err)
	}
	privKey, err := deriveKeyFromMaster(masterKey, path)
	if err != nil {
		t.Fatalf("deriveKeyFromMaster() failed: %v", err)
	}
	pubFromPriv := privKey.PubKey().SerializeCompressed()

	// Route B
	gen, err := DeriveOtherPartyGenerator(masterKey, otherParty)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator() failed: %v", err)
	}
	pubFromParent, err := derivePublicKeyFromParent(gen, chain, consent, p)
	if err != nil {
		t.Fatalf("derivePublicKeyFromParent() failed: %v", err)
	}

	if !bytes.Equal(pubFromPriv, pubFromParent.SerializeCompressed()) {
		t.Errorf("public key mismatch between private and public derivation paths:\n  private route: %x\n  public route:  %x",
			pubFromPriv, pubFromParent.SerializeCompressed())
	}
}

// ── deriveKeyFromMaster errors ────────────────────────────────────────────────────────

func TestDeriveKeyFromMaster_Errors(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	path, _ := NewPulseHDPath(2, 1, 62, purposes.PulsePurposeSignTx)

	if _, err := deriveKeyFromMaster(nil, path); err == nil {
		t.Error("expected error for nil masterKey")
	}
	if _, err := deriveKeyFromMaster(masterKey, nil); err == nil {
		t.Error("expected error for nil path")
	}
}

// ── derivePublicKeyFromParent errors ─────────────────────────────────────────────────

func TestDerivePublicKeyFromParent_Errors(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	gen, err := DeriveOtherPartyGenerator(masterKey, 2)
	if err != nil {
		t.Fatalf("DeriveOtherPartyGenerator() failed: %v", err)
	}

	if _, err := derivePublicKeyFromParent(nil, 1, 62, purposes.PulsePurposeSignTx); err == nil {
		t.Error("expected error for nil parentKey")
	}
	if _, err := derivePublicKeyFromParent(gen, 0x80000000, 62, purposes.PulsePurposeSignTx); err == nil {
		t.Error("expected error for hardened chain index")
	}
	if _, err := derivePublicKeyFromParent(gen, 1, 0x80000000, purposes.PulsePurposeSignTx); err == nil {
		t.Error("expected error for hardened consent index")
	}
	if _, err := derivePublicKeyFromParent(gen, 1, 62, purposes.PulseNoSymmetricPurpose); err == nil {
		t.Error("expected error for purpose 0")
	}
	if _, err := derivePublicKeyFromParent(gen, 1, 62, purposes.PulsePurpose(9)); err == nil {
		t.Error("expected error for undefined purpose 9")
	}
}

// ── Known values ──────────────────────────────────────────────────────────────────────

func TestDeriveKeyFromMaster_KnownValues(t *testing.T) {
	/*
	 * Derives the key at m/4410704'/2/1/62/1 from the BIP-32 Test Vector 1 seed.
	 *
	 * On first run, use `go test -v -run TestDeriveKeyFromMaster_KnownValues` and
	 * capture the logged values below. Copy them into the knownDerivedPrivKeyHex and
	 * knownDerivedPubKeyHex constants at the top of this file.
	 */
	masterKey := mustNewMasterKey(t)

	path, err := NewPulseHDPath(2, 1, 62, purposes.PulsePurposeSignTx)
	if err != nil {
		t.Fatalf("NewPulseHDPath() failed: %v", err)
	}

	privKey, err := deriveKeyFromMaster(masterKey, path)
	if err != nil {
		t.Fatalf("deriveKeyFromMaster() failed: %v", err)
	}
	if privKey == nil {
		t.Fatal("derived key is nil")
	}

	privHex := textformat.FormatHex(privKey.Serialize())
	pubHex := textformat.FormatHex(privKey.PubKey().SerializeCompressed())
	t.Logf("Derived private key: %s", privHex)
	t.Logf("Derived public key:  %s", pubHex)

	if knownDerivedPrivKeyHex != "" && privHex != knownDerivedPrivKeyHex {
		t.Errorf("private key mismatch:\n got:  %s\nwant: %s", privHex, knownDerivedPrivKeyHex)
	}
	if knownDerivedPubKeyHex != "" && pubHex != knownDerivedPubKeyHex {
		t.Errorf("public key mismatch:\n got:  %s\nwant: %s", pubHex, knownDerivedPubKeyHex)
	}
}

// ── Determinism ───────────────────────────────────────────────────────────────────────

func TestDeriveKeyFromMaster_Determinism(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	path, _ := NewPulseHDPath(2, 1, 62, purposes.PulsePurposeSignTx)

	key1, err := deriveKeyFromMaster(masterKey, path)
	if err != nil {
		t.Fatalf("first derive failed: %v", err)
	}
	key2, err := deriveKeyFromMaster(masterKey, path)
	if err != nil {
		t.Fatalf("second derive failed: %v", err)
	}

	if !bytes.Equal(key1.Serialize(), key2.Serialize()) {
		t.Error("deriveKeyFromMaster is not deterministic")
	}
}

// ── Different paths produce different keys ────────────────────────────────────────────

func TestDeriveKeyFromMaster_DifferentPaths(t *testing.T) {
	masterKey := mustNewMasterKey(t)

	paths := []struct{ otherParty, chain, consent uint32; purpose purposes.PulsePurpose }{
		{2, 1, 62, purposes.PulsePurposeSignTx},
		{3, 1, 62, purposes.PulsePurposeSignTx},                    // different otherParty
		{2, 2, 62, purposes.PulsePurposeSignTx},                    // different chain
		{2, 1, 63, purposes.PulsePurposeSignTx},                    // different consent
		{2, 1, 62, purposes.PulsePurposeEncryptConsentStructure},   // different purpose
	}

	keys := make([][]byte, len(paths))
	for i, p := range paths {
		path, err := NewPulseHDPath(p.otherParty, p.chain, p.consent, p.purpose)
		if err != nil {
			t.Fatalf("NewPulseHDPath(%v) failed: %v", p, err)
		}
		k, err := deriveKeyFromMaster(masterKey, path)
		if err != nil {
			t.Fatalf("deriveKeyFromMaster(%v) failed: %v", p, err)
		}
		keys[i] = k.Serialize()
	}

	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("paths[%d] and paths[%d] produced the same key", i, j)
			}
		}
	}
}

// ── EncryptConsentNotaryEC / EncryptRevokeNotaryEC round-trips ────────────────────────

func TestEncryptConsentNotaryEC_RoundTrip(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	notaryPriv, notaryPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	plaintext := []byte("consent notary record")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	result, err := EncryptConsentNotaryEC(masterKey, plaintext, otherParty, consent, notaryPub, *addr, chainId)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC() failed: %v", err)
	}
	if len(result.SealedData) == 0 {
		t.Fatal("SealedData is empty")
	}

	decrypted, err := DecryptEC(result, addr, notaryPriv, purposes.PulsePurposeEncryptConsentStructure, chainId, consent)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptRevokeNotaryEC_RoundTrip(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	notaryPriv, notaryPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	plaintext := []byte("revoke notary record")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	result, err := EncryptRevokeNotaryEC(masterKey, plaintext, otherParty, consent, notaryPub, *addr, chainId)
	if err != nil {
		t.Fatalf("EncryptRevokeNotaryEC() failed: %v", err)
	}
	if len(result.SealedData) == 0 {
		t.Fatal("SealedData is empty")
	}

	decrypted, err := DecryptEC(result, addr, notaryPriv, purposes.PulsePurposeEncryptRevokeStructure, chainId, consent)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// ── EncryptSignConsentEC round-trip ───────────────────────────────────────────────────

func TestEncryptSignConsentEC_RoundTrip(t *testing.T) {
	/*
	 * Alice holds a master HD key. She encrypts the consent record to Bob (other party)
	 * and signs it with her derived signing key.
	 *
	 * Steps verified:
	 *   1. Encryption succeeds and produces a non-empty ciphertext
	 *   2. Bob can decrypt the ciphertext with his private key
	 *   3. The decrypted plaintext matches the original
	 *   4. The signature can be recovered to a valid Ethereum address
	 *   5. A second call to SignConsentEC appends an additional signature (grantor counter-signs)
	 */
	masterKey := mustNewMasterKey(t)
	bobPriv, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	plaintext := []byte("consent record payload")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	// Step 1 & 2: encrypt + sign
	request, err := EncryptSignConsentEC(masterKey, plaintext, otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}
	if len(request.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(request.Signatures))
	}

	// Step 3: Bob decrypts
	decrypted, err := DecryptEC(&request.EncryptedData, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, chainId, consent)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Step 4: Signature can be recovered
	signingCBOR, err := request.EncryptedData.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() failed: %v", err)
	}
	cid, err := ipfs.GetCid(signingCBOR)
	if err != nil {
		t.Fatalf("getCid() failed: %v", err)
	}
	recoveredAddr, err := GetConsentAddress(request.Signatures[0], contractAddr, cid.String())
	if err != nil {
		t.Fatalf("GetConsentAddress() failed: %v", err)
	}
	if len(recoveredAddr) != 20 {
		t.Errorf("recovered address has wrong length: %d", len(recoveredAddr))
	}
	t.Logf("Recovered signing address: %s", hex.EncodeToString(recoveredAddr[:]))

	// Step 5: A second party counter-signs (appends a second signature)
	if err = SignConsentRequest(masterKey, request, otherParty, consent, contractAddr, chainId); err != nil {
		t.Fatalf("second SignConsentRequest() failed: %v", err)
	}
	if len(request.Signatures) != 2 {
		t.Fatalf("expected 2 signatures after counter-sign, got %d", len(request.Signatures))
	}
}

// ── SignConsentRequest on pre-built request ───────────────────────────────────────────

func TestSignConsentRequest_OnExistingRequest(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(5), uint32(100), uint32(137)

	request := &types.PulseConsentRequestEC{}

	// Build a request with only encrypted data (no signature yet)
	result, err := EncryptConsentNotaryEC(masterKey, []byte("data"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC() failed: %v", err)
	}
	request.EncryptedData = *result

	// Sign it — SignConsentRequest works for any consent type (EC or PQ)
	if err = SignConsentRequest(masterKey, request, otherParty, consent, contractAddr, chainId); err != nil {
		t.Fatalf("SignConsentRequest() failed: %v", err)
	}
	if len(request.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(request.Signatures))
	}
}
