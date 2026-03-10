package crypto

/*
 * Tests for the revoke encrypt/sign/decrypt functions added in Phase 5.
 *
 * Pattern mirrors the consent tests in hdwallet_test.go.
 * All tests use BIP-32 Test Vector 1 as the master key seed.
 */

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── EncryptSignRevokeEC round-trip ────────────────────────────────────────────

func TestEncryptSignRevokeEC_RoundTrip(t *testing.T) {
	/*
	 * Alice holds a master HD key. She first produces a consent, then revokes it.
	 *
	 * Steps verified:
	 *   1. Revoke encryption succeeds and produces a non-empty ciphertext
	 *   2. ConsentCid is stored correctly in the request
	 *   3. A single signature is present
	 *   4. Bob can decrypt the revoke ciphertext with his private key
	 *   5. The decrypted plaintext matches the original
	 *   6. The signature can be recovered to a valid Ethereum address via GetRevokeAddress
	 */
	masterKey := mustNewMasterKey(t)
	bobPriv, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	// Build a fake consentCid (in production this is the CID of the consent's EncryptedData CBOR)
	const fakeConsentCid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"
	revokeData := []byte("revoke record payload")

	// Step 1–3: encrypt + sign
	request, err := EncryptSignRevokeEC(masterKey, revokeData, otherParty, consent, bobPub, contractAddr, chainId, fakeConsentCid)
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}
	if len(request.EncryptedData.SealedData) == 0 {
		t.Fatal("SealedData is empty")
	}
	if request.ConsentCid != fakeConsentCid {
		t.Errorf("ConsentCid = %q, want %q", request.ConsentCid, fakeConsentCid)
	}
	if len(request.Signature) == 0 {
		t.Fatal("Signature is empty")
	}

	// Step 4–5: Bob decrypts
	decrypted, err := DecryptEC(&request.EncryptedData, addr, bobPriv, purposes.PulsePurposeEncryptRevokeStructure, chainId, consent)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(revokeData, decrypted) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, revokeData)
	}

	// Step 6: Signature recovery
	revokeCBOR, err := request.EncryptedData.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() failed: %v", err)
	}
	revokeCid, err := ipfs.GetCid(revokeCBOR)
	if err != nil {
		t.Fatalf("GetCid() failed: %v", err)
	}
	recoveredAddr, err := GetRevokeAddress(request.Signature, contractAddr, fakeConsentCid, revokeCid.String())
	if err != nil {
		t.Fatalf("GetRevokeAddress() failed: %v", err)
	}
	if len(recoveredAddr) != 20 {
		t.Errorf("recovered address has wrong length: %d", len(recoveredAddr))
	}
	t.Logf("Recovered revoke signing address: %s", hex.EncodeToString(recoveredAddr[:]))
}

// ── SignRevokeRequest on a pre-built request ──────────────────────────────────

func TestSignRevokeRequest_OnExistingRequest(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(5), uint32(100), uint32(137)
	const fakeConsentCid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"

	// Build encrypted data without signing
	result, err := EncryptRevokeNotaryEC(masterKey, []byte("data"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptRevokeNotaryEC() failed: %v", err)
	}
	request := &types.PulseRevokeRequestEC{
		ConsentCid:    fakeConsentCid,
		EncryptedData: *result,
	}

	// SignRevokeRequest works for any revoke type (EC or PQ)
	if err = SignRevokeRequest(masterKey, request, otherParty, consent, contractAddr, chainId); err != nil {
		t.Fatalf("SignRevokeRequest() failed: %v", err)
	}
	if len(request.Signature) == 0 {
		t.Fatal("Signature is empty after SignRevokeRequest")
	}
}

// ── DecryptConsentEC ──────────────────────────────────────────────────────────

func TestDecryptConsentEC_RoundTrip(t *testing.T) {
	/*
	 * Verifies that DecryptConsentEC can decrypt what EncryptSignConsentEC produced,
	 * recovering the same plaintext that Bob would get via DecryptEC directly.
	 */
	masterKey := mustNewMasterKey(t)
	bobPriv, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	plaintext := []byte("consent payload for HD decrypt test")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	request, err := EncryptSignConsentEC(masterKey, plaintext, otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	// HD-wallet holder (Alice) decrypts via master key
	gotHD, err := DecryptConsentEC(masterKey, request, otherParty, consent, contractAddr, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentEC() failed: %v", err)
	}
	if !bytes.Equal(plaintext, gotHD) {
		t.Errorf("DecryptConsentEC plaintext mismatch: got %q, want %q", gotHD, plaintext)
	}

	// Bob decrypts directly — must produce the same result
	gotBob, err := DecryptEC(&request.EncryptedData, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, chainId, consent)
	if err != nil {
		t.Fatalf("DecryptEC(bob) failed: %v", err)
	}
	if !bytes.Equal(gotHD, gotBob) {
		t.Errorf("Alice and Bob decrypted different plaintexts: alice=%q bob=%q", gotHD, gotBob)
	}
}

func TestDecryptConsentEC_WrongKey(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	request, err := EncryptSignConsentEC(masterKey, []byte("payload"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	// A different HD path (wrong consent number) — must fail or produce garbled output
	_, err = DecryptConsentEC(masterKey, request, otherParty, consent+1, contractAddr, chainId)
	if err == nil {
		t.Error("expected decryption error for wrong consent number, got nil")
	}
}

// ── DecryptRevokeEC ───────────────────────────────────────────────────────────

func TestDecryptRevokeEC_RoundTrip(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	bobPriv, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	revokeData := []byte("revoke payload for HD decrypt test")
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)
	const fakeConsentCid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"

	request, err := EncryptSignRevokeEC(masterKey, revokeData, otherParty, consent, bobPub, contractAddr, chainId, fakeConsentCid)
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}

	// HD-wallet holder (Alice) decrypts via master key
	gotHD, err := DecryptRevokeEC(masterKey, request, otherParty, consent, contractAddr, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokeEC() failed: %v", err)
	}
	if !bytes.Equal(revokeData, gotHD) {
		t.Errorf("DecryptRevokeEC plaintext mismatch: got %q, want %q", gotHD, revokeData)
	}

	// Bob decrypts directly — must produce the same result
	gotBob, err := DecryptEC(&request.EncryptedData, addr, bobPriv, purposes.PulsePurposeEncryptRevokeStructure, chainId, consent)
	if err != nil {
		t.Fatalf("DecryptEC(bob) failed: %v", err)
	}
	if !bytes.Equal(gotHD, gotBob) {
		t.Errorf("Alice and Bob decrypted different plaintexts: alice=%q bob=%q", gotHD, gotBob)
	}
}

func TestDecryptRevokeEC_WrongKey(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)
	const fakeConsentCid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"

	request, err := EncryptSignRevokeEC(masterKey, []byte("payload"), otherParty, consent, bobPub, contractAddr, chainId, fakeConsentCid)
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}

	_, err = DecryptRevokeEC(masterKey, request, otherParty, consent+1, contractAddr, chainId)
	if err == nil {
		t.Error("expected decryption error for wrong consent number, got nil")
	}
}

// ── Consent and revoke ciphertexts are unlinkable ────────────────────────────

func TestConsentRevokeUnlinkability(t *testing.T) {
	/*
	 * Two consent records for the same (otherParty, chain) but different consent
	 * numbers must encrypt with completely different keys (different HD paths).
	 * The ciphertexts — and in particular Key1, the sender's derived public key —
	 * must differ between the two records.
	 */
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, chainId = uint32(2), uint32(1)

	r1, err := EncryptSignConsentEC(masterKey, []byte("consent 1"), otherParty, 0, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("consent 1 failed: %v", err)
	}
	r2, err := EncryptSignConsentEC(masterKey, []byte("consent 2"), otherParty, 1, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("consent 2 failed: %v", err)
	}

	if bytes.Equal(r1.EncryptedData.Key1, r2.EncryptedData.Key1) {
		t.Error("consent 1 and consent 2 share the same sender public key — paths are not independent")
	}
	if bytes.Equal(r1.Signatures[0], r2.Signatures[0]) {
		t.Error("consent 1 and consent 2 share the same signature — signing keys are not independent")
	}
}
