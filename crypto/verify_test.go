package crypto

/*
 * Tests for ConsentSigners and RevokeSignerWasConsentSigner (verify.go).
 *
 * Uses BIP-32 Test Vector 1 master key and the same fixtures as hdwallet_test.go.
 */

import (
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── ConsentSigners ────────────────────────────────────────────────────────────

func TestConsentSigners_SingleSignature(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	request, err := EncryptSignConsentEC(masterKey, []byte("payload"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	addrs, err := ConsentSigners(request, contractAddr)
	if err != nil {
		t.Fatalf("ConsentSigners() failed: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}
	t.Logf("Consent signer address: %s", addrs[0].Hex())
}

func TestConsentSigners_TwoSignatures(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	// Alice signs first
	request, err := EncryptSignConsentEC(masterKey, []byte("payload"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}
	// Alice counter-signs (simulates a second party using the same key for simplicity)
	reqCBOR, err := ipfs.MarshalConsentEC(&request.EncryptedData)
	if err != nil {
		t.Fatalf("MarshalConsentEC() failed: %v", err)
	}
	if err = SignConsentRequest(masterKey, request, reqCBOR, otherParty, consent, contractAddr, chainId); err != nil {
		t.Fatalf("second SignConsentRequest() failed: %v", err)
	}

	addrs, err := ConsentSigners(request, contractAddr)
	if err != nil {
		t.Fatalf("ConsentSigners() failed: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}
	// Both signatures came from the same key, so both addresses should be equal
	if addrs[0] != addrs[1] {
		t.Errorf("expected same address for both signatures, got %s and %s", addrs[0].Hex(), addrs[1].Hex())
	}
}

func TestConsentSigners_NilRequest(t *testing.T) {
	_, err := ConsentSigners(nil, "0x0102030405060708090a0b0c0d0e0f1011121314")
	if err == nil {
		t.Error("expected error for nil request")
	}
}

func TestConsentSigners_NoSignatures(t *testing.T) {
	request := &types.PulseConsentRequestEC{
		EncryptedData: types.PulseECEncryptionResult{
			SealedData: []byte("x"),
			Key1:       make([]byte, 33),
			Key2:       make([]byte, 33),
		},
	}
	_, err := ConsentSigners(request, "0x0102030405060708090a0b0c0d0e0f1011121314")
	if err == nil {
		t.Error("expected error for empty signatures")
	}
}

// ── RevokeSignerWasConsentSigner ──────────────────────────────────────────────

func TestRevokeSignerWasConsentSigner_Valid(t *testing.T) {
	/*
	 * Alice creates a consent and then revokes it.
	 * The revoke signer (Alice) must be recognised as one of the consent signers.
	 */
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	// Create consent
	consentReq, err := EncryptSignConsentEC(masterKey, []byte("consent payload"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	// Derive the consent CID (as the mid-tier would)
	consentCBOR, err := ipfs.MarshalConsentEC(&consentReq.EncryptedData)
	if err != nil {
		t.Fatalf("MarshalConsentEC() failed: %v", err)
	}
	consentCid, err := ipfs.GetCid(consentCBOR)
	if err != nil {
		t.Fatalf("GetCid() failed: %v", err)
	}

	// Create revoke (same party, same consent number — this is a revoke, not an update)
	revokeReq, err := EncryptSignRevokeEC(masterKey, []byte("revoke payload"), otherParty, consent, bobPub, contractAddr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}

	ok, err := RevokeSignerWasConsentSigner(revokeReq, consentReq, contractAddr)
	if err != nil {
		t.Fatalf("RevokeSignerWasConsentSigner() failed: %v", err)
	}
	if !ok {
		t.Error("expected revoke signer to be recognised as a consent signer")
	}
}

func TestRevokeSignerWasConsentSigner_DifferentKey(t *testing.T) {
	/*
	 * A revoke signed with a completely different key must not be recognised.
	 */
	masterKey := mustNewMasterKey(t)
	differentKey := mustNewMasterKey(t) // same seed, but imagine a different key
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	consentReq, err := EncryptSignConsentEC(masterKey, []byte("consent"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}

	consentCBOR, err := ipfs.MarshalConsentEC(&consentReq.EncryptedData)
	if err != nil {
		t.Fatalf("MarshalConsentEC() failed: %v", err)
	}
	consentCid, err := ipfs.GetCid(consentCBOR)
	if err != nil {
		t.Fatalf("GetCid() failed: %v", err)
	}

	// Revoke signed with a different master key + different otherParty → different signing key
	revokeReq, err := EncryptSignRevokeEC(differentKey, []byte("revoke"), otherParty+1, consent, bobPub, contractAddr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}

	ok, err := RevokeSignerWasConsentSigner(revokeReq, consentReq, contractAddr)
	if err != nil {
		t.Fatalf("RevokeSignerWasConsentSigner() failed unexpectedly: %v", err)
	}
	if ok {
		t.Error("expected revoke signer NOT to be recognised as a consent signer")
	}
}

func TestRevokeSignerWasConsentSigner_MultipleConsentSigners(t *testing.T) {
	/*
	 * When the consent has two signers, the revoke is valid if the signer matches
	 * either of them.  Here the revoke uses the same HD key as the consent (Alice),
	 * so it must be found even though Alice's signature is at index 0.
	 */
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	consentReq, err := EncryptSignConsentEC(masterKey, []byte("consent"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC() failed: %v", err)
	}
	// Add a second (counter-)signature
	consentCBORForSign, _ := ipfs.MarshalConsentEC(&consentReq.EncryptedData)
	if err = SignConsentRequest(masterKey, consentReq, consentCBORForSign, otherParty, consent, contractAddr, chainId); err != nil {
		t.Fatalf("second SignConsentRequest() failed: %v", err)
	}
	if len(consentReq.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(consentReq.Signatures))
	}

	consentCBOR, err := ipfs.MarshalConsentEC(&consentReq.EncryptedData)
	if err != nil {
		t.Fatalf("MarshalConsentEC() failed: %v", err)
	}
	consentCid, err := ipfs.GetCid(consentCBOR)
	if err != nil {
		t.Fatalf("GetCid() failed: %v", err)
	}

	revokeReq, err := EncryptSignRevokeEC(masterKey, []byte("revoke"), otherParty, consent, bobPub, contractAddr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC() failed: %v", err)
	}

	ok, err := RevokeSignerWasConsentSigner(revokeReq, consentReq, contractAddr)
	if err != nil {
		t.Fatalf("RevokeSignerWasConsentSigner() failed: %v", err)
	}
	if !ok {
		t.Error("expected revoke signer to be found among two consent signers")
	}
}

func TestRevokeSignerWasConsentSigner_NilInputs(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	consentReq, _ := EncryptSignConsentEC(masterKey, []byte("consent"), otherParty, consent, bobPub, contractAddr, chainId)
	consentCBOR, _ := ipfs.MarshalConsentEC(&consentReq.EncryptedData)
	consentCid, _ := ipfs.GetCid(consentCBOR)
	revokeReq, _ := EncryptSignRevokeEC(masterKey, []byte("revoke"), otherParty, consent, bobPub, contractAddr, chainId, consentCid.String())

	if _, err := RevokeSignerWasConsentSigner(nil, consentReq, contractAddr); err == nil {
		t.Error("expected error for nil revoke")
	}
	if _, err := RevokeSignerWasConsentSigner(revokeReq, nil, contractAddr); err == nil {
		t.Error("expected error for nil consent")
	}

	// Revoke with no signature
	emptyRevoke := &types.PulseRevokeRequestEC{}
	if _, err := RevokeSignerWasConsentSigner(emptyRevoke, consentReq, contractAddr); err == nil {
		t.Error("expected error for revoke with no signature")
	}
}

// ── Consent address is stable across repeated signs ───────────────────────────

func TestConsentSigners_AddressIsStable(t *testing.T) {
	/*
	 * Signing the same consent twice with the same key must produce the same
	 * recovered address both times.
	 */
	masterKey := mustNewMasterKey(t)
	_, bobPub := mustNewOtherPartyKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const otherParty, consent, chainId = uint32(3), uint32(10), uint32(137)

	r1, err := EncryptSignConsentEC(masterKey, []byte("data"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("first EncryptSignConsentEC() failed: %v", err)
	}
	r2, err := EncryptSignConsentEC(masterKey, []byte("data"), otherParty, consent, bobPub, contractAddr, chainId)
	if err != nil {
		t.Fatalf("second EncryptSignConsentEC() failed: %v", err)
	}

	addrs1, err := ConsentSigners(r1, contractAddr)
	if err != nil {
		t.Fatalf("ConsentSigners(r1): %v", err)
	}
	addrs2, err := ConsentSigners(r2, contractAddr)
	if err != nil {
		t.Fatalf("ConsentSigners(r2): %v", err)
	}

	// Same inputs → same signing key → same recovered address
	// (plaintext and ECDH nonce are random, but the signing key is deterministic)
	_ = purposes.PulsePurposeSignTx // import check
	if addrs1[0] != addrs2[0] {
		t.Errorf("address not stable: %s vs %s", addrs1[0].Hex(), addrs2[0].Hex())
	}
}
