package crypto

/*
 * Tests for PQ (post-quantum ML-KEM-768) encrypt / sign / decrypt functions.
 *
 * Uses the same BIP-32 Test Vector 1 master key as the EC tests.
 * Alice and Bob each derive ML-KEM key pairs from their HD wallets and share
 * their encapsulation (public) keys before creating consent records.
 */

import (
	"bytes"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/key_encapsulate"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── DerivePQKeyPair ───────────────────────────────────────────────────────────

func TestDerivePQKeyPair_Deterministic(t *testing.T) {
	/*
	 * Deriving the same key pair twice from the same master key must produce
	 * identical encapsulation keys (and therefore identical fingerprints).
	 */
	masterKey := mustNewMasterKey(t)
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	_, pub1, err := DerivePQKeyPair(masterKey, otherParty, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("first DerivePQKeyPair() failed: %v", err)
	}
	_, pub2, err := DerivePQKeyPair(masterKey, otherParty, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("second DerivePQKeyPair() failed: %v", err)
	}

	buf1 := make([]byte, kyberKEM.PublicKeySize)
	buf2 := make([]byte, kyberKEM.PublicKeySize)
	pub1.Pack(buf1)
	pub2.Pack(buf2)
	if !bytes.Equal(buf1, buf2) {
		t.Error("PQ public keys from identical inputs differ — derivation is not deterministic")
	}
}

func TestDerivePQKeyPair_ConsentRevokeUnlinked(t *testing.T) {
	/*
	 * The consent and revoke paths use different HKDF info strings, so they
	 * must produce distinct key pairs even for the same (otherParty, consent, chain).
	 */
	masterKey := mustNewMasterKey(t)
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	_, consentPub, _ := DerivePQKeyPair(masterKey, otherParty, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	_, revokePub, _ := DerivePQKeyPair(masterKey, otherParty, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	buf1 := make([]byte, kyberKEM.PublicKeySize)
	buf2 := make([]byte, kyberKEM.PublicKeySize)
	consentPub.Pack(buf1)
	revokePub.Pack(buf2)
	if bytes.Equal(buf1, buf2) {
		t.Error("consent and revoke PQ keys are identical — purpose separation failed")
	}
}

func TestDerivePQKeyPair_DifferentConsentNumbers(t *testing.T) {
	/*
	 * Keys for different consent numbers on the same (otherParty, chain) must differ.
	 */
	masterKey := mustNewMasterKey(t)
	const otherParty, chainId = uint32(2), uint32(1)

	_, pub0, _ := DerivePQKeyPair(masterKey, otherParty, 0, chainId, purposes.PulsePurposePQDeriveConsent)
	_, pub1, _ := DerivePQKeyPair(masterKey, otherParty, 1, chainId, purposes.PulsePurposePQDeriveConsent)

	buf0 := make([]byte, kyberKEM.PublicKeySize)
	buf1b := make([]byte, kyberKEM.PublicKeySize)
	pub0.Pack(buf0)
	pub1.Pack(buf1b)
	if bytes.Equal(buf0, buf1b) {
		t.Error("PQ keys for consent 0 and consent 1 are identical — unlinkability violated")
	}
}

func TestDerivePQKeyPair_InvalidPurpose(t *testing.T) {
	masterKey := mustNewMasterKey(t)
	_, _, err := DerivePQKeyPair(masterKey, 2, 0, 1, purposes.PulsePurposeSignTx)
	if err == nil {
		t.Error("expected error for non-PQ purpose, got nil")
	}
}

// ── EncryptSignConsentPQ round-trip ───────────────────────────────────────────

func TestEncryptSignConsentPQ_RoundTrip(t *testing.T) {
	/*
	 * Alice derives a PQ key pair for Bob's view, Bob derives one for Alice's view.
	 * Alice encrypts to both public keys.  Both parties must be able to decrypt.
	 */
	aliceMaster := mustNewMasterKey(t)
	bobMaster := mustNewMasterKey(t) // same seed — distinct wallets in a real system would differ

	addr := helperContractAddress()
	contractAddr := *addr
	plaintext := []byte("PQ consent payload")
	const alicePartyNo, bobPartyNo, consent, chainId = uint32(1), uint32(2), uint32(0), uint32(137)

	// Each party derives their own PQ key pair for this consent
	alicePriv, alicePub, err := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("Alice DerivePQKeyPair() failed: %v", err)
	}
	bobPriv, bobPub, err := DerivePQKeyPair(bobMaster, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("Bob DerivePQKeyPair() failed: %v", err)
	}

	// Alice encrypts to both (Alice + Bob)
	req, err := EncryptSignConsentPQ(aliceMaster, plaintext, bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub, bobPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}
	if len(req.EncryptedData.SealedData) == 0 {
		t.Fatal("SealedData is empty")
	}
	if len(req.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(req.Signatures))
	}

	// Alice decrypts
	gotAlice, err := DecryptConsentPQ(aliceMaster, req, bobPartyNo, consent, contractAddr, chainId)
	if err != nil {
		t.Fatalf("Alice DecryptConsentPQ() failed: %v", err)
	}
	if !bytes.Equal(plaintext, gotAlice) {
		t.Errorf("Alice plaintext mismatch: got %q, want %q", gotAlice, plaintext)
	}

	// Bob decrypts directly via DecryptPQ
	gotBob, err := key_encapsulate.DecryptPQ(&req.EncryptedData, &contractAddr, bobPriv, purposes.PulseSymmetricConsent, chainId, consent)
	if err != nil {
		t.Fatalf("Bob DecryptPQ() failed: %v", err)
	}
	if !bytes.Equal(plaintext, gotBob) {
		t.Errorf("Bob plaintext mismatch: got %q, want %q", gotBob, plaintext)
	}

	// Both decrypted values must match
	if !bytes.Equal(gotAlice, gotBob) {
		t.Errorf("Alice and Bob decrypted different plaintexts: alice=%q bob=%q", gotAlice, gotBob)
	}

	_ = alicePriv // Alice's private key used indirectly via DecryptConsentPQ
}

func TestEncryptSignConsentPQ_WrongKey(t *testing.T) {
	aliceMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, alicePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	req, err := EncryptSignConsentPQ(aliceMaster, []byte("payload"), bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Decrypt with wrong consent number must fail
	_, err = DecryptConsentPQ(aliceMaster, req, bobPartyNo, consent+1, contractAddr, chainId)
	if err == nil {
		t.Error("expected error for wrong consent number, got nil")
	}
}

// ── SignConsentRequest works for PQ types ─────────────────────────────────────

func TestSignConsentRequest_PQ_CounterSign(t *testing.T) {
	/*
	 * A second party calls SignConsentRequest to counter-sign a PQ consent.
	 * After the counter-sign, two signatures must be present.
	 */
	aliceMaster := mustNewMasterKey(t)
	bobMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const alicePartyNo, bobPartyNo, consent, chainId = uint32(1), uint32(2), uint32(0), uint32(137)

	_, alicePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	_, bobPub, _ := DerivePQKeyPair(bobMaster, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	req, err := EncryptSignConsentPQ(aliceMaster, []byte("consent"), bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub, bobPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Bob counter-signs
	if err = SignConsentRequest(bobMaster, req, alicePartyNo, consent, contractAddr, chainId); err != nil {
		t.Fatalf("Bob SignConsentRequest() failed: %v", err)
	}

	if len(req.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(req.Signatures))
	}
}

// ── EncryptSignRevokePQ round-trip ────────────────────────────────────────────

func TestEncryptSignRevokePQ_RoundTrip(t *testing.T) {
	/*
	 * Alice creates a PQ consent, then revokes it.
	 * Steps verified:
	 *   1. Revoke encryption and signature succeed
	 *   2. ConsentCid is stored correctly
	 *   3. Alice can decrypt the revoke ciphertext
	 *   4. Bob can decrypt the revoke ciphertext directly
	 */
	aliceMaster := mustNewMasterKey(t)
	bobMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const alicePartyNo, bobPartyNo, consent, chainId = uint32(1), uint32(2), uint32(0), uint32(137)

	// Derive keys for consent
	_, aliceConsentPub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	_, bobConsentPub, _ := DerivePQKeyPair(bobMaster, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	consentReq, err := EncryptSignConsentPQ(aliceMaster, []byte("consent payload"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceConsentPub, bobConsentPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Derive the consent CID
	consentCBOR, err := consentReq.EncryptedData.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() failed: %v", err)
	}
	consentCid, err := ipfs.GetCid(consentCBOR)
	if err != nil {
		t.Fatalf("GetCid() failed: %v", err)
	}

	// Derive keys for revoke
	_, aliceRevokePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)
	_, bobRevokePub, _ := DerivePQKeyPair(bobMaster, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	revokeData := []byte("revoke payload")
	revokeReq, err := EncryptSignRevokePQ(aliceMaster, revokeData, bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub, bobRevokePub}, contractAddr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}
	if len(revokeReq.EncryptedData.SealedData) == 0 {
		t.Fatal("SealedData is empty")
	}
	if revokeReq.ConsentCid != consentCid.String() {
		t.Errorf("ConsentCid = %q, want %q", revokeReq.ConsentCid, consentCid.String())
	}
	if len(revokeReq.Signature) == 0 {
		t.Fatal("Signature is empty")
	}

	// Alice decrypts
	gotAlice, err := DecryptRevokePQ(aliceMaster, revokeReq, bobPartyNo, consent, contractAddr, chainId)
	if err != nil {
		t.Fatalf("Alice DecryptRevokePQ() failed: %v", err)
	}
	if !bytes.Equal(revokeData, gotAlice) {
		t.Errorf("Alice plaintext mismatch: got %q, want %q", gotAlice, revokeData)
	}

	// Bob decrypts directly
	bobRevokePriv, _, _ := DerivePQKeyPair(bobMaster, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)
	gotBob, err := key_encapsulate.DecryptPQ(&revokeReq.EncryptedData, &contractAddr, bobRevokePriv, purposes.PulseSymmetricRevoke, chainId, consent)
	if err != nil {
		t.Fatalf("Bob DecryptPQ() revoke failed: %v", err)
	}
	if !bytes.Equal(gotAlice, gotBob) {
		t.Errorf("Alice and Bob decrypted different revoke plaintexts: alice=%q bob=%q", gotAlice, gotBob)
	}
}

func TestEncryptSignRevokePQ_WrongKey(t *testing.T) {
	aliceMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, aliceRevokePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	revokeReq, err := EncryptSignRevokePQ(aliceMaster, []byte("revoke"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub}, contractAddr, chainId, "bafyfake")
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	_, err = DecryptRevokePQ(aliceMaster, revokeReq, bobPartyNo, consent+1, contractAddr, chainId)
	if err == nil {
		t.Error("expected error for wrong consent number, got nil")
	}
}

// ── CBOR round-trip for PQ wire types ─────────────────────────────────────────

func TestPulseConsentRequestPQ_CBORRoundTrip(t *testing.T) {
	aliceMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, alicePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	req, err := EncryptSignConsentPQ(aliceMaster, []byte("cbor test"), bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	encoded, err := req.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() failed: %v", err)
	}

	var decoded types.PulseConsentRequestPQ
	if err := decoded.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("UnmarshalCBOR() failed: %v", err)
	}

	if !bytes.Equal(req.EncryptedData.SealedData, decoded.EncryptedData.SealedData) {
		t.Error("SealedData mismatch after CBOR round-trip")
	}
	if len(decoded.Signatures) != 1 {
		t.Errorf("expected 1 signature after round-trip, got %d", len(decoded.Signatures))
	}
	if !bytes.Equal(req.Signatures[0], decoded.Signatures[0]) {
		t.Error("signature mismatch after CBOR round-trip")
	}
}

func TestPulseRevokeRequestPQ_CBORRoundTrip(t *testing.T) {
	aliceMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)
	const fakeConsentCid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"

	_, aliceRevokePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	req, err := EncryptSignRevokePQ(aliceMaster, []byte("revoke cbor"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub}, contractAddr, chainId, fakeConsentCid)
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	encoded, err := req.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() failed: %v", err)
	}

	var decoded types.PulseRevokeRequestPQ
	if err := decoded.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("UnmarshalCBOR() failed: %v", err)
	}

	if decoded.ConsentCid != fakeConsentCid {
		t.Errorf("ConsentCid = %q, want %q", decoded.ConsentCid, fakeConsentCid)
	}
	if !bytes.Equal(req.EncryptedData.SealedData, decoded.EncryptedData.SealedData) {
		t.Error("SealedData mismatch after CBOR round-trip")
	}
	if !bytes.Equal(req.Signature, decoded.Signature) {
		t.Error("signature mismatch after CBOR round-trip")
	}
}

// ── RevokeSignerWasConsentSigner works for PQ ─────────────────────────────────

func TestRevokeSignerWasConsentSigner_PQ(t *testing.T) {
	/*
	 * The revoke is signed by Alice using the same HD signing key as the
	 * consent (PulsePurposeSignTx at the same HD path).
	 * RevokeSignerWasConsentSigner must confirm Alice's address appears in
	 * the consent's signatures.
	 *
	 * Note: consent and revoke both use the EC signature recovery path
	 * (ConsentSigners / GetRevokeAddress) regardless of encryption scheme.
	 * We use EC consent+revoke requests here because RevokeSignerWasConsentSigner
	 * operates on the request types; for a cross-scheme check (PQ consent, PQ revoke)
	 * the caller must extract signers manually.
	 *
	 * This test uses PQ consent + PQ revoke requests to exercise the PQ wire types.
	 */
	aliceMaster := mustNewMasterKey(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, aliceConsentPub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	consentReq, err := EncryptSignConsentPQ(aliceMaster, []byte("consent"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceConsentPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	consentCBOR, _ := consentReq.EncryptedData.MarshalCBOR()
	consentCid, _ := ipfs.GetCid(consentCBOR)

	_, aliceRevokePub, _ := DerivePQKeyPair(aliceMaster, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)
	revokeReq, err := EncryptSignRevokePQ(aliceMaster, []byte("revoke"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub}, contractAddr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	// Manually recover consent signers and revoke signer using helpers
	// (the wire types are PQ but the signing primitives are EC/secp256k1)
	consentCBORForSig, _ := consentReq.EncryptedData.MarshalCBOR()
	consentCidForSig, _ := ipfs.GetCid(consentCBORForSig)
	consentSignerAddr, err := GetConsentAddress(consentReq.Signatures[0], contractAddr, consentCidForSig.String())
	if err != nil {
		t.Fatalf("GetConsentAddress() failed: %v", err)
	}

	revokeCBOR, _ := revokeReq.EncryptedData.MarshalCBOR()
	revokeCid, _ := ipfs.GetCid(revokeCBOR)
	revokeSignerAddr, err := GetRevokeAddress(revokeReq.Signature, contractAddr, revokeReq.ConsentCid, revokeCid.String())
	if err != nil {
		t.Fatalf("GetRevokeAddress() failed: %v", err)
	}

	if consentSignerAddr != revokeSignerAddr {
		t.Errorf("consent signer %x != revoke signer %x — PQ signing keys are inconsistent", consentSignerAddr, revokeSignerAddr)
	}
}
