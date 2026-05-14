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

	kyberKEM "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/key_encapsulate"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// ── DerivePQKeyPair ───────────────────────────────────────────────────────────

func TestDerivePQKeyPair_Deterministic(t *testing.T) {
	/*
	 * Deriving the same key pair twice from the same master key must produce
	 * identical encapsulation keys (and therefore identical fingerprints).
	 */
	wallet := mustNewTestWallet(t)
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	_, pub1, err := DerivePQKeyPair(wallet, otherParty, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("first DerivePQKeyPair() failed: %v", err)
	}
	_, pub2, err := DerivePQKeyPair(wallet, otherParty, consent, chainId, purposes.PulsePurposePQDeriveConsent)
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
	wallet := mustNewTestWallet(t)
	const otherParty, consent, chainId = uint32(2), uint32(62), uint32(1)

	_, consentPub, _ := DerivePQKeyPair(wallet, otherParty, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	_, revokePub, _ := DerivePQKeyPair(wallet, otherParty, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

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
	wallet := mustNewTestWallet(t)
	const otherParty, chainId = uint32(2), uint32(1)

	_, pub0, _ := DerivePQKeyPair(wallet, otherParty, 0, chainId, purposes.PulsePurposePQDeriveConsent)
	_, pub1, _ := DerivePQKeyPair(wallet, otherParty, 1, chainId, purposes.PulsePurposePQDeriveConsent)

	buf0 := make([]byte, kyberKEM.PublicKeySize)
	buf1b := make([]byte, kyberKEM.PublicKeySize)
	pub0.Pack(buf0)
	pub1.Pack(buf1b)
	if bytes.Equal(buf0, buf1b) {
		t.Error("PQ keys for consent 0 and consent 1 are identical — unlinkability violated")
	}
}

func TestDerivePQKeyPair_InvalidPurpose(t *testing.T) {
	wallet := mustNewTestWallet(t)
	_, _, err := DerivePQKeyPair(wallet, 2, 0, 1, purposes.PulsePurposeSignTx)
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
	aliceWallet := mustNewTestWallet(t)
	bobWallet := mustNewTestWallet(t) // same seed — distinct wallets in a real system would differ

	addr := helperContractAddress()
	contractAddr := *addr
	plaintext := []byte("PQ consent payload")
	const alicePartyNo, bobPartyNo, consent, chainId = uint32(1), uint32(2), uint32(0), uint32(137)

	// Each party derives their own PQ key pair for this consent
	alicePriv, alicePub, err := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("Alice DerivePQKeyPair() failed: %v", err)
	}
	bobPriv, bobPub, err := DerivePQKeyPair(bobWallet, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("Bob DerivePQKeyPair() failed: %v", err)
	}

	// Alice encrypts to both (Alice + Bob)
	req, err := EncryptSignConsentPQ(aliceWallet, plaintext, bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub, bobPub}, contractAddr, chainId)
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
	gotAlice, err := DecryptConsentPQ(aliceWallet, req, bobPartyNo, consent, contractAddr, chainId)
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
	aliceWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, alicePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	req, err := EncryptSignConsentPQ(aliceWallet, []byte("payload"), bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Decrypt with wrong consent number must fail
	_, err = DecryptConsentPQ(aliceWallet, req, bobPartyNo, consent+1, contractAddr, chainId)
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
	aliceWallet := mustNewTestWallet(t)
	bobWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const alicePartyNo, bobPartyNo, consent, chainId = uint32(1), uint32(2), uint32(0), uint32(137)

	_, alicePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	_, bobPub, _ := DerivePQKeyPair(bobWallet, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	req, err := EncryptSignConsentPQ(aliceWallet, []byte("consent"), bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub, bobPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Bob counter-signs
	reqCBOR, _ := ipfs.MarshalConsentPQ(&req.EncryptedData)
	if err = SignConsentRequest(bobWallet, req, reqCBOR, alicePartyNo, consent, contractAddr, chainId); err != nil {
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
	aliceWallet := mustNewTestWallet(t)
	bobWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const alicePartyNo, bobPartyNo, consent, chainId = uint32(1), uint32(2), uint32(0), uint32(137)

	// Derive keys for consent
	_, aliceConsentPub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	_, bobConsentPub, _ := DerivePQKeyPair(bobWallet, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	consentReq, err := EncryptSignConsentPQ(aliceWallet, []byte("consent payload"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceConsentPub, bobConsentPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	// Derive the consent CID
	consentCBOR, err := ipfs.MarshalConsentPQ(&consentReq.EncryptedData)
	if err != nil {
		t.Fatalf("MarshalConsentPQ() failed: %v", err)
	}
	consentCid, err := ipfs.GetCid(consentCBOR)
	if err != nil {
		t.Fatalf("GetCid() failed: %v", err)
	}

	// Derive keys for revoke
	_, aliceRevokePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)
	_, bobRevokePub, _ := DerivePQKeyPair(bobWallet, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	revokeData := []byte("revoke payload")
	revokeReq, err := EncryptSignRevokePQ(aliceWallet, revokeData, bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub, bobRevokePub}, contractAddr, chainId, consentCid.String())
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
	gotAlice, err := DecryptRevokePQ(aliceWallet, revokeReq, bobPartyNo, consent, contractAddr, chainId)
	if err != nil {
		t.Fatalf("Alice DecryptRevokePQ() failed: %v", err)
	}
	if !bytes.Equal(revokeData, gotAlice) {
		t.Errorf("Alice plaintext mismatch: got %q, want %q", gotAlice, revokeData)
	}

	// Bob decrypts directly
	bobRevokePriv, _, _ := DerivePQKeyPair(bobWallet, alicePartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)
	gotBob, err := key_encapsulate.DecryptPQ(&revokeReq.EncryptedData, &contractAddr, bobRevokePriv, purposes.PulseSymmetricRevoke, chainId, consent)
	if err != nil {
		t.Fatalf("Bob DecryptPQ() revoke failed: %v", err)
	}
	if !bytes.Equal(gotAlice, gotBob) {
		t.Errorf("Alice and Bob decrypted different revoke plaintexts: alice=%q bob=%q", gotAlice, gotBob)
	}
}

func TestEncryptSignRevokePQ_WrongKey(t *testing.T) {
	aliceWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, aliceRevokePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	revokeReq, err := EncryptSignRevokePQ(aliceWallet, []byte("revoke"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub}, contractAddr, chainId, "bafyfake")
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	_, err = DecryptRevokePQ(aliceWallet, revokeReq, bobPartyNo, consent+1, contractAddr, chainId)
	if err == nil {
		t.Error("expected error for wrong consent number, got nil")
	}
}

// ── CBOR round-trip for PQ wire types ─────────────────────────────────────────

func TestPulseConsentRequestPQ_CBORRoundTrip(t *testing.T) {
	aliceWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, alicePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)

	req, err := EncryptSignConsentPQ(aliceWallet, []byte("cbor test"), bobPartyNo, consent, []*kyberKEM.PublicKey{alicePub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	encoded, err := ipfs.MarshalConsentRequestPQ(req)
	if err != nil {
		t.Fatalf("MarshalConsentRequestPQ() failed: %v", err)
	}

	decoded, err := ipfs.UnmarshalConsentRequestPQ(encoded)
	if err != nil {
		t.Fatalf("UnmarshalConsentRequestPQ() failed: %v", err)
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
	aliceWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)
	const fakeConsentCid = "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly"

	_, aliceRevokePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)

	req, err := EncryptSignRevokePQ(aliceWallet, []byte("revoke cbor"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub}, contractAddr, chainId, fakeConsentCid)
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	encoded, err := ipfs.MarshalRevokeRequestPQ(req)
	if err != nil {
		t.Fatalf("MarshalRevokeRequestPQ() failed: %v", err)
	}

	decoded, err := ipfs.UnmarshalRevokeRequestPQ(encoded)
	if err != nil {
		t.Fatalf("UnmarshalRevokeRequestPQ() failed: %v", err)
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
	aliceWallet := mustNewTestWallet(t)
	addr := helperContractAddress()
	contractAddr := *addr
	const bobPartyNo, consent, chainId = uint32(2), uint32(0), uint32(137)

	_, aliceConsentPub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveConsent)
	consentReq, err := EncryptSignConsentPQ(aliceWallet, []byte("consent"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceConsentPub}, contractAddr, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ() failed: %v", err)
	}

	consentCBOR, _ := ipfs.MarshalConsentPQ(&consentReq.EncryptedData)
	consentCid, _ := ipfs.GetCid(consentCBOR)

	_, aliceRevokePub, _ := DerivePQKeyPair(aliceWallet, bobPartyNo, consent, chainId, purposes.PulsePurposePQDeriveRevoke)
	revokeReq, err := EncryptSignRevokePQ(aliceWallet, []byte("revoke"), bobPartyNo, consent, []*kyberKEM.PublicKey{aliceRevokePub}, contractAddr, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ() failed: %v", err)
	}

	// Manually recover consent signers and revoke signer using helpers
	// (the wire types are PQ but the signing primitives are EC/secp256k1)
	consentCBORForSig, _ := ipfs.MarshalConsentPQ(&consentReq.EncryptedData)
	consentCidForSig, _ := ipfs.GetCid(consentCBORForSig)
	consentSignerAddr, err := GetConsentAddress(consentReq.Signatures[0], contractAddr, consentCidForSig.String())
	if err != nil {
		t.Fatalf("GetConsentAddress() failed: %v", err)
	}

	revokeCBOR, _ := ipfs.MarshalConsentPQ(&revokeReq.EncryptedData)
	revokeCid, _ := ipfs.GetCid(revokeCBOR)
	revokeSignerAddr, err := GetRevokeAddress(revokeReq.Signature, contractAddr, revokeReq.ConsentCid, revokeCid.String())
	if err != nil {
		t.Fatalf("GetRevokeAddress() failed: %v", err)
	}

	if consentSignerAddr != revokeSignerAddr {
		t.Errorf("consent signer %x != revoke signer %x — PQ signing keys are inconsistent", consentSignerAddr, revokeSignerAddr)
	}
}
