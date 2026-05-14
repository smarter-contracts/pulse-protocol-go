// pq_encrypt_decrypt_sign demonstrates end-to-end use of the Pulse Protocol
// post-quantum cryptographic operations using two HD wallets:
//
//   - Two wallets are created (Alice and Bob), each with their own BIP-32 master key
//   - Each party derives an ML-KEM-768 key pair from their HD wallet for consent and revoke
//   - Alice shares her encapsulation (public) key with Bob and vice versa
//   - Alice encrypts and signs a consent record addressed to both parties
//   - Bob counter-signs using his own wallet
//   - Both parties decrypt the consent record independently
//   - Signer addresses are recovered from the secp256k1 signatures
//   - Alice creates a PQ revoke request bound to the original consent
//   - The revoke signing address is confirmed to match the original consent signer
//
// The encryption uses ML-KEM-768 (Kyber768) hybrid encryption: a random AES-256-GCM
// key encrypts the data, then the AES key is encapsulated once per recipient using
// ML-KEM-768.  Signing remains secp256k1/EIP-191 — identical to the EC variant.
//
// Run from the crypto/ directory:
//
//	go run ./examples/pq_encrypt_decrypt_sign
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	kyberKEM "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	bip32 "github.com/jamesradley/go-bip32"
	"github.com/smarter-contracts/pulse-protocol-go/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// ── Wallet implementation ─────────────────────────────────────────────────────

type memoryWallet struct {
	name      string
	masterKey *bip32.Key
}

func (w *memoryWallet) GetMasterKey() (*bip32.Key, error) {
	return w.masterKey, nil
}

func newWallet(name string) (*memoryWallet, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generating seed: %w", err)
	}
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("deriving master key: %w", err)
	}
	fmt.Printf("  [%s] Seed (keep secret!):  %s\n", name, hex.EncodeToString(seed))
	fmt.Printf("  [%s] Master public key:    %s\n", name, hex.EncodeToString(masterKey.PublicKey().Key))
	return &memoryWallet{name: name, masterKey: masterKey}, nil
}

// packPubKey serialises a Kyber768 public key to a hex string for display.
func packPubKey(pk *kyberKEM.PublicKey) string {
	buf := make([]byte, kyberKEM.PublicKeySize)
	pk.Pack(buf)
	return hex.EncodeToString(buf[:8]) + "…" // show first 8 bytes for brevity
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// ── Parameters ────────────────────────────────────────────────────────────
	//
	// alicePartyNo = Alice's index in Bob's wallet tree
	// bobPartyNo   = Bob's index in Alice's wallet tree
	const (
		alicePartyNo  = uint32(1)
		bobPartyNo    = uint32(2)
		consentNumber = uint32(0)
		chainId       = uint32(137)
	)
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"

	consentData := []byte(`{"purpose":"marketing","scope":"email","expiry":"2027-01-01"}`)

	// ── Step 1: Create Alice's wallet ─────────────────────────────────────────
	section("1. Create Alice's wallet")

	alice, err := newWallet("Alice")
	must("create Alice's wallet", err)

	// ── Step 2: Create Bob's wallet ───────────────────────────────────────────
	section("2. Create Bob's wallet")

	bob, err := newWallet("Bob")
	must("create Bob's wallet", err)

	// ── Step 3: Each party derives and shares their ML-KEM consent public key ─
	//
	// Unlike EC (where Bob can share a single extended public key generator),
	// ML-KEM has no hierarchical public key derivation.  Each party must derive
	// their ML-KEM key pair for a specific (otherParty, chain, consent, purpose)
	// and share the encapsulation (public) key out-of-band.
	//
	// In practice these keys would be registered in a DID document, published
	// on-chain, or delivered via a pre-key bundle (similar to Signal's X3DH).
	section("3. Both parties derive and share their ML-KEM consent public keys")

	// Alice derives her consent ML-KEM key pair (from Bob's perspective: alicePartyNo)
	// She uses bobPartyNo here because she is deriving her own key in her own wallet
	// (Alice identifies Bob as party #2 in her wallet).
	aliceConsentPriv, aliceConsentPub, err := crypto.DerivePQKeyPair(
		alice, bobPartyNo, consentNumber, chainId,
		purposes.PulsePurposePQDeriveConsent,
	)
	must("Alice: DerivePQKeyPair (consent)", err)
	fmt.Printf("  [Alice] Consent encapsulation key (first 8 bytes): %s\n", packPubKey(aliceConsentPub))

	// Bob derives his consent ML-KEM key pair
	_, bobConsentPub, err := crypto.DerivePQKeyPair(
		bob, alicePartyNo, consentNumber, chainId,
		purposes.PulsePurposePQDeriveConsent,
	)
	must("Bob: DerivePQKeyPair (consent)", err)
	fmt.Printf("  [Bob]   Consent encapsulation key (first 8 bytes): %s\n", packPubKey(bobConsentPub))

	_ = aliceConsentPriv // used via DecryptConsentPQ below

	// ── Step 4: Alice encrypts and signs the consent record ───────────────────
	//
	// EncryptSignConsentPQ:
	//   • Encrypts with ML-KEM-768 hybrid encryption for both Alice and Bob
	//   • Signs the CID of the encrypted data using Alice's signing key at
	//     m/4410704'/bobPartyNo/chainId/consentNumber/1 (SignTx)
	section("4. Alice encrypts and signs the consent record (PQ)")

	fmt.Printf("  Plaintext (%d bytes): %s\n", len(consentData), consentData)

	consentRequest, err := crypto.EncryptSignConsentPQ(
		alice,
		consentData,
		bobPartyNo,
		consentNumber,
		[]*kyberKEM.PublicKey{aliceConsentPub, bobConsentPub},
		contractAddress,
		chainId,
	)
	must("Alice: EncryptSignConsentPQ", err)

	fmt.Printf("  Ciphertext length:      %d bytes\n", len(consentRequest.EncryptedData.SealedData))
	fmt.Printf("  Encapsulated keys:      %d (one per recipient)\n", len(consentRequest.EncryptedData.Keys))
	fmt.Printf("  Signatures so far:      %d\n", len(consentRequest.Signatures))
	fmt.Printf("  Alice's signature:      %s\n", hex.EncodeToString(consentRequest.Signatures[0]))

	consentCBOR, err := ipfs.MarshalConsentPQ(&consentRequest.EncryptedData)
	must("marshal consent encrypted data to CBOR", err)
	consentCid, err := ipfs.GetCid(consentCBOR)
	must("compute consent CID", err)
	fmt.Printf("  Consent CID:            %s\n", consentCid.String())

	// ── Step 5: Bob counter-signs ─────────────────────────────────────────────
	//
	// SignConsentRequest works identically for EC and PQ request types — both
	// implement the SignableConsent interface.
	section("5. Bob counter-signs the consent record")

	must("Bob: SignConsentRequest", crypto.SignConsentRequest(
		bob,
		consentRequest,
		consentCBOR,
		alicePartyNo,
		consentNumber,
		contractAddress,
		chainId,
	))
	fmt.Printf("  Signatures after counter-sign: %d\n", len(consentRequest.Signatures))
	fmt.Printf("  Bob's signature:               %s\n", hex.EncodeToString(consentRequest.Signatures[1]))

	// ── Step 6: Decrypt the consent record ───────────────────────────────────
	//
	// Each party derives their ML-KEM private key from their own wallet and
	// calls DecryptConsentPQ.
	section("6. Both parties decrypt the consent record")

	decryptedByAlice, err := crypto.DecryptConsentPQ(
		alice,
		consentRequest,
		bobPartyNo,
		consentNumber,
		contractAddress,
		chainId,
	)
	must("Alice: DecryptConsentPQ", err)
	fmt.Printf("  [Alice] Decrypted: %s\n", decryptedByAlice)

	decryptedByBob, err := crypto.DecryptConsentPQ(
		bob,
		consentRequest,
		alicePartyNo,
		consentNumber,
		contractAddress,
		chainId,
	)
	must("Bob: DecryptConsentPQ", err)
	fmt.Printf("  [Bob]   Decrypted: %s\n", decryptedByBob)

	// ── Step 7: Recover signer addresses ─────────────────────────────────────
	//
	// The signing key (SignTx, purpose 1) is a secp256k1 key — identical to the
	// EC scheme.  We recover Ethereum addresses from each signature using the
	// same GetConsentAddress helper used by the EC variant.
	section("7. Recover signer addresses")

	consentCidStr := consentCid.String()
	for i, sig := range consentRequest.Signatures {
		addr, err := crypto.GetConsentAddress(sig, contractAddress, consentCidStr)
		must(fmt.Sprintf("GetConsentAddress[%d]", i), err)
		fmt.Printf("  Signature[%d] signed by: %s\n", i, hex.EncodeToString(addr[:]))
	}

	// ── Step 8: Derive PQ revoke keys and create revoke request ───────────────
	//
	// PulsePurposePQDeriveRevoke (10) produces a different ML-KEM key pair
	// from PulsePurposePQDeriveConsent (9) — the two are cryptographically
	// unlinkable.
	section("8. Both parties derive their ML-KEM revoke public keys")

	_, aliceRevokePub, err := crypto.DerivePQKeyPair(
		alice, bobPartyNo, consentNumber, chainId,
		purposes.PulsePurposePQDeriveRevoke,
	)
	must("Alice: DerivePQKeyPair (revoke)", err)
	_, bobRevokePub, err := crypto.DerivePQKeyPair(
		bob, alicePartyNo, consentNumber, chainId,
		purposes.PulsePurposePQDeriveRevoke,
	)
	must("Bob: DerivePQKeyPair (revoke)", err)
	fmt.Printf("  [Alice] Revoke encapsulation key (first 8 bytes): %s\n", packPubKey(aliceRevokePub))
	fmt.Printf("  [Bob]   Revoke encapsulation key (first 8 bytes): %s\n", packPubKey(bobRevokePub))

	// ── Step 9: Alice creates a PQ revoke request ─────────────────────────────
	section("9. Alice encrypts and signs a PQ revoke request")

	revokeData := []byte(`{"reason":"withdrawn","timestamp":"2026-06-01T00:00:00Z"}`)
	fmt.Printf("  Revoke data (%d bytes): %s\n", len(revokeData), revokeData)

	revokeRequest, err := crypto.EncryptSignRevokePQ(
		alice,
		revokeData,
		bobPartyNo,
		consentNumber,
		[]*kyberKEM.PublicKey{aliceRevokePub, bobRevokePub},
		contractAddress,
		chainId,
		consentCid.String(),
	)
	must("Alice: EncryptSignRevokePQ", err)

	fmt.Printf("  Revoke ciphertext length: %d bytes\n", len(revokeRequest.EncryptedData.SealedData))
	fmt.Printf("  Bound to consent CID:     %s\n", revokeRequest.ConsentCid)
	fmt.Printf("  Alice's revoke signature: %s\n", hex.EncodeToString(revokeRequest.Signature))

	// ── Step 10: Confirm revoke signer matches a consent signer ───────────────
	//
	// Recover Alice's address from both the consent signature and the revoke
	// signature, then confirm they are the same Ethereum address.
	section("10. Confirm revoke signer was a consent signer")

	revokeCBOR, err := ipfs.MarshalConsentPQ(&revokeRequest.EncryptedData)
	must("marshal revoke encrypted data", err)
	revokeCid, err := ipfs.GetCid(revokeCBOR)
	must("compute revoke CID", err)

	revokeAddr, err := crypto.GetRevokeAddress(revokeRequest.Signature, contractAddress, revokeRequest.ConsentCid, revokeCid.String())
	must("GetRevokeAddress", err)

	consentAddr, err := crypto.GetConsentAddress(consentRequest.Signatures[0], contractAddress, consentCidStr)
	must("GetConsentAddress (Alice)", err)

	fmt.Printf("  Consent signer address: %s\n", hex.EncodeToString(consentAddr[:]))
	fmt.Printf("  Revoke  signer address: %s\n", hex.EncodeToString(revokeAddr[:]))

	if consentAddr == revokeAddr {
		fmt.Println("  ✓ Revoke signer is an authorised consent signer")
	} else {
		fmt.Println("  ✗ Revoke signer is NOT an authorised consent signer")
	}

	fmt.Println()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func section(title string) {
	fmt.Printf("\n── %s\n", title)
}

func must(op string, err error) {
	if err != nil {
		log.Fatalf("FATAL: %s: %v", op, err)
	}
}
