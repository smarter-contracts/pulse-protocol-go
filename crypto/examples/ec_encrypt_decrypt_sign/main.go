// ec_encrypt_decrypt_sign demonstrates end-to-end use of the Pulse Protocol
// EC cryptographic operations using two HD wallets:
//
//   - Two wallets are created (Alice and Bob), each with their own BIP-32 master key
//   - Bob shares an extended public key (generator) so Alice can derive his encryption key
//   - Alice encrypts and signs a consent record addressed to Bob
//   - Bob counter-signs using his own wallet
//   - Both parties decrypt the consent record independently
//   - Signer addresses are recovered from the signatures
//   - Alice creates a revoke request bound to the original consent
//   - The revoke authorisation is verified
//
// In this simulation:
//   - Alice's identifier in Bob's wallet: alicePartyNo = 1
//   - Bob's identifier in Alice's wallet: bobPartyNo   = 2
//   - Both wallets agree on chainId, consentNumber, and purpose
//
// Run from the crypto/ directory:
//
//	go run ./examples/ec_encrypt_decrypt_sign
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	bip32 "github.com/jamesradley/go-bip32"
	"github.com/smarter-contracts/pulse-protocol-go/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// ── Wallet implementation ─────────────────────────────────────────────────────

// memoryWallet is a minimal in-memory implementation of crypto.Wallet.
// In production, replace this with a secure key store (e.g. HashiCorp Vault,
// Secure Enclave, HSM).  The crypto library never stores or exports key material
// — it only calls GetMasterKey() at the point of derivation.
type memoryWallet struct {
	name      string
	masterKey *bip32.Key
}

func (w *memoryWallet) GetMasterKey() (*bip32.Key, error) {
	return w.masterKey, nil
}

// newWallet generates a fresh random 32-byte seed and derives a BIP-32 master key.
// In a real application the seed would come from a BIP-39 mnemonic that the user
// has stored securely offline.
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

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	// ── Parameters ────────────────────────────────────────────────────────────
	//
	// Each party identifies the other by a stable uint32 number within their own
	// HD wallet tree.  In practice these come from an OtherPartyRegistry:
	//   alicePartyNo = registry.LookupOrCreate(alice's DID)   — Bob's view of Alice
	//   bobPartyNo   = registry.LookupOrCreate(bob's DID)     — Alice's view of Bob
	//
	// chainId and consentNumber must agree between both parties for the ECDH
	// shared secret to be the same on both sides.
	const (
		alicePartyNo  = uint32(1) // Alice's number in Bob's wallet
		bobPartyNo    = uint32(2) // Bob's number in Alice's wallet
		consentNumber = uint32(0) // first consent between these two parties on this chain
		chainId       = uint32(137)
	)
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"

	// Consent data — in a real system this would be a serialised consent schema
	// (e.g. a CBOR-encoded data-sharing agreement).
	consentData := []byte(`{"purpose":"marketing","scope":"email","expiry":"2027-01-01"}`)

	// ── Step 1: Create Alice's wallet ─────────────────────────────────────────
	section("1. Create Alice's wallet")

	alice, err := newWallet("Alice")
	must("create Alice's wallet", err)
	aliceMasterKey, err := alice.GetMasterKey()
	must("get Alice's master key", err)

	// ── Step 2: Create Bob's wallet ───────────────────────────────────────────
	section("2. Create Bob's wallet")

	bob, err := newWallet("Bob")
	must("create Bob's wallet", err)
	bobMasterKey, err := bob.GetMasterKey()
	must("get Bob's master key", err)

	// ── Step 3: Bob shares his encryption public key with Alice ───────────────
	//
	// Bob derives an extended public key (generator) for Alice at the path
	//   m/4410704'/alicePartyNo
	// and shares it with Alice.  Alice can use this to derive Bob's public key
	// for any (chain, consent, purpose) combination without ever seeing Bob's
	// private key.  In practice Bob would publish this to a DID document or
	// on-chain registry.
	section("3. Bob derives and shares his generator key for Alice")

	bobGeneratorForAlice, err := crypto.DeriveOtherPartyGenerator(bobMasterKey, alicePartyNo)
	must("Bob: DeriveOtherPartyGenerator", err)
	fmt.Printf("  [Bob] Generator public key (m/4410704'/%d): %s\n",
		alicePartyNo, hex.EncodeToString(bobGeneratorForAlice.Key))

	// Alice uses the generator to derive Bob's encryption public key for this
	// specific consent.  The derived key is at the path:
	//   m/4410704'/alicePartyNo/chainId/consentNumber/3  (EncryptConsentStructure)
	// from Bob's wallet — which Alice can compute without Bob's private key.
	bobEncPubKey, err := crypto.DerivePublicKeyFromParent(
		bobGeneratorForAlice,
		chainId,
		consentNumber,
		purposes.PulsePurposeEncryptConsentStructure,
	)
	must("Alice: DerivePublicKeyFromParent", err)
	fmt.Printf("  [Alice] Derived Bob's encryption public key: %s\n",
		hex.EncodeToString(bobEncPubKey.SerializeCompressed()))

	// ── Step 4: Alice encrypts and signs the consent record ───────────────────
	//
	// EncryptSignConsentEC:
	//   • Derives Alice's encryption key at m/4410704'/bobPartyNo/chainId/consentNumber/3
	//   • Performs ECDH with Bob's derived public key to encrypt the consent data
	//   • Derives Alice's signing key at m/4410704'/bobPartyNo/chainId/consentNumber/1
	//   • Signs the CID of the encrypted data (EIP-191)
	section("4. Alice encrypts and signs the consent record")

	fmt.Printf("  Plaintext (%d bytes): %s\n", len(consentData), consentData)

	consentRequest, err := crypto.EncryptSignConsentEC(
		aliceMasterKey,
		consentData,
		bobPartyNo,
		consentNumber,
		bobEncPubKey,
		contractAddress,
		chainId,
	)
	must("Alice: EncryptSignConsentEC", err)

	fmt.Printf("  Ciphertext length:          %d bytes\n", len(consentRequest.EncryptedData.SealedData))
	fmt.Printf("  Key1 (Alice's derived pubkey): %s\n",
		hex.EncodeToString(consentRequest.EncryptedData.Key1))
	fmt.Printf("  Key2 (Bob's derived pubkey):   %s\n",
		hex.EncodeToString(consentRequest.EncryptedData.Key2))
	fmt.Printf("  Signatures so far: %d\n", len(consentRequest.Signatures))
	fmt.Printf("  Alice's signature: %s\n",
		hex.EncodeToString(consentRequest.Signatures[0]))

	// Compute and display the consent CID — this is what gets stored on-chain
	// and referenced in any future revoke request.
	consentCBOR, err := consentRequest.EncryptedData.MarshalCBOR()
	must("marshal consent encrypted data to CBOR", err)
	consentCid, err := ipfs.GetCid(consentCBOR)
	must("compute consent CID", err)
	fmt.Printf("  Consent CID: %s\n", consentCid.String())

	// ── Step 5: Bob counter-signs ─────────────────────────────────────────────
	//
	// Bob receives the request, verifies the encrypted data, and appends his own
	// signature using his master key.  His signing key is at:
	//   m/4410704'/alicePartyNo/chainId/consentNumber/1  (SignTx)
	// Note that Bob uses alicePartyNo (his view of Alice), while Alice used
	// bobPartyNo (her view of Bob) — the otherPartyNo always refers to the
	// other party from the signer's perspective.
	//
	// SignConsentRequest works for any consent request type (EC or PQ).
	section("5. Bob counter-signs the consent record")

	must("Bob: SignConsentRequest", crypto.SignConsentRequest(
		bobMasterKey,
		consentRequest,
		alicePartyNo,  // Bob's view: Alice is the other party
		consentNumber,
		contractAddress,
		chainId,
	))
	fmt.Printf("  Signatures after counter-sign: %d\n", len(consentRequest.Signatures))
	fmt.Printf("  Bob's signature: %s\n",
		hex.EncodeToString(consentRequest.Signatures[1]))

	// ── Step 6: Decrypt the consent record ───────────────────────────────────
	//
	// Both parties can decrypt independently using their own HD wallet key.
	// DecryptConsentEC derives the encryption private key from the master key at
	// the same path used during encryption and calls DecryptEC.
	section("6. Both parties decrypt the consent record")

	decryptedByAlice, err := crypto.DecryptConsentEC(
		aliceMasterKey,
		consentRequest,
		bobPartyNo,    // Alice's view: Bob is the other party
		consentNumber,
		contractAddress,
		chainId,
	)
	must("Alice: DecryptConsentEC", err)
	fmt.Printf("  [Alice] Decrypted: %s\n", decryptedByAlice)

	decryptedByBob, err := crypto.DecryptConsentEC(
		bobMasterKey,
		consentRequest,
		alicePartyNo,  // Bob's view: Alice is the other party
		consentNumber,
		contractAddress,
		chainId,
	)
	must("Bob: DecryptConsentEC", err)
	fmt.Printf("  [Bob]   Decrypted: %s\n", decryptedByBob)

	// ── Step 7: Recover signer addresses ─────────────────────────────────────
	//
	// ConsentSigners recovers the Ethereum address for each signature.  These
	// addresses can be checked against an on-chain registry or whitelist to
	// confirm both authorised parties have signed.
	section("7. Recover signer addresses")

	signerAddresses, err := crypto.ConsentSigners(consentRequest, contractAddress)
	must("ConsentSigners", err)
	for i, addr := range signerAddresses {
		fmt.Printf("  Signature[%d] signed by: %s\n", i, addr.Hex())
	}

	// ── Step 8: Alice creates a revoke request ────────────────────────────────
	//
	// EncryptSignRevokeEC mirrors step 4 but uses the revoke encryption purpose
	// (m/.../5) and a signing message that binds together the consent CID and
	// the revoke data CID.  This prevents the revoke signature from being
	// replayed against a different consent record.
	section("8. Alice encrypts and signs a revoke request")

	revokeData := []byte(`{"reason":"withdrawn","timestamp":"2026-06-01T00:00:00Z"}`)
	fmt.Printf("  Revoke data (%d bytes): %s\n", len(revokeData), revokeData)

	// Alice needs Bob's public key for the revoke encryption path (purpose 5).
	bobRevokePubKey, err := crypto.DerivePublicKeyFromParent(
		bobGeneratorForAlice,
		chainId,
		consentNumber,
		purposes.PulsePurposeEncryptRevokeStructure,
	)
	must("Alice: DerivePublicKeyFromParent (revoke)", err)

	revokeRequest, err := crypto.EncryptSignRevokeEC(
		aliceMasterKey,
		revokeData,
		bobPartyNo,
		consentNumber,
		bobRevokePubKey,
		contractAddress,
		chainId,
		consentCid.String(),
	)
	must("Alice: EncryptSignRevokeEC", err)

	fmt.Printf("  Revoke ciphertext length: %d bytes\n", len(revokeRequest.EncryptedData.SealedData))
	fmt.Printf("  Bound to consent CID:     %s\n", revokeRequest.ConsentCid)
	fmt.Printf("  Alice's revoke signature: %s\n", hex.EncodeToString(revokeRequest.Signature))

	// ── Step 9: Verify revoke authorisation ──────────────────────────────────
	//
	// RevokeSignerWasConsentSigner confirms that the revoke was signed by one of
	// the original consent signers.  This is the chain-of-authorisation check
	// the mid-tier performs before accepting a revocation.
	section("9. Verify revoke authorisation")

	authorised, err := crypto.RevokeSignerWasConsentSigner(revokeRequest, consentRequest, contractAddress)
	must("RevokeSignerWasConsentSigner", err)
	if authorised {
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
