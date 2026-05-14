package crypto

/*
 * Known-value (KV) tests for the HD wallet PQ (ML-KEM-768) consent/revoke lifecycle.
 *
 * If you are implementing this protocol in another language, replicate these
 * tests to verify compatibility with the reference Go implementation.
 * All binary values are encoded as lowercase hex strings.
 *
 * Notary blocks are still encrypted with EC (ECDH), so those values are
 * identical to the EC KV test.  The consent and revoke payloads use PQ
 * (ML-KEM-768) encryption, which involves random KEM encapsulation —
 * therefore the encrypted output, CIDs, and signatures over those CIDs
 * are NOT deterministic across runs.  This test pins:
 *
 *   - All HD derivation paths (deterministic)
 *   - All derived secp256k1 keys for notary & signing (deterministic)
 *   - All derived ML-KEM-768 public key fingerprints (deterministic)
 *   - EC notary encryption output (deterministic, standalone notary key)
 *   - Signing key path and key material (deterministic)
 *   - Round-trip decrypt correctness (functional)
 *   - Signature recovery to correct addresses (functional)
 *
 * ── Test parameters (same as EC KV test) ─────────────────────────────────────
 *   Alice seed (BIP-32 Test Vector 1): 000102030405060708090a0b0c0d0e0f
 *   Bob seed:                          101112131415161718191a1b1c1d1e1f
 *   contractAddress: "0x0102030405060708091011121314"
 *   chainId:         1
 *   otherParty:      3  (Bob's party number from Alice's perspective)
 *   consentNumber:   2
 *
 * ── Lifecycle ────────────────────────────────────────────────────────────────
 *   1. Alice derives PQ consent key pair, Bob derives PQ consent key pair
 *   2. Alice encrypts notary data (EC)     → EncryptConsentNotaryEC (purpose 2)
 *   3. Alice builds consent plaintext       (notaryCBOR + consent payload)
 *   4. Alice encrypts + signs consent (PQ) → EncryptSignConsentPQ
 *   5. Bob counter-signs consent           → SignConsentRequest
 *   6. Both parties decrypt consent        → DecryptConsentPQ
 *   7. Alice derives PQ revoke key pair, Bob derives PQ revoke key pair
 *   8. Alice encrypts revoke notary (EC)   → EncryptRevokeNotaryEC (purpose 4)
 *   9. Alice encrypts + signs revoke (PQ)  → EncryptSignRevokePQ
 *  10. Bob decrypts revoke                 → DecryptRevokePQ
 */

import (
	"bytes"
	"encoding/hex"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// ── Known values (populated from first run with -v) ─────────────────────────
// To regenerate: clear all kvPQ* constants, run with -v, paste logged values.
//
// As of v1.1.0 the KEM uses NIST ML-KEM-768 (FIPS 203) via circl/kem/mlkem/mlkem768.
// Previously circl/kem/kyber/kyber768 (CRYSTALS-Kyber Round 3) was used; the
// fingerprint values changed because ML-KEM uses SHA3-512(seed || K) for key
// generation whereas Kyber R3 used SHA3-512(seed).
//
// PQ encryption is non-deterministic (random KEM), so only deterministic
// derivations are pinned.  Encrypted output, CIDs, and signatures are
// verified functionally (round-trip) rather than by known value.

const (
	// PQ consent key derivation (purpose 9 — PulsePurposePQDeriveConsent)
	kvPQConsentKeyPath       = "m/4410704'/3/1/2/9"
	kvPQAliceConsentPubFP    = "339dd3c75c1d9050c74a343b02babd5415bde0eace37a7d0ecc0682d750984d6" // NIST ML-KEM-768 public key fingerprint (Keccak256)
	kvPQBobConsentPubFP      = "83f0b64c4e38c3c8167f5286b9b079e926c91d15c140bc516bcd70b789e22331"
	kvPQConsentNodeAlicePriv = "7d3607e752508cf9e8e3188ef8db8890f5d7aac618865c9d4a52460f76d32a6b" // secp256k1 node key used to derive PQ seed
	kvPQConsentNodeAlicePub  = "02704fab5d7282c0e6719bcc762f2e45d481351741598483900b8e4c429d11e2b3"
	kvPQConsentNodeBobPriv   = "af988f9d0ab2f603851d56d20bd0eb3749814dd44bfd2d5d638f900cee0be74b"
	kvPQConsentNodeBobPub    = "03f7a0062f05bc7fc1f9187d80e22b72962195f198955a49ac0e2d86798ffb1db8"

	// Notary EC encryption (purpose 2 — EncryptConsentNotaryBlock, standalone notary key)
	kvPQNotaryPath      = "m/4410704'/3/1/2/2"
	kvPQNotaryAlicePriv = "de9ff0acd0e4774ec79ef72dd2e086b8e45e97214fed3cac5b7b352c94e8eeaa"
	kvPQNotaryAlicePub  = "03c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188"
	kvPQNotarySealedHex = "5633c336c4f8c6dcda0399783b83daf472b1023b49f522746780cecec098284fc39b162fb912866008591f865bba8389"

	// Signing key (purpose 1 — PulsePurposeSignTx, same for EC and PQ)
	kvPQSigningPath      = "m/4410704'/3/1/2/1"
	kvPQSigningAlicePriv = "abc5df3dacf1cfd8fb11cacf2a4b23688326dfb14f14f03bfd733057d89e3583"
	kvPQSigningAlicePub  = "0238e67685c6addffef2ba3f18d37d6ae4411b38753adfa89cceed5767093e7f44"
	kvPQSigningBobPriv   = "7619026ba76aa9b51a8480076296d8e92bea454ea40cadc49937964804e63cca"
	kvPQSigningBobPub    = "03fa4b3d0c976d2836cbf200e1b5f3935982b2a6bbd71b74b69d703cae5b9b6a40"

	// PQ revoke key derivation (purpose 10 — PulsePurposePQDeriveRevoke)
	kvPQRevokeKeyPath       = "m/4410704'/3/1/2/10"
	kvPQAliceRevokePubFP    = "bffe71771b9b84ccec7b2c9cb24ae736a128f25bffed5e197ad56c3c31ded1bc" // NIST ML-KEM-768
	kvPQBobRevokePubFP      = "30a4275b6c98c1bd3e4f32db360d224e40cfae3b3ac62be10c1955215dda7512"
	kvPQRevokeNodeAlicePriv = "923b9ee0e2e2ef45d8c5b8f91ac02c4be9bf6982d71ab5751c928021abba52af"
	kvPQRevokeNodeAlicePub  = "03f3bb3680cfaec89a75fd0e99e8a20737e40f644f6c3243a8f058fd92ecc53aa4"
	kvPQRevokeNodeBobPriv   = "8162d312cd9f751121b09ddd34b3d4f57ba056c73cd9c9d1c83367e3d4372be8"
	kvPQRevokeNodeBobPub    = "03f8998a3047c33e613107cfe9d68d142000c25e9e2efeb344ad4319eefb169545"

	// Revoke notary EC encryption (purpose 4 — EncryptRevokeNotaryBlock, standalone notary key)
	kvPQRevokeNotaryPath      = "m/4410704'/3/1/2/4"
	kvPQRevokeNotaryAlicePriv = "fc216eb1fe324fef31308b8550dbd2e31e627143334d7dec596c9dd685c594bb"
	kvPQRevokeNotaryAlicePub  = "03ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8"
	kvPQRevokeNotarySealedHex = "efbddc817f89c54b6cb47afa479bcb7516456053683414762ccc5dd0b44f86d6d9267668cdc9f6ced99973ad147285d41d72941b92bb3f"
)

// pqPubKeyFingerprint returns the Keccak256 fingerprint of an ML-KEM public key,
// matching the fingerprint stored in PulsePQEncryptionKey.KeyFingerPrint.
func pqPubKeyFingerprint(pub *kyberKEM.PublicKey) []byte {
	packed := make([]byte, kyberKEM.PublicKeySize)
	pub.Pack(packed)
	h := make([]byte, 32)
	copy(h, hash.PulseHashBytes(packed))
	return h
}

func TestHDWalletPQ_KnownValues(t *testing.T) {
	// ── Fixed inputs (same as EC KV test) ────────────────────────────────
	aliceMaster := mustNewMasterKey(t)
	bobMaster := mustNewBobMasterKey(t)
	aliceWallet := &testWalletStore{key: aliceMaster}
	bobWallet := &testWalletStore{key: bobMaster}

	const (
		contractAddress = "0x0102030405060708091011121314"
		chainId         = uint32(1)
		otherParty      = uint32(3)
		consentNumber   = uint32(2)
	)
	notaryData := []byte("notary block payload for kv test")

	// ── Step 1: Derive PQ consent key pairs ──────────────────────────────
	aliceConsentPrivPQ, aliceConsentPubPQ, err := DerivePQKeyPair(aliceWallet, otherParty, consentNumber, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("Alice DerivePQKeyPair(consent): %v", err)
	}
	_, bobConsentPubPQ, err := DerivePQKeyPair(bobWallet, otherParty, consentNumber, chainId, purposes.PulsePurposePQDeriveConsent)
	if err != nil {
		t.Fatalf("Bob DerivePQKeyPair(consent): %v", err)
	}
	_ = aliceConsentPrivPQ // used in decrypt

	// Log and check PQ consent derivation
	consentKeyPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposePQDeriveConsent)
	consentNodeAlice, _ := deriveKeyFromMaster(aliceMaster, consentKeyPath)
	consentNodeBob, _ := deriveKeyFromMaster(bobMaster, consentKeyPath)

	aliceConsentFP := pqPubKeyFingerprint(aliceConsentPubPQ)
	bobConsentFP := pqPubKeyFingerprint(bobConsentPubPQ)

	t.Logf("PQ consent key path:         %s", consentKeyPath.String())
	t.Logf("PQ consent node Alice priv:  %s", textformat.FormatHex(consentNodeAlice.Serialize()))
	t.Logf("PQ consent node Alice pub:   %s", textformat.FormatHex(consentNodeAlice.PubKey().SerializeCompressed()))
	t.Logf("PQ consent node Bob priv:    %s", textformat.FormatHex(consentNodeBob.Serialize()))
	t.Logf("PQ consent node Bob pub:     %s", textformat.FormatHex(consentNodeBob.PubKey().SerializeCompressed()))
	t.Logf("PQ Alice consent pub FP:     %s", textformat.FormatHex(aliceConsentFP))
	t.Logf("PQ Bob consent pub FP:       %s", textformat.FormatHex(bobConsentFP))

	assertKV(t, "PQ consent key path", consentKeyPath.String(), kvPQConsentKeyPath)
	assertKVHex(t, "PQ consent node Alice priv", consentNodeAlice.Serialize(), kvPQConsentNodeAlicePriv)
	assertKVHex(t, "PQ consent node Alice pub", consentNodeAlice.PubKey().SerializeCompressed(), kvPQConsentNodeAlicePub)
	assertKVHex(t, "PQ consent node Bob priv", consentNodeBob.Serialize(), kvPQConsentNodeBobPriv)
	assertKVHex(t, "PQ consent node Bob pub", consentNodeBob.PubKey().SerializeCompressed(), kvPQConsentNodeBobPub)
	assertKVHex(t, "PQ Alice consent pub FP", aliceConsentFP, kvPQAliceConsentPubFP)
	assertKVHex(t, "PQ Bob consent pub FP", bobConsentFP, kvPQBobConsentPubFP)

	// ── Step 2: Alice encrypts notary data (EC, purpose 2) ──────────────
	// Notary uses a standalone key pair (same one used in EC KV test)
	_, notaryPub := mustNewNotaryKey(t)

	notaryPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptConsentNotaryBlock)
	notaryAlicePriv, _ := deriveKeyFromMaster(aliceMaster, notaryPath)

	notaryResult, err := EncryptConsentNotaryEC(aliceWallet, notaryData, otherParty, consentNumber, notaryPub, contractAddress, chainId)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC: %v", err)
	}

	t.Logf("Notary path:                 %s", notaryPath.String())
	t.Logf("Notary Alice priv:           %s", textformat.FormatHex(notaryAlicePriv.Serialize()))
	t.Logf("Notary Alice pub:            %s", textformat.FormatHex(notaryAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Notary sealed data:          %s", textformat.FormatHex(notaryResult.SealedData))

	assertKV(t, "Notary path", notaryPath.String(), kvPQNotaryPath)
	assertKVHex(t, "Notary Alice priv", notaryAlicePriv.Serialize(), kvPQNotaryAlicePriv)
	assertKVHex(t, "Notary Alice pub", notaryAlicePriv.PubKey().SerializeCompressed(), kvPQNotaryAlicePub)
	assertKVHex(t, "Notary sealed data", notaryResult.SealedData, kvPQNotarySealedHex)

	// ── Step 3: Build consent plaintext with embedded notary CBOR ────────
	notaryCBOR, err := ipfs.MarshalConsentEC(notaryResult)
	if err != nil {
		t.Fatalf("notary MarshalCBOR: %v", err)
	}
	consentPlaintext := append(notaryCBOR, []byte("|consent payload for kv test")...)
	t.Logf("Notary CBOR len:             %d bytes", len(notaryCBOR))
	t.Logf("Consent plaintext len:       %d bytes", len(consentPlaintext))

	// ── Step 4: Alice encrypts + signs consent (PQ) ──────────────────────
	consentReq, err := EncryptSignConsentPQ(aliceWallet, consentPlaintext, otherParty, consentNumber,
		[]*kyberKEM.PublicKey{aliceConsentPubPQ, bobConsentPubPQ}, contractAddress, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentPQ: %v", err)
	}

	if len(consentReq.EncryptedData.SealedData) == 0 {
		t.Fatal("PQ consent SealedData is empty")
	}
	if len(consentReq.EncryptedData.Keys) != 2 {
		t.Fatalf("expected 2 PQ keys, got %d", len(consentReq.EncryptedData.Keys))
	}
	t.Logf("PQ consent sealed len:       %d bytes", len(consentReq.EncryptedData.SealedData))
	t.Logf("PQ consent key[0] FP:        %s", textformat.FormatHex(consentReq.EncryptedData.Keys[0].KeyFingerPrint[:]))
	t.Logf("PQ consent key[1] FP:        %s", textformat.FormatHex(consentReq.EncryptedData.Keys[1].KeyFingerPrint[:]))

	// Verify key fingerprints match derived PQ public keys
	if !bytes.Equal(consentReq.EncryptedData.Keys[0].KeyFingerPrint[:], aliceConsentFP) &&
		!bytes.Equal(consentReq.EncryptedData.Keys[1].KeyFingerPrint[:], aliceConsentFP) {
		t.Error("Alice's PQ consent pub FP not found in encrypted keys")
	}
	if !bytes.Equal(consentReq.EncryptedData.Keys[0].KeyFingerPrint[:], bobConsentFP) &&
		!bytes.Equal(consentReq.EncryptedData.Keys[1].KeyFingerPrint[:], bobConsentFP) {
		t.Error("Bob's PQ consent pub FP not found in encrypted keys")
	}

	// Log signing key (deterministic)
	signingPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeSignTx)
	signingAlicePriv, _ := deriveKeyFromMaster(aliceMaster, signingPath)
	signingBobPriv, _ := deriveKeyFromMaster(bobMaster, signingPath)

	t.Logf("Signing path:                %s", signingPath.String())
	t.Logf("Signing Alice priv:          %s", textformat.FormatHex(signingAlicePriv.Serialize()))
	t.Logf("Signing Alice pub:           %s", textformat.FormatHex(signingAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Signing Bob priv:            %s", textformat.FormatHex(signingBobPriv.Serialize()))
	t.Logf("Signing Bob pub:             %s", textformat.FormatHex(signingBobPriv.PubKey().SerializeCompressed()))
	t.Logf("Alice consent sig:           %s", textformat.FormatHex(consentReq.Signatures[0]))

	assertKV(t, "Signing path", signingPath.String(), kvPQSigningPath)
	assertKVHex(t, "Signing Alice priv", signingAlicePriv.Serialize(), kvPQSigningAlicePriv)
	assertKVHex(t, "Signing Alice pub", signingAlicePriv.PubKey().SerializeCompressed(), kvPQSigningAlicePub)
	assertKVHex(t, "Signing Bob priv", signingBobPriv.Serialize(), kvPQSigningBobPriv)
	assertKVHex(t, "Signing Bob pub", signingBobPriv.PubKey().SerializeCompressed(), kvPQSigningBobPub)

	// Consent CID and Alice's address (non-deterministic CID, but address recovery must work)
	consentCBOR, _ := ipfs.MarshalConsentPQ(&consentReq.EncryptedData)
	consentCid, _ := ipfs.GetCid(consentCBOR)
	t.Logf("PQ consent CID:              %s", consentCid.String())

	aliceConsentAddr, err := GetConsentAddress(consentReq.Signatures[0], contractAddress, consentCid.String())
	if err != nil {
		t.Fatalf("GetConsentAddress(alice): %v", err)
	}
	t.Logf("Alice consent addr:          %s", hex.EncodeToString(aliceConsentAddr[:]))

	// ── Step 5: Bob counter-signs consent ────────────────────────────────
	if err := SignConsentRequest(bobWallet, consentReq, consentCBOR, otherParty, consentNumber, contractAddress, chainId); err != nil {
		t.Fatalf("SignConsentRequest(bob): %v", err)
	}
	if len(consentReq.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(consentReq.Signatures))
	}

	bobConsentAddr, err := GetConsentAddress(consentReq.Signatures[1], contractAddress, consentCid.String())
	if err != nil {
		t.Fatalf("GetConsentAddress(bob): %v", err)
	}
	t.Logf("Bob consent addr:            %s", hex.EncodeToString(bobConsentAddr[:]))

	// ── Step 6: Both parties decrypt consent ─────────────────────────────
	decryptedAlice, err := DecryptConsentPQ(aliceWallet, consentReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentPQ(alice): %v", err)
	}
	if !bytes.Equal(consentPlaintext, decryptedAlice) {
		t.Fatalf("Alice consent plaintext mismatch: got %q, want %q", decryptedAlice, consentPlaintext)
	}
	t.Logf("Alice decrypted consent:     %s", string(decryptedAlice))

	decryptedBob, err := DecryptConsentPQ(bobWallet, consentReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentPQ(bob): %v", err)
	}
	if !bytes.Equal(consentPlaintext, decryptedBob) {
		t.Fatalf("Bob consent plaintext mismatch")
	}
	t.Logf("Bob decrypted consent:       %d bytes (OK)", len(decryptedBob))

	// ── Step 6b: Alice decrypts embedded notary ─────────────────────────
	aliceDecryptedNotary, err := DecryptConsentNotaryEC(aliceWallet, notaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentNotaryEC(alice): %v", err)
	}
	if !bytes.Equal(notaryData, aliceDecryptedNotary) {
		t.Fatalf("Alice notary plaintext mismatch: got %q, want %q", aliceDecryptedNotary, notaryData)
	}
	t.Logf("Alice decrypted notary:      %s", string(aliceDecryptedNotary))

	// ── Step 6c: Bob cannot decrypt notary ──────────────────────────────
	_, err = DecryptConsentNotaryEC(bobWallet, notaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err == nil {
		t.Error("expected Bob to fail decrypting notary, but succeeded")
	} else {
		t.Logf("Bob notary decrypt:          failed as expected (%v)", err)
	}

	// ── Step 7: Derive PQ revoke key pairs ───────────────────────────────
	_, aliceRevokePubPQ, err := DerivePQKeyPair(aliceWallet, otherParty, consentNumber, chainId, purposes.PulsePurposePQDeriveRevoke)
	if err != nil {
		t.Fatalf("Alice DerivePQKeyPair(revoke): %v", err)
	}
	_, bobRevokePubPQ, err := DerivePQKeyPair(bobWallet, otherParty, consentNumber, chainId, purposes.PulsePurposePQDeriveRevoke)
	if err != nil {
		t.Fatalf("Bob DerivePQKeyPair(revoke): %v", err)
	}

	revokeKeyPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposePQDeriveRevoke)
	revokeNodeAlice, _ := deriveKeyFromMaster(aliceMaster, revokeKeyPath)
	revokeNodeBob, _ := deriveKeyFromMaster(bobMaster, revokeKeyPath)

	aliceRevokeFP := pqPubKeyFingerprint(aliceRevokePubPQ)
	bobRevokeFP := pqPubKeyFingerprint(bobRevokePubPQ)

	t.Logf("PQ revoke key path:          %s", revokeKeyPath.String())
	t.Logf("PQ revoke node Alice priv:   %s", textformat.FormatHex(revokeNodeAlice.Serialize()))
	t.Logf("PQ revoke node Alice pub:    %s", textformat.FormatHex(revokeNodeAlice.PubKey().SerializeCompressed()))
	t.Logf("PQ revoke node Bob priv:     %s", textformat.FormatHex(revokeNodeBob.Serialize()))
	t.Logf("PQ revoke node Bob pub:      %s", textformat.FormatHex(revokeNodeBob.PubKey().SerializeCompressed()))
	t.Logf("PQ Alice revoke pub FP:      %s", textformat.FormatHex(aliceRevokeFP))
	t.Logf("PQ Bob revoke pub FP:        %s", textformat.FormatHex(bobRevokeFP))

	assertKV(t, "PQ revoke key path", revokeKeyPath.String(), kvPQRevokeKeyPath)
	assertKVHex(t, "PQ revoke node Alice priv", revokeNodeAlice.Serialize(), kvPQRevokeNodeAlicePriv)
	assertKVHex(t, "PQ revoke node Alice pub", revokeNodeAlice.PubKey().SerializeCompressed(), kvPQRevokeNodeAlicePub)
	assertKVHex(t, "PQ revoke node Bob priv", revokeNodeBob.Serialize(), kvPQRevokeNodeBobPriv)
	assertKVHex(t, "PQ revoke node Bob pub", revokeNodeBob.PubKey().SerializeCompressed(), kvPQRevokeNodeBobPub)
	assertKVHex(t, "PQ Alice revoke pub FP", aliceRevokeFP, kvPQAliceRevokePubFP)
	assertKVHex(t, "PQ Bob revoke pub FP", bobRevokeFP, kvPQBobRevokePubFP)

	// ── Step 8: Alice encrypts revoke notary (EC, purpose 4) ────────────
	revokeNotaryData := []byte("revoke notary block payload for kv test")

	revokeNotaryPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptRevokeNotaryBlock)
	revokeNotaryAlicePriv, _ := deriveKeyFromMaster(aliceMaster, revokeNotaryPath)

	revokeNotaryResult, err := EncryptRevokeNotaryEC(aliceWallet, revokeNotaryData, otherParty, consentNumber, notaryPub, contractAddress, chainId)
	if err != nil {
		t.Fatalf("EncryptRevokeNotaryEC: %v", err)
	}

	t.Logf("Revoke notary path:          %s", revokeNotaryPath.String())
	t.Logf("Revoke notary Alice priv:    %s", textformat.FormatHex(revokeNotaryAlicePriv.Serialize()))
	t.Logf("Revoke notary Alice pub:     %s", textformat.FormatHex(revokeNotaryAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Revoke notary sealed:        %s", textformat.FormatHex(revokeNotaryResult.SealedData))

	assertKV(t, "Revoke notary path", revokeNotaryPath.String(), kvPQRevokeNotaryPath)
	assertKVHex(t, "Revoke notary Alice priv", revokeNotaryAlicePriv.Serialize(), kvPQRevokeNotaryAlicePriv)
	assertKVHex(t, "Revoke notary Alice pub", revokeNotaryAlicePriv.PubKey().SerializeCompressed(), kvPQRevokeNotaryAlicePub)
	assertKVHex(t, "Revoke notary sealed", revokeNotaryResult.SealedData, kvPQRevokeNotarySealedHex)

	// ── Step 9: Alice encrypts + signs revoke (PQ) ───────────────────────
	revokeNotaryCBOR, _ := ipfs.MarshalConsentEC(revokeNotaryResult)
	revokePlaintext := append(revokeNotaryCBOR, []byte("|revoke payload for kv test")...)
	t.Logf("Revoke notary CBOR len:      %d bytes", len(revokeNotaryCBOR))
	t.Logf("Revoke plaintext len:        %d bytes", len(revokePlaintext))

	revokeReq, err := EncryptSignRevokePQ(aliceWallet, revokePlaintext, otherParty, consentNumber,
		[]*kyberKEM.PublicKey{aliceRevokePubPQ, bobRevokePubPQ}, contractAddress, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokePQ: %v", err)
	}

	if len(revokeReq.EncryptedData.SealedData) == 0 {
		t.Fatal("PQ revoke SealedData is empty")
	}
	if len(revokeReq.EncryptedData.Keys) != 2 {
		t.Fatalf("expected 2 PQ revoke keys, got %d", len(revokeReq.EncryptedData.Keys))
	}
	t.Logf("PQ revoke sealed len:        %d bytes", len(revokeReq.EncryptedData.SealedData))
	t.Logf("PQ revoke key[0] FP:         %s", textformat.FormatHex(revokeReq.EncryptedData.Keys[0].KeyFingerPrint[:]))
	t.Logf("PQ revoke key[1] FP:         %s", textformat.FormatHex(revokeReq.EncryptedData.Keys[1].KeyFingerPrint[:]))

	// Verify revoke key fingerprints match derived PQ public keys
	if !bytes.Equal(revokeReq.EncryptedData.Keys[0].KeyFingerPrint[:], aliceRevokeFP) &&
		!bytes.Equal(revokeReq.EncryptedData.Keys[1].KeyFingerPrint[:], aliceRevokeFP) {
		t.Error("Alice's PQ revoke pub FP not found in encrypted keys")
	}
	if !bytes.Equal(revokeReq.EncryptedData.Keys[0].KeyFingerPrint[:], bobRevokeFP) &&
		!bytes.Equal(revokeReq.EncryptedData.Keys[1].KeyFingerPrint[:], bobRevokeFP) {
		t.Error("Bob's PQ revoke pub FP not found in encrypted keys")
	}

	// Revoke signature recovery
	revokeCBOR, _ := ipfs.MarshalConsentPQ(&revokeReq.EncryptedData)
	revokeCid, _ := ipfs.GetCid(revokeCBOR)
	t.Logf("PQ revoke CID (rcid):        %s", revokeCid.String())

	revokeAddr, err := GetRevokeAddress(revokeReq.Signature, contractAddress, consentCid.String(), revokeCid.String())
	if err != nil {
		t.Fatalf("GetRevokeAddress: %v", err)
	}
	t.Logf("Revoke Alice addr:           %s", hex.EncodeToString(revokeAddr[:]))

	// Revoke signer must be one of the consent signers
	// (RevokeSignerWasConsentSigner is EC-only; verify manually for PQ)
	if revokeAddr != aliceConsentAddr && revokeAddr != bobConsentAddr {
		t.Error("revoke signer was not a consent signer")
	}

	// ── Step 10: Both parties decrypt revoke; only Alice decrypts notary ─
	decryptedRevokeAlice, err := DecryptRevokePQ(aliceWallet, revokeReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokePQ(alice): %v", err)
	}
	if !bytes.Equal(revokePlaintext, decryptedRevokeAlice) {
		t.Fatalf("Alice revoke plaintext mismatch")
	}
	t.Logf("Alice decrypted revoke:      %d bytes (OK)", len(decryptedRevokeAlice))

	decryptedRevokeBob, err := DecryptRevokePQ(bobWallet, revokeReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokePQ(bob): %v", err)
	}
	if !bytes.Equal(revokePlaintext, decryptedRevokeBob) {
		t.Fatalf("Bob revoke plaintext mismatch")
	}
	t.Logf("Bob decrypted revoke:        %d bytes (OK)", len(decryptedRevokeBob))

	// Alice can decrypt revoke notary
	aliceDecryptedRevokeNotary, err := DecryptRevokeNotaryEC(aliceWallet, revokeNotaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokeNotaryEC(alice): %v", err)
	}
	if !bytes.Equal(revokeNotaryData, aliceDecryptedRevokeNotary) {
		t.Fatalf("Alice revoke notary plaintext mismatch")
	}
	t.Logf("Alice decrypted revoke notary: %s", string(aliceDecryptedRevokeNotary))

	// Bob cannot decrypt revoke notary
	_, err = DecryptRevokeNotaryEC(bobWallet, revokeNotaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err == nil {
		t.Error("expected Bob to fail decrypting revoke notary, but succeeded")
	} else {
		t.Logf("Bob revoke notary decrypt:   failed as expected (%v)", err)
	}
}
