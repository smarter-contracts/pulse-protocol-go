package crypto

/*
 * Known-value (KV) tests for the HD wallet EC consent/revoke lifecycle.
 *
 * If you are implementing this protocol in another language, replicate these
 * tests to verify compatibility with the reference Go implementation.
 * All binary values are encoded as lowercase hex strings.
 *
 * ── Test parameters ──────────────────────────────────────────────────────────
 *   Alice seed (BIP-32 Test Vector 1): 000102030405060708090a0b0c0d0e0f
 *   Bob seed:                          101112131415161718191a1b1c1d1e1f
 *   Notary private key (hex):          aa01020304050607080910111213141516171819202122232425262728293031
 *   contractAddress: "0x0102030405060708091011121314"
 *   chainId:         1
 *   otherParty:      3  (Bob's party number from Alice's perspective)
 *   consentNumber:   2
 *   notaryData:      "notary block payload for kv test"
 *   consentData:     constructed as notaryCBOR + "|consent payload for kv test"
 *   revokeNotaryData: "revoke notary block payload for kv test"
 *   revokeData:      constructed as revokeNotaryCBOR + "|revoke payload for kv test"
 *
 * ── Notary key ───────────────────────────────────────────────────────────────
 *   The notary public key is a standalone secp256k1 key pair (not derived from
 *   any HD wallet).  The same notary key is used for both consent and revoke
 *   notary blocks.  Only Alice (the HD wallet holder) can decrypt the notary;
 *   Bob can decrypt the outer consent/revoke structure but NOT the embedded
 *   notary.
 *
 * ── Lifecycle ────────────────────────────────────────────────────────────────
 *   1. Alice encrypts notary data          → EncryptConsentNotaryEC (purpose 2)
 *   2. Alice builds consent plaintext       (notaryCBOR + consent payload)
 *   3. Alice encrypts + signs consent      → EncryptSignConsentEC   (purpose 3)
 *   4. Bob counter-signs consent           → SignConsentRequest
 *   5. Both parties decrypt consent        → DecryptConsentEC
 *   6. Alice decrypts embedded notary      → DecryptConsentNotaryEC
 *   7. Bob cannot decrypt embedded notary  (negative test)
 *   8. Alice encrypts revoke notary data   → EncryptRevokeNotaryEC  (purpose 4)
 *   9. Alice encrypts + signs revoke       → EncryptSignRevokeEC    (purpose 5)
 *  10. Both parties decrypt revoke; only Alice decrypts revoke notary
 */

import (
	"bytes"
	"encoding/hex"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	bip32 "github.com/jamesradley/go-bip32"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// ── Fixed seeds ──────────────────────────────────────────────────────────────

var kvBobSeed = []byte{
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

func mustNewBobMasterKey(t *testing.T) *bip32.Key {
	t.Helper()
	key, err := bip32.NewMasterKey(kvBobSeed)
	if err != nil {
		t.Fatalf("NewMasterKey(bob) failed: %v", err)
	}
	return key
}

// kvNotarySeed is a fixed 32-byte private key for the standalone notary key pair.
// This is NOT derived from any HD wallet — it represents the notary service's key.
var kvNotarySeed, _ = hex.DecodeString("aa01020304050607080910111213141516171819202122232425262728293031")

func mustNewNotaryKey(t *testing.T) (*secp.PrivateKey, *secp.PublicKey) {
	t.Helper()
	priv := secp.PrivKeyFromBytes(kvNotarySeed)
	return priv, priv.PubKey()
}

// ── Known values (populated from first run with -v) ─────────────────────────
// To regenerate: clear all kv* constants, run with -v, paste logged values.

const (
	// Notary key (standalone, not from wallet)
	kvNotaryPubHex = "02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805" // compressed secp256k1 public key of the notary

	// Notary encryption (purpose 2 — EncryptConsentNotaryBlock)
	kvNotaryPath      = "m/4410704'/3/1/2/2"
	kvNotaryAlicePriv = "de9ff0acd0e4774ec79ef72dd2e086b8e45e97214fed3cac5b7b352c94e8eeaa"
	kvNotaryAlicePub  = "03c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188"
	kvNotarySealedHex = "5633c336c4f8c6dcda0399783b83daf472b1023b49f522746780cecec098284fc39b162fb912866008591f865bba8389"

	// Consent encryption (purpose 3 — EncryptConsentStructure)
	kvConsentPath      = "m/4410704'/3/1/2/3"
	kvConsentAlicePriv = "61e1d6824a3faf93e939d06471854c887497d2a7e93bb3fbfe23ea643009682c"
	kvConsentAlicePub  = "02759a7c74a13b454e94c4846d0ee14366d4f8716bd6bc1fce99507952e7220a2c"
	kvConsentSealedHex = "db219c2219c93f39a70afd40327b0853662991b123a8056a6415e6b95cbe896edf976ab220d20cd91654e1ec105d4a48eb0282eed2fa57ad1a68d047a0038ae8806c14ab61b0f85bd62b68655740c0240fd54697952996c7121172a0af2f9cea878ca2c6a441749454599896d0d098f7bb34d738a4d91e7022731f19834f71d4bb9bf3c3e9f53b20310ae4ed73569acbfe10f6df79d9ac838e5d375c52c6f1a72fbf7e8cae1589dcf9ecfcb9d5c1e4b0ff50b2f9fdc7"
	kvConsentCid       = "bafyreiabnu633o7opc26xejbewl22zsuhao4kjoeuayzhfep3h2nzfir6i"

	// Consent signatures
	kvAliceConsentSigHex = "25ae549d74b2ce9eba99926a6004ca7348fee56627f0b9567f782b8433c4ca1e1e7fc07dc433341c66c4e85f3227c390842dd281ceacbf627adf298df79cb5b91b"
	kvBobConsentSigHex   = "e99dec3d32237d06252c37e002f05c2da522c5d74b321893d8e28ecc77c37bbb42668c6b1bbed29629d44cb2f1fb1dca5836e6a74d3c41af2d396cef8f22b80f1c"
	kvAliceConsentAddr   = "1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0"
	kvBobConsentAddr     = "a897e536ce08d36cd12387b21dbe0053f4c091c7"

	// Revoke notary encryption (purpose 4 — EncryptRevokeNotaryBlock)
	kvRevokeNotaryPath      = "m/4410704'/3/1/2/4"
	kvRevokeNotaryAlicePriv = "fc216eb1fe324fef31308b8550dbd2e31e627143334d7dec596c9dd685c594bb"
	kvRevokeNotaryAlicePub  = "03ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8"
	kvRevokeNotarySealedHex = "efbddc817f89c54b6cb47afa479bcb7516456053683414762ccc5dd0b44f86d6d9267668cdc9f6ced99973ad147285d41d72941b92bb3f"

	// Revoke encryption (purpose 5 — EncryptRevokeStructure)
	kvRevokePath      = "m/4410704'/3/1/2/5"
	kvRevokeAlicePriv = "e36c8f883748b24f1ce6c2202c0f9eea257b7d8e6ddb334130dd2878b7c74731"
	kvRevokeAlicePub  = "03ee864493c54357eefca45c3531d444650cc30dd1e15e82c990f069b11ad07993"
	kvRevokeSealedHex = "53e53faaabf5c36457e1a4a36cff83fe517728e32f7f526ac05991355b4c1f6dfa98cafa9f6bd652439a911d11e12bbef2290cbb7e6c39bac36e65c3b85fc206bee68360ac82f9eeffe09b12b24a4cdf07c28894c2b56dfd0eedc173499183af5cbe45cde0e24146306bbe8bc18598663bdb38452268966fd02261cc5c57c90c27fe0d4f80c7e4624d442f82b2bdc9453189bc077111bad6df3b466bc4b97888444daac402976a31690888e463b44ef3b35af0abdac2b399d969f3eb"
	kvRevokeCid       = "bafyreicugoorid62wdueq6fjj5elgrd3az2zeyp6nws353g4kh3km7tqy4"

	// Revoke signature
	kvRevokeAliceSigHex = "1124ea27c9eca5072fbfb2a45156b72a3692e0b1c0a8ab3791579d12e5120127474a8bbddbf488dce638ad3cfba31589ec1f99fae4d687979a3f9aed5d97bb091c"
	kvRevokeAliceAddr   = "1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0"
)

func TestHDWalletEC_KnownValues(t *testing.T) {
	// ── Fixed inputs ─────────────────────────────────────────────────────
	aliceMaster := mustNewMasterKey(t)
	bobMaster := mustNewBobMasterKey(t)
	notaryPriv, notaryPub := mustNewNotaryKey(t)
	_ = notaryPriv // only needed for negative decrypt test reference

	const (
		contractAddress = "0x0102030405060708091011121314"
		chainId         = uint32(1)
		otherParty      = uint32(3) // Bob's party number
		consentNumber   = uint32(2)
	)
	notaryData := []byte("notary block payload for kv test")

	t.Logf("Notary pub key:         %s", textformat.FormatHex(notaryPub.SerializeCompressed()))
	assertKVHex(t, "Notary pub key", notaryPub.SerializeCompressed(), kvNotaryPubHex)

	// Derive Bob's encryption public key for the consent structure purpose
	bobConsentPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptConsentStructure)
	bobConsentPriv, err := deriveKeyFromMaster(bobMaster, bobConsentPath)
	if err != nil {
		t.Fatalf("derive Bob consent key: %v", err)
	}
	bobConsentPub := bobConsentPriv.PubKey()

	// ── Step 1: Alice encrypts notary data (purpose 2) ──────────────────
	notaryPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptConsentNotaryBlock)
	notaryAlicePriv, _ := deriveKeyFromMaster(aliceMaster, notaryPath)

	notaryResult, err := EncryptConsentNotaryEC(aliceMaster, notaryData, otherParty, consentNumber, notaryPub, contractAddress, chainId)
	if err != nil {
		t.Fatalf("EncryptConsentNotaryEC: %v", err)
	}

	t.Logf("Notary path:            %s", notaryPath.String())
	t.Logf("Notary Alice priv:      %s", textformat.FormatHex(notaryAlicePriv.Serialize()))
	t.Logf("Notary Alice pub:       %s", textformat.FormatHex(notaryAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Notary sealed data:     %s", textformat.FormatHex(notaryResult.SealedData))

	assertKV(t, "Notary path", notaryPath.String(), kvNotaryPath)
	assertKVHex(t, "Notary Alice priv", notaryAlicePriv.Serialize(), kvNotaryAlicePriv)
	assertKVHex(t, "Notary Alice pub", notaryAlicePriv.PubKey().SerializeCompressed(), kvNotaryAlicePub)
	assertKVHex(t, "Notary sealed data", notaryResult.SealedData, kvNotarySealedHex)

	// ── Step 2: Build consent plaintext with embedded notary CBOR ────────
	notaryCBOR, err := notaryResult.MarshalCBOR()
	if err != nil {
		t.Fatalf("notary MarshalCBOR: %v", err)
	}
	consentPlaintext := append(notaryCBOR, []byte("|consent payload for kv test")...)
	t.Logf("Notary CBOR len:        %d bytes", len(notaryCBOR))
	t.Logf("Consent plaintext len:  %d bytes", len(consentPlaintext))

	// ── Step 3: Alice encrypts + signs consent (purpose 3) ──────────────
	consentPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptConsentStructure)
	consentAlicePriv, _ := deriveKeyFromMaster(aliceMaster, consentPath)

	consentReq, err := EncryptSignConsentEC(aliceMaster, consentPlaintext, otherParty, consentNumber, bobConsentPub, contractAddress, chainId)
	if err != nil {
		t.Fatalf("EncryptSignConsentEC: %v", err)
	}

	consentCBOR, err := consentReq.EncryptedData.MarshalCBOR()
	if err != nil {
		t.Fatalf("consent MarshalCBOR: %v", err)
	}
	consentCid, err := ipfs.GetCid(consentCBOR)
	if err != nil {
		t.Fatalf("consent GetCid: %v", err)
	}

	t.Logf("Consent path:           %s", consentPath.String())
	t.Logf("Consent Alice priv:     %s", textformat.FormatHex(consentAlicePriv.Serialize()))
	t.Logf("Consent Alice pub:      %s", textformat.FormatHex(consentAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Consent sealed data:    %s", textformat.FormatHex(consentReq.EncryptedData.SealedData))
	t.Logf("Consent CID:            %s", consentCid.String())
	t.Logf("Alice consent sig:      %s", textformat.FormatHex(consentReq.Signatures[0]))

	assertKV(t, "Consent path", consentPath.String(), kvConsentPath)
	assertKVHex(t, "Consent Alice priv", consentAlicePriv.Serialize(), kvConsentAlicePriv)
	assertKVHex(t, "Consent Alice pub", consentAlicePriv.PubKey().SerializeCompressed(), kvConsentAlicePub)
	assertKVHex(t, "Consent sealed data", consentReq.EncryptedData.SealedData, kvConsentSealedHex)
	assertKV(t, "Consent CID", consentCid.String(), kvConsentCid)
	assertKVHex(t, "Alice consent sig", consentReq.Signatures[0], kvAliceConsentSigHex)

	// Alice consent address
	aliceConsentAddr, err := GetConsentAddress(consentReq.Signatures[0], contractAddress, consentCid.String())
	if err != nil {
		t.Fatalf("GetConsentAddress(alice): %v", err)
	}
	t.Logf("Alice consent addr:     %s", hex.EncodeToString(aliceConsentAddr[:]))
	assertKV(t, "Alice consent addr", hex.EncodeToString(aliceConsentAddr[:]), kvAliceConsentAddr)

	// ── Step 4: Bob counter-signs consent ────────────────────────────────
	if err := SignConsentRequest(bobMaster, consentReq, otherParty, consentNumber, contractAddress, chainId); err != nil {
		t.Fatalf("SignConsentRequest(bob): %v", err)
	}
	if len(consentReq.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(consentReq.Signatures))
	}

	t.Logf("Bob consent sig:        %s", textformat.FormatHex(consentReq.Signatures[1]))
	assertKVHex(t, "Bob consent sig", consentReq.Signatures[1], kvBobConsentSigHex)

	bobConsentAddr, err := GetConsentAddress(consentReq.Signatures[1], contractAddress, consentCid.String())
	if err != nil {
		t.Fatalf("GetConsentAddress(bob): %v", err)
	}
	t.Logf("Bob consent addr:       %s", hex.EncodeToString(bobConsentAddr[:]))
	assertKV(t, "Bob consent addr", hex.EncodeToString(bobConsentAddr[:]), kvBobConsentAddr)

	// ── Step 5: Both parties decrypt consent ─────────────────────────────
	decryptedBob, err := DecryptConsentEC(bobMaster, consentReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentEC(bob): %v", err)
	}
	if !bytes.Equal(consentPlaintext, decryptedBob) {
		t.Fatalf("Bob consent plaintext mismatch: got %d bytes, want %d bytes", len(decryptedBob), len(consentPlaintext))
	}
	t.Logf("Bob decrypted consent:  %d bytes (OK)", len(decryptedBob))

	decryptedAlice, err := DecryptConsentEC(aliceMaster, consentReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentEC(alice): %v", err)
	}
	if !bytes.Equal(consentPlaintext, decryptedAlice) {
		t.Fatalf("Alice consent plaintext mismatch")
	}
	t.Logf("Alice decrypted consent: %d bytes (OK)", len(decryptedAlice))

	// ── Step 6: Alice decrypts embedded notary ──────────────────────────
	aliceDecryptedNotary, err := DecryptConsentNotaryEC(aliceMaster, notaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentNotaryEC(alice): %v", err)
	}
	if !bytes.Equal(notaryData, aliceDecryptedNotary) {
		t.Fatalf("Alice notary plaintext mismatch: got %q, want %q", aliceDecryptedNotary, notaryData)
	}
	t.Logf("Alice decrypted notary: %s", string(aliceDecryptedNotary))

	// ── Step 7: Bob cannot decrypt notary ────────────────────────────────
	// Bob does not hold the notary private key, and his HD wallet derives a
	// different key at the notary block purpose, so DecryptConsentNotaryEC
	// must fail when called with Bob's master key.
	_, err = DecryptConsentNotaryEC(bobMaster, notaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err == nil {
		t.Error("expected Bob to fail decrypting notary, but succeeded")
	} else {
		t.Logf("Bob notary decrypt:     failed as expected (%v)", err)
	}

	// ── Step 8: Alice encrypts revoke notary (purpose 4) ────────────────
	revokeNotaryData := []byte("revoke notary block payload for kv test")

	revokeNotaryPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptRevokeNotaryBlock)
	revokeNotaryAlicePriv, _ := deriveKeyFromMaster(aliceMaster, revokeNotaryPath)

	revokeNotaryResult, err := EncryptRevokeNotaryEC(aliceMaster, revokeNotaryData, otherParty, consentNumber, notaryPub, contractAddress, chainId)
	if err != nil {
		t.Fatalf("EncryptRevokeNotaryEC: %v", err)
	}

	t.Logf("Revoke notary path:     %s", revokeNotaryPath.String())
	t.Logf("Revoke notary Alice priv: %s", textformat.FormatHex(revokeNotaryAlicePriv.Serialize()))
	t.Logf("Revoke notary Alice pub:  %s", textformat.FormatHex(revokeNotaryAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Revoke notary sealed:   %s", textformat.FormatHex(revokeNotaryResult.SealedData))

	assertKV(t, "Revoke notary path", revokeNotaryPath.String(), kvRevokeNotaryPath)
	assertKVHex(t, "Revoke notary Alice priv", revokeNotaryAlicePriv.Serialize(), kvRevokeNotaryAlicePriv)
	assertKVHex(t, "Revoke notary Alice pub", revokeNotaryAlicePriv.PubKey().SerializeCompressed(), kvRevokeNotaryAlicePub)
	assertKVHex(t, "Revoke notary sealed", revokeNotaryResult.SealedData, kvRevokeNotarySealedHex)

	// ── Step 9: Alice builds revoke plaintext and encrypts + signs ───────
	revokeNotaryCBOR, _ := revokeNotaryResult.MarshalCBOR()
	revokePlaintext := append(revokeNotaryCBOR, []byte("|revoke payload for kv test")...)
	t.Logf("Revoke notary CBOR len: %d bytes", len(revokeNotaryCBOR))
	t.Logf("Revoke plaintext len:   %d bytes", len(revokePlaintext))

	// Derive Bob's revoke encryption key
	bobRevokePath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptRevokeStructure)
	bobRevokePriv, _ := deriveKeyFromMaster(bobMaster, bobRevokePath)
	bobRevokePub := bobRevokePriv.PubKey()

	revokePath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptRevokeStructure)
	revokeAlicePriv, _ := deriveKeyFromMaster(aliceMaster, revokePath)

	revokeReq, err := EncryptSignRevokeEC(aliceMaster, revokePlaintext, otherParty, consentNumber, bobRevokePub, contractAddress, chainId, consentCid.String())
	if err != nil {
		t.Fatalf("EncryptSignRevokeEC: %v", err)
	}

	revokeCBOR, _ := revokeReq.EncryptedData.MarshalCBOR()
	revokeCid, _ := ipfs.GetCid(revokeCBOR)

	t.Logf("Revoke path:            %s", revokePath.String())
	t.Logf("Revoke Alice priv:      %s", textformat.FormatHex(revokeAlicePriv.Serialize()))
	t.Logf("Revoke Alice pub:       %s", textformat.FormatHex(revokeAlicePriv.PubKey().SerializeCompressed()))
	t.Logf("Revoke sealed data:     %s", textformat.FormatHex(revokeReq.EncryptedData.SealedData))
	t.Logf("Revoke CID (rcid):      %s", revokeCid.String())
	t.Logf("Revoke Alice sig:       %s", textformat.FormatHex(revokeReq.Signature))

	assertKV(t, "Revoke path", revokePath.String(), kvRevokePath)
	assertKVHex(t, "Revoke Alice priv", revokeAlicePriv.Serialize(), kvRevokeAlicePriv)
	assertKVHex(t, "Revoke Alice pub", revokeAlicePriv.PubKey().SerializeCompressed(), kvRevokeAlicePub)
	assertKVHex(t, "Revoke sealed data", revokeReq.EncryptedData.SealedData, kvRevokeSealedHex)
	assertKV(t, "Revoke CID", revokeCid.String(), kvRevokeCid)
	assertKVHex(t, "Revoke Alice sig", revokeReq.Signature, kvRevokeAliceSigHex)

	revokeAddr, err := GetRevokeAddress(revokeReq.Signature, contractAddress, consentCid.String(), revokeCid.String())
	if err != nil {
		t.Fatalf("GetRevokeAddress: %v", err)
	}
	t.Logf("Revoke Alice addr:      %s", hex.EncodeToString(revokeAddr[:]))
	assertKV(t, "Revoke Alice addr", hex.EncodeToString(revokeAddr[:]), kvRevokeAliceAddr)

	// Verify revoke signer was consent signer
	match, err := RevokeSignerWasConsentSigner(revokeReq, consentReq, contractAddress)
	if err != nil {
		t.Fatalf("RevokeSignerWasConsentSigner: %v", err)
	}
	if !match {
		t.Error("revoke signer was not a consent signer")
	}

	// ── Step 10: Both parties decrypt revoke; only Alice decrypts notary ─
	decryptedRevokeAlice, err := DecryptRevokeEC(aliceMaster, revokeReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokeEC(alice): %v", err)
	}
	if !bytes.Equal(revokePlaintext, decryptedRevokeAlice) {
		t.Fatalf("Alice revoke plaintext mismatch")
	}
	t.Logf("Alice decrypted revoke: %d bytes (OK)", len(decryptedRevokeAlice))

	decryptedRevokeBob, err := DecryptRevokeEC(bobMaster, revokeReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokeEC(bob): %v", err)
	}
	if !bytes.Equal(revokePlaintext, decryptedRevokeBob) {
		t.Fatalf("Bob revoke plaintext mismatch")
	}
	t.Logf("Bob decrypted revoke:   %d bytes (OK)", len(decryptedRevokeBob))

	// Alice can decrypt revoke notary
	aliceDecryptedRevokeNotary, err := DecryptRevokeNotaryEC(aliceMaster, revokeNotaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptRevokeNotaryEC(alice): %v", err)
	}
	if !bytes.Equal(revokeNotaryData, aliceDecryptedRevokeNotary) {
		t.Fatalf("Alice revoke notary plaintext mismatch")
	}
	t.Logf("Alice decrypted revoke notary: %s", string(aliceDecryptedRevokeNotary))

	// Bob cannot decrypt revoke notary
	_, err = DecryptRevokeNotaryEC(bobMaster, revokeNotaryResult, otherParty, consentNumber, contractAddress, chainId)
	if err == nil {
		t.Error("expected Bob to fail decrypting revoke notary, but succeeded")
	} else {
		t.Logf("Bob revoke notary decrypt: failed as expected (%v)", err)
	}
}

// ── Assertion helpers ────────────────────────────────────────────────────────

// assertKV checks a string value against a known value. Skips if kv is empty.
func assertKV(t *testing.T, label string, got string, kv string) {
	t.Helper()
	if kv == "" {
		return // no known value yet — run with -v to capture
	}
	if got != kv {
		t.Errorf("%s: got %s, want %s", label, got, kv)
	}
}

// assertKVHex checks a byte slice against a hex-encoded known value. Skips if kv is empty.
func assertKVHex(t *testing.T, label string, got []byte, kv string) {
	t.Helper()
	if kv == "" {
		return
	}
	expected, err := hex.DecodeString(kv)
	if err != nil {
		t.Fatalf("%s: bad known-value hex: %v", label, err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("%s: got %x, want %s", label, got, kv)
	}
}
