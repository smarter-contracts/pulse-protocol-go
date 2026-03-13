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
 *   contractAddress: "0x0102030405060708091011121314"
 *   chainId:         1
 *   otherParty:      3  (Bob's party number from Alice's perspective)
 *   consentNumber:   2
 *   notaryData:      "notary block payload for kv test"
 *   consentData:     constructed as notaryCid + "|consent payload for kv test"
 *   revokeNotaryData: "revoke notary block payload for kv test"
 *   revokeData:      constructed as revokeNotaryCid + "|revoke payload for kv test"
 *
 * ── Lifecycle ────────────────────────────────────────────────────────────────
 *   1. Alice encrypts notary data          → EncryptConsentNotaryEC
 *   2. Alice builds consent plaintext       (notaryCid + consent payload)
 *   3. Alice encrypts + signs consent      → EncryptSignConsentEC
 *   4. Bob counter-signs consent           → SignConsentRequest
 *   5. Bob decrypts consent                → DecryptConsentEC
 *   6. Alice encrypts revoke notary data   → EncryptRevokeNotaryEC
 *   7. Alice encrypts + signs revoke       → EncryptSignRevokeEC
 */

import (
	"bytes"
	"encoding/hex"
	"testing"

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

// ── Known values (populated from first run with -v) ─────────────────────────
// To regenerate: clear all kv* constants, run with -v, paste logged values.

const (
	// Notary encryption (purpose 3 — EncryptConsentStructure)
	kvNotaryPath      = "m/4410704'/3/1/2/3"
	kvNotaryAlicePriv = "61e1d6824a3faf93e939d06471854c887497d2a7e93bb3fbfe23ea643009682c"
	kvNotaryAlicePub  = "02759a7c74a13b454e94c4846d0ee14366d4f8716bd6bc1fce99507952e7220a2c"
	kvNotarySealedHex = "102f9c210ed37e2dca07f51a4a2a6aef08adac93c707e123c68834e0a8d7532008dbfbe94f8d78061f5f6b1ba69cf61a"

	// Consent encryption (purpose 3 — EncryptConsentStructure)
	kvConsentPath      = "m/4410704'/3/1/2/3"
	kvConsentAlicePriv = "61e1d6824a3faf93e939d06471854c887497d2a7e93bb3fbfe23ea643009682c"
	kvConsentAlicePub  = "02759a7c74a13b454e94c4846d0ee14366d4f8716bd6bc1fce99507952e7220a2c"
	kvConsentSealedHex = "1c218e390ecf3728ca5be512013465e516b1ab9fd317fd3283862af4bdc7422cb5cbf7f20f56889401a2bfe4ee97b752ee4ab1bfb177e55272156c8de26f23e36eae745660501da51476793ff4c4867361ea163bf53891d1e3e192153cb2cab77d3b50b4e2295d"
	kvConsentCid       = "bafyreighzi443e5s5o4fuwhwf5vqrtickdewp7jn4ul6xcvlllcumag3g4"

	// Consent signatures
	kvAliceConsentSigHex = "d60d2d7fe716968734f18e111fffdd90263d7ba5c15a5660f89385ac835b00cd1b9d04cf6186f8e832e95118212ed72f95de42043efdc803112299f8450900a71c"
	kvBobConsentSigHex   = "f1b5688ac257871225c6be17a6bd629581e9e7775845a79f9d2139ec7b861fc749a44af842e5309ec7fd566a9731c986db4dfd018e799ba6a14521bee12455651c"
	kvAliceConsentAddr   = "1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0"
	kvBobConsentAddr     = "a897e536ce08d36cd12387b21dbe0053f4c091c7"

	// Revoke notary encryption (purpose 5 — EncryptRevokeStructure)
	kvRevokeNotaryPath      = "m/4410704'/3/1/2/5"
	kvRevokeNotaryAlicePriv = "e36c8f883748b24f1ce6c2202c0f9eea257b7d8e6ddb334130dd2878b7c74731"
	kvRevokeNotaryAlicePub  = "03ee864493c54357eefca45c3531d444650cc30dd1e15e82c990f069b11ad07993"
	kvRevokeNotarySealedHex = "84e13da7a5f3827c39f7aee04dfee2585f86256cd0350e5df58e659466d515288026d10d92e729d9fcaa01b4000853f7c338108cd77071"

	// Revoke encryption (purpose 5 — EncryptRevokeStructure)
	kvRevokePath      = "m/4410704'/3/1/2/5"
	kvRevokeAlicePriv = "e36c8f883748b24f1ce6c2202c0f9eea257b7d8e6ddb334130dd2878b7c74731"
	kvRevokeAlicePub  = "03ee864493c54357eefca45c3531d444650cc30dd1e15e82c990f069b11ad07993"
	kvRevokeSealedHex = "94e52db1bcf3cb7a3dfbb7a059b3ea595291362fce2d1543a99571c477d2117d83628b1f87fb68d9210e46229effa2bfab7d36ed12a18d46e9528c09eb3973115e2fb7cdbc7a091333b8ce0e18d358c374ab8c29b4a3be246db863361f231c28de94e529ce5e"
	kvRevokeCid       = "bafyreift2xak4frxworujwg6oggkr2xgagpekowor524wnt62kyetbuqhq"

	// Revoke signature
	kvRevokeAliceSigHex = "a7f73138feb86955b2d87e57b66f283acd20dba30f674f26ed233e92bd7d34ab28d461a1f494bf3b8dfb14667ab6b39b46143995a566f550abb24fae73cd08b71c"
	kvRevokeAliceAddr   = "1147b934b5c0fcabbaed2cf128a3db1eb71ef2c0"
)

func TestHDWalletEC_KnownValues(t *testing.T) {
	// ── Fixed inputs ─────────────────────────────────────────────────────
	aliceMaster := mustNewMasterKey(t)
	bobMaster := mustNewBobMasterKey(t)

	const (
		contractAddress = "0x0102030405060708091011121314"
		chainId         = uint32(1)
		otherParty      = uint32(3) // Bob's party number
		consentNumber   = uint32(2)
	)
	notaryData := []byte("notary block payload for kv test")

	// Derive Bob's encryption public key for the consent purpose
	bobConsentPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptConsentStructure)
	bobConsentPriv, err := deriveKeyFromMaster(bobMaster, bobConsentPath)
	if err != nil {
		t.Fatalf("derive Bob consent key: %v", err)
	}
	bobConsentPub := bobConsentPriv.PubKey()

	// ── Step 1: Alice encrypts notary data ───────────────────────────────
	notaryPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptConsentStructure)
	notaryAlicePriv, _ := deriveKeyFromMaster(aliceMaster, notaryPath)

	notaryResult, err := EncryptConsentNotaryEC(aliceMaster, notaryData, otherParty, consentNumber, bobConsentPub, contractAddress, chainId)
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

	// ── Step 2: Build consent plaintext including notary CID ─────────────
	notaryCBOR, err := notaryResult.MarshalCBOR()
	if err != nil {
		t.Fatalf("notary MarshalCBOR: %v", err)
	}
	notaryCid, err := ipfs.GetCid(notaryCBOR)
	if err != nil {
		t.Fatalf("notary GetCid: %v", err)
	}
	consentPlaintext := []byte(notaryCid.String() + "|consent payload for kv test")
	t.Logf("Notary CID:             %s", notaryCid.String())
	t.Logf("Consent plaintext:      %s", string(consentPlaintext))

	// ── Step 3: Alice encrypts + signs consent ───────────────────────────
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
	// Assert signature BEFORE GetConsentAddress, which mutates the recovery byte in-place
	assertKVHex(t, "Bob consent sig", consentReq.Signatures[1], kvBobConsentSigHex)

	bobConsentAddr, err := GetConsentAddress(consentReq.Signatures[1], contractAddress, consentCid.String())
	if err != nil {
		t.Fatalf("GetConsentAddress(bob): %v", err)
	}
	t.Logf("Bob consent addr:       %s", hex.EncodeToString(bobConsentAddr[:]))
	assertKV(t, "Bob consent addr", hex.EncodeToString(bobConsentAddr[:]), kvBobConsentAddr)

	// ── Step 5: Bob decrypts consent ─────────────────────────────────────
	decryptedConsent, err := DecryptConsentEC(bobMaster, consentReq, otherParty, consentNumber, contractAddress, chainId)
	if err != nil {
		t.Fatalf("DecryptConsentEC(bob): %v", err)
	}
	if !bytes.Equal(consentPlaintext, decryptedConsent) {
		t.Fatalf("consent plaintext mismatch: got %q, want %q", decryptedConsent, consentPlaintext)
	}
	t.Logf("Bob decrypted consent:  %s", string(decryptedConsent))

	// ── Step 6: Alice encrypts revoke notary ─────────────────────────────
	revokeNotaryData := []byte("revoke notary block payload for kv test")

	// Derive Bob's revoke encryption key
	bobRevokePath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptRevokeStructure)
	bobRevokePriv, _ := deriveKeyFromMaster(bobMaster, bobRevokePath)
	bobRevokePub := bobRevokePriv.PubKey()

	revokeNotaryPath, _ := newpulseHDPath(otherParty, chainId, consentNumber, purposes.PulsePurposeEncryptRevokeStructure)
	revokeNotaryAlicePriv, _ := deriveKeyFromMaster(aliceMaster, revokeNotaryPath)

	revokeNotaryResult, err := EncryptRevokeNotaryEC(aliceMaster, revokeNotaryData, otherParty, consentNumber, bobRevokePub, contractAddress, chainId)
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

	// ── Step 7: Alice builds revoke plaintext and encrypts + signs ───────
	revokeNotaryCBOR, _ := revokeNotaryResult.MarshalCBOR()
	revokeNotaryCid, _ := ipfs.GetCid(revokeNotaryCBOR)
	revokePlaintext := []byte(revokeNotaryCid.String() + "|revoke payload for kv test")
	t.Logf("Revoke notary CID:      %s", revokeNotaryCid.String())
	t.Logf("Revoke plaintext:       %s", string(revokePlaintext))

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
