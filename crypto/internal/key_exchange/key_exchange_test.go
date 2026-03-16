package key_exchange

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
)

func mustPrivFromHex(h string) *secp.PrivateKey {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return secp.PrivKeyFromBytes(b)
}

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func helperContractAddress() *string {
	var b [symmetric.EthAddressLength]byte
	for i := 0; i < symmetric.EthAddressLength; i++ {
		b[i] = byte(i + 1)
	}
	hexConvert := func(x byte) string {
		const hexdigits = "0123456789abcdef"
		return string([]byte{hexdigits[x>>4], hexdigits[x&0x0f]})
	}
	s := "0x"
	for i := 0; i < len(b); i++ {
		s += hexConvert(b[i])
	}
	return &s
}

func TestEncrypt_Values(t *testing.T) {
	pt := []byte("This is the consent record")
	alicePriv := mustPrivFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	bobPriv := mustPrivFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20")

	alicePubExpected := mustHexDecode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2")
	bobPubExpected := mustHexDecode("03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc")
	sharedSecretExpected := mustHexDecode("3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e")
	aesKeyExpected := mustHexDecode("e52121ff74c5fc185d5aa165c47283889378492f64a53fbf5d53f3e5dc5e4e82")
	aesNonceExpected := mustHexDecode("9b6585bef61692965127d170")
	cipherTextExpected := mustHexDecode("8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee")
	chainId := uint32(1)
	consentNumber := uint32(2)
	expectedCBOR := "a56174626563617601626b315821036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2626b32582103131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc627364582a8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee"
	expectedJSON := []byte("{\"sealedData\":\"j4hSqxa7CVlrnYzpSnSCrHFdrNcRU3h4pIptdigoe6o0I6BTU0ZZM3Xu\",\"key1\":\"A21sqsJIr5b2r6f5BPVQJToPPvP1qi/mg4qVshZpFGji\",\"key2\":\"AxMTQeshVN3tEuOOC84D+QaAL7EGkOwbKycwOkqfuoi8\"}")

	alicePub := alicePriv.PubKey()
	bobPub := bobPriv.PubKey()
	if !bytes.Equal(alicePub.SerializeCompressed(), alicePubExpected) {
		t.Fatalf("Alice pub key mismatch: expected %x, got %x", alicePubExpected, alicePub.SerializeCompressed())
	}

	if !bytes.Equal(bobPub.SerializeCompressed(), bobPubExpected) {
		t.Fatalf("Bob pub key mismatch: expected %x, got %x", bobPubExpected, bobPub.SerializeCompressed())
	}

	sharedSecretA := secp.GenerateSharedSecret(alicePriv, bobPub)
	sharedSecretB := secp.GenerateSharedSecret(bobPriv, alicePub)
	if !bytes.Equal(sharedSecretA, sharedSecretB) {
		t.Fatalf("Shared secret mismatch: expected %x, got %x", sharedSecretA, sharedSecretB)
	}

	if !bytes.Equal(sharedSecretExpected, sharedSecretA) {
		t.Fatalf("Shared secret mismatch: expected %x, got %x", sharedSecretExpected, sharedSecretA)
	}

	addr := helperContractAddress()
	contextHash := context.ContextHash(0x01, *addr, 2)
	transcriptHash := generateTranscriptHash(textformat.FormatHex(alicePub.SerializeCompressed()),
		textformat.FormatHex(bobPub.SerializeCompressed()))

	aesKey, aesNonce, err := generateAESKey(alicePriv, bobPub, transcriptHash, contextHash)
	if err != nil {
		t.Fatalf("generateAESKey() failed: %v", err)
	}

	if !bytes.Equal(aesKey, aesKeyExpected) {
		t.Fatalf("AES key mismatch: expected %x, got %x", aesKeyExpected, aesKey)
	}

	if !bytes.Equal(aesNonce, aesNonceExpected) {
		t.Fatalf("Nonce mismatch: expected %x, got %x", aesNonceExpected, aesNonce)
	}

	if len(aesNonce) != symmetric.AESGCMNonceSize {
		t.Fatalf("AES nonce size mismatch: expected %d, got %d", symmetric.AESGCMNonceSize, len(aesNonce))
	}

	result, err := EncryptECDH(pt, addr, alicePriv, bobPub, purposes.PulsePurposeEncryptConsentStructure, chainId, consentNumber)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	if !bytes.Equal(result.SealedData, cipherTextExpected) {
		t.Fatalf("Ciphertext mismatch: expected %x, got %x", cipherTextExpected, result.SealedData)
	}

	if !bytes.Equal(result.Key1, alicePub.SerializeCompressed()) {
		t.Fatalf("result Key1 mismatch: got %x want %x", result.Key1, alicePub.SerializeCompressed())
	}
	if !bytes.Equal(result.Key2, bobPub.SerializeCompressed()) {
		t.Fatalf("result Key2 mismatch: got %x want %x", result.Key2, bobPub.SerializeCompressed())
	}

	cbor, err := result.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to CBOR marshal result: %v", err)
	}
	if strings.Compare(textformat.FormatHex(cbor), expectedCBOR) != 0 {
		t.Fatalf("output CBOR mismatch: got %s want %s", textformat.FormatHex(cbor), expectedCBOR)
	}

	jsonString, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to JSON marshal result: %v", err)
	}
	if !bytes.Equal(jsonString, expectedJSON) {
		t.Fatalf("output JSON mismatch: got %s want %s", jsonString, expectedJSON)
	}

	decrypted, err := DecryptEC(result, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, chainId, consentNumber)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(pt, decrypted) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, pt)
	}
}

func TestGenerateTranscriptHash(t *testing.T) {
	key1 := "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
	key2 := "03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc"

	// keys sorted: key2, key1
	recipientString := "|pulse|group|v1|03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc|036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|"
	tString := generateTranscriptString(key1, key2)
	if strings.Compare(tString, recipientString) != 0 {
		t.Errorf("generateTranscriptString is wrong: got %s, expected %s", tString, recipientString)
	}

	hash1 := generateTranscriptHash(key1, key2)
	hash2 := generateTranscriptHash(key2, key1)

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("generateTranscriptHash is not deterministic: %x != %x", hash1, hash2)
	}

	expectedHash := mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4")
	if !bytes.Equal(hash1, expectedHash) {
		t.Errorf("generateTranscriptHash mismatch: got %x, want %x", hash1, expectedHash)
	}
}

func TestGenerateAESKey_NilKeys(t *testing.T) {
	// Both keys nil → must return error.
	_, _, err := generateAESKey(nil, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil keys, got nil")
	}

	// One key nil → must return error.
	priv, _ := secp.GeneratePrivateKey()
	pub := priv.PubKey()

	_, _, err = generateAESKey(priv, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil public key, got nil")
	}

	_, _, err = generateAESKey(nil, pub, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil private key, got nil")
	}
}

// ── Tests merged from crypto/key_exchange_test.go ────────────────────────────

func TestEncryptECDH_RoundTrip_WithResult(t *testing.T) {
	alicePriv, _ := secp.GeneratePrivateKey()
	alicePub := alicePriv.PubKey()
	bobPriv, _ := secp.GeneratePrivateKey()
	bobPub := bobPriv.PubKey()

	pt := []byte("hello pulse")
	addr := helperContractAddress()

	res, err := EncryptECDH(pt, addr, alicePriv, bobPub, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	if !bytes.Equal(res.Key1, alicePub.SerializeCompressed()) {
		t.Fatalf("result Key1 mismatch: got %x want %x", res.Key1, alicePub.SerializeCompressed())
	}
	if !bytes.Equal(res.Key2, bobPub.SerializeCompressed()) {
		t.Fatalf("result Key2 mismatch: got %x want %x", res.Key2, bobPub.SerializeCompressed())
	}
	if len(res.SealedData) == 0 {
		t.Fatalf("sealed data is empty")
	}

	decrypted, err := DecryptEC(res, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(pt, decrypted) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, pt)
	}
}

func TestDecryptEC_KeyOrderIrrelevant(t *testing.T) {
	alicePriv, _ := secp.GeneratePrivateKey()
	bobPriv, _ := secp.GeneratePrivateKey()
	bobPub := bobPriv.PubKey()

	pt := []byte("order test")
	addr := helperContractAddress()

	res, err := EncryptECDH(pt, addr, alicePriv, bobPub, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	// Swap keys in the result to ensure unpacking still finds the other key
	res.Key1, res.Key2 = res.Key2, res.Key1

	decrypted, err := DecryptEC(res, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err != nil {
		t.Fatalf("DecryptEC() failed with swapped keys: %v", err)
	}
	if !bytes.Equal(pt, decrypted) {
		t.Fatalf("plaintext mismatch after swapped keys: got %q want %q", decrypted, pt)
	}
}

func TestEncryptECDH_Errors(t *testing.T) {
	alicePriv, _ := secp.GeneratePrivateKey()
	bobPriv, _ := secp.GeneratePrivateKey()
	bobPub := bobPriv.PubKey()
	addr := helperContractAddress()
	pt := []byte("hello")

	// Missing private key
	_, err := EncryptECDH(pt, addr, nil, bobPub, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err == nil {
		t.Fatal("expected error with nil private key")
	}

	// Missing other public key
	_, err = EncryptECDH(pt, addr, alicePriv, nil, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err == nil {
		t.Fatal("expected error with nil public key")
	}
}

func TestDecryptEC_Errors(t *testing.T) {
	alicePriv, _ := secp.GeneratePrivateKey()
	bobPriv, _ := secp.GeneratePrivateKey()
	bobPub := bobPriv.PubKey()
	addr := helperContractAddress()
	pt := []byte("secret")

	res, err := EncryptECDH(pt, addr, alicePriv, bobPub, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	// Decrypt with wrong private key
	wrongPriv, _ := secp.GeneratePrivateKey()
	_, err = DecryptEC(res, addr, wrongPriv, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err == nil || err.Error() != "no matching public key found in encryption result" {
		t.Fatalf("expected 'no matching public key found in encryption result', got %v", err)
	}

	// Tamper ciphertext
	resTampered := *res
	resTampered.SealedData = make([]byte, len(res.SealedData))
	copy(resTampered.SealedData, res.SealedData)
	resTampered.SealedData[0] ^= 0xff
	_, err = DecryptEC(&resTampered, addr, bobPriv, purposes.PulsePurposeEncryptConsentStructure, 0x01, 0)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}
