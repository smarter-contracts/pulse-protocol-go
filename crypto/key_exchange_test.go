package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
)

/*
 * Test pack for Elliptic Curve key exchange. If you are trying to build your own test pack/implementation, the public
 * tests should be replicated in your code to ensure that your results are consistent with the reference implementation.
 *
 * Further down are tests that are specific to this Go implementation, which are not essential to replicate.
 * [ Binary values are written as Hex strings below! ]
 *
 * EncryptionKey values for the tests (binary/byte arrays coded as hex strings)::
 *    Alice Private EncryptionKey = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ( 32 bytes as hex)
 *    Bob Private EncryptionKey = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20 ( 32 bytes as hex)
 *    ChainId = 0x1
 *    Purpose = 1  ( Consent )
 *    ContractAddress = 0x0102030405060708090a0b0c0d0e0f1011121314 ( 20 bytes )
 *    Plaintext = "hello pulse"
 *
 *    For a key exchange with this parameters, this should give you:
 *    Alice Public EncryptionKey = 0x036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2
 *    Bob Public EncryptionKey = 0x03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc
 *    Shared Secret (from ECDH exchange) = 0x3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e
 *    AES EncryptionKey ( after HKDR ) = 0xbd9da74e79f8fd0825101e39d0070cc2e51fbcf1ee6e0baef2158da48b2cb979
 *    (Correct Nonce/AEAD handling checked in symmetric_test.go)
 *    Ciphertext = 0xb7ecde16dd92210d7ba904af353799a38c1f7ce959211946e3f77b
 */

// helperContractAddress returns a valid 20-byte Ethereum-like address string pointer (0x + 40 hex chars).
func helperContractAddress() *string {
	// 20 sequential bytes -> 0x010203...14
	var b [symmetric.EthAddressLength]byte
	for i := 0; i < symmetric.EthAddressLength; i++ {
		b[i] = byte(i + 1)
	}
	// Manually format to avoid bringing in hex for a tiny helper
	hex := func(x byte) string {
		const hexdigits = "0123456789abcdef"
		return string([]byte{hexdigits[x>>4], hexdigits[x&0x0f]})
	}
	s := "0x"
	for i := 0; i < len(b); i++ {
		s += hex(b[i])
	}
	return &s
}

func mustKeys(t *testing.T) (*secp.PrivateKey, *secp.PublicKey, *secp.PrivateKey, *secp.PublicKey) {
	t.Helper()
	aPriv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to generate alice key: %v", err)
	}
	bPriv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to generate bob key: %v", err)
	}
	return aPriv, aPriv.PubKey(), bPriv, bPriv.PubKey()
}

func mustPrivFromHex(h string) *secp.PrivateKey {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	// PrivKeyFromBytes reduces mod N and handles lengths > 32.
	return secp.PrivKeyFromBytes(b)
}

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncrypt_Values(t *testing.T) {
	alicePriv := mustPrivFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	bobPriv := mustPrivFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20")

	alicePubExpected := mustHexDecode("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2")
	bobPubExpected := mustHexDecode("03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc")
	sharedSecretExpected := mustHexDecode("3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e")
	aesKeyExpected := mustHexDecode("c9ae71fe55522a05260be2b9e781e8361cb3443384a965f1cd399b201aca3e25")
	cipherTextExpected := mustHexDecode("5f92a03688c83bd73fda26cffb908427a32bfa2b3fcbecf1a4a940")

	alicePub := alicePriv.PubKey()
	bobPub := bobPriv.PubKey()
	if !bytes.Equal(alicePub.SerializeCompressed(), alicePubExpected) {
		t.Fatalf("Alice pub key mismatch: expected %x, got %x", alicePubExpected, alicePub.SerializeCompressed())
	}

	if !bytes.Equal(bobPub.SerializeCompressed(), bobPubExpected) {
		t.Fatalf("Bob pub key mismatch: expected %x, got %x", bobPubExpected, bobPub.SerializeCompressed())
	}

	// This isn't really testing a function of this library -- we're calling the secp library, but it's a good sanity
	// check for developers writing their own implementation -- if the shared secret isn't coming out right, then the
	// AES key ain't going to be right either, so we check the interim value here to rule out one cause of failure.
	sharedSecretA := secp.GenerateSharedSecret(alicePriv, bobPub)
	sharedSecretB := secp.GenerateSharedSecret(bobPriv, alicePub)
	if !bytes.Equal(sharedSecretA, sharedSecretB) {
		t.Fatalf("Shared secret mismatch: expected %x, got %x", sharedSecretA, sharedSecretB)
	}

	if !bytes.Equal(sharedSecretExpected, sharedSecretA) {
		t.Fatalf("Shared secret mismatch: expected %x, got %x", sharedSecretExpected, sharedSecretA)
	}

	// Alice encrypts to Bob -- if the shared secrets are correct above, it'll work the other way around too.
	// Check AES EncryptionKey generation, post HKDF
	addr := helperContractAddress()
	contextHash := textformat.ContextHash(0x01, *addr, 0)
	transcriptHash := generateTranscriptHash(textformat.FormatHex(alicePub.SerializeCompressed()),
		textformat.FormatHex(bobPub.SerializeCompressed()))

	aesKey, aesNonce, err := generateAESKey(alicePriv, bobPub, transcriptHash, contextHash)
	if err != nil {
		t.Fatalf("generateAESKey() failed: %v", err)
	}

	if !bytes.Equal(aesKey, aesKeyExpected) {
		t.Fatalf("AES key mismatch: expected %x, got %x", aesKeyExpected, aesKey)
	}

	if len(aesNonce) != symmetric.AESGCMNonceSize {
		t.Fatalf("AES nonce size mismatch: expected %d, got %d", symmetric.AESGCMNonceSize, len(aesNonce))
	}

	// Finally, check the ciphertext post encryption
	pt := []byte("hello pulse")
	// addr already defined above

	result, err := EncryptECDH(pt, addr, alicePriv, bobPub, symmetric.PulseSymmetricConsent, 0x01, 0)
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

	decrypted, err := DecryptEC(result, addr, bobPriv, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(pt, decrypted) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, pt)
	}
}

func TestPulseECEncryption_RoundTrip_WithResult(t *testing.T) {
	alicePriv, alicePub, bobPriv, bobPub := mustKeys(t)

	pt := []byte("hello pulse")
	addr := helperContractAddress()

	// Alice encrypts to Bob using ECDH(aPriv, bPub)
	res, err := EncryptECDH(pt, addr, alicePriv, bobPub, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	// Result should include the two compressed public keys in (my, other) order
	if !bytes.Equal(res.Key1, alicePub.SerializeCompressed()) {
		t.Fatalf("result Key1 mismatch: got %x want %x", res.Key1, alicePub.SerializeCompressed())
	}
	if !bytes.Equal(res.Key2, bobPub.SerializeCompressed()) {
		t.Fatalf("result Key2 mismatch: got %x want %x", res.Key2, bobPub.SerializeCompressed())
	}
	if len(res.SealedData) == 0 {
		t.Fatalf("sealed data is empty")
	}

	// Bob decrypts using only the result
	decrypted, err := DecryptEC(res, addr, bobPriv, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err != nil {
		t.Fatalf("DecryptEC() failed: %v", err)
	}
	if !bytes.Equal(pt, decrypted) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, pt)
	}
}

func TestPulseECEncryption_UnpackResult_KeyOrderIrrelevant(t *testing.T) {
	alicePriv, _, bobPriv, bobPub := mustKeys(t)

	pt := []byte("order test")
	addr := helperContractAddress()

	res, err := EncryptECDH(pt, addr, alicePriv, bobPub, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	// Swap keys in the result to ensure unpacking still finds the other key
	res.Key1, res.Key2 = res.Key2, res.Key1

	decrypted, err := DecryptEC(res, addr, bobPriv, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err != nil {
		t.Fatalf("DecryptEC() failed with swapped keys: %v", err)
	}
	if !bytes.Equal(pt, decrypted) {
		t.Fatalf("plaintext mismatch after swapped keys: got %q want %q", decrypted, pt)
	}
}

/********************************************************************************************************
 * Implmentation-specific tests from here on down.
 */

func TestPulseECEncryption_Encrypt_Errors(t *testing.T) {
	alicePriv, _, _, bobPub := mustKeys(t)
	addr := helperContractAddress()
	pt := []byte("hello")

	// Missing private key
	_, err := EncryptECDH(pt, addr, nil, bobPub, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err == nil {
		t.Fatal("expected error with nil private key")
	}

	// Missing other public key
	_, err = EncryptECDH(pt, addr, alicePriv, nil, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err == nil {
		t.Fatal("expected error with nil public key")
	}
}

func TestPulseECEncryption_Decrypt_Errors(t *testing.T) {
	alicePriv, _, bobPriv, bobPub := mustKeys(t)
	addr := helperContractAddress()
	pt := []byte("secret")

	res, err := EncryptECDH(pt, addr, alicePriv, bobPub, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err != nil {
		t.Fatalf("EncryptECDH() failed: %v", err)
	}

	// Decrypt with wrong private key
	wrongPriv, _ := secp.GeneratePrivateKey()
	_, err = DecryptEC(res, addr, wrongPriv, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err == nil || err.Error() != "No matching public key found in encryption result" {
		t.Fatalf("expected 'No matching public key found in encryption result', got %v", err)
	}

	// Tamper ciphertext
	resTampered := *res
	resTampered.SealedData = make([]byte, len(res.SealedData))
	copy(resTampered.SealedData, res.SealedData)
	resTampered.SealedData[0] ^= 0xff
	_, err = DecryptEC(&resTampered, addr, bobPriv, symmetric.PulseSymmetricConsent, 0x01, 0)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}

func TestGenerateTranscriptHash(t *testing.T) {
	key1 := "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
	key2 := "03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc"

	// keys sorted: key2, key1
	// recipientString := "|pulse|group|v1|03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc|036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2|"

	hash1 := generateTranscriptHash(key1, key2)
	hash2 := generateTranscriptHash(key2, key1)

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("generateTranscriptHash is not deterministic: %x != %x", hash1, hash2)
	}

	// Known hash for these keys (Keccak256)
	expectedHash := mustHexDecode("879b0d62da2ce9ba60803165ca683f77ff3245828ea733fe681f53e07dfd8b9d")
	if !bytes.Equal(hash1, expectedHash) {
		t.Errorf("generateTranscriptHash mismatch: got %x, want %x", hash1, expectedHash)
	}
}
