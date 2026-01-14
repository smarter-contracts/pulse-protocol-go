package symmetric

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
)

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSymmetric_KnownValues(t *testing.T) {
	tests := []struct {
		name           string
		plaintext      []byte
		aesKey         []byte
		nonce          []byte
		purpose        PulseSymmetricPurpose
		cipherSuite    string
		recipientHash  []byte
		contextHash    []byte
		transcriptHash []byte
		expectedAAD    string
		expectedCipher []byte
	}{
		{
			name:           "Key Exchange Known Values",
			plaintext:      []byte("This is the consent record"),
			aesKey:         mustHexDecode("cee5d3c958a8be9fdea4e4dca39cf4bf52ca824a1f71d026319e350a6b0ef67a"),
			nonce:          mustHexDecode("3298b5b0da18ab57667cf999"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "ecdh-secp256k1+hkdf-keccak256+aes-gcm-256",
			recipientHash:  mustHexDecode(""),
			contextHash:    mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			transcriptHash: mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4"),
			expectedAAD:    "|pulse|consent|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|nonce=3298b5b0da18ab57667cf999|",
			expectedCipher: mustHexDecode("36dae43a0870c0f96bea88d074d8136e0cda62a5d5a67bc0bd8ccf2eee27618951ce1cb2391d2688da0a"),
		},
		{
			name:           "Key Encapsulation Known Values Data",
			plaintext:      []byte("This is the consent record"),
			aesKey:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			nonce:          mustHexDecode("202122232425262728292a2b"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "rng+aes-gcm-256",
			recipientHash:  mustHexDecode("9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922"),
			contextHash:    mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			transcriptHash: hash.PulseHashBytes(mustHexDecode("202122232425262728292a2b")),
			expectedAAD:    "|pulse|consent|v1|rng+aes-gcm-256|rid=9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=08cbbdefe5c86347efb3a00eda9ac05c0e8b8da6d0443410f229ad7bd0a82253|nonce=202122232425262728292a2b|",
			expectedCipher: mustHexDecode("8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d69"),
		},
		{
			name:           "Symmetric Known Values 1",
			plaintext:      []byte("pulse test"),
			aesKey:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			nonce:          mustHexDecode("000102030405060708090a0b"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "aes-gcm-256",
			recipientHash:  mustHexDecode("0102030405060708090a0b0c0d0e0f1011121314"),
			contextHash:    mustHexDecode("212223"), // This isn't really a hash but we use it for testing
			transcriptHash: mustHexDecode("313233"),
			expectedAAD:    "|pulse|consent|v1|aes-gcm-256|rid=0102030405060708090a0b0c0d0e0f1011121314|ctx=212223|th=313233|nonce=000102030405060708090a0b|",
			expectedCipher: mustHexDecode("3777ba68a0c5b67efe35cfa9a692dd1bd440590a55ab87a1ca4f"),
		},
		{
			name:           "Symmetric Known Values 2 (KeyWrap)",
			plaintext:      mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f11223344556677889900aabbccddeeff"), // AES Key + Nonce
			aesKey:         mustHexDecode("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
			nonce:          mustHexDecode("1112131415161718191a1b1c"),
			purpose:        PulseSymmetricKeyWrap,
			cipherSuite:    "kyber768+hkdf-keccak256+aes-gcm-256",
			recipientHash:  mustHexDecode("70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"),
			contextHash:    mustHexDecode("6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea"),
			transcriptHash: mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4"),
			expectedAAD:    "|pulse|keywrap|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|ctx=6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|nonce=1112131415161718191a1b1c|",
			expectedCipher: mustHexDecode("f6058785d4fea6790470dfce54417e1cef02f62ef7351ee5fea187865ad407a864c428eb25e17f764f0be39541f2550a1fb69b7ccd6cee56bedf691d0cdc3ca8"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aad := buildAAD(tt.purpose, tt.cipherSuite, tt.recipientHash, tt.nonce, tt.contextHash, tt.transcriptHash)
			if string(aad) != tt.expectedAAD {
				t.Errorf("AAD mismatch:\nGot:  %s\nWant: %s", string(aad), tt.expectedAAD)
			}

			ciphertext, err := PulseSeal(tt.plaintext, tt.aesKey, tt.nonce, tt.purpose, tt.cipherSuite, tt.recipientHash, tt.contextHash, tt.transcriptHash)
			if err != nil {
				t.Fatalf("PulseSeal failed: %v", err)
			}

			if !bytes.Equal(ciphertext, tt.expectedCipher) {
				t.Errorf("Ciphertext mismatch:\nGot:  %x\nWant: %x", ciphertext, tt.expectedCipher)
			}

			decrypted, err := PulseOpen(ciphertext, tt.aesKey, tt.nonce, tt.purpose, tt.cipherSuite, tt.recipientHash, tt.contextHash, tt.transcriptHash)
			if err != nil {
				t.Fatalf("PulseOpen failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted plaintext mismatch:\nGot:  %s\nWant: %s", string(decrypted), string(tt.plaintext))
			}
		})
	}
}

/*
 * Test values for Symmetric encryption.
 *
 * EncryptionKey = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ( 32 bytes )
 * Nonce = 0x000102030405060708090a0b ( 12 bytes )
 * Purpose = 1 ( PulseSymmetricConsent )
 * Recipient = 0x0102030405060708090a0b0c0d0e0f1011121314 ( 20 bytes )
 * Context = 0x212223 ( "!"# )
 * Plaintext = "pulse test"
 */

func getTestKey() []byte {
	key := make([]byte, AESGCMKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func getTestNonce() []byte {
	nonce := make([]byte, AESGCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

func getTestRecipient() []byte {
	recipient := make([]byte, 20)
	for i := range recipient {
		recipient[i] = byte(i + 1)
	}
	return recipient
}

func TestPulseSeal_PulseOpen_RoundTrip(t *testing.T) {
	plaintext := []byte("pulse test")
	key := getTestKey()
	nonce := getTestNonce()
	recipient := getTestRecipient()
	purpose := PulseSymmetricConsent
	context := []byte("context")
	suite := "test-suite"
	transcript := []byte("test transcript")

	ciphertext, err := PulseSeal(plaintext, key, nonce, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseSeal failed: %v", err)
	}

	decrypted, err := PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseOpen failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestPulseSealWithNewKey_RoundTrip(t *testing.T) {
	plaintext := []byte("pulse test with new key")
	recipient := getTestRecipient()
	purpose := PulseSymmetricUpdate
	context := []byte("another context")
	suite := "test-suite"

	ciphertext, key, nonce, err := PulseSealWithNewKey(nil, plaintext, purpose, suite, recipient, context)
	if err != nil {
		t.Fatalf("PulseSealWithNewKey failed: %v", err)
	}

	if len(key) != AESGCMKeySize {
		t.Errorf("Generated key size mismatch: got %d, want %d", len(key), AESGCMKeySize)
	}
	if len(nonce) != AESGCMNonceSize {
		t.Errorf("Generated nonce size mismatch: got %d, want %d", len(nonce), AESGCMNonceSize)
	}

	// PulseSealWithNewKey uses Keccak256(nonce) as transcriptHash
	transcriptHash := hash.PulseHashBytes(nonce)

	decrypted, err := PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, context, transcriptHash)
	if err != nil {
		t.Fatalf("PulseOpen failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestPulseOpen_AuthenticationFailure(t *testing.T) {
	plaintext := []byte("pulse test")
	key := getTestKey()
	nonce := getTestNonce()
	recipient := getTestRecipient()
	purpose := PulseSymmetricConsent
	context := []byte("context")
	suite := "test-suite"
	transcript := []byte("transcript")

	ciphertext, err := PulseSeal(plaintext, key, nonce, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseSeal failed: %v", err)
	}

	// Test with wrong key
	wrongKey := make([]byte, AESGCMKeySize)
	copy(wrongKey, key)
	wrongKey[0] ^= 0xFF
	_, err = PulseOpen(ciphertext, wrongKey, nonce, purpose, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong key")
	}

	// Test with wrong nonce
	wrongNonce := make([]byte, AESGCMNonceSize)
	copy(wrongNonce, nonce)
	wrongNonce[0] ^= 0xFF
	_, err = PulseOpen(ciphertext, key, wrongNonce, purpose, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong nonce")
	}

	// Test with wrong purpose
	_, err = PulseOpen(ciphertext, key, nonce, PulseSymmetricRevoke, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong purpose")
	}

	// Test with wrong recipient
	wrongRecipient := make([]byte, 20)
	copy(wrongRecipient, recipient)
	wrongRecipient[0] ^= 0xFF
	_, err = PulseOpen(ciphertext, key, nonce, purpose, suite, wrongRecipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong recipient")
	}

	// Test with wrong context
	_, err = PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, []byte("wrong context"), transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong context")
	}

	// Test with modified ciphertext
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF
	_, err = PulseOpen(corruptedCiphertext, key, nonce, purpose, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with corrupted ciphertext")
	}
}

func TestBuildAAD(t *testing.T) {
	purpose := PulseSymmetricConsent
	cipherSuite := "aes-gcm"
	recipient := getTestRecipient()
	nonce := getTestNonce()
	context := []byte("context")
	transcript := []byte("transcript")

	aad := buildAAD(purpose, cipherSuite, recipient, nonce, context, transcript)

	// Verify that AAD contains expected components
	if !bytes.Contains(aad, []byte("pulse|")) {
		t.Error("AAD missing 'pulse|' prefix")
	}
	if !bytes.Contains(aad, []byte("consent|")) {
		t.Error("AAD missing purpose string")
	}
	if !bytes.Contains(aad, []byte("v1|")) {
		t.Error("AAD missing version string")
	}
	if !bytes.Contains(aad, []byte(cipherSuite)) {
		t.Error("AAD missing cipher suite")
	}
	if !bytes.Contains(aad, []byte("rid="+textformat.FormatHex(recipient))) {
		t.Error("AAD missing recipient hex")
	}
	if !bytes.Contains(aad, []byte("nonce="+textformat.FormatHex(nonce))) {
		t.Error("AAD missing nonce hex")
	}
	if !bytes.Contains(aad, []byte("ctx=")) {
		t.Error("AAD missing context prefix 'ctx='")
	}
	if !bytes.Contains(aad, []byte("th=")) {
		t.Error("AAD missing transcript prefix 'th='")
	}
}

func TestPulseSymmetricPurposes(t *testing.T) {
	tests := []struct {
		purpose PulseSymmetricPurpose
		want    string
	}{
		{PulseSymmetricConsent, "consent"},
		{PulseSymmetricRevoke, "revoke"},
		{PulseSymmetricUpdate, "update"},
		{PulseSymmetricKeyWrap, "keywrap"},
	}

	recipient := getTestRecipient()
	nonce := getTestNonce()
	context := []byte("ctx")
	transcript := []byte("transcript")

	for _, tt := range tests {
		aad := buildAAD(tt.purpose, "test", recipient, nonce, context, transcript)
		if !bytes.Contains(aad, []byte(tt.want)) {
			t.Errorf("buildAAD for purpose %v: expected to contain %q, got %q", tt.purpose, tt.want, string(aad))
		}
	}
}
