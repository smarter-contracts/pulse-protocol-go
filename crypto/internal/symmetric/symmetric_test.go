package symmetric

import (
	"bytes"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
)

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
	transcript := []byte("test transcript")

	ciphertext, key, nonce, err := PulseSealWithNewKey(plaintext, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseSealWithNewKey failed: %v", err)
	}

	if len(key) != AESGCMKeySize {
		t.Errorf("Generated key size mismatch: got %d, want %d", len(key), AESGCMKeySize)
	}
	if len(nonce) != AESGCMNonceSize {
		t.Errorf("Generated nonce size mismatch: got %d, want %d", len(nonce), AESGCMNonceSize)
	}

	decrypted, err := PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, context, transcript)
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
	if !bytes.Contains(aad, []byte("th=transcript")) {
		t.Error("AAD missing transcript")
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
