package hkdf

import (
	"bytes"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
)

func TestPulseHKDFKyber(t *testing.T) {
	sharedSecret := make([]byte, 32)
	transcript := []byte("test transcript")
	recipientId := make([]byte, 20)
	context := []byte("test context")

	key, nonce, err := PulseHKDFKyber(sharedSecret, transcript, recipientId, context)
	if err != nil {
		t.Fatalf("PulseHKDFKyber failed: %v", err)
	}

	if len(key) != symmetric.AESGCMKeySize {
		t.Errorf("Expected key length %d, got %d", symmetric.AESGCMKeySize, len(key))
	}

	if len(nonce) != symmetric.AESGCMNonceSize {
		t.Errorf("Expected nonce length %d, got %d", symmetric.AESGCMNonceSize, len(nonce))
	}

	// Test consistency
	key2, nonce2, _ := PulseHKDFKyber(sharedSecret, transcript, recipientId, context)
	if !bytes.Equal(key, key2) {
		t.Error("Deterministic output failed for key")
	}
	if !bytes.Equal(nonce, nonce2) {
		t.Error("Deterministic output failed for nonce")
	}

	// Test difference with different shared secret
	sharedSecret2 := make([]byte, 32)
	sharedSecret2[0] = 1
	key3, _, _ := PulseHKDFKyber(sharedSecret2, transcript, recipientId, context)
	if bytes.Equal(key, key3) {
		t.Error("Different shared secret produced same key")
	}
}

func TestPulseHKDFECDH(t *testing.T) {
	sharedSecret := make([]byte, 32)
	transcript := []byte("test transcript")
	recipientId := make([]byte, 20)
	context := []byte("test context")

	key, nonce, err := PulseHKDFECDH(sharedSecret, transcript, recipientId, context)
	if err != nil {
		t.Fatalf("PulseHKDFECDH failed: %v", err)
	}

	if len(key) != symmetric.AESGCMKeySize {
		t.Errorf("Expected key length %d, got %d", symmetric.AESGCMKeySize, len(key))
	}

	if len(nonce) != symmetric.AESGCMNonceSize {
		t.Errorf("Expected nonce length %d, got %d", symmetric.AESGCMNonceSize, len(nonce))
	}

	// Test consistency
	key2, nonce2, _ := PulseHKDFECDH(sharedSecret, transcript, recipientId, context)
	if !bytes.Equal(key, key2) {
		t.Error("Deterministic output failed for key")
	}
	if !bytes.Equal(nonce, nonce2) {
		t.Error("Deterministic output failed for nonce")
	}
}

func TestPulseHKDFDifferentiation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	transcript := []byte("test transcript")
	recipientId := make([]byte, 20)
	context := []byte("test context")

	keyKyber, _, _ := PulseHKDFKyber(sharedSecret, transcript, recipientId, context)
	keyECDH, _, _ := PulseHKDFECDH(sharedSecret, transcript, recipientId, context)

	if bytes.Equal(keyKyber, keyECDH) {
		t.Error("PulseHKDFKyber and PulseHKDFECDH produced the same key for same inputs")
	}
}

func TestPulseHKDFNilInputs(t *testing.T) {
	// HKDF should handle nil inputs (treat as empty) without crashing
	key, nonce, err := PulseHKDFKyber(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("PulseHKDFKyber failed with nil inputs: %v", err)
	}
	if len(key) != symmetric.AESGCMKeySize || len(nonce) != symmetric.AESGCMNonceSize {
		t.Error("Invalid output lengths for nil inputs")
	}
}

func TestCreateSalt(t *testing.T) {
	algo := "kyber768"
	transcript := []byte("transcript")

	salt1 := createSalt(algo, transcript)
	salt2 := createSalt(algo, transcript)

	if !bytes.Equal(salt1, salt2) {
		t.Error("createSalt is not deterministic")
	}

	salt3 := createSalt("secp256k1", transcript)
	if bytes.Equal(salt1, salt3) {
		t.Error("createSalt should differ with different algorithms")
	}

	salt4 := createSalt(algo, []byte("different transcript"))
	if bytes.Equal(salt1, salt4) {
		t.Error("createSalt should differ with different transcripts")
	}
}

func TestCreateInfo(t *testing.T) {
	purpose := "keywrap-aes"
	suite := "kyber768+hkdf-keccak256"
	recipientId := []byte{0x01, 0x02}
	context := []byte("context")

	infoKey := createInfo(purpose, false, suite, recipientId, context)
	infoNonce := createInfo(purpose, true, suite, recipientId, context)

	if bytes.Equal(infoKey, infoNonce) {
		t.Error("createInfo should differ between key and nonce")
	}

	if !bytes.Contains(infoKey, []byte("key")) {
		t.Error("infoKey should contain 'key'")
	}

	if !bytes.Contains(infoNonce, []byte("nonce")) {
		t.Error("infoNonce should contain 'nonce'")
	}

	if !bytes.Contains(infoKey, []byte(purpose)) {
		t.Error("info should contain purpose")
	}

	if !bytes.Contains(infoKey, []byte(suite)) {
		t.Error("info should contain suite")
	}
}
