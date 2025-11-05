package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

/*
 * Test pack for Symmetric encryption. If you are trying to build your own test pack/implmentation, the public tests
 * should be replicated in your code to ensure that your results are consistent with the reference implementation.
 *
 * Further down are tests that are specific to this Go implementation, which are not essential to replicate.
 *
 * Key values for the tests (binary/byte arrays coded as hex strings)::
 *    AESKey = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ( 32 bytes )
 *    ChainId = 0x1
 *    Purpose = 1  ( Consent )
 *    ContractAddress = 0x0102030405060708090a0b0c0d0e0f1011121314 ( 20 bytes )
 *    Plaintext = "pulse test"
 *
 *    For an AES encryption using a pre-supplied key, this should give you:
 *    Nonce = AAD = 0x1e385a6c84bfd9f31a3f5d74
 *    Ciphertext = 0xa9f54755732d0d2bd12f2cd099744b485b7adc8fae7f78e5bb5c
 */

func mustAddress(t *testing.T) *string {
	t.Helper()
	// 20 bytes => 40 hex chars
	addr := make([]byte, EthAddressLength)
	for i := range addr {
		addr[i] = byte(i + 1)
	}
	retVal := "0x" + hex.EncodeToString(addr)
	return &retVal
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, AESGCMKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestPulseSymmetric_Nonce(t *testing.T) {
	e := NewPulseSymmetricEncryption().
		SetChainId(1).
		SetContractAddress(mustAddress(t))
	if err := e.decodeContractAddress(); err != nil {
		t.Fatalf("failed to decode contract address: %v", err)
	}
	e.purpose = PulseSymmetricConsent

	e.generateNonce()

	expectedHex := "1e385a6c84bfd9f31a3f5d74"

	if hex.EncodeToString(e.nonce[:]) != expectedHex {
		t.Fatalf("nonce mismatch: want %q got %q", expectedHex, hex.EncodeToString(e.nonce[:]))
	}
}

func TestPulseSymmetric_Encrypt(t *testing.T) {
	pt := []byte("pulse test")

	e := NewPulseSymmetricEncryption().
		SetKey(mustKey(t)).
		SetChainId(1).
		SetContractAddress(mustAddress(t)).
		SetPlaintext(pt)
	if err := e.SealConsent(); err != nil {
		t.Fatalf("sealPlaintext failed: %v", err)
	}

	if hex.EncodeToString(e.Ciphertext()) != "a9f54755732d0d2bd12f2cd099744b485b7adc8fae7f78e5bb5c" {
		t.Fatalf("ciphertext mismatch: want %q got %q", "0x90", hex.EncodeToString(e.Ciphertext()))
	}
}

func TestPulseSymmetric_Consent_RoundTrip(t *testing.T) {
	pt := []byte("pulse test")

	e := NewPulseSymmetricEncryption().
		SetKey(mustKey(t)).
		SetChainId(1).
		SetContractAddress(mustAddress(t)).
		SetPlaintext(pt)
	if err := e.SealConsent(); err != nil {
		t.Fatalf("sealPlaintext failed: %v", err)
	}

	// Decrypt using a fresh instance with the same parameters
	d := NewPulseSymmetricEncryption().
		SetKey(mustKey(t)).
		SetChainId(1).
		SetContractAddress(e.contractAddressString).
		SetCiphertext(e.Ciphertext())
	if err := d.OpenConsent(); err != nil {
		t.Fatalf("openCiphertext failed: %v", err)
	}

	if !bytes.Equal(pt, d.Plaintext()) {
		t.Fatalf("plaintext mismatch: want %q got %q", pt, d.Plaintext())
	}
}

// Tests below here a specific to this implementation, and are not essential to replicate

func TestPulseSymmetric_EncryptErrors(t *testing.T) {
	key := make([]byte, AESGCMKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// No plaintext provided
	e1 := NewPulseSymmetricEncryption().
		SetKey(key).
		SetChainId(1).
		SetContractAddress(mustAddress(t))
	if err := e1.SealConsent(); err == nil || err.Error() != "no plaintext to sealPlaintext" {
		t.Fatalf("expected 'no plaintext to sealPlaintext', got %v", err)
	}

	// Missing contract address / chainId / purpose handled as 'no contract address' in current implementation
	e2 := NewPulseSymmetricEncryption().
		SetKey(key).
		SetPlaintext([]byte("data"))
	if err := e2.SealConsent(); err == nil || err.Error() != "no contract address, chainId or purpose" {
		t.Fatalf("expected 'no contract address', got %v", err)
	}

	// Bad contract address length
	badAddress := "0x1234"
	e3 := NewPulseSymmetricEncryption().
		SetKey(key).
		SetChainId(1).
		SetContractAddress(&badAddress).
		SetPlaintext([]byte("data"))
	if err := e3.SealConsent(); err == nil || err.Error() != "failed to decode contract address: contract address must be 40 hex characters" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPulseSymmetric_DecryptErrors(t *testing.T) {
	key := make([]byte, AESGCMKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	// No ciphertext
	d1 := NewPulseSymmetricEncryption().
		SetKey(key).
		SetChainId(1).
		SetContractAddress(mustAddress(t))
	if err := d1.OpenConsent(); err == nil || err.Error() != "no ciphertext to sealPlaintext" { // current message in openCiphertext()
		t.Fatalf("expected 'no ciphertext to sealPlaintext', got %v", err)
	}

	// Missing key
	e := NewPulseSymmetricEncryption().
		SetKey(key).
		SetChainId(1).
		SetContractAddress(mustAddress(t)).
		SetPlaintext([]byte("hello"))
	if err := e.SealConsent(); err != nil {
		t.Fatalf("unexpected sealPlaintext error: %v", err)
	}
	d2 := NewPulseSymmetricEncryption().
		SetChainId(1).
		SetContractAddress(e.contractAddressString).
		SetCiphertext(e.Ciphertext())
	if err := d2.OpenConsent(); err == nil || err.Error() != "missing key for decryption" {
		t.Fatalf("expected 'missing key for decryption', got %v", err)
	}
}
