package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
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
		SetPurpose(PulseSymmetricConsent).
		SetPlaintext(pt)
	if err := e.SealPlaintext(); err != nil {
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
		SetPurpose(PulseSymmetricConsent).
		SetPlaintext(pt)
	if err := e.SealPlaintext(); err != nil {
		t.Fatalf("sealPlaintext failed: %v", err)
	}

	// Decrypt using a fresh instance with the same parameters
	d := NewPulseSymmetricEncryption().
		SetKey(mustKey(t)).
		SetChainId(1).
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetCiphertext(e.Ciphertext())
	if err := d.OpenCiphertext(); err != nil {
		t.Fatalf("openCiphertext failed: %v", err)
	}

	if !bytes.Equal(pt, d.Plaintext()) {
		t.Fatalf("plaintext mismatch: want %q got %q", pt, d.Plaintext())
	}
}

func TestPulseSymmetric_Consent_RoundTripNoKey(t *testing.T) {
	pt := []byte("pulse test")

	e := NewPulseSymmetricEncryption().
		SetChainId(1).
		SetContractAddress(mustAddress(t)).
		SetPurpose(PulseSymmetricConsent).
		SetPlaintext(pt)
	if err := e.SealPlaintext(); err != nil {
		t.Fatalf("sealPlaintext failed: %v", err)
	}

	// Decrypt using a fresh instance with the same parameters
	d := NewPulseSymmetricEncryption().
		SetKey(e.Key()).
		SetChainId(1).
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetCiphertext(e.Ciphertext())
	if err := d.OpenCiphertext(); err != nil {
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
		SetPurpose(PulseSymmetricConsent).
		SetContractAddress(mustAddress(t))
	if err := e1.SealPlaintext(); err == nil || err.Error() != "no plaintext to sealPlaintext" {
		t.Fatalf("expected 'no plaintext to sealPlaintext', got %v", err)
	}

	// Missing contract address / chainId / purpose handled as 'no contract address' in current implementation
	e2 := NewPulseSymmetricEncryption().
		SetKey(key).
		SetPlaintext([]byte("data"))
	if err := e2.SealPlaintext(); err == nil || err.Error() != "no contract address, chainId or purpose" {
		t.Fatalf("expected 'no contract address', got %v", err)
	}

	// Bad contract address length
	badAddress := "0x1234"
	e3 := NewPulseSymmetricEncryption().
		SetKey(key).
		SetChainId(1).
		SetContractAddress(&badAddress).
		SetPurpose(PulseSymmetricConsent).
		SetPlaintext([]byte("data"))
	if err := e3.SealPlaintext(); err == nil || err.Error() != "failed to decode contract address: contract address must be 40 hex characters" {
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
		SetPurpose(PulseSymmetricConsent).
		SetContractAddress(mustAddress(t))
	if err := d1.OpenCiphertext(); err == nil || err.Error() != "no ciphertext to sealPlaintext" { // current message in openCiphertext()
		t.Fatalf("expected 'no ciphertext to sealPlaintext', got %v", err)
	}

	e := NewPulseSymmetricEncryption().
		SetKey(key).
		SetChainId(1).
		SetContractAddress(mustAddress(t)).
		SetPurpose(PulseSymmetricConsent).
		SetPlaintext([]byte("hello"))
	if err := e.SealPlaintext(); err != nil {
		t.Fatalf("unexpected sealPlaintext error: %v", err)
	}

	// Missing key
	missingKeyDecrypt := NewPulseSymmetricEncryption().
		SetChainId(1).
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetCiphertext(e.Ciphertext())
	if err := missingKeyDecrypt.OpenCiphertext(); err == nil || err.Error() != "missing key for decryption" {
		t.Fatalf("expected 'missing key for decryption', got %v", err)
	}

	missingChainIdDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetKey(key).
		SetCiphertext(e.Ciphertext())
	if err := missingChainIdDecrypt.OpenCiphertext(); err == nil || err.Error() != "no contract address, chainId or purpose" {
		t.Fatalf("expected 'no contract address, chainId or purpose', got %v", err)
	}

	missingPurposeDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(e.contractAddressString).
		SetChainId(1).
		SetKey(key).
		SetCiphertext(e.Ciphertext())
	if err := missingPurposeDecrypt.OpenCiphertext(); err == nil || err.Error() != "no contract address, chainId or purpose" {
		t.Fatalf("expected 'no contract address, chainId or purpose', got %v", err)
	}

	missingContractAddDecrypt := NewPulseSymmetricEncryption().
		SetPurpose(PulseSymmetricConsent).
		SetChainId(1).
		SetKey(key).
		SetCiphertext(e.Ciphertext())
	if err := missingContractAddDecrypt.OpenCiphertext(); err == nil || err.Error() != "no contract address, chainId or purpose" {
		t.Fatalf("expected 'no contract address, chainId or purpose', got %v", err)
	}

	// These fields are used to build the nonce, which is also the AAD for encrpytion. We expect authentication failure
	// for the AEAD.
	wrongChainIdDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(2).
		SetKey(key).
		SetCiphertext(e.Ciphertext())
	if err := wrongChainIdDecrypt.OpenCiphertext(); err == nil || err.Error() != "cipher: message authentication failed" {
		t.Fatalf("expected 'message authentication failed', got %v", err)
	}

	wrongPurposeDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricRevoke).
		SetChainId(1).
		SetKey(key).
		SetCiphertext(e.Ciphertext())
	if err := wrongPurposeDecrypt.OpenCiphertext(); err == nil || err.Error() != "cipher: message authentication failed" {
		t.Fatalf("expected 'message authentication failed', got %v", err)
	}

	badContract := strings.Replace(*e.contractAddressString, "d", "e", 1)
	strings.Replace(badContract, "d", "e", 1)
	wrongContractDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(&badContract).
		SetPurpose(PulseSymmetricRevoke).
		SetChainId(1).
		SetKey(key).
		SetCiphertext(e.Ciphertext())
	if err := wrongContractDecrypt.OpenCiphertext(); err == nil || err.Error() != "cipher: message authentication failed" {
		t.Fatalf("expected 'message authentication failed', got %v", err)
	}

	badKey := make([]byte, AESGCMKeySize)
	for i := range badKey {
		badKey[i] = byte(i) + 1
	}
	badKeyDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(1).
		SetKey(badKey).
		SetCiphertext(e.Ciphertext())
	if err := badKeyDecrypt.OpenCiphertext(); err == nil || err.Error() != "cipher: message authentication failed" {
		t.Fatalf("expected 'cipher: message authentication failed', got %v", err)
	}

	badCiphertext := make([]byte, len(e.Ciphertext()))
	for i := range badCiphertext {
		badCiphertext[i] = e.ciphertext[i]
	}
	badCiphertext[0] = badCiphertext[0] + 1
	badCipherTextDecrypt := NewPulseSymmetricEncryption().
		SetContractAddress(e.contractAddressString).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(1).
		SetKey(key).
		SetCiphertext(badCiphertext)
	if err := badCipherTextDecrypt.OpenCiphertext(); err == nil || err.Error() != "cipher: message authentication failed" {
		t.Fatalf("expected 'cipher: message authentication failed', got %v", err)
	}
}

func TestPulseSymmetric_NonceErrors(t *testing.T) {
	e := NewPulseSymmetricEncryption().
		SetChainId(1).
		SetContractAddress(mustAddress(t)).
		SetPurpose(PulseSymmetricConsent)

	err := e.decodeContractAddress()
	if err != nil {
		t.Fatalf("failed to decode contract address: %v", err)
	}

	e.generateNonce()
	firstNonce := e.nonce

	e.generateNonce()

	if !bytes.Equal(firstNonce[:], e.nonce[:]) {
		t.Fatalf("nonce mismatch, should be deterministic: want %q got %q", firstNonce, e.nonce)
	}

	e.SetPurpose(PulseSymmetricUpdate)
	e.generateNonce()
	if bytes.Equal(firstNonce[:], e.nonce[:]) {
		t.Fatalf("nonce match, should be different for different purposes: want %q got %q", firstNonce, e.nonce)
	}
	e.SetPurpose(PulseSymmetricConsent).SetChainId(2)
	e.generateNonce()
	if bytes.Equal(firstNonce[:], e.nonce[:]) {
		t.Fatalf("nonce match, should be different for different chainids: want %q got %q", firstNonce, e.nonce)
	}

	differentAddress := strings.Replace(*e.contractAddressString, "d", "e", 1)
	e.SetChainId(1).SetContractAddress(&differentAddress)
	err = e.decodeContractAddress()
	if err != nil {
		t.Fatalf("failed to decode contract address: %v", err)
	}
	e.generateNonce()
	if bytes.Equal(firstNonce[:], e.nonce[:]) {
		t.Fatalf("nonce match, should be different for different contracts: want %q got %q", firstNonce, e.nonce)
	}

}
