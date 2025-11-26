package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
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
 *    Plaintext = "pulse test"
 *
 *    For a key exchange with this parameters, this should give you:
 *    Alice Public EncryptionKey = 0x036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2
 *    Bob Public EncryptionKey = 0x03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc
 *    Shared Secret (from ECDH exchange) = 0x3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e
 *    AES EncryptionKey ( after HKDR ) = 0x75ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a
 *    (Correct Nonce/AEAD handling checked in symmetric_test.go)
 *    Ciphertext = 0x7c2fc63d17f029d739c368463daf4bd5ad7dd284cfd41baa0907ea
 */

// helperContractAddress returns a valid 20-byte Ethereum-like address string pointer (0x + 40 hex chars).
func helperContractAddress() *string {
	// 20 sequential bytes -> 0x010203...14
	var b [EthAddressLength]byte
	for i := 0; i < EthAddressLength; i++ {
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
	aesKeyExpected := mustHexDecode("75ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a")
	cipherTextExpected := mustHexDecode("7c2fc63d17f029d739c368463daf4bd5ad7dd284cfd41baa0907ea")

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
	aesKey, err := generateAESKey(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("generateAESKey() failed: %v", err)
	}

	if !bytes.Equal(aesKey, aesKeyExpected) {
		t.Fatalf("AES key mismatch: expected %x, got %x", aesKeyExpected, aesKey)
	}

	// Finally, check the ciphertext post encryption
	pt := []byte("hello pulse")
	addr := helperContractAddress()
	enc := NewPulseECEncryption().
		SetPlaintext(pt).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)

	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	if !bytes.Equal(enc.ciphertext, cipherTextExpected) {
		t.Fatalf("Ciphertext mismatch: expected %x, got %x", cipherTextExpected, enc.ciphertext)
	}

	result := enc.GetEncryptionResult()
	if !bytes.Equal(result.Key1, alicePub.SerializeCompressed()) {
		t.Fatalf("result Key1 mismatch: got %x want %x", result.Key1, alicePub.SerializeCompressed())
	}
	if !bytes.Equal(result.Key2, bobPub.SerializeCompressed()) {
		t.Fatalf("result Key2 mismatch: got %x want %x", result.Key2, bobPub.SerializeCompressed())
	}
	if len(result.SealedData) == 0 {
		t.Fatalf("sealed data is empty")
	}
	if !bytes.Equal(result.SealedData, cipherTextExpected) {
		t.Fatalf("sealed data mismatch: got %x want %x", result.SealedData, cipherTextExpected)
	}

	dec := NewPulseECEncryption().
		SetContractAddress(addr).
		SetMyPrivateKey(bobPriv).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(result)

	if err := dec.Decrypt(); err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(pt, dec.Plaintext()) {
		t.Fatalf("plaintext mismatch: got %q want %q", dec.Plaintext(), pt)
	}
}

func TestPulseECEncryption_RoundTrip_WithResult(t *testing.T) {
	alicePriv, alicePub, bobPriv, bobPub := mustKeys(t)

	pt := []byte("hello pulse")
	addr := helperContractAddress()

	// Alice encrypts to Bob using ECDH(aPriv, bPub)
	enc := NewPulseECEncryption().
		SetPlaintext(pt).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)

	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Result should include the two compressed public keys in (my, other) order
	res := enc.GetEncryptionResult()
	if !bytes.Equal(res.Key1, alicePub.SerializeCompressed()) {
		t.Fatalf("result Key1 mismatch: got %x want %x", res.Key1, alicePub.SerializeCompressed())
	}
	if !bytes.Equal(res.Key2, bobPub.SerializeCompressed()) {
		t.Fatalf("result Key2 mismatch: got %x want %x", res.Key2, bobPub.SerializeCompressed())
	}
	if len(res.SealedData) == 0 {
		t.Fatalf("sealed data is empty")
	}

	// Bob decrypts using only the result (no explicit other key or ciphertext set)
	dec := NewPulseECEncryption().
		SetContractAddress(addr).
		SetMyPrivateKey(bobPriv).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(res)

	if err := dec.Decrypt(); err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(pt, dec.Plaintext()) {
		t.Fatalf("plaintext mismatch: got %q want %q", dec.Plaintext(), pt)
	}
}

func TestPulseECEncryption_UnpackResult_KeyOrderIrrelevant(t *testing.T) {
	alicePriv, _, bobPriv, bobPub := mustKeys(t)

	pt := []byte("order test")
	addr := helperContractAddress()

	enc := NewPulseECEncryption().
		SetPlaintext(pt).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)

	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	res := enc.GetEncryptionResult()
	// Swap keys in the result to ensure unpacking still finds the other key
	res.Key1, res.Key2 = res.Key2, res.Key1

	dec := NewPulseECEncryption().
		SetContractAddress(addr).
		SetMyPrivateKey(bobPriv).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(res)

	if err := dec.Decrypt(); err != nil {
		t.Fatalf("Decrypt() failed with swapped keys: %v", err)
	}
	if !bytes.Equal(pt, dec.Plaintext()) {
		t.Fatalf("plaintext mismatch after swapped keys: got %q want %q", dec.Plaintext(), pt)
	}
}

/********************************************************************************************************
 * Implmentation-specific tests from here on down.
 */

func TestPulseECEncryption_Encrypt_Errors(t *testing.T) {
	alicePriv, _, _, bobPub := mustKeys(t)
	addr := helperContractAddress()

	// Missing plaintext
	e := NewPulseECEncryption().
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)
	if err := e.Encrypt(); err == nil || err.Error() != "must provide plaintext" {
		t.Fatalf("expected plaintext error, got %v", err)
	}

	// Missing contract address
	e = NewPulseECEncryption().
		SetPlaintext([]byte("x")).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)
	if err := e.Encrypt(); err == nil || err.Error() != "must provide contract address" {
		t.Fatalf("expected contract address error, got %v", err)
	}

	// Missing purpose
	e = NewPulseECEncryption().
		SetPlaintext([]byte("x")).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetChainId(0x01)
	if err := e.Encrypt(); err == nil || err.Error() != "must provide purpose" {
		t.Fatalf("expected purpose error, got %v", err)
	}

	// Missing chainId
	e = NewPulseECEncryption().
		SetPlaintext([]byte("x")).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent)
	if err := e.Encrypt(); err == nil || err.Error() != "must provide chainId" {
		t.Fatalf("expected chainId error, got %v", err)
	}

	// Missing my private key
	e = NewPulseECEncryption().
		SetPlaintext([]byte("x")).
		SetContractAddress(addr).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)
	if err := e.Encrypt(); err == nil || err.Error() != "must provide private key" {
		t.Fatalf("expected private key error, got %v", err)
	}

	// Missing other public key
	e = NewPulseECEncryption().
		SetPlaintext([]byte("x")).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)
	if err := e.Encrypt(); err == nil || err.Error() != "must provide public key" {
		t.Fatalf("expected public key error, got %v", err)
	}
}

func TestPulseECEncryption_Decrypt_Errors(t *testing.T) {
	alicePriv, _, bobPriv, bobPub := mustKeys(t)
	addr := helperContractAddress()

	// Missing encryption result and missing ciphertext/otherPublicKey
	d := NewPulseECEncryption().
		SetContractAddress(addr).
		SetMyPrivateKey(bobPriv).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)
	if err := d.Decrypt(); err == nil || err.Error() != "problem deciphering encryption result: missing encryption result structure, and no ciphertext or otherPublicKey provided" {
		t.Fatalf("expected missing result error, got %v", err)
	}

	// Provide result with no matching key
	enc := NewPulseECEncryption().
		SetPlaintext([]byte("x")).
		SetContractAddress(addr).
		SetMyPrivateKey(alicePriv).
		SetOtherPublicKey(bobPub).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01)
	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	res := enc.GetEncryptionResult()
	// Overwrite keys with random ones that won't match Bob's compressed pub key
	tmpPriv, _ := secp.GeneratePrivateKey()
	res.Key1 = tmpPriv.PubKey().SerializeCompressed()
	tmpPriv2, _ := secp.GeneratePrivateKey()
	res.Key2 = tmpPriv2.PubKey().SerializeCompressed()

	d = NewPulseECEncryption().
		SetContractAddress(addr).
		SetMyPrivateKey(bobPriv).
		SetPurpose(PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(res)
	if err := d.Decrypt(); err == nil || err.Error() != "problem deciphering encryption result: no matching public key found in encryption result" {
		t.Fatalf("expected no matching key error, got %v", err)
	}
}
