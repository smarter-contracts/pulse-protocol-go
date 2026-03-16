package key_exchange

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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
	tests := []struct {
		name             string
		plaintext        string
		alicePrivHex     string
		bobPrivHex       string
		alicePubHex      string
		bobPubHex        string
		sharedSecretHex  string
		aesKeyHex        string
		aesNonceHex      string
		cipherTextHex    string
		chainId          uint32
		consentNumber    uint32
		purpose          purposes.PulsePurpose
		expectedCBORHex  string
		expectedJSON     string
	}{
		{
			name:             "Consent record — Alice encrypts to Bob",
			plaintext:        "This is the consent record",
			alicePrivHex:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			bobPrivHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20",
			alicePubHex:      "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
			bobPubHex:        "03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc",
			sharedSecretHex:  "3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e",
			aesKeyHex:        "e52121ff74c5fc185d5aa165c47283889378492f64a53fbf5d53f3e5dc5e4e82",
			aesNonceHex:      "9b6585bef61692965127d170",
			cipherTextHex:    "8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee",
			chainId:          1,
			consentNumber:    2,
			purpose:          purposes.PulsePurposeEncryptConsentStructure,
			expectedCBORHex:  "a56174626563617601626b315821036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2626b32582103131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc627364582a8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee",
			expectedJSON:     `{"sealedData":"j4hSqxa7CVlrnYzpSnSCrHFdrNcRU3h4pIptdigoe6o0I6BTU0ZZM3Xu","key1":"A21sqsJIr5b2r6f5BPVQJToPPvP1qi/mg4qVshZpFGji","key2":"AxMTQeshVN3tEuOOC84D+QaAL7EGkOwbKycwOkqfuoi8"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pt := []byte(tt.plaintext)
			alicePriv := mustPrivFromHex(tt.alicePrivHex)
			bobPriv := mustPrivFromHex(tt.bobPrivHex)
			alicePub := alicePriv.PubKey()
			bobPub := bobPriv.PubKey()

			// Verify derived public keys
			if got := textformat.FormatHex(alicePub.SerializeCompressed()); got != tt.alicePubHex {
				t.Fatalf("Alice pub key mismatch: got %s, want %s", got, tt.alicePubHex)
			}
			if got := textformat.FormatHex(bobPub.SerializeCompressed()); got != tt.bobPubHex {
				t.Fatalf("Bob pub key mismatch: got %s, want %s", got, tt.bobPubHex)
			}

			// Verify shared secret is symmetric and matches expected value
			sharedSecretA := secp.GenerateSharedSecret(alicePriv, bobPub)
			sharedSecretB := secp.GenerateSharedSecret(bobPriv, alicePub)
			if !bytes.Equal(sharedSecretA, sharedSecretB) {
				t.Fatalf("Shared secret not symmetric: A=%x, B=%x", sharedSecretA, sharedSecretB)
			}
			if got := textformat.FormatHex(sharedSecretA); got != tt.sharedSecretHex {
				t.Fatalf("Shared secret mismatch: got %s, want %s", got, tt.sharedSecretHex)
			}

			// Verify AES key derivation
			addr := helperContractAddress()
			contextHash := context.ContextHash(tt.chainId, *addr, tt.consentNumber)
			transcriptHash := generateTranscriptHash(
				textformat.FormatHex(alicePub.SerializeCompressed()),
				textformat.FormatHex(bobPub.SerializeCompressed()))

			aesKey, aesNonce, err := generateAESKey(alicePriv, bobPub, transcriptHash, contextHash)
			if err != nil {
				t.Fatalf("generateAESKey() failed: %v", err)
			}
			if got := textformat.FormatHex(aesKey); got != tt.aesKeyHex {
				t.Fatalf("AES key mismatch: got %s, want %s", got, tt.aesKeyHex)
			}
			if got := textformat.FormatHex(aesNonce); got != tt.aesNonceHex {
				t.Fatalf("AES nonce mismatch: got %s, want %s", got, tt.aesNonceHex)
			}
			if len(aesNonce) != symmetric.AESGCMNonceSize {
				t.Fatalf("AES nonce size: got %d, want %d", len(aesNonce), symmetric.AESGCMNonceSize)
			}

			// Encrypt and verify ciphertext, keys, CBOR, and JSON
			result, err := EncryptECDH(pt, addr, alicePriv, bobPub, tt.purpose, tt.chainId, tt.consentNumber)
			if err != nil {
				t.Fatalf("EncryptECDH() failed: %v", err)
			}
			if got := textformat.FormatHex(result.SealedData); got != tt.cipherTextHex {
				t.Fatalf("Ciphertext mismatch: got %s, want %s", got, tt.cipherTextHex)
			}
			if !bytes.Equal(result.Key1, alicePub.SerializeCompressed()) {
				t.Fatalf("result Key1 mismatch: got %x, want %x", result.Key1, alicePub.SerializeCompressed())
			}
			if !bytes.Equal(result.Key2, bobPub.SerializeCompressed()) {
				t.Fatalf("result Key2 mismatch: got %x, want %x", result.Key2, bobPub.SerializeCompressed())
			}

			cbor, err := result.MarshalCBOR()
			if err != nil {
				t.Fatalf("CBOR marshal failed: %v", err)
			}
			if got := textformat.FormatHex(cbor); got != tt.expectedCBORHex {
				t.Fatalf("CBOR mismatch: got %s, want %s", got, tt.expectedCBORHex)
			}

			jsonBytes, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("JSON marshal failed: %v", err)
			}
			if string(jsonBytes) != tt.expectedJSON {
				t.Fatalf("JSON mismatch: got %s, want %s", jsonBytes, tt.expectedJSON)
			}

			// Round-trip: Bob decrypts
			decrypted, err := DecryptEC(result, addr, bobPriv, tt.purpose, tt.chainId, tt.consentNumber)
			if err != nil {
				t.Fatalf("DecryptEC() failed: %v", err)
			}
			if !bytes.Equal(pt, decrypted) {
				t.Fatalf("plaintext mismatch: got %q, want %q", decrypted, pt)
			}
		})
	}
}

func TestGenerateTranscriptHash(t *testing.T) {
	tests := []struct {
		name                    string
		key1                    string
		key2                    string
		expectedTranscriptString string
		expectedHashHex         string
	}{
		{
			name:                    "Alice and Bob — keys sorted lexicographically",
			key1:                    "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
			key2:                    "03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc",
			expectedTranscriptString: "|pulse|group|v1|03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc|036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|",
			expectedHashHex:         "1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tString := generateTranscriptString(tt.key1, tt.key2)
			if tString != tt.expectedTranscriptString {
				t.Errorf("generateTranscriptString mismatch:\n  got  %s\n  want %s", tString, tt.expectedTranscriptString)
			}

			hash1 := generateTranscriptHash(tt.key1, tt.key2)
			hash2 := generateTranscriptHash(tt.key2, tt.key1)

			if !bytes.Equal(hash1, hash2) {
				t.Errorf("generateTranscriptHash is not deterministic: %x != %x", hash1, hash2)
			}

			expectedHash := mustHexDecode(tt.expectedHashHex)
			if !bytes.Equal(hash1, expectedHash) {
				t.Errorf("generateTranscriptHash mismatch: got %x, want %x", hash1, expectedHash)
			}
		})
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
