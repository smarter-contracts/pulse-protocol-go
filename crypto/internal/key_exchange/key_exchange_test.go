package key_exchange

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
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
		name            string
		plaintext       string
		alicePrivHex    string
		bobPrivHex      string
		alicePubHex     string
		bobPubHex       string
		contractAddress string // empty = use helperContractAddress()
		sharedSecretHex string
		aesKeyHex       string
		aesNonceHex     string
		cipherTextHex   string
		chainId         uint32
		consentNumber   uint32
		purpose         purposes.PulsePurpose
		expectedCBORHex string
		expectedJSON    string
	}{
		{
			name:            "Consent record — Alice encrypts to Bob",
			plaintext:       "This is the consent record",
			alicePrivHex:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			bobPrivHex:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20",
			alicePubHex:     "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
			bobPubHex:       "03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc",
			sharedSecretHex: "3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e",
			aesKeyHex:       "e52121ff74c5fc185d5aa165c47283889378492f64a53fbf5d53f3e5dc5e4e82",
			aesNonceHex:     "9b6585bef61692965127d170",
			cipherTextHex:   "8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee",
			chainId:         1,
			consentNumber:   2,
			purpose:         purposes.PulsePurposeEncryptConsentStructure,
			expectedCBORHex: "a56174626563617601626b315821036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2626b32582103131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc627364582a8f8852ab16bb09596b9d8ce94a7482ac715dacd711537878a48a6d7628287baa3423a0535346593375ee",
			expectedJSON:    `{"sealedData":"j4hSqxa7CVlrnYzpSnSCrHFdrNcRU3h4pIptdigoe6o0I6BTU0ZZM3Xu","key1":"A21sqsJIr5b2r6f5BPVQJToPPvP1qi/mg4qVshZpFGji","key2":"AxMTQeshVN3tEuOOC84D+QaAL7EGkOwbKycwOkqfuoi8"}`,
		},
		{
			// HD wallet consent notary encryption (purpose 2).
			// Alice key derived at m/4410704'/3/1/2/2; notary is a standalone secp256k1 key.
			// Matches Step 1 of hdwallet_ec_kv_test.go.
			name:            "HD wallet consent notary — Alice encrypts to notary (purpose 2)",
			plaintext:       "notary block payload for kv test",
			alicePrivHex:    "de9ff0acd0e4774ec79ef72dd2e086b8e45e97214fed3cac5b7b352c94e8eeaa",
			bobPrivHex:      "aa01020304050607080910111213141516171819202122232425262728293031",
			alicePubHex:     "03c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188",
			bobPubHex:       "02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805",
			contractAddress: "0x0102030405060708091011121314",
			sharedSecretHex: "b5d29adc5df221d234d80db987fa4b32dece8bb723fe39a4cb74b9ef628c45cb",
			aesKeyHex:       "81453d770f7a2aae63de96e3c65df4fad6da385b57e09bdcba8021f76965e926",
			aesNonceHex:     "6ed55e9040df901e49bfdb9e",
			cipherTextHex:   "5633c336c4f8c6dcda0399783b83daf472b1023b49f522746780cecec098284fc39b162fb912866008591f865bba8389",
			chainId:         1,
			consentNumber:   2,
			purpose:         purposes.PulsePurposeEncryptConsentNotaryBlock,
			expectedCBORHex: "a56174626563617601626b31582103c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188626b32582102fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d80562736458305633c336c4f8c6dcda0399783b83daf472b1023b49f522746780cecec098284fc39b162fb912866008591f865bba8389",
			expectedJSON:    `{"sealedData":"VjPDNsT4xtzaA5l4O4Pa9HKxAjtJ9SJ0Z4DOzsCYKE/DmxYvuRKGYAhZH4ZbuoOJ","key1":"A8UC61xGxMmLO4L2pHmADKk6XD/4LEjv7yglly9xiaGI","key2":"AvrelBgJiLYhA8d4i6wU3XGBnJKtPHV6xes0dwVJcNgF"}`,
		},
		{
			// HD wallet revoke notary encryption (purpose 4).
			// Alice key derived at m/4410704'/3/1/2/4; notary is the same standalone key.
			// Matches Step 8 of hdwallet_ec_kv_test.go.
			name:            "HD wallet revoke notary — Alice encrypts to notary (purpose 4)",
			plaintext:       "revoke notary block payload for kv test",
			alicePrivHex:    "fc216eb1fe324fef31308b8550dbd2e31e627143334d7dec596c9dd685c594bb",
			bobPrivHex:      "aa01020304050607080910111213141516171819202122232425262728293031",
			alicePubHex:     "03ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8",
			bobPubHex:       "02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805",
			contractAddress: "0x0102030405060708091011121314",
			sharedSecretHex: "f478248ce6ba52d5eaf268f80ec39bc3927fa3bf0f27ef79679f3602c6eabdf9",
			aesKeyHex:       "c2643aad50e12bec09f9429c224d596914c5ec19dcf8b218c0490959bcce6ccf",
			aesNonceHex:     "bbaf81b713fba08bf601efd0",
			cipherTextHex:   "efbddc817f89c54b6cb47afa479bcb7516456053683414762ccc5dd0b44f86d6d9267668cdc9f6ced99973ad147285d41d72941b92bb3f",
			chainId:         1,
			consentNumber:   2,
			purpose:         purposes.PulsePurposeEncryptRevokeNotaryBlock,
			expectedCBORHex: "a56174626563617601626b31582103ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8626b32582102fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d8056273645837efbddc817f89c54b6cb47afa479bcb7516456053683414762ccc5dd0b44f86d6d9267668cdc9f6ced99973ad147285d41d72941b92bb3f",
			expectedJSON:    `{"sealedData":"773cgX+JxUtstHr6R5vLdRZFYFNoNBR2LMxd0LRPhtbZJnZozcn2ztmZc60UcoXUHXKUG5K7Pw==","key1":"A8phkmavjyslW1q2kIFb9nhlEcg7g2j/i+QS8q1G+Gz4","key2":"AvrelBgJiLYhA8d4i6wU3XGBnJKtPHV6xes0dwVJcNgF"}`,
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
			if tt.sharedSecretHex != "" {
				if got := textformat.FormatHex(sharedSecretA); got != tt.sharedSecretHex {
					t.Fatalf("Shared secret mismatch: got %s, want %s", got, tt.sharedSecretHex)
				}
			} else {
				t.Logf("Shared secret:  %s", textformat.FormatHex(sharedSecretA))
			}

			// Verify AES key derivation
			var addr *string
			if tt.contractAddress != "" {
				addr = &tt.contractAddress
			} else {
				addr = helperContractAddress()
			}
			contextHash := context.ContextHash(tt.chainId, *addr, tt.consentNumber)
			transcriptHash := generateTranscriptHash(
				textformat.FormatHex(alicePub.SerializeCompressed()),
				textformat.FormatHex(bobPub.SerializeCompressed()))

			aesKey, aesNonce, err := generateAESKey(alicePriv, bobPub, transcriptHash, contextHash)
			if err != nil {
				t.Fatalf("generateAESKey() failed: %v", err)
			}
			if tt.aesKeyHex != "" {
				if got := textformat.FormatHex(aesKey); got != tt.aesKeyHex {
					t.Fatalf("AES key mismatch: got %s, want %s", got, tt.aesKeyHex)
				}
			} else {
				t.Logf("AES key:        %s", textformat.FormatHex(aesKey))
			}
			if tt.aesNonceHex != "" {
				if got := textformat.FormatHex(aesNonce); got != tt.aesNonceHex {
					t.Fatalf("AES nonce mismatch: got %s, want %s", got, tt.aesNonceHex)
				}
			} else {
				t.Logf("AES nonce:      %s", textformat.FormatHex(aesNonce))
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

			cbor, err := ipfs.MarshalConsentEC(result)
			if err != nil {
				t.Fatalf("CBOR marshal failed: %v", err)
			}
			if tt.expectedCBORHex != "" {
				if got := textformat.FormatHex(cbor); got != tt.expectedCBORHex {
					t.Fatalf("CBOR mismatch: got %s, want %s", got, tt.expectedCBORHex)
				}
			} else {
				t.Logf("CBOR:           %s", textformat.FormatHex(cbor))
			}

			jsonBytes, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("JSON marshal failed: %v", err)
			}
			if tt.expectedJSON != "" {
				if string(jsonBytes) != tt.expectedJSON {
					t.Fatalf("JSON mismatch: got %s, want %s", jsonBytes, tt.expectedJSON)
				}
			} else {
				t.Logf("JSON:           %s", string(jsonBytes))
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
		{
			// HD wallet consent notary: Alice (m/4410704'/3/1/2/2) and standalone notary key
			name:                    "HD wallet consent notary — Alice and notary keys",
			key1:                    "03c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188",
			key2:                    "02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805",
			expectedTranscriptString: "|pulse|group|v1|02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805|03c502eb5c46c4c98b3b82f6a479800ca93a5c3ff82c48efef2825972f7189a188|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|",
			expectedHashHex:         "ab3298cf53e2ab4cba39ac80210d1a27fdb9e1f01adb64bc460db3d1798ed5e4",
		},
		{
			// HD wallet revoke notary: Alice (m/4410704'/3/1/2/4) and standalone notary key
			name:                    "HD wallet revoke notary — Alice and notary keys",
			key1:                    "03ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8",
			key2:                    "02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805",
			expectedTranscriptString: "|pulse|group|v1|02fade94180988b62103c7788bac14dd71819c92ad3c757ac5eb3477054970d805|03ca619266af8f2b255b5ab690815bf6786511c83b8368ff8be412f2ad46f86cf8|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|",
			expectedHashHex:         "2070da9c4ee5c8bd957f294fabefc228c1379aee8a5c1ce0619209c5fe74b8be",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tString := generateTranscriptString(tt.key1, tt.key2)
			if tt.expectedTranscriptString != "" {
				if tString != tt.expectedTranscriptString {
					t.Errorf("generateTranscriptString mismatch:\n  got  %s\n  want %s", tString, tt.expectedTranscriptString)
				}
			} else {
				t.Logf("Transcript string: %s", tString)
			}

			hash1 := generateTranscriptHash(tt.key1, tt.key2)
			hash2 := generateTranscriptHash(tt.key2, tt.key1)

			if !bytes.Equal(hash1, hash2) {
				t.Errorf("generateTranscriptHash is not deterministic: %x != %x", hash1, hash2)
			}

			if tt.expectedHashHex != "" {
				expectedHash := mustHexDecode(tt.expectedHashHex)
				if !bytes.Equal(hash1, expectedHash) {
					t.Errorf("generateTranscriptHash mismatch: got %x, want %x", hash1, expectedHash)
				}
			} else {
				t.Logf("Transcript hash:   %s", textformat.FormatHex(hash1))
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
