package hkdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPulseHKDF_KnownValues(t *testing.T) {
	tests := []struct {
		name         string
		mode         string // "ECDH" or "Kyber"
		sharedSecret []byte
		transcript   []byte
		recipientId  []byte
		context      []byte
		// Expected outputs
		expectedSaltString      string
		expectedSalt            []byte
		expectedPrk             []byte
		expectedInfoStringAES   string
		expectedInfoStringNonce string
		expectedAESKey          []byte
		expectedAESNonce        []byte
	}{
		{
			name:         "ECDH call",
			mode:         "ECDH",
			sharedSecret: mustHexDecode("3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e"),
			transcript:   mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4"),
			recipientId:  nil,
			context:      mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			// Expected values
			expectedSaltString:      "pulse|kdf|v1|salt|secp256k1|1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|",
			expectedSalt:            mustHexDecode("1ec80f02e80bc5f74a6b4975477a579545067042088d26149950b288562693af"),
			expectedPrk:             mustHexDecode("f7c1f084075cb16f0a7fa816e6dabf354af548e802585216bd7b3c3d7b5b5f69"),
			expectedInfoStringAES:   "|pulse|kdf|v1|aead:channel:key|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedInfoStringNonce: "|pulse|kdf|v1|aead:channel:nonce|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedAESKey:          mustHexDecode("cee5d3c958a8be9fdea4e4dca39cf4bf52ca824a1f71d026319e350a6b0ef67a"),
			expectedAESNonce:        mustHexDecode("3298b5b0da18ab57667cf999"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Test Salt String and Salt Value
			parentAlgo, purpose, suite := getSettings(tt.mode)

			saltString := createSaltString(parentAlgo, tt.transcript)
			if saltString != tt.expectedSaltString {
				t.Errorf("saltString mismatch: got %q, want %q", saltString, tt.expectedSaltString)
			}
			salt := createSalt(parentAlgo, tt.transcript)
			if !bytes.Equal(salt, tt.expectedSalt) {
				t.Errorf("salt mismatch: got %x, want %x", salt, tt.expectedSalt)
			}

			infoKey := createInfo(purpose, false, suite, tt.recipientId, tt.context)
			if string(infoKey) != tt.expectedInfoStringAES {
				t.Errorf("infoKeyString mismatch: got %q, want %q", string(infoKey), tt.expectedInfoStringAES)
			}

			infoNonce := createInfo(purpose, true, suite, tt.recipientId, tt.context)
			if string(infoNonce) != tt.expectedInfoStringNonce {
				t.Errorf("infoNonceString mismatch: got %q, want %q", string(infoNonce), tt.expectedInfoStringNonce)
			}

			// 3. Test PRK, AES Key and AES Nonce
			prk := pulseExtract(tt.sharedSecret, parentAlgo, tt.transcript)
			if !bytes.Equal(prk, tt.expectedPrk) {
				t.Errorf("PRK mismatch: got %x, want %x", prk, tt.expectedPrk)
			}

			var key, nonce []byte
			var err error
			if tt.mode == "ECDH" {
				key, nonce, err = PulseHKDFECDH(tt.sharedSecret, tt.transcript, tt.recipientId, tt.context)
			} else {
				key, nonce, err = PulseHKDFKyber(tt.sharedSecret, tt.transcript, tt.recipientId, tt.context)
			}

			if err != nil {
				t.Fatalf("HKDF failed: %v", err)
			}

			if !bytes.Equal(key, tt.expectedAESKey) {
				t.Errorf("AES key mismatch: got %x, want %x", key, tt.expectedAESKey)
			}
			if !bytes.Equal(nonce, tt.expectedAESNonce) {
				t.Errorf("AES nonce mismatch: got %x, want %x", nonce, tt.expectedAESNonce)
			}
		})
	}
}
