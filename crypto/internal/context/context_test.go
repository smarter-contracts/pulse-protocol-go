package context

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestContextString(t *testing.T) {
	tests := []struct {
		name            string
		chainId         uint32
		contractAddress string
		consentNumber   uint32
		want            string
		hashOut         string
	}{
		{
			name:            "key_exchange_known_values",
			chainId:         1,
			contractAddress: "0x0102030405060708090a0b0c0d0e0f1011121314",
			consentNumber:   2,
			want:            "|pulse|ctx|v1|chain=1|contract=0x0102030405060708090a0b0c0d0e0f1011121314|consentNumber=2",
			hashOut:         "7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3",
		},
		{
			name:            "basic context",
			chainId:         1,
			contractAddress: "0x0102030405060708090a0b0c0d0e0f1011121314",
			consentNumber:   0,
			want:            "|pulse|ctx|v1|chain=1|contract=0x0102030405060708090a0b0c0d0e0f1011121314|consentNumber=0",
			hashOut:         "6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea",
		},
		{
			name:            "different chain and consent",
			chainId:         137,
			contractAddress: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			consentNumber:   1234,
			want:            "|pulse|ctx|v1|chain=137|contract=0x742d35Cc6634C0532925a3b844Bc454e4438f44e|consentNumber=1234",
			hashOut:         "7e9b68d32341c8a6b8149450d5dbdea7006ca44fb85b1612424b9f6901c33d50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContextString(tt.chainId, tt.contractAddress, tt.consentNumber)
			if got != tt.want {
				t.Errorf("ContextString() = %q, want %q", got, tt.want)
			}
			h := ContextHash(tt.chainId, tt.contractAddress, tt.consentNumber)
			gotHash := hex.EncodeToString(h)
			if strings.Compare(gotHash, tt.hashOut) != 0 {
				t.Errorf("ContextHash() = %q, want %q", gotHash, tt.hashOut)
			}
		})
	}
}

func TestContextHash(t *testing.T) {
	chainId := uint32(1)
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"
	consentNumber := uint32(0)

	// Known Keccak-256 hash for "|pulse|ctx|v1|chain=1|contract=0x0102030405060708090a0b0c0d0e0f1011121314|consentNumber=0"
	// We can verify this against the value used in key_encapsulation_test.go if available,
	// or calculate it.
	// From key_encapsulation_test.go:
	// expectedContextHash := "6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea"

	hash := ContextHash(chainId, contractAddress, consentNumber)

	// Hash length should be 32 bytes.
	if len(hash) != 32 {
		t.Errorf("ContextHash length = %d, want 121", len(hash))
	}

	// Test determinism
	hash2 := ContextHash(chainId, contractAddress, consentNumber)
	if !bytes.Equal(hash, hash2) {
		t.Error("ContextHash is not deterministic")
	}

	// Known value test (calculated using concatenation of the string and Keccak256 of empty string)
	expectedHex := "6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea"
	gotHex := hex.EncodeToString(hash)
	if gotHex != expectedHex {
		t.Errorf("ContextHash() = %s, want %s", gotHex, expectedHex)
	}
}
