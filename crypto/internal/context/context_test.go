package context

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestContextString(t *testing.T) {
	tests := []struct {
		name            string
		chainId         int32
		contractAddress string
		consentNumber   int32
		want            string
	}{
		{
			name:            "basic context",
			chainId:         1,
			contractAddress: "0x0102030405060708090a0b0c0d0e0f1011121314",
			consentNumber:   0,
			want:            "|pulse|ctx|v1|chain=1|contract=0x0102030405060708090a0b0c0d0e0f1011121314|consentNumber=0",
		},
		{
			name:            "different chain and consent",
			chainId:         137,
			contractAddress: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			consentNumber:   1234,
			want:            "|pulse|ctx|v1|chain=137|contract=0x742d35Cc6634C0532925a3b844Bc454e4438f44e|consentNumber=1234",
		},
		{
			name:            "negative values (though unlikely)",
			chainId:         -1,
			contractAddress: "0x00",
			consentNumber:   -5,
			want:            "|pulse|ctx|v1|chain=-1|contract=0x00|consentNumber=-5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContextString(tt.chainId, tt.contractAddress, tt.consentNumber)
			if got != tt.want {
				t.Errorf("ContextString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContextHash(t *testing.T) {
	chainId := int32(1)
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"
	consentNumber := int32(0)

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
