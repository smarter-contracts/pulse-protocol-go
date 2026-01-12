package hash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPulseHashBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string // hex encoded
	}{
		{
			name:     "empty byte slice",
			input:    []byte{},
			expected: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
		},
		{
			name:     "multiple bytes - pulse",
			input:    []byte("pulse"),
			expected: "6db1f6525ccc1966e3fc8c06df53e9935e2404e341e61b7bf45d002e1eee6cf9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := PulseHashBytes(tt.input)
			if len(hash) != 32 {
				t.Errorf("PulseHashBytes() length = %d, want 32", len(hash))
			}
			gotHex := hex.EncodeToString(hash)
			if gotHex != tt.expected {
				t.Errorf("PulseHashBytes() = %s, want %s", gotHex, tt.expected)
			}
		})
	}
}

func TestPulseHashString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // hex encoded
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			name:     "pulse string",
			input:    "pulse",
			expected: "6db1f6525ccc1966e3fc8c06df53e9935e2404e341e61b7bf45d002e1eee6cf9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := PulseHashString(tt.input)
			if len(hash) != 32 {
				t.Errorf("PulseHashString() length = %d, want 32", len(hash))
			}
			gotHex := hex.EncodeToString(hash)
			if gotHex != tt.expected {
				t.Errorf("PulseHashString() = %s, want %s", gotHex, tt.expected)
			}
		})
	}
}

func TestDeterminism(t *testing.T) {
	input := []byte("deterministic test")
	hash1 := PulseHashBytes(input)
	hash2 := PulseHashBytes(input)

	if !bytes.Equal(hash1, hash2) {
		t.Error("PulseHashBytes is not deterministic")
	}

	hash3 := PulseHashString("deterministic test")
	if !bytes.Equal(hash1, hash3) {
		t.Error("PulseHashString output differs from PulseHashBytes for same data")
	}
}
