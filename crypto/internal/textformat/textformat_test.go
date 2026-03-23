package textformat

import (
	"testing"
)

func TestFormatHex(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "basic bytes",
			input:    []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			expected: "0123456789abcdef",
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "nil slice",
			input:    nil,
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "00",
		},
		{
			name:     "all zeros",
			input:    []byte{0x00, 0x00, 0x00},
			expected: "000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatHex(tt.input)
			if got != tt.expected {
				t.Errorf("FormatHex() = %v, want %v", got, tt.expected)
			}
		})
	}
}
