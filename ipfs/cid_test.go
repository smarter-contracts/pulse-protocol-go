package ipfs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCid(t *testing.T) {
	tests := []struct {
		name     string
		block    []byte
		expected string
	}{
		{
			name:     "KnownValue: hello world",
			block:    []byte("hello world"),
			expected: "bafyreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e",
		},
		{
			name:     "KnownValue: CBOR 'a'",
			block:    []byte{0x61, 0x61},
			expected: "bafyreiewdnw5h3pdzohmxkwl22g6aqgnpdvs5vmiseymz22mjeti5jgvay",
		},
		{
			name:     "Empty block",
			block:    []byte{},
			expected: "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
		},
		{
			name:     "Copy send_test_consent.js",
			block:    []byte{163, 100, 107, 101, 121, 49, 106, 75, 69, 89, 49, 114, 97, 110, 100, 111, 109, 100, 107, 101, 121, 50, 106, 75, 69, 89, 50, 114, 97, 110, 100, 111, 109, 103, 99, 111, 110, 115, 101, 110, 116, 120, 42, 67, 79, 78, 83, 69, 78, 84, 95, 82, 69, 86, 84, 69, 83, 84, 49, 49, 55, 54, 57, 48, 49, 49, 51, 49, 53, 52, 53, 56, 49, 55, 54, 57, 48, 49, 49, 51, 49, 53, 52, 53, 56},
			expected: "bafyreid2bvcka3iw7ag2lwxy7jvpd3wil4vj4ftmhyehty3b6ypbfge3pu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := GetCid(tt.block)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, c.String())
		})
	}
}
