package ipfs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
)

func TestMarshalNotaryBlock_RoundTrip(t *testing.T) {
	orig := &pptypes.NotaryBlock{
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
		IPAddress: "203.0.113.42",
		UserAgent: "PulsePlus/1.0 (iOS 17.0)",
		Location:  "GB",
	}

	block, err := MarshalNotaryBlock(orig)
	require.NoError(t, err)
	require.NotEmpty(t, block)

	got, err := UnmarshalNotaryBlock(block)
	require.NoError(t, err)

	assert.Equal(t, orig.Timestamp.Unix(), got.Timestamp.Unix())
	assert.Equal(t, orig.IPAddress, got.IPAddress)
	assert.Equal(t, orig.UserAgent, got.UserAgent)
	assert.Equal(t, orig.Location, got.Location)
}

func TestUnmarshalNotaryBlock_WrongType(t *testing.T) {
	orig := &pptypes.NotaryBlock{
		Timestamp: time.Now().UTC(),
		IPAddress: "127.0.0.1",
	}
	block, err := MarshalNotaryBlock(orig)
	require.NoError(t, err)

	// Corrupt the type field by marshalling an EC block with the same bytes
	// — simpler: just verify that a mismatched type string is rejected.
	// We do that by marshalling a different type and trying to unmarshal as notary.
	ecBlock, err := MarshalConsentEC(&pptypes.PulseECEncryptionResult{
		SealedData: []byte("sd"), Key1: []byte("k1"), Key2: []byte("k2"),
	})
	require.NoError(t, err)
	_ = block // silence unused warning

	_, err = UnmarshalNotaryBlock(ecBlock)
	assert.ErrorContains(t, err, "unexpected structure type")
}
