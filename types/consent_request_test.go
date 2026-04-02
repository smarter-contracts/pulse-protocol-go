package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func sampleECEncryptionResult() PulseECEncryptionResult {
	return PulseECEncryptionResult{
		SealedData: []byte("sealed-consent-data"),
		Key1:       []byte("key1-33-bytes-padding-here-xxxxx"),
		Key2:       []byte("key2-33-bytes-padding-here-xxxxx"),
	}
}

// ── PulseConsentRequestEC — JSON ──────────────────────────────────────────────

func TestPulseConsentRequestEC_JSON_RoundTrip(t *testing.T) {
	orig := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures: [][]byte{
			{0x01, 0x02, 0x03, 0x04},
			{0x05, 0x06, 0x07, 0x08},
		},
	}

	data, err := orig.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	got := &PulseConsentRequestEC{}
	require.NoError(t, got.UnmarshalJSON(data))

	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	assert.Equal(t, orig.EncryptedData.Key1, got.EncryptedData.Key1)
	assert.Equal(t, orig.EncryptedData.Key2, got.EncryptedData.Key2)
	assert.Equal(t, orig.Signatures, got.Signatures)
}

func TestPulseConsentRequestEC_JSON_EmptySignatures(t *testing.T) {
	orig := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures:    [][]byte{},
	}

	data, err := orig.MarshalJSON()
	require.NoError(t, err)

	got := &PulseConsentRequestEC{}
	require.NoError(t, got.UnmarshalJSON(data))
	assert.Empty(t, got.Signatures)
}

// ── PulseRevokeRequestEC — JSON ───────────────────────────────────────────────

func TestPulseRevokeRequestEC_JSON_RoundTrip(t *testing.T) {
	orig := &PulseRevokeRequestEC{
		ConsentCid:    "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly",
		EncryptedData: sampleECEncryptionResult(),
		Signature:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	data, err := orig.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	got := &PulseRevokeRequestEC{}
	require.NoError(t, got.UnmarshalJSON(data))

	assert.Equal(t, orig.ConsentCid, got.ConsentCid)
	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	assert.Equal(t, orig.EncryptedData.Key1, got.EncryptedData.Key1)
	assert.Equal(t, orig.EncryptedData.Key2, got.EncryptedData.Key2)
	assert.Equal(t, orig.Signature, got.Signature)
}
