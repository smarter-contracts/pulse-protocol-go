package types

import (
	"bytes"
	"testing"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
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

// ── PulseConsentRequestEC — CBOR ──────────────────────────────────────────────

func TestPulseConsentRequestEC_CBOR_RoundTrip(t *testing.T) {
	orig := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures: [][]byte{
			{0xaa, 0xbb, 0xcc},
			{0xdd, 0xee, 0xff},
		},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	got := &PulseConsentRequestEC{}
	require.NoError(t, got.UnmarshalCBOR(cborData))

	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	assert.Equal(t, orig.EncryptedData.Key1, got.EncryptedData.Key1)
	assert.Equal(t, orig.EncryptedData.Key2, got.EncryptedData.Key2)
	assert.Equal(t, orig.Signatures, got.Signatures)
}

func TestPulseConsentRequestEC_CBOR_SingleSignature(t *testing.T) {
	orig := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures:    [][]byte{{0x01, 0x02}},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)

	got := &PulseConsentRequestEC{}
	require.NoError(t, got.UnmarshalCBOR(cborData))

	require.Len(t, got.Signatures, 1)
	assert.Equal(t, orig.Signatures[0], got.Signatures[0])
}

func TestPulseConsentRequestEC_CBOR_EmptySignatures(t *testing.T) {
	orig := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures:    [][]byte{},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)

	got := &PulseConsentRequestEC{}
	require.NoError(t, got.UnmarshalCBOR(cborData))
	assert.Empty(t, got.Signatures)
}

func TestPulseConsentRequestEC_UnmarshalCBOR_Errors(t *testing.T) {
	t.Run("wrong type", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("revoke-ec") // wrong type
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseConsentRequestEC{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected structure type")
	})

	t.Run("wrong version", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("consent-ec")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(2) // wrong version
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseConsentRequestEC{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected consent-ec version")
	})

	t.Run("invalid cbor", func(t *testing.T) {
		err := (&PulseConsentRequestEC{}).UnmarshalCBOR([]byte{0xff, 0xfe, 0xfd})
		assert.Error(t, err)
	})
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

// ── PulseRevokeRequestEC — CBOR ───────────────────────────────────────────────

func TestPulseRevokeRequestEC_CBOR_RoundTrip(t *testing.T) {
	orig := &PulseRevokeRequestEC{
		ConsentCid:    "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly",
		EncryptedData: sampleECEncryptionResult(),
		Signature:     []byte{0xde, 0xad, 0xbe, 0xef},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	got := &PulseRevokeRequestEC{}
	require.NoError(t, got.UnmarshalCBOR(cborData))

	assert.Equal(t, orig.ConsentCid, got.ConsentCid)
	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	assert.Equal(t, orig.EncryptedData.Key1, got.EncryptedData.Key1)
	assert.Equal(t, orig.EncryptedData.Key2, got.EncryptedData.Key2)
	assert.Equal(t, orig.Signature, got.Signature)
}

func TestPulseRevokeRequestEC_UnmarshalCBOR_Errors(t *testing.T) {
	t.Run("wrong type", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("consent-ec") // wrong type
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseRevokeRequestEC{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected structure type")
	})

	t.Run("wrong version", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("revoke-ec")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(99)
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseRevokeRequestEC{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected revoke-ec version")
	})

	t.Run("invalid cbor", func(t *testing.T) {
		err := (&PulseRevokeRequestEC{}).UnmarshalCBOR([]byte{0xff, 0xfe, 0xfd})
		assert.Error(t, err)
	})
}

// ── cross-type sanity ─────────────────────────────────────────────────────────

// TestConsentRevokeCBOR_TypeDiscrimination verifies that consent-ec CBOR is
// rejected by PulseRevokeRequestEC and vice-versa.
func TestConsentRevokeCBOR_TypeDiscrimination(t *testing.T) {
	consent := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures:    [][]byte{{0x01}},
	}
	consentCBOR, err := consent.MarshalCBOR()
	require.NoError(t, err)

	revoke := &PulseRevokeRequestEC{
		ConsentCid:    "bafytest",
		EncryptedData: sampleECEncryptionResult(),
		Signature:     []byte{0x01},
	}
	revokeCBOR, err := revoke.MarshalCBOR()
	require.NoError(t, err)

	// consent bytes → revoke decoder must fail
	assert.Error(t, (&PulseRevokeRequestEC{}).UnmarshalCBOR(consentCBOR))

	// revoke bytes → consent decoder must fail
	assert.Error(t, (&PulseConsentRequestEC{}).UnmarshalCBOR(revokeCBOR))
}
