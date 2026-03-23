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

func samplePQEncryptionResult() PulsePQEncryptionResult {
	return PulsePQEncryptionResult{
		SealedData: []byte("sealed-pq-consent-data"),
		Keys: []*PulsePQEncryptionKey{
			{
				KeyFingerPrint:      [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
				EncapsulatedKeyKey:  []byte("encapsulated-key-key-alice"),
				EncapsulatedDataKey: []byte("encapsulated-data-key-alice"),
			},
			{
				KeyFingerPrint:      [32]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40},
				EncapsulatedKeyKey:  []byte("encapsulated-key-key-bob"),
				EncapsulatedDataKey: []byte("encapsulated-data-key-bob"),
			},
		},
	}
}

// ── PulseConsentRequestPQ — JSON ──────────────────────────────────────────────

func TestPulseConsentRequestPQ_JSON_RoundTrip(t *testing.T) {
	orig := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures: [][]byte{
			{0xaa, 0xbb, 0xcc},
			{0xdd, 0xee, 0xff},
		},
	}

	data, err := orig.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	got := &PulseConsentRequestPQ{}
	require.NoError(t, got.UnmarshalJSON(data))

	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	require.Len(t, got.EncryptedData.Keys, 2)
	assert.Equal(t, orig.EncryptedData.Keys[0].KeyFingerPrint, got.EncryptedData.Keys[0].KeyFingerPrint)
	assert.Equal(t, orig.EncryptedData.Keys[1].EncapsulatedKeyKey, got.EncryptedData.Keys[1].EncapsulatedKeyKey)
	assert.Equal(t, orig.Signatures, got.Signatures)
}

func TestPulseConsentRequestPQ_JSON_EmptySignatures(t *testing.T) {
	orig := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures:    [][]byte{},
	}

	data, err := orig.MarshalJSON()
	require.NoError(t, err)

	got := &PulseConsentRequestPQ{}
	require.NoError(t, got.UnmarshalJSON(data))
	assert.Empty(t, got.Signatures)
}

// ── PulseConsentRequestPQ — CBOR ──────────────────────────────────────────────

func TestPulseConsentRequestPQ_CBOR_RoundTrip(t *testing.T) {
	orig := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures: [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	got := &PulseConsentRequestPQ{}
	require.NoError(t, got.UnmarshalCBOR(cborData))

	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	require.Len(t, got.EncryptedData.Keys, 2)
	for i := range orig.EncryptedData.Keys {
		assert.Equal(t, orig.EncryptedData.Keys[i].KeyFingerPrint, got.EncryptedData.Keys[i].KeyFingerPrint)
		assert.Equal(t, orig.EncryptedData.Keys[i].EncapsulatedKeyKey, got.EncryptedData.Keys[i].EncapsulatedKeyKey)
		assert.Equal(t, orig.EncryptedData.Keys[i].EncapsulatedDataKey, got.EncryptedData.Keys[i].EncapsulatedDataKey)
	}
	assert.Equal(t, orig.Signatures, got.Signatures)
}

func TestPulseConsentRequestPQ_CBOR_SingleSignature(t *testing.T) {
	orig := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures:    [][]byte{{0xde, 0xad}},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)

	got := &PulseConsentRequestPQ{}
	require.NoError(t, got.UnmarshalCBOR(cborData))

	require.Len(t, got.Signatures, 1)
	assert.Equal(t, orig.Signatures[0], got.Signatures[0])
}

func TestPulseConsentRequestPQ_CBOR_EmptySignatures(t *testing.T) {
	orig := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures:    [][]byte{},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)

	got := &PulseConsentRequestPQ{}
	require.NoError(t, got.UnmarshalCBOR(cborData))
	assert.Empty(t, got.Signatures)
}

func TestPulseConsentRequestPQ_UnmarshalCBOR_Errors(t *testing.T) {
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

		err := (&PulseConsentRequestPQ{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected structure type")
	})

	t.Run("wrong version", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("consent-pq")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(99)
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseConsentRequestPQ{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected consent-pq version")
	})

	t.Run("invalid cbor", func(t *testing.T) {
		err := (&PulseConsentRequestPQ{}).UnmarshalCBOR([]byte{0xff, 0xfe, 0xfd})
		assert.Error(t, err)
	})
}

// ── PulseRevokeRequestPQ — JSON ───────────────────────────────────────────────

func TestPulseRevokeRequestPQ_JSON_RoundTrip(t *testing.T) {
	orig := &PulseRevokeRequestPQ{
		ConsentCid:    "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly",
		EncryptedData: samplePQEncryptionResult(),
		Signature:     []byte{0xca, 0xfe, 0xba, 0xbe},
	}

	data, err := orig.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	got := &PulseRevokeRequestPQ{}
	require.NoError(t, got.UnmarshalJSON(data))

	assert.Equal(t, orig.ConsentCid, got.ConsentCid)
	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	require.Len(t, got.EncryptedData.Keys, 2)
	assert.Equal(t, orig.Signature, got.Signature)
}

// ── PulseRevokeRequestPQ — CBOR ───────────────────────────────────────────────

func TestPulseRevokeRequestPQ_CBOR_RoundTrip(t *testing.T) {
	orig := &PulseRevokeRequestPQ{
		ConsentCid:    "bafyreifepiu23okd26ixpwptj76hjnbkk6nofql7pojk5bxjyb6c74gbly",
		EncryptedData: samplePQEncryptionResult(),
		Signature:     []byte{0xde, 0xad, 0xbe, 0xef},
	}

	cborData, err := orig.MarshalCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	got := &PulseRevokeRequestPQ{}
	require.NoError(t, got.UnmarshalCBOR(cborData))

	assert.Equal(t, orig.ConsentCid, got.ConsentCid)
	assert.Equal(t, orig.EncryptedData.SealedData, got.EncryptedData.SealedData)
	require.Len(t, got.EncryptedData.Keys, 2)
	for i := range orig.EncryptedData.Keys {
		assert.Equal(t, orig.EncryptedData.Keys[i].KeyFingerPrint, got.EncryptedData.Keys[i].KeyFingerPrint)
		assert.Equal(t, orig.EncryptedData.Keys[i].EncapsulatedKeyKey, got.EncryptedData.Keys[i].EncapsulatedKeyKey)
		assert.Equal(t, orig.EncryptedData.Keys[i].EncapsulatedDataKey, got.EncryptedData.Keys[i].EncapsulatedDataKey)
	}
	assert.Equal(t, orig.Signature, got.Signature)
}

func TestPulseRevokeRequestPQ_UnmarshalCBOR_Errors(t *testing.T) {
	t.Run("wrong type", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("consent-pq") // wrong type
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseRevokeRequestPQ{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected structure type")
	})

	t.Run("wrong version", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("revoke-pq")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(99)
		_ = ma.Finish()

		var buf bytes.Buffer
		require.NoError(t, dagcbor.Encode(nb.Build(), &buf))

		err := (&PulseRevokeRequestPQ{}).UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected revoke-pq version")
	})

	t.Run("invalid cbor", func(t *testing.T) {
		err := (&PulseRevokeRequestPQ{}).UnmarshalCBOR([]byte{0xff, 0xfe, 0xfd})
		assert.Error(t, err)
	})
}

// ── Cross-type discrimination (PQ) ───────────────────────────────────────────

func TestConsentRevokePQ_CBOR_TypeDiscrimination(t *testing.T) {
	consent := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures:    [][]byte{{0x01}},
	}
	consentCBOR, err := consent.MarshalCBOR()
	require.NoError(t, err)

	revoke := &PulseRevokeRequestPQ{
		ConsentCid:    "bafytest",
		EncryptedData: samplePQEncryptionResult(),
		Signature:     []byte{0x01},
	}
	revokeCBOR, err := revoke.MarshalCBOR()
	require.NoError(t, err)

	// consent-pq bytes → revoke-pq decoder must fail
	assert.Error(t, (&PulseRevokeRequestPQ{}).UnmarshalCBOR(consentCBOR))

	// revoke-pq bytes → consent-pq decoder must fail
	assert.Error(t, (&PulseConsentRequestPQ{}).UnmarshalCBOR(revokeCBOR))
}

// Cross-scheme: EC CBOR rejected by PQ decoder and vice versa
func TestConsentRequest_CrossScheme_TypeDiscrimination(t *testing.T) {
	ec := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
		Signatures:    [][]byte{{0x01}},
	}
	ecCBOR, err := ec.MarshalCBOR()
	require.NoError(t, err)

	pq := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
		Signatures:    [][]byte{{0x01}},
	}
	pqCBOR, err := pq.MarshalCBOR()
	require.NoError(t, err)

	// EC consent → PQ decoder must fail
	assert.Error(t, (&PulseConsentRequestPQ{}).UnmarshalCBOR(ecCBOR))

	// PQ consent → EC decoder must fail
	assert.Error(t, (&PulseConsentRequestEC{}).UnmarshalCBOR(pqCBOR))
}

// ── SignableConsent / SignableRevoke interface tests ───────────────────────────

func TestPulseConsentRequestPQ_SignableConsent(t *testing.T) {
	req := &PulseConsentRequestPQ{
		EncryptedData: samplePQEncryptionResult(),
	}

	// EncryptedDataCBOR returns valid CBOR
	cborData, err := req.EncryptedDataCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	// Verify the CBOR is a valid PQ encryption result
	var decoded PulsePQEncryptionResult
	require.NoError(t, decoded.UnmarshalCBOR(cborData))
	assert.Equal(t, req.EncryptedData.SealedData, decoded.SealedData)

	// AppendSignature adds to the Signatures slice
	assert.Empty(t, req.Signatures)
	req.AppendSignature([]byte{0xaa, 0xbb})
	require.Len(t, req.Signatures, 1)
	assert.Equal(t, []byte{0xaa, 0xbb}, req.Signatures[0])

	req.AppendSignature([]byte{0xcc, 0xdd})
	require.Len(t, req.Signatures, 2)
	assert.Equal(t, []byte{0xcc, 0xdd}, req.Signatures[1])
}

func TestPulseRevokeRequestPQ_SignableRevoke(t *testing.T) {
	req := &PulseRevokeRequestPQ{
		ConsentCid:    "bafytest123",
		EncryptedData: samplePQEncryptionResult(),
	}

	// EncryptedDataCBOR returns valid CBOR
	cborData, err := req.EncryptedDataCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	// GetConsentCid returns the stored CID
	assert.Equal(t, "bafytest123", req.GetConsentCid())

	// AppendSignature replaces the Signature field
	assert.Empty(t, req.Signature)
	req.AppendSignature([]byte{0xde, 0xad})
	assert.Equal(t, []byte{0xde, 0xad}, req.Signature)
}

func TestPulseConsentRequestEC_SignableConsent(t *testing.T) {
	req := &PulseConsentRequestEC{
		EncryptedData: sampleECEncryptionResult(),
	}

	// EncryptedDataCBOR returns valid CBOR
	cborData, err := req.EncryptedDataCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	// Verify the CBOR is a valid EC encryption result
	var decoded PulseECEncryptionResult
	require.NoError(t, decoded.UnmarshalCBOR(cborData))
	assert.Equal(t, req.EncryptedData.SealedData, decoded.SealedData)

	// AppendSignature adds to the Signatures slice
	assert.Empty(t, req.Signatures)
	req.AppendSignature([]byte{0x11, 0x22})
	require.Len(t, req.Signatures, 1)
	assert.Equal(t, []byte{0x11, 0x22}, req.Signatures[0])
}

func TestPulseRevokeRequestEC_SignableRevoke(t *testing.T) {
	req := &PulseRevokeRequestEC{
		ConsentCid:    "bafytest456",
		EncryptedData: sampleECEncryptionResult(),
	}

	// EncryptedDataCBOR returns valid CBOR
	cborData, err := req.EncryptedDataCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	// GetConsentCid returns the stored CID
	assert.Equal(t, "bafytest456", req.GetConsentCid())

	// AppendSignature replaces the Signature field
	assert.Empty(t, req.Signature)
	req.AppendSignature([]byte{0xbe, 0xef})
	assert.Equal(t, []byte{0xbe, 0xef}, req.Signature)
}
