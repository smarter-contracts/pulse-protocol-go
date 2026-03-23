package types

import (
	"bytes"
	"testing"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPulsePQEncryptionResult_JSON(t *testing.T) {
	res := &PulsePQEncryptionResult{
		SealedData: []byte("sealed-data"),
		Keys: []*PulsePQEncryptionKey{
			{
				KeyFingerPrint:      [32]byte{1, 2, 3},
				EncapsulatedKeyKey:  []byte("ekk1"),
				EncapsulatedDataKey: []byte("edk1"),
			},
			{
				KeyFingerPrint:      [32]byte{4, 5, 6},
				EncapsulatedKeyKey:  []byte("ekk2"),
				EncapsulatedDataKey: []byte("edk2"),
			},
		},
	}

	data, err := res.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	res2 := &PulsePQEncryptionResult{}
	err = res2.UnmarshalJSON(data)
	require.NoError(t, err)

	assert.Equal(t, res.SealedData, res2.SealedData)
	require.Equal(t, len(res.Keys), len(res2.Keys))
	for i := range res.Keys {
		assert.Equal(t, res.Keys[i].KeyFingerPrint, res2.Keys[i].KeyFingerPrint)
		assert.Equal(t, res.Keys[i].EncapsulatedKeyKey, res2.Keys[i].EncapsulatedKeyKey)
		assert.Equal(t, res.Keys[i].EncapsulatedDataKey, res2.Keys[i].EncapsulatedDataKey)
	}
}

func TestPulsePQEncryptionResult_CBOR(t *testing.T) {
	res := &PulsePQEncryptionResult{
		SealedData: []byte("sealed-data"),
		Keys: []*PulsePQEncryptionKey{
			{
				KeyFingerPrint:      [32]byte{1, 2, 3},
				EncapsulatedKeyKey:  []byte("ekk1"),
				EncapsulatedDataKey: []byte("edk1"),
			},
		},
	}

	cborData, err := res.MarshalCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	nb := basicnode.Prototype.Any.NewBuilder()
	err = dagcbor.Decode(nb, bytes.NewReader(cborData))
	require.NoError(t, err)

	res2 := &PulsePQEncryptionResult{}
	err = res2.UnmarshalCBOR(cborData)
	require.NoError(t, err)

	assert.Equal(t, res.SealedData, res2.SealedData)
	require.Equal(t, len(res.Keys), len(res2.Keys))
	assert.Equal(t, res.Keys[0].KeyFingerPrint, res2.Keys[0].KeyFingerPrint)
	assert.Equal(t, res.Keys[0].EncapsulatedKeyKey, res2.Keys[0].EncapsulatedKeyKey)
	assert.Equal(t, res.Keys[0].EncapsulatedDataKey, res2.Keys[0].EncapsulatedDataKey)
}

func TestPulsePQEncryptionResult_UnmarshalCBOR_Errors(t *testing.T) {
	t.Run("wrong type", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("ec") // wrong type
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.Finish()

		var buf bytes.Buffer
		err := dagcbor.Encode(nb.Build(), &buf)
		assert.NoError(t, err)

		res := &PulsePQEncryptionResult{}
		err = res.UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected structure type")
	})

	t.Run("wrong version", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("pq")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(2) // wrong version
		_ = ma.Finish()

		var buf bytes.Buffer
		err := dagcbor.Encode(nb.Build(), &buf)
		assert.NoError(t, err)

		res := &PulsePQEncryptionResult{}
		err = res.UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected ec structure version")
	})

	t.Run("invalid fingerprint length", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(4)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("pq")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.AssembleKey().AssignString("sd")
		_ = ma.AssembleValue().AssignBytes([]byte("sd"))

		_ = ma.AssembleKey().AssignString("keys")
		la, _ := ma.AssembleValue().BeginList(1)
		kb := basicnode.Prototype.Map.NewBuilder()
		kma, _ := kb.BeginMap(1)
		_ = kma.AssembleKey().AssignString("fp")
		_ = kma.AssembleValue().AssignBytes([]byte("too-short")) // not 32 bytes
		_ = kma.Finish()
		_ = la.AssembleValue().AssignNode(kb.Build())
		_ = la.Finish()
		_ = ma.Finish()

		var buf bytes.Buffer
		err := dagcbor.Encode(nb.Build(), &buf)
		assert.NoError(t, err)

		res := &PulsePQEncryptionResult{}
		err = res.UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "fp must be 32 bytes")
	})
}
