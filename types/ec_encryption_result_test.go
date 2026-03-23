package types

import (
	"bytes"
	"testing"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPulseECEncryptionResult_JSON(t *testing.T) {
	res := &PulseECEncryptionResult{
		SealedData: []byte("sealed-data"),
		Key1:       []byte("key1-33-bytes-long-padding-here"),
		Key2:       []byte("key2-33-bytes-long-padding-here"),
	}

	data, err := res.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	res2 := &PulseECEncryptionResult{}
	err = res2.UnmarshalJSON(data)
	require.NoError(t, err)

	assert.Equal(t, res.SealedData, res2.SealedData)
	assert.Equal(t, res.Key1, res2.Key1)
	assert.Equal(t, res.Key2, res2.Key2)
}

func TestPulseECEncryptionResult_CBOR(t *testing.T) {
	res := &PulseECEncryptionResult{
		SealedData: []byte("sealed-data"),
		Key1:       []byte("key1-33-bytes-long-padding-here"),
		Key2:       []byte("key2-33-bytes-long-padding-here"),
	}

	cborData, err := res.MarshalCBOR()
	require.NoError(t, err)
	assert.NotEmpty(t, cborData)

	/*
		nb := basicnode.Prototype.Any.NewBuilder()
		err = dagcbor.Decode(nb, bytes.NewReader(cborData))
		require.NoError(t, err)
	*/
	res2 := &PulseECEncryptionResult{}
	err = res2.UnmarshalCBOR(cborData)
	require.NoError(t, err)

	assert.Equal(t, res.SealedData, res2.SealedData)
	assert.Equal(t, res.Key1, res2.Key1)
	assert.Equal(t, res.Key2, res2.Key2)
}

func TestPulseECEncryptionResult_UnmarshalCBOR_Errors(t *testing.T) {
	t.Run("wrong type", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("pq") // wrong type
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.Finish()

		var buf bytes.Buffer
		err := dagcbor.Encode(nb.Build(), &buf)
		assert.NoError(t, err)

		res := &PulseECEncryptionResult{}
		err = res.UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected structure type")
	})

	t.Run("wrong version", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("ec")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(2) // wrong version
		_ = ma.Finish()

		var buf bytes.Buffer
		err := dagcbor.Encode(nb.Build(), &buf)
		assert.NoError(t, err)

		res := &PulseECEncryptionResult{}
		err = res.UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected ec structure version")
	})

	t.Run("missing fields", func(t *testing.T) {
		nb := basicnode.Prototype.Map.NewBuilder()
		ma, _ := nb.BeginMap(2)
		_ = ma.AssembleKey().AssignString("t")
		_ = ma.AssembleValue().AssignString("ec")
		_ = ma.AssembleKey().AssignString("v")
		_ = ma.AssembleValue().AssignInt(1)
		_ = ma.Finish()

		var buf bytes.Buffer
		err := dagcbor.Encode(nb.Build(), &buf)
		assert.NoError(t, err)

		res := &PulseECEncryptionResult{}
		err = res.UnmarshalCBOR(buf.Bytes())
		assert.Error(t, err)
	})
}
