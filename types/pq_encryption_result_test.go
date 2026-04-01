package types

import (
	"testing"

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
