package types

import (
	"testing"

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
