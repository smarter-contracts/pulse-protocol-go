package ipfs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

func TestMarshalFeedPermission_RoundTrip(t *testing.T) {
	orig := &feedpermission.FeedPermissionPayload{
		ConsentNo:        42,
		WalletId:         "wlt-abc123",
		GrantorWebId:     "https://pod.example/alice/profile/card#me",
		CounterpartyDid:  "did:web:feeds.example.com",
		FeedType:         "open-banking",
		PodContainerPath: "pulse/feeds/open-banking/",
		Permissions:      []string{"read", "write"},
		DataCategories:   []string{"transaction-history", "account-balance"},
		IssuedAt:         time.Unix(1_700_000_000, 0).Unix(),
		ExpiresAt:        time.Unix(1_730_000_000, 0).Unix(),
		EncryptedNotary:  []byte("encrypted-notary-block-bytes"),
		NotaryKey1:       make([]byte, 33),
		NotaryKey2:       make([]byte, 33),
	}
	orig.NotaryKey1[0] = 0x02
	orig.NotaryKey2[0] = 0x03

	block, err := MarshalFeedPermission(orig)
	require.NoError(t, err)
	require.NotEmpty(t, block)

	got, err := UnmarshalFeedPermission(block)
	require.NoError(t, err)

	assert.Equal(t, orig.ConsentNo, got.ConsentNo)
	assert.Equal(t, orig.WalletId, got.WalletId)
	assert.Equal(t, orig.GrantorWebId, got.GrantorWebId)
	assert.Equal(t, orig.CounterpartyDid, got.CounterpartyDid)
	assert.Equal(t, orig.FeedType, got.FeedType)
	assert.Equal(t, orig.PodContainerPath, got.PodContainerPath)
	assert.Equal(t, orig.Permissions, got.Permissions)
	assert.Equal(t, orig.DataCategories, got.DataCategories)
	assert.Equal(t, orig.IssuedAt, got.IssuedAt)
	assert.Equal(t, orig.ExpiresAt, got.ExpiresAt)
	assert.Equal(t, orig.EncryptedNotary, got.EncryptedNotary)
	assert.Equal(t, orig.NotaryKey1, got.NotaryKey1)
	assert.Equal(t, orig.NotaryKey2, got.NotaryKey2)
}

func TestMarshalFeedPermission_EmptyLists(t *testing.T) {
	orig := &feedpermission.FeedPermissionPayload{
		ConsentNo:        1,
		WalletId:         "wlt-x",
		GrantorWebId:     "https://pod.example/bob/profile/card#me",
		CounterpartyDid:  "did:example:counterparty",
		FeedType:         "health",
		PodContainerPath: "pulse/feeds/health/",
		Permissions:      []string{},
		DataCategories:   []string{},
		IssuedAt:         1_700_000_000,
		ExpiresAt:        0,
		EncryptedNotary:  []byte("notary"),
		NotaryKey1:       make([]byte, 33),
		NotaryKey2:       make([]byte, 33),
	}

	block, err := MarshalFeedPermission(orig)
	require.NoError(t, err)

	got, err := UnmarshalFeedPermission(block)
	require.NoError(t, err)

	assert.Equal(t, orig.ExpiresAt, got.ExpiresAt)
	// Empty slices may unmarshal as nil — both are acceptable
	assert.Empty(t, got.Permissions)
	assert.Empty(t, got.DataCategories)
}

func TestUnmarshalFeedPermission_WrongType(t *testing.T) {
	ecBlock, err := MarshalConsentEC(&pptypes.PulseECEncryptionResult{
		SealedData: []byte("sd"), Key1: []byte("k1"), Key2: []byte("k2"),
	})
	require.NoError(t, err)

	_, err = UnmarshalFeedPermission(ecBlock)
	assert.ErrorContains(t, err, "unexpected structure type")
}
