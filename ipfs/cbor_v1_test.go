package ipfs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smarter-contracts/pulse-protocol-go/types/v1"
)

// Fixed inputs shared across all V1 canary tests.
// These values are arbitrary but permanent — changing them invalidates the canary.
const (
	canaryConsent   = "Q09OU0VOVF9EQVRBCg==" // base64("CONSENT_DATA\n")
	canaryKey1      = "S0VZX09ORQo="          // base64("KEY_ONE\n")
	canaryKey2      = "S0VZX1RXTwo="           // base64("KEY_TWO\n")
	canaryRevokeEC  = "UkVWT0tFX0RBVEEКCg==" // fixed revoke payload (EC)
	canaryRevokePQ  = "UkVWT0tFX0RBVEEК=="   // fixed revoke payload (PQ)
)

// ── ConsentStructureMulti (PQ) ────────────────────────────────────────────────

// TestMarshalV1ConsentPQ_KnownCID is the canary test for the PQ consent record.
// It verifies that the CBOR encoding of a ConsentStructureMulti with known inputs
// always produces the same DAG-CBOR bytes (and therefore the same CID).
// If this test fails, the on-disk format has changed and existing IPFS records
// would be unreadable or produce incorrect CIDs.
func TestMarshalV1ConsentPQ_KnownCID(t *testing.T) {
	const wantCID = "bafyreihkmatajiavaikdp6qpetxfywwbgp2gfm45xbgpcz5i4qp4f2uxy4"

	csm := &v1.ConsentStructureMulti{
		Consent: canaryConsent,
		Keys:    []string{canaryKey1, canaryKey2},
	}
	block, err := MarshalV1ConsentPQ(csm)
	require.NoError(t, err)

	c, err := GetCid(block)
	require.NoError(t, err)
	assert.Equal(t, wantCID, c.String(), "PQ consent CID mismatch — on-disk format has changed")
}

// TestMarshalV1ConsentPQ_RoundTrip verifies that unmarshalling the marshalled bytes
// produces the original struct.
func TestMarshalV1ConsentPQ_RoundTrip(t *testing.T) {
	orig := &v1.ConsentStructureMulti{
		Consent: canaryConsent,
		Keys:    []string{canaryKey1, canaryKey2},
	}
	block, err := MarshalV1ConsentPQ(orig)
	require.NoError(t, err)

	got, err := UnmarshalV1ConsentPQ(block)
	require.NoError(t, err)

	assert.Equal(t, orig.Consent, got.Consent)
	assert.Equal(t, orig.Keys, got.Keys)
}

// ── RevokeStructureMulti (PQ) ─────────────────────────────────────────────────

// TestMarshalV1RevokePQ_KnownCID is the canary for the PQ revoke record.
func TestMarshalV1RevokePQ_KnownCID(t *testing.T) {
	const (
		grantRef = "bafyreihkmatajiavaikdp6qpetxfywwbgp2gfm45xbgpcz5i4qp4f2uxy4"
		wantCID  = "bafyreia7ja7foieoyxcee54pcmz7bs6eui5gagmnumgewfdnklephgxtem"
	)

	rsm := &v1.RevokeStructureMulti{
		Revoke:   canaryRevokePQ,
		Keys:     []string{canaryKey1, canaryKey2},
		GrantRef: grantRef,
	}
	block, err := MarshalV1RevokePQ(rsm)
	require.NoError(t, err)

	c, err := GetCid(block)
	require.NoError(t, err)
	assert.Equal(t, wantCID, c.String(), "PQ revoke CID mismatch — on-disk format has changed")
}

// TestMarshalV1RevokePQ_RoundTrip verifies unmarshal inverts marshal for PQ revokes.
func TestMarshalV1RevokePQ_RoundTrip(t *testing.T) {
	const grantRef = "bafyreihkmatajiavaikdp6qpetxfywwbgp2gfm45xbgpcz5i4qp4f2uxy4"

	orig := &v1.RevokeStructureMulti{
		Revoke:   canaryRevokePQ,
		Keys:     []string{canaryKey1, canaryKey2},
		GrantRef: grantRef,
	}
	block, err := MarshalV1RevokePQ(orig)
	require.NoError(t, err)

	got, err := UnmarshalV1RevokePQ(block)
	require.NoError(t, err)

	assert.Equal(t, orig.Revoke, got.Revoke)
	assert.Equal(t, orig.Keys, got.Keys)
	assert.Equal(t, orig.GrantRef, got.GrantRef)
}

// ── ConsentStructure (EC) ─────────────────────────────────────────────────────

// TestMarshalV1ConsentEC_KnownCID is the canary for the EC consent record.
func TestMarshalV1ConsentEC_KnownCID(t *testing.T) {
	const wantCID = "bafyreidjcwewdrb2ohtccavsj2tuwzgzutqxuo5p5h6al5uwlnnrkk7btu"

	cs := &v1.ConsentStructure{
		Consent: canaryConsent,
		Key1:    canaryKey1,
		Key2:    canaryKey2,
	}
	block, err := MarshalV1ConsentEC(cs)
	require.NoError(t, err)

	c, err := GetCid(block)
	require.NoError(t, err)
	assert.Equal(t, wantCID, c.String(), "EC consent CID mismatch — on-disk format has changed")
}

// TestMarshalV1ConsentEC_RoundTrip verifies unmarshal inverts marshal for EC consents.
func TestMarshalV1ConsentEC_RoundTrip(t *testing.T) {
	orig := &v1.ConsentStructure{
		Consent: canaryConsent,
		Key1:    canaryKey1,
		Key2:    canaryKey2,
	}
	block, err := MarshalV1ConsentEC(orig)
	require.NoError(t, err)

	got, err := UnmarshalV1ConsentEC(block)
	require.NoError(t, err)

	assert.Equal(t, orig.Consent, got.Consent)
	assert.Equal(t, orig.Key1, got.Key1)
	assert.Equal(t, orig.Key2, got.Key2)
}

// ── RevokeStructure (EC) ──────────────────────────────────────────────────────

// TestMarshalV1RevokeEC_KnownCID is the canary for the EC revoke record.
func TestMarshalV1RevokeEC_KnownCID(t *testing.T) {
	const (
		grantRef = "bafyreidjcwewdrb2ohtccavsj2tuwzgzutqxuo5p5h6al5uwlnnrkk7btu"
		wantCID  = "bafyreia55347u7sckkq6sj44x5axgvyfuxzs5xzbx6ryyltyyo42ij43ge"
	)

	rs := &v1.RevokeStructure{
		Revoke:   canaryRevokeEC,
		Key1:     canaryKey1,
		Key2:     canaryKey2,
		GrantRef: grantRef,
	}
	block, err := MarshalV1RevokeEC(rs)
	require.NoError(t, err)

	c, err := GetCid(block)
	require.NoError(t, err)
	assert.Equal(t, wantCID, c.String(), "EC revoke CID mismatch — on-disk format has changed")
}

// TestMarshalV1RevokeEC_RoundTrip verifies unmarshal inverts marshal for EC revokes.
func TestMarshalV1RevokeEC_RoundTrip(t *testing.T) {
	const grantRef = "bafyreidjcwewdrb2ohtccavsj2tuwzgzutqxuo5p5h6al5uwlnnrkk7btu"

	orig := &v1.RevokeStructure{
		Revoke:   canaryRevokeEC,
		Key1:     canaryKey1,
		Key2:     canaryKey2,
		GrantRef: grantRef,
	}
	block, err := MarshalV1RevokeEC(orig)
	require.NoError(t, err)

	got, err := UnmarshalV1RevokeEC(block)
	require.NoError(t, err)

	assert.Equal(t, orig.Revoke, got.Revoke)
	assert.Equal(t, orig.Key1, got.Key1)
	assert.Equal(t, orig.Key2, got.Key2)
	assert.Equal(t, orig.GrantRef, got.GrantRef)
}
