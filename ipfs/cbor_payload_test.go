package ipfs

// Known-value CBOR tests for the polymorphic MarshalRevoke/MarshalConsent functions.
//
// Each test encodes a fixed canonical input via the PulseRevokePayload /
// PulseConsentPayload path and verifies the resulting CID matches a hardcoded
// expected value.  Byte-identity with the former RevokeStructure / ConsentStructure
// path is confirmed in the *_ByteIdentical* tests, which must pass before
// those types are removed.
//
// The const values below were captured by running the *_ByteIdentical* tests
// with the old and new paths simultaneously and logging ComputeCID on the
// shared bytes.

import (
	"testing"

	pptypes "github.com/smarter-contracts/pulse-protocol-go/types/v2"
)

// ── Canary inputs ─────────────────────────────────────────────────────────────

var (
	payloadTestSealedData = []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	payloadTestKey1       = []byte{0x02, 0x10, 0x20, 0x30, 0x40}
	payloadTestKey2       = []byte{0x03, 0x50, 0x60, 0x70, 0x80}
	payloadTestGrantRef   = "bafyreidknownvalue001"

	payloadTestPQKey = &pptypes.PulsePQEncryptionKey{
		KeyFingerPrint:      [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		EncapsulatedKeyKey:  []byte{0xAA, 0xBB, 0xCC},
		EncapsulatedDataKey: []byte{0x11, 0x22, 0x33},
	}
)

// ── EC revoke ─────────────────────────────────────────────────────────────────

// TestMarshalRevoke_EC_KnownCID guards against accidental wire-format changes
// to the EC revoke CBOR encoding.
// CID was captured from MarshalRevoke vs former MarshalRevokeEC byte-identity check.
func TestMarshalRevoke_EC_KnownCID(t *testing.T) {
	const want = "bafyreihjqdlyrcq6pwf3befiag6mvws6p4oftvl4uzktv4rorcgtsngkv4"

	cbor, err := MarshalRevoke(&pptypes.PulseRevokePayload{
		SealedData: payloadTestSealedData,
		Key1:       payloadTestKey1,
		Key2:       payloadTestKey2,
		GrantRef:   payloadTestGrantRef,
	})
	if err != nil {
		t.Fatalf("MarshalRevoke: %v", err)
	}
	got, err := ComputeCID(cbor)
	if err != nil {
		t.Fatalf("ComputeCID: %v", err)
	}
	if got != want {
		t.Errorf("EC revoke CID changed (wire format regression):\n  got  %q\n  want %q", got, want)
	}
}

// ── PQ revoke ─────────────────────────────────────────────────────────────────

// TestMarshalRevoke_PQ_KnownCID guards against accidental wire-format changes
// to the PQ revoke CBOR encoding.
// CID was captured from MarshalRevoke vs former MarshalRevokePQ byte-identity check.
func TestMarshalRevoke_PQ_KnownCID(t *testing.T) {
	const want = "bafyreiglc3gmrbrn4hm7tjlqne5ebbfkwh6qwgda2gnfqoctp5zls5lgny"

	cbor, err := MarshalRevoke(&pptypes.PulseRevokePayload{
		SealedData: payloadTestSealedData,
		Keys:       []*pptypes.PulsePQEncryptionKey{payloadTestPQKey},
		GrantRef:   payloadTestGrantRef,
	})
	if err != nil {
		t.Fatalf("MarshalRevoke: %v", err)
	}
	got, err := ComputeCID(cbor)
	if err != nil {
		t.Fatalf("ComputeCID: %v", err)
	}
	if got != want {
		t.Errorf("PQ revoke CID changed (wire format regression):\n  got  %q\n  want %q", got, want)
	}
}

// ── EC consent ────────────────────────────────────────────────────────────────

// TestMarshalConsent_EC_KnownCID guards against accidental wire-format changes
// to the EC consent CBOR encoding.
// CID was captured from MarshalConsent vs MarshalConsentEC byte-identity check.
func TestMarshalConsent_EC_KnownCID(t *testing.T) {
	const want = "bafyreibycrajtid4jjzm3w2s6myfqbxtkf4tstwwbh6s2clnzym3ax4zam"

	cbor, err := MarshalConsent(&pptypes.PulseConsentPayload{
		SealedData: payloadTestSealedData,
		Key1:       payloadTestKey1,
		Key2:       payloadTestKey2,
	})
	if err != nil {
		t.Fatalf("MarshalConsent: %v", err)
	}
	got, err := ComputeCID(cbor)
	if err != nil {
		t.Fatalf("ComputeCID: %v", err)
	}
	if got != want {
		t.Errorf("EC consent CID changed (wire format regression):\n  got  %q\n  want %q", got, want)
	}
}

// ── PQ consent ────────────────────────────────────────────────────────────────

// TestMarshalConsent_PQ_KnownCID guards against accidental wire-format changes
// to the PQ consent CBOR encoding.
// CID was captured from MarshalConsent vs MarshalConsentPQ byte-identity check.
func TestMarshalConsent_PQ_KnownCID(t *testing.T) {
	const want = "bafyreidt4lws7mpguyvvnr6adc5dpiyjyeqtymvpbcy3chieni332bqbwe"

	cbor, err := MarshalConsent(&pptypes.PulseConsentPayload{
		SealedData: payloadTestSealedData,
		Keys:       []*pptypes.PulsePQEncryptionKey{payloadTestPQKey},
	})
	if err != nil {
		t.Fatalf("MarshalConsent: %v", err)
	}
	got, err := ComputeCID(cbor)
	if err != nil {
		t.Fatalf("ComputeCID: %v", err)
	}
	if got != want {
		t.Errorf("PQ consent CID changed (wire format regression):\n  got  %q\n  want %q", got, want)
	}
}
