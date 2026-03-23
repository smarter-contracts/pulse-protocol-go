package types_test

import (
	"encoding/json"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── RevokeStructure ───────────────────────────────────────────────────────────────────

func TestRevokeStructure_JSONRoundTrip(t *testing.T) {
	orig := &types.RevokeStructure{
		PulseECEncryptionResult: types.PulseECEncryptionResult{
			SealedData: []byte("sealed"),
			Key1:       []byte("key1"),
			Key2:       []byte("key2"),
		},
		Grant: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.RevokeStructure
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData: got %q, want %q", got.SealedData, orig.SealedData)
	}
	if string(got.Key1) != string(orig.Key1) {
		t.Errorf("Key1: got %q, want %q", got.Key1, orig.Key1)
	}
	if string(got.Key2) != string(orig.Key2) {
		t.Errorf("Key2: got %q, want %q", got.Key2, orig.Key2)
	}
	if got.Grant != orig.Grant {
		t.Errorf("Grant: got %q, want %q", got.Grant, orig.Grant)
	}
}

func TestRevokeStructure_CBORRoundTrip(t *testing.T) {
	orig := &types.RevokeStructure{
		PulseECEncryptionResult: types.PulseECEncryptionResult{
			SealedData: []byte{0x01, 0x02, 0x03},
			Key1:       []byte{0x04, 0x05, 0x06},
			Key2:       []byte{0x07, 0x08, 0x09},
		},
		Grant: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	}

	encoded, err := orig.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	var got types.RevokeStructure
	if err := got.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("UnmarshalCBOR: %v", err)
	}

	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData: got %v, want %v", got.SealedData, orig.SealedData)
	}
	if string(got.Key1) != string(orig.Key1) {
		t.Errorf("Key1: got %v, want %v", got.Key1, orig.Key1)
	}
	if string(got.Key2) != string(orig.Key2) {
		t.Errorf("Key2: got %v, want %v", got.Key2, orig.Key2)
	}
	if got.Grant != orig.Grant {
		t.Errorf("Grant: got %q, want %q", got.Grant, orig.Grant)
	}
}

func TestRevokeStructure_CBORRejectsWrongType(t *testing.T) {
	// An EC consent structure CBOR (t:"ec") must not unmarshal as a RevokeStructure.
	consent := &types.ConsentStructure{
		SealedData: []byte{0x01},
		Key1:       []byte{0x02},
		Key2:       []byte{0x03},
	}
	encoded, err := consent.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	var revoke types.RevokeStructure
	if err := revoke.UnmarshalCBOR(encoded); err == nil {
		t.Error("expected error when unmarshalling consent CBOR as RevokeStructure, got nil")
	}
}

// ── RevokeStructureMulti ──────────────────────────────────────────────────────────────

func TestRevokeStructureMulti_JSONRoundTrip(t *testing.T) {
	fp := [32]byte{0x01}
	orig := &types.RevokeStructureMulti{
		PulsePQEncryptionResult: types.PulsePQEncryptionResult{
			SealedData: []byte("sealed-pq"),
			Keys: []*types.PulsePQEncryptionKey{
				{
					KeyFingerPrint:      fp,
					EncapsulatedKeyKey:  []byte("ekk"),
					EncapsulatedDataKey: []byte("edk"),
				},
			},
		},
		Grant: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.RevokeStructureMulti
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData: got %q, want %q", got.SealedData, orig.SealedData)
	}
	if got.Grant != orig.Grant {
		t.Errorf("Grant: got %q, want %q", got.Grant, orig.Grant)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("Keys length: got %d, want 1", len(got.Keys))
	}
	if got.Keys[0].KeyFingerPrint != fp {
		t.Errorf("KeyFingerPrint mismatch")
	}
}

func TestRevokeStructureMulti_CBORRoundTrip(t *testing.T) {
	var fp [32]byte
	for i := range fp {
		fp[i] = byte(i)
	}

	orig := &types.RevokeStructureMulti{
		PulsePQEncryptionResult: types.PulsePQEncryptionResult{
			SealedData: []byte{0xAA, 0xBB},
			Keys: []*types.PulsePQEncryptionKey{
				{
					KeyFingerPrint:      fp,
					EncapsulatedKeyKey:  []byte("ekk-bytes"),
					EncapsulatedDataKey: []byte("edk-bytes"),
				},
			},
		},
		Grant: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	}

	encoded, err := orig.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	var got types.RevokeStructureMulti
	if err := got.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("UnmarshalCBOR: %v", err)
	}

	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData mismatch")
	}
	if got.Grant != orig.Grant {
		t.Errorf("Grant: got %q, want %q", got.Grant, orig.Grant)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("Keys length: got %d, want 1", len(got.Keys))
	}
	if got.Keys[0].KeyFingerPrint != fp {
		t.Errorf("KeyFingerPrint mismatch")
	}
	if string(got.Keys[0].EncapsulatedKeyKey) != string(orig.Keys[0].EncapsulatedKeyKey) {
		t.Errorf("EncapsulatedKeyKey mismatch")
	}
}

// ── Alias sanity checks ───────────────────────────────────────────────────────────────

// Verify that ConsentStructure and PulseECEncryptionResult are the same type
// by assigning one to the other without a cast.
func TestConsentStructureIsAlias(t *testing.T) {
	ec := types.PulseECEncryptionResult{SealedData: []byte("x"), Key1: []byte("a"), Key2: []byte("b")}
	var cs types.ConsentStructure = ec
	if string(cs.SealedData) != "x" {
		t.Errorf("alias assignment failed")
	}
}

func TestConsentStructureMultiIsAlias(t *testing.T) {
	pq := types.PulsePQEncryptionResult{SealedData: []byte("y")}
	var csm types.ConsentStructureMulti = pq
	if string(csm.SealedData) != "y" {
		t.Errorf("alias assignment failed")
	}
}
