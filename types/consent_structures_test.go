package types_test

import (
	"encoding/json"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/types"
)

func TestPulseRevokePayload_EC_JSONRoundTrip(t *testing.T) {
	orig := &types.PulseRevokePayload{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1"),
		Key2:       []byte("key2"),
		GrantRef:   "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.PulseRevokePayload
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
	if got.GrantRef != orig.GrantRef {
		t.Errorf("GrantRef: got %q, want %q", got.GrantRef, orig.GrantRef)
	}
}

func TestPulseRevokePayload_PQ_JSONRoundTrip(t *testing.T) {
	fp := [32]byte{0x01}
	orig := &types.PulseRevokePayload{
		SealedData: []byte("sealed-pq"),
		Keys: []*types.PulsePQEncryptionKey{
			{
				KeyFingerPrint:      fp,
				EncapsulatedKeyKey:  []byte("ekk"),
				EncapsulatedDataKey: []byte("edk"),
			},
		},
		GrantRef: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.PulseRevokePayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData: got %q, want %q", got.SealedData, orig.SealedData)
	}
	if got.GrantRef != orig.GrantRef {
		t.Errorf("GrantRef: got %q, want %q", got.GrantRef, orig.GrantRef)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("Keys length: got %d, want 1", len(got.Keys))
	}
	if got.Keys[0].KeyFingerPrint != fp {
		t.Errorf("KeyFingerPrint mismatch")
	}
}

func TestPulseConsentPayload_EC_JSONRoundTrip(t *testing.T) {
	orig := &types.PulseConsentPayload{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1"),
		Key2:       []byte("key2"),
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.PulseConsentPayload
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
}

func TestPulseConsentPayload_PQ_JSONRoundTrip(t *testing.T) {
	fp := [32]byte{0x02}
	orig := &types.PulseConsentPayload{
		SealedData: []byte("sealed-pq"),
		Keys: []*types.PulsePQEncryptionKey{
			{
				KeyFingerPrint:      fp,
				EncapsulatedKeyKey:  []byte("ekk"),
				EncapsulatedDataKey: []byte("edk"),
			},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got types.PulseConsentPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData: got %q, want %q", got.SealedData, orig.SealedData)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("Keys length: got %d, want 1", len(got.Keys))
	}
	if got.Keys[0].KeyFingerPrint != fp {
		t.Errorf("KeyFingerPrint mismatch")
	}
}
