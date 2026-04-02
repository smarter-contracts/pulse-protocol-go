package ipfs

import (
	"testing"

	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
	v1 "github.com/smarter-contracts/pulse-protocol-go/types/v1"
)

// ── DecodeConsent ─────────────────────────────────────────────────────────────

func TestDecodeConsent_V2EC(t *testing.T) {
	orig := &pptypes.ConsentStructure{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1data"),
		Key2:       []byte("key2data"),
	}
	block, err := MarshalConsentEC(orig)
	if err != nil {
		t.Fatalf("MarshalConsentEC: %v", err)
	}

	got, err := DecodeConsent(block)
	if err != nil {
		t.Fatalf("DecodeConsent: %v", err)
	}
	if got.Kind != RecordKindV2EC {
		t.Errorf("Kind = %v, want RecordKindV2EC", got.Kind)
	}
	if got.V2EC == nil {
		t.Fatal("V2EC is nil")
	}
	if string(got.V2EC.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData mismatch")
	}
	if string(got.V2EC.Key1) != string(orig.Key1) {
		t.Errorf("Key1 mismatch")
	}
	if string(got.V2EC.Key2) != string(orig.Key2) {
		t.Errorf("Key2 mismatch")
	}
}

func TestDecodeConsent_V2PQ(t *testing.T) {
	var fp [32]byte
	fp[0] = 0xAB
	orig := &pptypes.ConsentStructureMulti{
		SealedData: []byte("sealed-pq"),
		Keys: []*pptypes.PulsePQEncryptionKey{
			{KeyFingerPrint: fp, EncapsulatedKeyKey: []byte("ekk"), EncapsulatedDataKey: []byte("edk")},
		},
	}
	block, err := MarshalConsentPQ(orig)
	if err != nil {
		t.Fatalf("MarshalConsentPQ: %v", err)
	}

	got, err := DecodeConsent(block)
	if err != nil {
		t.Fatalf("DecodeConsent: %v", err)
	}
	if got.Kind != RecordKindV2PQ {
		t.Errorf("Kind = %v, want RecordKindV2PQ", got.Kind)
	}
	if got.V2PQ == nil {
		t.Fatal("V2PQ is nil")
	}
	if len(got.V2PQ.Keys) != 1 || got.V2PQ.Keys[0].KeyFingerPrint != fp {
		t.Errorf("PQ keys mismatch")
	}
}

func TestDecodeConsent_V1EC(t *testing.T) {
	orig := &v1.ConsentStructure{
		Consent: "CONSENT_DATA",
		Key1:    "KEY1base64",
		Key2:    "KEY2base64",
	}
	block, err := MarshalV1ConsentEC(orig)
	if err != nil {
		t.Fatalf("MarshalV1ConsentEC: %v", err)
	}

	got, err := DecodeConsent(block)
	if err != nil {
		t.Fatalf("DecodeConsent: %v", err)
	}
	if got.Kind != RecordKindV1EC {
		t.Errorf("Kind = %v, want RecordKindV1EC", got.Kind)
	}
	if got.V1EC == nil {
		t.Fatal("V1EC is nil")
	}
	if got.V1EC.Consent != orig.Consent {
		t.Errorf("Consent mismatch: got %q, want %q", got.V1EC.Consent, orig.Consent)
	}
}

func TestDecodeConsent_V1PQ(t *testing.T) {
	orig := &v1.ConsentStructureMulti{
		Consent: "CONSENT_MULTI",
		Keys:    []string{"KEY1", "KEY2", "KEY3"},
	}
	block, err := MarshalV1ConsentPQ(orig)
	if err != nil {
		t.Fatalf("MarshalV1ConsentPQ: %v", err)
	}

	got, err := DecodeConsent(block)
	if err != nil {
		t.Fatalf("DecodeConsent: %v", err)
	}
	if got.Kind != RecordKindV1PQ {
		t.Errorf("Kind = %v, want RecordKindV1PQ", got.Kind)
	}
	if got.V1PQ == nil {
		t.Fatal("V1PQ is nil")
	}
	if len(got.V1PQ.Keys) != 3 {
		t.Errorf("Keys len = %d, want 3", len(got.V1PQ.Keys))
	}
}

func TestDecodeConsent_InvalidBytes(t *testing.T) {
	_, err := DecodeConsent([]byte("not cbor"))
	if err == nil {
		t.Error("expected error for invalid bytes, got nil")
	}
}

// ── DecodeRevoke ──────────────────────────────────────────────────────────────

func TestDecodeRevoke_V2EC(t *testing.T) {
	orig := &pptypes.RevokeStructure{
		PulseECEncryptionResult: pptypes.PulseECEncryptionResult{
			SealedData: []byte("revoke-sealed"),
			Key1:       []byte("key1"),
			Key2:       []byte("key2"),
		},
		Grant: "bafy...",
	}
	block, err := MarshalRevokeEC(orig)
	if err != nil {
		t.Fatalf("MarshalRevokeEC: %v", err)
	}

	got, err := DecodeRevoke(block)
	if err != nil {
		t.Fatalf("DecodeRevoke: %v", err)
	}
	if got.Kind != RecordKindV2EC {
		t.Errorf("Kind = %v, want RecordKindV2EC", got.Kind)
	}
	if got.V2EC == nil {
		t.Fatal("V2EC is nil")
	}
	if got.V2EC.Grant != orig.Grant {
		t.Errorf("Grant mismatch: got %q, want %q", got.V2EC.Grant, orig.Grant)
	}
}

func TestDecodeRevoke_V2PQ(t *testing.T) {
	var fp [32]byte
	fp[1] = 0xCD
	orig := &pptypes.RevokeStructureMulti{
		PulsePQEncryptionResult: pptypes.PulsePQEncryptionResult{
			SealedData: []byte("revoke-pq"),
			Keys: []*pptypes.PulsePQEncryptionKey{
				{KeyFingerPrint: fp, EncapsulatedKeyKey: []byte("ekk"), EncapsulatedDataKey: []byte("edk")},
			},
		},
		Grant: "bafy...",
	}
	block, err := MarshalRevokePQ(orig)
	if err != nil {
		t.Fatalf("MarshalRevokePQ: %v", err)
	}

	got, err := DecodeRevoke(block)
	if err != nil {
		t.Fatalf("DecodeRevoke: %v", err)
	}
	if got.Kind != RecordKindV2PQ {
		t.Errorf("Kind = %v, want RecordKindV2PQ", got.Kind)
	}
	if got.V2PQ == nil {
		t.Fatal("V2PQ is nil")
	}
	if got.V2PQ.Grant != orig.Grant {
		t.Errorf("Grant mismatch")
	}
}

func TestDecodeRevoke_V1EC(t *testing.T) {
	orig := &v1.RevokeStructure{
		Revoke:   "REVOKE_DATA",
		Key1:     "KEY1",
		Key2:     "KEY2",
		GrantRef: "bafy...",
	}
	block, err := MarshalV1RevokeEC(orig)
	if err != nil {
		t.Fatalf("MarshalV1RevokeEC: %v", err)
	}

	got, err := DecodeRevoke(block)
	if err != nil {
		t.Fatalf("DecodeRevoke: %v", err)
	}
	if got.Kind != RecordKindV1EC {
		t.Errorf("Kind = %v, want RecordKindV1EC", got.Kind)
	}
	if got.V1EC == nil {
		t.Fatal("V1EC is nil")
	}
	if got.V1EC.GrantRef != orig.GrantRef {
		t.Errorf("GrantRef mismatch: got %q, want %q", got.V1EC.GrantRef, orig.GrantRef)
	}
}

func TestDecodeRevoke_V1PQ(t *testing.T) {
	orig := &v1.RevokeStructureMulti{
		Revoke:   "REVOKE_MULTI",
		Keys:     []string{"KEY1", "KEY2"},
		GrantRef: "bafy...",
	}
	block, err := MarshalV1RevokePQ(orig)
	if err != nil {
		t.Fatalf("MarshalV1RevokePQ: %v", err)
	}

	got, err := DecodeRevoke(block)
	if err != nil {
		t.Fatalf("DecodeRevoke: %v", err)
	}
	if got.Kind != RecordKindV1PQ {
		t.Errorf("Kind = %v, want RecordKindV1PQ", got.Kind)
	}
	if got.V1PQ == nil {
		t.Fatal("V1PQ is nil")
	}
}

func TestDecodeRevoke_InvalidBytes(t *testing.T) {
	_, err := DecodeRevoke([]byte{0xFF, 0x00})
	if err == nil {
		t.Error("expected error for invalid bytes, got nil")
	}
}

// ── ComputeCID ────────────────────────────────────────────────────────────────

func TestComputeCID_V2EC_Deterministic(t *testing.T) {
	record := &pptypes.ConsentStructure{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1"),
		Key2:       []byte("key2"),
	}

	block1, err := MarshalConsentEC(record)
	if err != nil {
		t.Fatalf("MarshalConsentEC: %v", err)
	}
	cid1, err := ComputeCID(block1)
	if err != nil {
		t.Fatalf("ComputeCID: %v", err)
	}

	block2, err := MarshalConsentEC(record)
	if err != nil {
		t.Fatalf("MarshalConsentEC second call: %v", err)
	}
	cid2, err := ComputeCID(block2)
	if err != nil {
		t.Fatalf("ComputeCID second call: %v", err)
	}

	if cid1 != cid2 {
		t.Errorf("ComputeCID is not deterministic: %q != %q", cid1, cid2)
	}
	if len(cid1) < 4 || cid1[:4] != "bafy" {
		t.Errorf("unexpected CID prefix: %q", cid1)
	}
}

func TestComputeCID_V1EC_KnownValue(t *testing.T) {
	// Known CID from the existing mid-tier tests for the legacy EC consent format.
	record := &v1.ConsentStructure{
		Consent: "CONSENT_REVTEST1",
		Key1:    "KEY1random",
		Key2:    "KEY2random",
	}
	block, err := MarshalV1ConsentEC(record)
	if err != nil {
		t.Fatalf("MarshalV1ConsentEC: %v", err)
	}
	cid, err := ComputeCID(block)
	if err != nil {
		t.Fatalf("ComputeCID: %v", err)
	}
	const want = "bafyreihohqybhurwuozt25xqbaa7rkb7jlt4rwdk2l52ohoqattgeq7zqq"
	if cid != want {
		t.Errorf("CID = %q, want %q", cid, want)
	}
}
