package types

import (
	"encoding/json"
	"testing"
)

// ── PulsePQEncryptionKey JSON ─────────────────────────────────────────────────

func TestPulsePQEncryptionKey_JSONRoundTrip(t *testing.T) {
	var fp [32]byte
	for i := range fp {
		fp[i] = byte(i)
	}
	orig := &PulsePQEncryptionKey{
		KeyFingerPrint:      fp,
		EncapsulatedKeyKey:  []byte("ekk-data"),
		EncapsulatedDataKey: []byte("edk-data"),
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got PulsePQEncryptionKey
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.KeyFingerPrint != orig.KeyFingerPrint {
		t.Errorf("KeyFingerPrint mismatch: got %v, want %v", got.KeyFingerPrint, orig.KeyFingerPrint)
	}
	if string(got.EncapsulatedKeyKey) != string(orig.EncapsulatedKeyKey) {
		t.Errorf("EncapsulatedKeyKey mismatch")
	}
	if string(got.EncapsulatedDataKey) != string(orig.EncapsulatedDataKey) {
		t.Errorf("EncapsulatedDataKey mismatch")
	}
}

func TestPulsePQEncryptionKey_UnmarshalJSON_WrongFingerprintLength(t *testing.T) {
	// 31 bytes — should be rejected
	data := `{"keyFingerPrint":"AQIDBA==","encapsulatedKeyKey":"ZWtr","encapsulatedDataKey":"ZWRr"}`
	var k PulsePQEncryptionKey
	if err := json.Unmarshal([]byte(data), &k); err == nil {
		t.Fatal("expected error for short fingerprint, got nil")
	}
}

// ── PulseConsentPayload ───────────────────────────────────────────────────────

func TestPulseConsentPayload_EC_JSONRoundTrip(t *testing.T) {
	orig := PulseConsentPayload{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1data"),
		Key2:       []byte("key2data"),
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PulseConsentPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(got.SealedData) != string(orig.SealedData) {
		t.Errorf("SealedData mismatch")
	}
	if string(got.Key1) != string(orig.Key1) {
		t.Errorf("Key1 mismatch")
	}
	if string(got.Key2) != string(orig.Key2) {
		t.Errorf("Key2 mismatch")
	}
	if got.IsMultiKey() {
		t.Error("expected EC payload, got multi-key")
	}
}

func TestPulseConsentPayload_PQ_JSONRoundTrip(t *testing.T) {
	var fp [32]byte
	fp[0] = 0xAB
	orig := PulseConsentPayload{
		SealedData: []byte("sealed"),
		Keys: []*PulsePQEncryptionKey{
			{KeyFingerPrint: fp, EncapsulatedKeyKey: []byte("ekk"), EncapsulatedDataKey: []byte("edk")},
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PulseConsentPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.IsMultiKey() {
		t.Error("expected PQ payload, got EC")
	}
	if got.Keys[0].KeyFingerPrint != fp {
		t.Errorf("fingerprint mismatch")
	}
}

func TestPulseConsentPayload_EC_MarshalCBOR_MatchesECEncryptionResult(t *testing.T) {
	payload := PulseConsentPayload{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1"),
		Key2:       []byte("key2"),
	}
	got, err := payload.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	want, err := (&PulseECEncryptionResult{
		SealedData: []byte("sealed"),
		Key1:       []byte("key1"),
		Key2:       []byte("key2"),
	}).MarshalCBOR()
	if err != nil {
		t.Fatalf("reference MarshalCBOR: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("CBOR mismatch between PulseConsentPayload and PulseECEncryptionResult")
	}
}

func TestPulseConsentPayload_PQ_MarshalCBOR_MatchesPQEncryptionResult(t *testing.T) {
	var fp [32]byte
	fp[0] = 0x01
	key := &PulsePQEncryptionKey{
		KeyFingerPrint:      fp,
		EncapsulatedKeyKey:  []byte("ekk"),
		EncapsulatedDataKey: []byte("edk"),
	}
	payload := PulseConsentPayload{
		SealedData: []byte("sealed"),
		Keys:       []*PulsePQEncryptionKey{key},
	}
	got, err := payload.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	want, err := (&PulsePQEncryptionResult{
		SealedData: []byte("sealed"),
		Keys:       []*PulsePQEncryptionKey{key},
	}).MarshalCBOR()
	if err != nil {
		t.Fatalf("reference MarshalCBOR: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("CBOR mismatch between PulseConsentPayload and PulsePQEncryptionResult")
	}
}

func TestPulseConsentPayload_EC_MarshalCBOR_MissingKeys(t *testing.T) {
	payload := PulseConsentPayload{SealedData: []byte("sealed")}
	if _, err := payload.MarshalCBOR(); err == nil {
		t.Error("expected error for EC payload missing key1/key2")
	}
}

// ── PulseRevokePayload ────────────────────────────────────────────────────────

func TestPulseRevokePayload_EC_MarshalCBOR_MatchesRevokeStructure(t *testing.T) {
	payload := PulseRevokePayload{
		SealedData: []byte("sealed"),
		GrantRef:   "bafy...",
		Key1:       []byte("key1"),
		Key2:       []byte("key2"),
	}
	got, err := payload.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	want, err := (&RevokeStructure{
		PulseECEncryptionResult: PulseECEncryptionResult{
			SealedData: []byte("sealed"),
			Key1:       []byte("key1"),
			Key2:       []byte("key2"),
		},
		Grant: "bafy...",
	}).MarshalCBOR()
	if err != nil {
		t.Fatalf("reference MarshalCBOR: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("CBOR mismatch between PulseRevokePayload and RevokeStructure")
	}
}

func TestPulseRevokePayload_PQ_MarshalCBOR_MatchesRevokeStructureMulti(t *testing.T) {
	var fp [32]byte
	fp[0] = 0x02
	key := &PulsePQEncryptionKey{
		KeyFingerPrint:      fp,
		EncapsulatedKeyKey:  []byte("ekk"),
		EncapsulatedDataKey: []byte("edk"),
	}
	payload := PulseRevokePayload{
		SealedData: []byte("sealed"),
		GrantRef:   "bafy...",
		Keys:       []*PulsePQEncryptionKey{key},
	}
	got, err := payload.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	want, err := (&RevokeStructureMulti{
		PulsePQEncryptionResult: PulsePQEncryptionResult{
			SealedData: []byte("sealed"),
			Keys:       []*PulsePQEncryptionKey{key},
		},
		Grant: "bafy...",
	}).MarshalCBOR()
	if err != nil {
		t.Fatalf("reference MarshalCBOR: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("CBOR mismatch between PulseRevokePayload and RevokeStructureMulti")
	}
}

// ── PulseGrantRequest / PulseRevokeRequest — JSON round-trip ─────────────────

func TestPulseGrantRequest_EC_JSONRoundTrip(t *testing.T) {
	orig := PulseGrantRequest{
		Consent: PulseConsentPayload{
			SealedData: []byte("sealed"),
			Key1:       []byte("key1"),
			Key2:       []byte("key2"),
		},
		Signatures: []string{"0xdeadbeef"},
		Addresses:  []string{"0xabcdef"},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PulseGrantRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(got.Consent.SealedData) != string(orig.Consent.SealedData) {
		t.Errorf("SealedData mismatch")
	}
	if len(got.Signatures) != 1 || got.Signatures[0] != "0xdeadbeef" {
		t.Errorf("Signatures mismatch")
	}
}

func TestPulseRevokeRequest_JSONRoundTrip(t *testing.T) {
	orig := PulseRevokeRequest{
		Revoke: PulseRevokePayload{
			SealedData: []byte("sealed"),
			GrantRef:   "bafy...",
			Key1:       []byte("key1"),
			Key2:       []byte("key2"),
		},
		Signature:  "0xdeadbeef",
		SigAddress: "0xabcdef",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got PulseRevokeRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Revoke.GrantRef != "bafy..." {
		t.Errorf("GrantRef mismatch")
	}
	if got.Signature != "0xdeadbeef" {
		t.Errorf("Signature mismatch")
	}
}
