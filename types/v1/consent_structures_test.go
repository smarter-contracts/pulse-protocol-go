package v1_test

import (
	"encoding/json"
	"testing"

	v1 "github.com/smarter-contracts/pulse-protocol-go/types/v1"
)

// ── ConsentStructure ──────────────────────────────────────────────────────────

func TestConsentStructure_JSONRoundTrip(t *testing.T) {
	orig := &v1.ConsentStructure{
		Consent: "dGVzdC1jb25zZW50", // base64("test-consent")
		Key1:    "a2V5MQ==",          // base64("key1")
		Key2:    "a2V5Mg==",          // base64("key2")
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got v1.ConsentStructure
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Consent != orig.Consent {
		t.Errorf("Consent: got %q, want %q", got.Consent, orig.Consent)
	}
	if got.Key1 != orig.Key1 {
		t.Errorf("Key1: got %q, want %q", got.Key1, orig.Key1)
	}
	if got.Key2 != orig.Key2 {
		t.Errorf("Key2: got %q, want %q", got.Key2, orig.Key2)
	}
}

// ── ConsentStructureMulti ─────────────────────────────────────────────────────

func TestConsentStructureMulti_JSONRoundTrip(t *testing.T) {
	orig := &v1.ConsentStructureMulti{
		Consent: "dGVzdC1jb25zZW50",
		Keys:    []string{"a2V5MQ==", "a2V5Mg=="},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got v1.ConsentStructureMulti
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Consent != orig.Consent {
		t.Errorf("Consent mismatch")
	}
	if len(got.Keys) != len(orig.Keys) {
		t.Fatalf("Keys length mismatch")
	}
}
