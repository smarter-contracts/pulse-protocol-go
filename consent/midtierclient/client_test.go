package midtierclient_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/consent"
	"github.com/smarter-contracts/pulse-protocol-go/consent/midtierclient"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── GetConsentsSince ──────────────────────────────────────────────────────────

func TestGetConsentsSince_ReturnsEvents(t *testing.T) {
	events := []midtierclient.ConsentEventJSON{
		{
			ConsentID: "bafycid001",
			Type:      "grant",
			Status:    "confirmed",
			CID:       "bafycid001",
			Cursor:    "42",
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/consents-by-key/testxpub" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("since") != "prev-cursor" {
			t.Errorf("unexpected since: %s", r.URL.Query().Get("since"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	got, err := client.GetConsentsSince(context.Background(), "testxpub", "prev-cursor")
	if err != nil {
		t.Fatalf("GetConsentsSince: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].ConsentID != "bafycid001" {
		t.Errorf("ConsentID: got %q, want %q", got[0].ConsentID, "bafycid001")
	}
	if got[0].Type != consent.TransactionTypeGrant {
		t.Errorf("Type: got %q, want grant", got[0].Type)
	}
	if got[0].Cursor != "42" {
		t.Errorf("Cursor: got %q, want 42", got[0].Cursor)
	}
}

func TestGetConsentsSince_EmptyCursor_OmitsSinceParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("since") {
			t.Errorf("since should be absent for empty cursor, got %q", r.URL.Query().Get("since"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	got, err := client.GetConsentsSince(context.Background(), "xpub", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 events, got %d", len(got))
	}
}

func TestGetConsentsSince_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	_, err := client.GetConsentsSince(context.Background(), "xpub", "")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestGetConsentsSince_RevokeType_Mapped(t *testing.T) {
	events := []midtierclient.ConsentEventJSON{
		{ConsentID: "bafycid002", Type: "revoke", Status: "rev_confirmed", CID: "bafyrev001", Cursor: "99"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	got, err := client.GetConsentsSince(context.Background(), "xpub", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0].Type != consent.TransactionTypeRevoke {
		t.Errorf("Type: got %q, want revoke", got[0].Type)
	}
}

// ── SubmitGrant ───────────────────────────────────────────────────────────────

func TestSubmitGrant_CallsPutGrant(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v3/grant" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"OK","cid":"bafycid001"}`))
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	rec := consent.ConsentRecord{
		CID:         "bafycid001",
		SealedBytes: []byte("fake-sealed"),
	}
	err := client.SubmitGrant(context.Background(), rec, "", nil)
	if err != nil {
		t.Fatalf("SubmitGrant: %v", err)
	}
	if !called {
		t.Error("PUT /api/v3/grant was not called")
	}
}

func TestSubmitGrant_SendsCallbackURLHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Callback-URL")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"OK","cid":"bafycid001"}`))
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	rec := consent.ConsentRecord{SealedBytes: []byte("fake-sealed")}
	err := client.SubmitGrant(context.Background(), rec, "https://pulsepro.example.com/api/v1/callback/tok", nil)
	if err != nil {
		t.Fatalf("SubmitGrant: %v", err)
	}
	if gotHeader != "https://pulsepro.example.com/api/v1/callback/tok" {
		t.Errorf("X-Callback-URL: got %q", gotHeader)
	}
}

func TestSubmitGrant_EmptyCallbackURL_NoHeader(t *testing.T) {
	var hasHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasHeader = r.Header.Get("X-Callback-URL") != ""
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"OK"}`))
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	_ = client.SubmitGrant(context.Background(), consent.ConsentRecord{SealedBytes: []byte("x")}, "", nil)
	if hasHeader {
		t.Error("expected no X-Callback-URL header when callbackURL is empty")
	}
}

func TestSubmitGrant_SendsSealedDataKeysAndSignatures(t *testing.T) {
	var gotBody pptypes.PulseGrantRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"OK","cid":"bafy"}`))
	}))
	defer srv.Close()

	sealedData := []byte("raw-aes-gcm-ciphertext")
	key1 := []byte{0x02, 0xab, 0xcd}
	key2 := []byte{0x03, 0xef, 0x01}
	sig1 := []byte{0xaa, 0xbb, 0xcc}
	sig2 := []byte{0xdd, 0xee, 0xff}

	rec := consent.ConsentRecord{
		CID:        "bafycid001",
		SealedData: sealedData,
		Keys:       [][]byte{key1, key2},
		Signatures: [][]byte{sig1, sig2},
	}

	client := midtierclient.New(srv.URL)
	if err := client.SubmitGrant(context.Background(), rec, "", nil); err != nil {
		t.Fatalf("SubmitGrant: %v", err)
	}

	if !bytes.Equal(gotBody.Consent.SealedData, sealedData) {
		t.Errorf("SealedData: got %x, want %x", gotBody.Consent.SealedData, sealedData)
	}
	if !bytes.Equal(gotBody.Consent.Key1, key1) {
		t.Errorf("Key1: got %x, want %x", gotBody.Consent.Key1, key1)
	}
	if !bytes.Equal(gotBody.Consent.Key2, key2) {
		t.Errorf("Key2: got %x, want %x", gotBody.Consent.Key2, key2)
	}
	if len(gotBody.Signatures) != 2 {
		t.Fatalf("Signatures: got %d, want 2", len(gotBody.Signatures))
	}
	if gotBody.Signatures[0] != hex.EncodeToString(sig1) {
		t.Errorf("Signatures[0]: got %q, want %q", gotBody.Signatures[0], hex.EncodeToString(sig1))
	}
	if gotBody.Signatures[1] != hex.EncodeToString(sig2) {
		t.Errorf("Signatures[1]: got %q, want %q", gotBody.Signatures[1], hex.EncodeToString(sig2))
	}
}

func TestSubmitRevoke_SendsCallbackURLHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Callback-URL")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"OK"}`))
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	rec := consent.RevokeRecord{GrantCID: "bafycid001", SealedBytes: []byte("x"), Signature: []byte("s")}
	err := client.SubmitRevoke(context.Background(), rec, "https://pulsepro.example.com/api/v1/callback/tok", nil)
	if err != nil {
		t.Fatalf("SubmitRevoke: %v", err)
	}
	if gotHeader != "https://pulsepro.example.com/api/v1/callback/tok" {
		t.Errorf("X-Callback-URL: got %q", gotHeader)
	}
}

func TestSubmitRevoke_CallsDeleteGrant(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v3/grant" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"OK"}`))
	}))
	defer srv.Close()

	client := midtierclient.New(srv.URL)
	rec := consent.RevokeRecord{
		GrantCID:    "bafycid001",
		SealedBytes: []byte("fake-revoke"),
		Signature:   []byte("fake-sig"),
	}
	err := client.SubmitRevoke(context.Background(), rec, "", nil)
	if err != nil {
		t.Fatalf("SubmitRevoke: %v", err)
	}
	if !called {
		t.Error("DELETE /api/v3/grant was not called")
	}
}
