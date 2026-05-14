package midtierclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/consent"
	"github.com/smarter-contracts/pulse-protocol-go/consent/midtierclient"
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
