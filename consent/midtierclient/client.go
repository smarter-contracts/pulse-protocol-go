// Package midtierclient provides a concrete HTTP implementation of the
// consent.MidTierClient interface that communicates with the mid-tier service.
package midtierclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/smarter-contracts/pulse-protocol-go/consent"
)

// Client is an HTTP implementation of consent.MidTierClient.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New returns a Client pointed at baseURL (e.g. "http://localhost:3020").
func New(baseURL string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{},
	}
}

// ── GetConsentsSince ──────────────────────────────────────────────────────────

// ConsentEventJSON is the wire format returned by GET /api/v3/consents-by-key/{xpub}.
type ConsentEventJSON struct {
	ConsentID   string `json:"consentId"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	CID         string `json:"cid"`
	BlockNumber uint64 `json:"blockNumber"`
	Cursor      string `json:"cursor"`
}

// GetConsentsSince implements consent.MidTierClient.
// xpub must be the root protocol xpub at m/CMP' (use DeriveOtherPartyXpub(wallet,0)).
// cursor is the opaque value from the last ConsentEvent.Cursor; pass "" for full history.
func (c *Client) GetConsentsSince(ctx context.Context, xpub, cursor string) ([]consent.ConsentEvent, error) {
	url := fmt.Sprintf("%s/api/v3/consents-by-key/%s", c.baseURL, xpub)
	if cursor != "" {
		url += "?since=" + cursor
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("midtierclient: build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("midtierclient: GET consents-by-key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("midtierclient: GET consents-by-key: status %d", resp.StatusCode)
	}

	var wire []ConsentEventJSON
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("midtierclient: decode response: %w", err)
	}

	events := make([]consent.ConsentEvent, len(wire))
	for i, w := range wire {
		events[i] = consent.ConsentEvent{
			ConsentID:   w.ConsentID,
			Type:        consent.TransactionType(w.Type),
			Status:      consent.TransactionStatus(w.Status),
			CID:         w.CID,
			BlockNumber: w.BlockNumber,
			Cursor:      w.Cursor,
		}
	}
	return events, nil
}

// ── SubmitGrant ───────────────────────────────────────────────────────────────

// grantRequestWire is the JSON body sent to PUT /api/v3/grant.
// SealedBytes from ConsentRecord are base64-encoded as the sealedData field.
// Signatures and keys are included if present in the record.
type grantRequestWire struct {
	Consent    grantConsentWire `json:"consent"`
	Signatures []string         `json:"signatures"`
}

type grantConsentWire struct {
	SealedData string `json:"sealedData"`
}

// SubmitGrant implements consent.MidTierClient.
// record.SealedBytes must be the CBOR-encoded ConsentEC structure.
// callbackURL is forwarded as X-Callback-URL so mid-tier can route lifecycle
// callbacks back to PulsePro.
func (c *Client) SubmitGrant(ctx context.Context, record consent.ConsentRecord, callbackURL string, metadata map[string]any) error {
	body := grantRequestWire{
		Consent: grantConsentWire{
			SealedData: base64.StdEncoding.EncodeToString(record.SealedBytes),
		},
	}

	var extra map[string]string
	if callbackURL != "" {
		extra = map[string]string{"X-Callback-URL": callbackURL}
	}
	return c.doJSON(ctx, http.MethodPut, "/api/v3/grant", body, extra)
}

// ── SubmitRevoke ──────────────────────────────────────────────────────────────

// revokeRequestWire is the JSON body sent to DELETE /api/v3/grant.
type revokeRequestWire struct {
	Revoke    revokePayloadWire `json:"revoke"`
	Signature string            `json:"signature"`
}

type revokePayloadWire struct {
	SealedData string `json:"sealedData"`
	GrantRef   string `json:"grantRef"`
}

// SubmitRevoke implements consent.MidTierClient.
func (c *Client) SubmitRevoke(ctx context.Context, record consent.RevokeRecord, callbackURL string, metadata map[string]any) error {
	body := revokeRequestWire{
		Revoke: revokePayloadWire{
			SealedData: base64.StdEncoding.EncodeToString(record.SealedBytes),
			GrantRef:   record.GrantCID,
		},
		Signature: hex.EncodeToString(record.Signature),
	}

	var extra map[string]string
	if callbackURL != "" {
		extra = map[string]string{"X-Callback-URL": callbackURL}
	}
	return c.doJSON(ctx, http.MethodDelete, "/api/v3/grant", body, extra)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (c *Client) doJSON(ctx context.Context, method, path string, body any, extraHeaders map[string]string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("midtierclient: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("midtierclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("midtierclient: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("midtierclient: %s %s: status %d", method, path, resp.StatusCode)
	}
	return nil
}
