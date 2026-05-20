// Package midtierclient provides a concrete HTTP implementation of the
// consent.MidTierClient interface that communicates with the mid-tier service.
package midtierclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/smarter-contracts/pulse-protocol-go/consent"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
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

// SubmitGrant implements consent.MidTierClient.
// record.SealedData holds the raw AES-256-GCM ciphertext; record.Keys holds the
// EC public keys [Key1, Key2]; record.Signatures holds the ordered EIP-191 sigs.
// callbackURL is forwarded as X-Callback-URL so mid-tier can route lifecycle
// callbacks back to PulsePro.
func (c *Client) SubmitGrant(ctx context.Context, record consent.ConsentRecord, callbackURL string, metadata map[string]any) error {
	sigs := make([]string, len(record.Signatures))
	for i, sig := range record.Signatures {
		sigs[i] = hex.EncodeToString(sig)
	}

	body := pptypes.PulseGrantRequest{
		Consent: pptypes.PulseConsentPayload{
			SealedData: record.SealedData,
			Key1:       keyAt(record.Keys, 0),
			Key2:       keyAt(record.Keys, 1),
		},
		Signatures: sigs,
	}

	var extra map[string]string
	if callbackURL != "" {
		extra = map[string]string{"X-Callback-URL": callbackURL}
	}
	return c.doJSON(ctx, http.MethodPut, "/api/v3/grant", body, extra)
}

// keyAt returns keys[i] or nil when i is out of range.
func keyAt(keys [][]byte, i int) []byte {
	if i < len(keys) {
		return keys[i]
	}
	return nil
}

// ── SubmitRevoke ──────────────────────────────────────────────────────────────

// SubmitRevoke implements consent.MidTierClient.
func (c *Client) SubmitRevoke(ctx context.Context, record consent.RevokeRecord, callbackURL string, metadata map[string]any) error {
	body := pptypes.PulseRevokeRequest{
		Revoke: pptypes.PulseRevokePayload{
			SealedData: record.SealedBytes,
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
