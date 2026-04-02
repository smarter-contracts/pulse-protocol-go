package types

// ── PulseConsentPayload ───────────────────────────────────────────────────────

// PulseConsentPayload is the polymorphic consent content transmitted in a grant
// request. Exactly one of the two key forms must be present:
//
//	EC:  SealedData + Key1 + Key2
//	PQ:  SealedData + Keys
//
// It merges the previously-separate PulseECEncryptionResult and
// PulsePQEncryptionResult into a single JSON-friendly type suitable for use
// as a V3 API request body field.
type PulseConsentPayload struct {
	SealedData []byte                  `json:"sealedData"`
	Key1       []byte                  `json:"key1,omitempty"`
	Key2       []byte                  `json:"key2,omitempty"`
	Keys       []*PulsePQEncryptionKey `json:"keys,omitempty"`
}

// IsMultiKey reports whether this payload uses PQ (multi-key) encryption.
func (p *PulseConsentPayload) IsMultiKey() bool { return len(p.Keys) > 0 }

// ── PulseGrantRequest ─────────────────────────────────────────────────────────

// PulseGrantRequest is the V3 API request body for granting consent
// (PUT /api/v3/grant). It merges the previously-separate PulseConsentRequestEC
// and PulseConsentRequestPQ into a single polymorphic type; the encryption mode
// is determined by the Consent payload.
type PulseGrantRequest struct {
	Consent    PulseConsentPayload `json:"consent"`
	Signatures []string            `json:"signatures"`          // Hex-encoded EIP-191 signatures
	Addresses  []string            `json:"addresses,omitempty"` // Optional; derived from signatures if absent
}

// ── PulseRevokePayload ────────────────────────────────────────────────────────

// PulseRevokePayload is the polymorphic revoke content transmitted in a revoke
// request. Exactly one of the two key forms must be present:
//
//	EC:  SealedData + GrantRef + Key1 + Key2
//	PQ:  SealedData + GrantRef + Keys
type PulseRevokePayload struct {
	SealedData []byte                  `json:"sealedData"`
	GrantRef   string                  `json:"grantRef"`   // CID of the original consent
	Key1       []byte                  `json:"key1,omitempty"`
	Key2       []byte                  `json:"key2,omitempty"`
	Keys       []*PulsePQEncryptionKey `json:"keys,omitempty"`
}

// IsMultiKey reports whether this payload uses PQ (multi-key) encryption.
func (p *PulseRevokePayload) IsMultiKey() bool { return len(p.Keys) > 0 }

// ── PulseRevokeRequest ────────────────────────────────────────────────────────

// PulseRevokeRequest is the V3 API request body for revoking consent
// (DELETE /api/v3/grant). It merges the previously-separate PulseRevokeRequestEC
// and PulseRevokeRequestPQ into a single polymorphic type.
type PulseRevokeRequest struct {
	Revoke     PulseRevokePayload `json:"revoke"`
	Signature  string             `json:"signature"`
	SigAddress string             `json:"sigaddress,omitempty"`
}
