package types

import "fmt"

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

// MarshalCBOR encodes the payload to its V2 IPFS DAG-CBOR representation.
// PQ payloads encode as PulsePQEncryptionResult; EC payloads encode as
// PulseECEncryptionResult.
func (p *PulseConsentPayload) MarshalCBOR() ([]byte, error) {
	if p.IsMultiKey() {
		r := &PulsePQEncryptionResult{SealedData: p.SealedData, Keys: p.Keys}
		return r.MarshalCBOR()
	}
	if len(p.Key1) == 0 || len(p.Key2) == 0 {
		return nil, fmt.Errorf("EC consent payload requires key1 and key2")
	}
	r := &PulseECEncryptionResult{SealedData: p.SealedData, Key1: p.Key1, Key2: p.Key2}
	return r.MarshalCBOR()
}

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

// MarshalCBOR encodes the payload to its V2 IPFS DAG-CBOR representation.
// PQ payloads encode as RevokeStructureMulti; EC payloads encode as RevokeStructure.
func (p *PulseRevokePayload) MarshalCBOR() ([]byte, error) {
	if p.IsMultiKey() {
		r := &RevokeStructureMulti{
			PulsePQEncryptionResult: PulsePQEncryptionResult{SealedData: p.SealedData, Keys: p.Keys},
			Grant:                   p.GrantRef,
		}
		return r.MarshalCBOR()
	}
	if len(p.Key1) == 0 || len(p.Key2) == 0 {
		return nil, fmt.Errorf("EC revoke payload requires key1 and key2")
	}
	r := &RevokeStructure{
		PulseECEncryptionResult: PulseECEncryptionResult{SealedData: p.SealedData, Key1: p.Key1, Key2: p.Key2},
		Grant:                   p.GrantRef,
	}
	return r.MarshalCBOR()
}

// ── PulseRevokeRequest ────────────────────────────────────────────────────────

// PulseRevokeRequest is the V3 API request body for revoking consent
// (DELETE /api/v3/grant). It merges the previously-separate PulseRevokeRequestEC
// and PulseRevokeRequestPQ into a single polymorphic type.
type PulseRevokeRequest struct {
	Revoke     PulseRevokePayload `json:"revoke"`
	Signature  string             `json:"signature"`
	SigAddress string             `json:"sigaddress,omitempty"`
}
