package types

import "encoding/json"

// PulseConsentRequestPQ is the wire format for a consent record encrypted with
// ML-KEM-768 (post-quantum hybrid encryption).
// It wraps the encrypted consent data and carries one or more signatures over the
// CID of that data.  The signing scheme is identical to the EC variant — secp256k1
// EIP-191 — only the encryption layer differs.
//
// CBOR: {"t":"consent-pq","v":1,"ed":<bytes>,"sigs":[<bytes>,...]}
// where "ed" is the DAG-CBOR encoding of the inner PulsePQEncryptionResult.
type PulseConsentRequestPQ struct {
	EncryptedData PulsePQEncryptionResult `json:"consent"`
	Signatures    [][]byte                `json:"signatures"`
}

// PulseRevokeRequestPQ is the wire format for a revoke record encrypted with
// ML-KEM-768 (post-quantum hybrid encryption).
// It carries the CID of the original consent being revoked, the encrypted revoke
// payload, and a single signature from one of the original consent signers.
//
// CBOR: {"t":"revoke-pq","v":1,"ccid":<string>,"ed":<bytes>,"sig":<bytes>}
// where "ed" is the DAG-CBOR encoding of the inner PulsePQEncryptionResult.
type PulseRevokeRequestPQ struct {
	ConsentCid    string                  `json:"consentCid"`
	EncryptedData PulsePQEncryptionResult `json:"revoke"`
	Signature     []byte                  `json:"signature"`
}

// ── PulseConsentRequestPQ — SignableConsent ───────────────────────────────────

// AppendSignature appends an EIP-191 signature to the consent request.
func (p *PulseConsentRequestPQ) AppendSignature(sig []byte) {
	p.Signatures = append(p.Signatures, sig)
}

// ── PulseConsentRequestPQ — JSON ──────────────────────────────────────────────

// MarshalJSON implements json.Marshaler.
func (p *PulseConsentRequestPQ) MarshalJSON() ([]byte, error) {
	type Alias PulseConsentRequestPQ
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PulseConsentRequestPQ) UnmarshalJSON(data []byte) error {
	type Alias PulseConsentRequestPQ
	return json.Unmarshal(data, (*Alias)(p))
}

// ── PulseRevokeRequestPQ — SignableRevoke ─────────────────────────────────────

// GetConsentCid returns the CID of the original consent being revoked.
func (p *PulseRevokeRequestPQ) GetConsentCid() string {
	return p.ConsentCid
}

// AppendSignature sets the revoke signature (replaces any existing signature).
func (p *PulseRevokeRequestPQ) AppendSignature(sig []byte) {
	p.Signature = sig
}

// ── PulseRevokeRequestPQ — JSON ───────────────────────────────────────────────

// MarshalJSON implements json.Marshaler.
func (p *PulseRevokeRequestPQ) MarshalJSON() ([]byte, error) {
	type Alias PulseRevokeRequestPQ
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PulseRevokeRequestPQ) UnmarshalJSON(data []byte) error {
	type Alias PulseRevokeRequestPQ
	return json.Unmarshal(data, (*Alias)(p))
}
