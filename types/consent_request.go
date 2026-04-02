package types

import "encoding/json"

// PulseConsentRequestEC is the wire format for a consent record encrypted with EC (ECDH).
// It wraps the encrypted consent data and carries one or more signatures over the CID of
// that data.  The first signature is from the initiating party; the second (if present)
// is from the counterparty after they have verified and counter-signed.
//
// CBOR: {"t":"consent-ec","v":1,"ed":<bytes>,"sigs":[<bytes>,...]}
// where "ed" is the DAG-CBOR encoding of the inner PulseECEncryptionResult.
type PulseConsentRequestEC struct {
	EncryptedData PulseECEncryptionResult `json:"consent"`
	Signatures    [][]byte                `json:"signatures"`
}

// PulseRevokeRequestEC is the wire format for a revoke record encrypted with EC (ECDH).
// It carries the CID of the original consent being revoked, the encrypted revoke payload,
// and a single signature (which must come from one of the original consent signers).
//
// CBOR: {"t":"revoke-ec","v":1,"ccid":<string>,"ed":<bytes>,"sig":<bytes>}
// where "ed" is the DAG-CBOR encoding of the inner PulseECEncryptionResult.
type PulseRevokeRequestEC struct {
	ConsentCid    string                  `json:"consentCid"`
	EncryptedData PulseECEncryptionResult `json:"revoke"`
	Signature     []byte                  `json:"signature"`
}

// ── PulseConsentRequestEC — SignableConsent ───────────────────────────────────────────

// AppendSignature appends an EIP-191 signature to the consent request.
func (p *PulseConsentRequestEC) AppendSignature(sig []byte) {
	p.Signatures = append(p.Signatures, sig)
}

// ── PulseConsentRequestEC — JSON ─────────────────────────────────────────────────────

// MarshalJSON implements json.Marshaler.
func (p *PulseConsentRequestEC) MarshalJSON() ([]byte, error) {
	type Alias PulseConsentRequestEC
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PulseConsentRequestEC) UnmarshalJSON(data []byte) error {
	type Alias PulseConsentRequestEC
	return json.Unmarshal(data, (*Alias)(p))
}

// ── PulseRevokeRequestEC — SignableRevoke ─────────────────────────────────────────────

// GetConsentCid returns the CID of the original consent being revoked.
func (p *PulseRevokeRequestEC) GetConsentCid() string {
	return p.ConsentCid
}

// AppendSignature sets the revoke signature (replaces any existing signature).
func (p *PulseRevokeRequestEC) AppendSignature(sig []byte) {
	p.Signature = sig
}

// ── PulseRevokeRequestEC — JSON ───────────────────────────────────────────────────────

// MarshalJSON implements json.Marshaler.
func (p *PulseRevokeRequestEC) MarshalJSON() ([]byte, error) {
	type Alias PulseRevokeRequestEC
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PulseRevokeRequestEC) UnmarshalJSON(data []byte) error {
	type Alias PulseRevokeRequestEC
	return json.Unmarshal(data, (*Alias)(p))
}
