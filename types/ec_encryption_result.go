package types

import "encoding/json"

// PulseECEncryptionResult is a struct for holding the result of an encryption
// operation. It contains the sealed data, the two public keys involved in the
// exchange, for embedding in a consent record (Notary) or a Consent/Revoke/Update
// request.
type PulseECEncryptionResult struct {
	SealedData []byte `json:"sealedData"` // Encrypted data
	Key1       []byte `json:"key1"      ` // My public key, 33-byte compressed format
	Key2       []byte `json:"key2"      ` // Public key of the other party, 33-byte compressed format
}

// MarshalJSON implements json.Marshaler.
func (p *PulseECEncryptionResult) MarshalJSON() ([]byte, error) {
	type Alias PulseECEncryptionResult
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PulseECEncryptionResult) UnmarshalJSON(bytes []byte) error {
	type Alias PulseECEncryptionResult
	return json.Unmarshal(bytes, (*Alias)(p))
}
