package types

import "encoding/json"

// ConsentStructure is the canonical two-party (EC) record written to IPFS for a consent grant.
// It is a type alias for PulseECEncryptionResult — the IPFS record format is identical to the
// EC encryption output.
//
// CBOR: {"t":"ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>}
type ConsentStructure = PulseECEncryptionResult

// ConsentStructureMulti is the canonical multi-party (PQ) record written to IPFS for a consent
// grant. It is a type alias for PulsePQEncryptionResult — the IPFS record format is identical to
// the PQ encryption output.
//
// CBOR: {"t":"pq","v":1,"sd":<bytes>,"keys":[...]}
type ConsentStructureMulti = PulsePQEncryptionResult

// RevokeStructure is the canonical two-party (EC) record written to IPFS for a consent
// revocation. It carries the same encrypted payload structure as ConsentStructure, with the
// addition of a reference back to the CID of the original consent being revoked.
//
// CBOR: {"t":"rev-ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>,"gr":<string>}
type RevokeStructure struct {
	PulseECEncryptionResult
	Grant string `json:"grantRef"` // CID of the original consent being revoked
}

// RevokeStructureMulti is the canonical multi-party (PQ) record written to IPFS for a consent
// revocation. It carries the same encrypted payload structure as ConsentStructureMulti, with the
// addition of a reference back to the CID of the original consent being revoked.
//
// CBOR: {"t":"rev-pq","v":1,"sd":<bytes>,"keys":[...],"gr":<string>}
type RevokeStructureMulti struct {
	PulsePQEncryptionResult
	Grant string `json:"grantRef"` // CID of the original consent being revoked
}

// ── RevokeStructure — JSON ────────────────────────────────────────────────────────────

// MarshalJSON implements json.Marshaler.
func (r *RevokeStructure) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		SealedData []byte `json:"sealedData"`
		Key1       []byte `json:"key1"`
		Key2       []byte `json:"key2"`
		Grant      string `json:"grantRef"`
	}{
		SealedData: r.SealedData,
		Key1:       r.Key1,
		Key2:       r.Key2,
		Grant:      r.Grant,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *RevokeStructure) UnmarshalJSON(data []byte) error {
	var v struct {
		SealedData []byte `json:"sealedData"`
		Key1       []byte `json:"key1"`
		Key2       []byte `json:"key2"`
		Grant      string `json:"grantRef"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	r.SealedData = v.SealedData
	r.Key1 = v.Key1
	r.Key2 = v.Key2
	r.Grant = v.Grant
	return nil
}

// ── RevokeStructureMulti — JSON ───────────────────────────────────────────────────────

// MarshalJSON implements json.Marshaler.
func (r *RevokeStructureMulti) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		SealedData []byte                  `json:"sealedData"`
		Keys       []*PulsePQEncryptionKey `json:"keys"`
		Grant      string                  `json:"grantRef"`
	}{
		SealedData: r.SealedData,
		Keys:       r.Keys,
		Grant:      r.Grant,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *RevokeStructureMulti) UnmarshalJSON(data []byte) error {
	var v struct {
		SealedData []byte                  `json:"sealedData"`
		Keys       []*PulsePQEncryptionKey `json:"keys"`
		Grant      string                  `json:"grantRef"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	r.SealedData = v.SealedData
	r.Keys = v.Keys
	r.Grant = v.Grant
	return nil
}
