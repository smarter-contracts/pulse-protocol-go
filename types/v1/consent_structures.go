// Package v1 contains the Version 1 Pulse Protocol IPFS record types.
//
// These types represent the on-disk format of consent and revoke records that
// were written to IPFS by the mid-tier prior to the introduction of Version 2
// structures. They must not be altered — any change would produce a different
// CID for the same logical record, breaking verification of existing consents.
//
// Detection: a V1 record has no "t" (type) discriminator field in its CBOR map.
// A V2 (or later) record always has a "t" field.
//
// All V1 fields are CBOR text strings (base64-encoded bytes on the wire).
package v1

import "encoding/json"

// ── ConsentStructure (EC, two-party) ─────────────────────────────────────────
//
// On-disk DAG-CBOR map (keys in dag-cbor canonical order — length then lex):
//
//	{"key1": text, "key2": text, "consent": text}
//
// Originally written by the mid-tier via DagPutWithOpts(JSON), which causes the
// IPFS node to convert JSON→dag-cbor using canonical key ordering.

// ConsentStructure is the V1 encrypted consent record for a two-party (EC) consent.
type ConsentStructure struct {
	Consent string `json:"consent"` // Base64-encoded sealed data
	Key1    string `json:"key1"`    // Base64-encoded first party public key
	Key2    string `json:"key2"`    // Base64-encoded second party public key
}

// MarshalJSON and UnmarshalJSON use the struct tags directly.
func (c *ConsentStructure) MarshalJSON() ([]byte, error) {
	type Alias ConsentStructure
	return json.Marshal((*Alias)(c))
}

func (c *ConsentStructure) UnmarshalJSON(data []byte) error {
	type Alias ConsentStructure
	return json.Unmarshal(data, (*Alias)(c))
}

// ── RevokeStructure (EC, two-party) ──────────────────────────────────────────
//
// On-disk DAG-CBOR map (canonical key order):
//
//	{"key1": text, "key2": text, "revoke": text, "grant_ref": text}

// RevokeStructure is the V1 encrypted revocation record for a two-party (EC) consent.
type RevokeStructure struct {
	Revoke   string `json:"revoke"`     // Base64-encoded sealed data
	Key1     string `json:"key1"`       // Base64-encoded first party public key
	Key2     string `json:"key2"`       // Base64-encoded second party public key
	GrantRef string `json:"grant_ref"`  // CID of the original consent being revoked
}

func (r *RevokeStructure) MarshalJSON() ([]byte, error) {
	type Alias RevokeStructure
	return json.Marshal((*Alias)(r))
}

func (r *RevokeStructure) UnmarshalJSON(data []byte) error {
	type Alias RevokeStructure
	return json.Unmarshal(data, (*Alias)(r))
}

// ── ConsentStructureMulti (PQ, multi-party) ───────────────────────────────────
//
// On-disk DAG-CBOR map (insertion order from BuildIPFSBlock):
//
//	{"consent": text, "keys": [text, ...]}
//
// Note: originally written by BuildIPFSBlock using basicnode with "consent" first,
// so the on-disk key order is insertion order (consent, keys), not canonical dag-cbor
// order (keys, consent). MarshalV1ConsentPQ in the ipfs package preserves this
// insertion order for CID fidelity.

// ConsentStructureMulti is the V1 encrypted consent record for a multi-party (PQ) consent.
type ConsentStructureMulti struct {
	Consent string   `json:"consent"` // Base64-encoded sealed data
	Keys    []string `json:"keys"`    // Base64-encoded encapsulated keys, one per recipient
}

func (c *ConsentStructureMulti) MarshalJSON() ([]byte, error) {
	type Alias ConsentStructureMulti
	return json.Marshal((*Alias)(c))
}

func (c *ConsentStructureMulti) UnmarshalJSON(data []byte) error {
	type Alias ConsentStructureMulti
	return json.Unmarshal(data, (*Alias)(c))
}

// ── RevokeStructureMulti (PQ, multi-party) ────────────────────────────────────
//
// On-disk DAG-CBOR map (insertion order from BuildIPFSBlock):
//
//	{"revoke": text, "keys": [text, ...], "grant_ref": text}

// RevokeStructureMulti is the V1 encrypted revocation record for a multi-party (PQ) consent.
type RevokeStructureMulti struct {
	Revoke   string   `json:"revoke"`    // Base64-encoded sealed data
	Keys     []string `json:"keys"`      // Base64-encoded encapsulated keys
	GrantRef string   `json:"grant_ref"` // CID of the original consent being revoked
}

func (r *RevokeStructureMulti) MarshalJSON() ([]byte, error) {
	type Alias RevokeStructureMulti
	return json.Marshal((*Alias)(r))
}

func (r *RevokeStructureMulti) UnmarshalJSON(data []byte) error {
	type Alias RevokeStructureMulti
	return json.Unmarshal(data, (*Alias)(r))
}
