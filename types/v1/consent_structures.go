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

import (
	"bytes"
	"encoding/json"
	"fmt"

	ipld "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

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

// MarshalCBOR encodes as a DAG-CBOR map matching the V1 on-disk format.
// Keys are written in dag-cbor canonical order (length asc, then lex):
// key1(4), key2(4), consent(7).
func (c *ConsentStructure) MarshalCBOR() ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(3)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("key1")
	_ = ma.AssembleValue().AssignString(c.Key1)
	_ = ma.AssembleKey().AssignString("key2")
	_ = ma.AssembleValue().AssignString(c.Key2)
	_ = ma.AssembleKey().AssignString("consent")
	_ = ma.AssembleValue().AssignString(c.Consent)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalCBOR decodes a V1 DAG-CBOR consent block.
// Returns an error if a "t" field is present (indicating a V2+ record).
func (c *ConsentStructure) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}

	consent, err := ipfs.MustString(node, "consent")
	if err != nil {
		return fmt.Errorf("consent: %w", err)
	}
	key1, err := ipfs.MustString(node, "key1")
	if err != nil {
		return fmt.Errorf("key1: %w", err)
	}
	key2, err := ipfs.MustString(node, "key2")
	if err != nil {
		return fmt.Errorf("key2: %w", err)
	}
	c.Consent = consent
	c.Key1 = key1
	c.Key2 = key2
	return nil
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

// MarshalCBOR encodes as a DAG-CBOR map matching the V1 on-disk format.
// Keys in canonical order: key1(4), key2(4), revoke(6), grant_ref(9).
func (r *RevokeStructure) MarshalCBOR() ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(4)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("key1")
	_ = ma.AssembleValue().AssignString(r.Key1)
	_ = ma.AssembleKey().AssignString("key2")
	_ = ma.AssembleValue().AssignString(r.Key2)
	_ = ma.AssembleKey().AssignString("revoke")
	_ = ma.AssembleValue().AssignString(r.Revoke)
	_ = ma.AssembleKey().AssignString("grant_ref")
	_ = ma.AssembleValue().AssignString(r.GrantRef)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalCBOR decodes a V1 DAG-CBOR revoke block.
func (r *RevokeStructure) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}

	revoke, err := ipfs.MustString(node, "revoke")
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	key1, err := ipfs.MustString(node, "key1")
	if err != nil {
		return fmt.Errorf("key1: %w", err)
	}
	key2, err := ipfs.MustString(node, "key2")
	if err != nil {
		return fmt.Errorf("key2: %w", err)
	}
	grantRef, err := ipfs.MustString(node, "grant_ref")
	if err != nil {
		return fmt.Errorf("grant_ref: %w", err)
	}
	r.Revoke = revoke
	r.Key1 = key1
	r.Key2 = key2
	r.GrantRef = grantRef
	return nil
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
// order (keys, consent). MarshalCBOR preserves this insertion order for CID fidelity.

// ConsentStructureMulti is the V1 encrypted consent record for a multi-party (PQ) consent.
type ConsentStructureMulti struct {
	Consent string   `json:"consent"` // Base64-encoded sealed data
	Keys    []string `json:"keys"`    // Base64-encoded encapsulated keys, one per recipient
}

// MarshalCBOR encodes as a DAG-CBOR map matching the V1 on-disk format.
// Keys are written in insertion order (consent, keys) to match BuildIPFSBlock output.
func (c *ConsentStructureMulti) MarshalCBOR() ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(2)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("consent")
	_ = ma.AssembleValue().AssignString(c.Consent)

	_ = ma.AssembleKey().AssignString("keys")
	la, err := ma.AssembleValue().BeginList(int64(len(c.Keys)))
	if err != nil {
		return nil, err
	}
	for _, k := range c.Keys {
		_ = la.AssembleValue().AssignString(k)
	}
	if err := la.Finish(); err != nil {
		return nil, err
	}

	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalCBOR decodes a V1 DAG-CBOR multi-party consent block.
func (c *ConsentStructureMulti) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}

	consent, err := ipfs.MustString(node, "consent")
	if err != nil {
		return fmt.Errorf("consent: %w", err)
	}
	keys, err := stringList(node, "keys")
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	c.Consent = consent
	c.Keys = keys
	return nil
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

// MarshalCBOR encodes as a DAG-CBOR map matching the V1 on-disk format.
// Keys are written in insertion order (revoke, keys, grant_ref) to match BuildIPFSBlock.
func (r *RevokeStructureMulti) MarshalCBOR() ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(3)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("revoke")
	_ = ma.AssembleValue().AssignString(r.Revoke)

	_ = ma.AssembleKey().AssignString("keys")
	la, err := ma.AssembleValue().BeginList(int64(len(r.Keys)))
	if err != nil {
		return nil, err
	}
	for _, k := range r.Keys {
		_ = la.AssembleValue().AssignString(k)
	}
	if err := la.Finish(); err != nil {
		return nil, err
	}

	_ = ma.AssembleKey().AssignString("grant_ref")
	_ = ma.AssembleValue().AssignString(r.GrantRef)

	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalCBOR decodes a V1 DAG-CBOR multi-party revoke block.
func (r *RevokeStructureMulti) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}

	revoke, err := ipfs.MustString(node, "revoke")
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	keys, err := stringList(node, "keys")
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	grantRef, err := ipfs.MustString(node, "grant_ref")
	if err != nil {
		return fmt.Errorf("grant_ref: %w", err)
	}
	r.Revoke = revoke
	r.Keys = keys
	r.GrantRef = grantRef
	return nil
}

func (r *RevokeStructureMulti) MarshalJSON() ([]byte, error) {
	type Alias RevokeStructureMulti
	return json.Marshal((*Alias)(r))
}

func (r *RevokeStructureMulti) UnmarshalJSON(data []byte) error {
	type Alias RevokeStructureMulti
	return json.Unmarshal(data, (*Alias)(r))
}

// ── helpers ───────────────────────────────────────────────────────────────────

// stringList reads a named key from an IPLD map node and returns its list
// values as []string.
func stringList(n ipld.Node, key string) ([]string, error) {
	listNode, err := n.LookupByString(key)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, listNode.Length())
	iter := listNode.ListIterator()
	for !iter.Done() {
		_, v, err := iter.Next()
		if err != nil {
			return nil, err
		}
		s, err := v.AsString()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
