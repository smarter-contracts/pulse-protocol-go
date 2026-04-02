package ipfs

import (
	"bytes"
	"fmt"

	ipld "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	v1 "github.com/smarter-contracts/pulse-protocol-go/types/v1"
)

// ── V1 ConsentStructure (EC, two-party) ───────────────────────────────────────

// MarshalV1ConsentEC encodes a V1 EC consent record as a DAG-CBOR map.
// Keys are written in dag-cbor canonical order: key1(4), key2(4), consent(7).
func MarshalV1ConsentEC(c *v1.ConsentStructure) ([]byte, error) {
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

// UnmarshalV1ConsentEC decodes a V1 DAG-CBOR consent block.
// Returns an error if a "t" field is present (indicating a V2+ record).
func UnmarshalV1ConsentEC(block []byte) (*v1.ConsentStructure, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return nil, fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}
	consent, err := MustString(node, "consent")
	if err != nil {
		return nil, fmt.Errorf("consent: %w", err)
	}
	key1, err := MustString(node, "key1")
	if err != nil {
		return nil, fmt.Errorf("key1: %w", err)
	}
	key2, err := MustString(node, "key2")
	if err != nil {
		return nil, fmt.Errorf("key2: %w", err)
	}
	return &v1.ConsentStructure{Consent: consent, Key1: key1, Key2: key2}, nil
}

// ── V1 RevokeStructure (EC, two-party) ────────────────────────────────────────

// MarshalV1RevokeEC encodes a V1 EC revoke record as a DAG-CBOR map.
// Keys in canonical order: key1(4), key2(4), revoke(6), grant_ref(9).
func MarshalV1RevokeEC(r *v1.RevokeStructure) ([]byte, error) {
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

// UnmarshalV1RevokeEC decodes a V1 DAG-CBOR revoke block.
func UnmarshalV1RevokeEC(block []byte) (*v1.RevokeStructure, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return nil, fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}
	revoke, err := MustString(node, "revoke")
	if err != nil {
		return nil, fmt.Errorf("revoke: %w", err)
	}
	key1, err := MustString(node, "key1")
	if err != nil {
		return nil, fmt.Errorf("key1: %w", err)
	}
	key2, err := MustString(node, "key2")
	if err != nil {
		return nil, fmt.Errorf("key2: %w", err)
	}
	grantRef, err := MustString(node, "grant_ref")
	if err != nil {
		return nil, fmt.Errorf("grant_ref: %w", err)
	}
	return &v1.RevokeStructure{Revoke: revoke, Key1: key1, Key2: key2, GrantRef: grantRef}, nil
}

// ── V1 ConsentStructureMulti (PQ, multi-party) ────────────────────────────────

// MarshalV1ConsentPQ encodes a V1 PQ consent record as a DAG-CBOR map.
// Keys written in insertion order (consent, keys) to match the original on-disk format.
func MarshalV1ConsentPQ(c *v1.ConsentStructureMulti) ([]byte, error) {
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

// UnmarshalV1ConsentPQ decodes a V1 DAG-CBOR multi-party consent block.
func UnmarshalV1ConsentPQ(block []byte) (*v1.ConsentStructureMulti, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return nil, fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}
	consent, err := MustString(node, "consent")
	if err != nil {
		return nil, fmt.Errorf("consent: %w", err)
	}
	keys, err := stringList(node, "keys")
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return &v1.ConsentStructureMulti{Consent: consent, Keys: keys}, nil
}

// ── V1 RevokeStructureMulti (PQ, multi-party) ─────────────────────────────────

// MarshalV1RevokePQ encodes a V1 PQ revoke record as a DAG-CBOR map.
// Keys written in insertion order (revoke, keys, grant_ref) to match the original on-disk format.
func MarshalV1RevokePQ(r *v1.RevokeStructureMulti) ([]byte, error) {
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

// UnmarshalV1RevokePQ decodes a V1 DAG-CBOR multi-party revoke block.
func UnmarshalV1RevokePQ(block []byte) (*v1.RevokeStructureMulti, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding dag-cbor: %w", err)
	}
	node := na.Build()

	if _, err := node.LookupByString("t"); err == nil {
		return nil, fmt.Errorf("block has a type discriminator field; expected a V1 record")
	}
	revoke, err := MustString(node, "revoke")
	if err != nil {
		return nil, fmt.Errorf("revoke: %w", err)
	}
	keys, err := stringList(node, "keys")
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	grantRef, err := MustString(node, "grant_ref")
	if err != nil {
		return nil, fmt.Errorf("grant_ref: %w", err)
	}
	return &v1.RevokeStructureMulti{Revoke: revoke, Keys: keys, GrantRef: grantRef}, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// stringList reads a named key from an IPLD map node and returns its list values as []string.
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
