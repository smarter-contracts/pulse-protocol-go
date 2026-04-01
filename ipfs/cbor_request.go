package ipfs

import (
	"bytes"
	"fmt"

	ipld "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── Dispatch ──────────────────────────────────────────────────────────────────

// MarshalConsent encodes a PulseConsentPayload to its V2 IPFS DAG-CBOR representation.
// PQ payloads encode as PulsePQEncryptionResult; EC payloads encode as PulseECEncryptionResult.
func MarshalConsent(p *pptypes.PulseConsentPayload) ([]byte, error) {
	if p.IsMultiKey() {
		return MarshalConsentPQ(&pptypes.PulsePQEncryptionResult{SealedData: p.SealedData, Keys: p.Keys})
	}
	if len(p.Key1) == 0 || len(p.Key2) == 0 {
		return nil, fmt.Errorf("EC consent payload requires key1 and key2")
	}
	return MarshalConsentEC(&pptypes.PulseECEncryptionResult{SealedData: p.SealedData, Key1: p.Key1, Key2: p.Key2})
}

// MarshalRevoke encodes a PulseRevokePayload to its V2 IPFS DAG-CBOR representation.
// PQ payloads encode as RevokeStructureMulti; EC payloads encode as RevokeStructure.
func MarshalRevoke(p *pptypes.PulseRevokePayload) ([]byte, error) {
	if p.IsMultiKey() {
		return MarshalRevokePQ(&pptypes.RevokeStructureMulti{
			PulsePQEncryptionResult: pptypes.PulsePQEncryptionResult{SealedData: p.SealedData, Keys: p.Keys},
			Grant:                   p.GrantRef,
		})
	}
	if len(p.Key1) == 0 || len(p.Key2) == 0 {
		return nil, fmt.Errorf("EC revoke payload requires key1 and key2")
	}
	return MarshalRevokeEC(&pptypes.RevokeStructure{
		PulseECEncryptionResult: pptypes.PulseECEncryptionResult{SealedData: p.SealedData, Key1: p.Key1, Key2: p.Key2},
		Grant:                   p.GrantRef,
	})
}

// ── PulseConsentRequestEC ─────────────────────────────────────────────────────

// MarshalConsentRequestEC encodes a PulseConsentRequestEC as a DAG-CBOR map:
// {"t":"consent-ec","v":1,"ed":<bytes>,"sigs":[<bytes>,...]}
// where "ed" is the DAG-CBOR encoding of the inner PulseECEncryptionResult.
func MarshalConsentRequestEC(p *pptypes.PulseConsentRequestEC) ([]byte, error) {
	edBytes, err := MarshalConsentEC(&p.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(4)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("consent-ec")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("ed")
	_ = ma.AssembleValue().AssignBytes(edBytes)
	_ = ma.AssembleKey().AssignString("sigs")
	la, err := ma.AssembleValue().BeginList(int64(len(p.Signatures)))
	if err != nil {
		return nil, err
	}
	for _, sig := range p.Signatures {
		if err := la.AssembleValue().AssignBytes(sig); err != nil {
			return nil, err
		}
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

// UnmarshalConsentRequestEC decodes a DAG-CBOR block into a PulseConsentRequestEC.
func UnmarshalConsentRequestEC(block []byte) (*pptypes.PulseConsentRequestEC, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "consent-ec" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected consent-ec version: %d", ver)
	}
	edBytes, err := MustBytes(node, "ed")
	if err != nil {
		return nil, fmt.Errorf("ed: %w", err)
	}
	encData, err := UnmarshalConsentEC(edBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted data: %w", err)
	}
	sigs, err := decodeBytesList(node, "sigs")
	if err != nil {
		return nil, err
	}
	return &pptypes.PulseConsentRequestEC{EncryptedData: *encData, Signatures: sigs}, nil
}

// ── PulseRevokeRequestEC ──────────────────────────────────────────────────────

// MarshalRevokeRequestEC encodes a PulseRevokeRequestEC as a DAG-CBOR map:
// {"t":"revoke-ec","v":1,"ccid":<string>,"ed":<bytes>,"sig":<bytes>}
func MarshalRevokeRequestEC(p *pptypes.PulseRevokeRequestEC) ([]byte, error) {
	edBytes, err := MarshalConsentEC(&p.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(5)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("revoke-ec")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("ccid")
	_ = ma.AssembleValue().AssignString(p.ConsentCid)
	_ = ma.AssembleKey().AssignString("ed")
	_ = ma.AssembleValue().AssignBytes(edBytes)
	_ = ma.AssembleKey().AssignString("sig")
	_ = ma.AssembleValue().AssignBytes(p.Signature)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalRevokeRequestEC decodes a DAG-CBOR block into a PulseRevokeRequestEC.
func UnmarshalRevokeRequestEC(block []byte) (*pptypes.PulseRevokeRequestEC, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "revoke-ec" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected revoke-ec version: %d", ver)
	}
	ccid, err := MustString(node, "ccid")
	if err != nil {
		return nil, fmt.Errorf("ccid: %w", err)
	}
	edBytes, err := MustBytes(node, "ed")
	if err != nil {
		return nil, fmt.Errorf("ed: %w", err)
	}
	encData, err := UnmarshalConsentEC(edBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted data: %w", err)
	}
	sig, err := MustBytes(node, "sig")
	if err != nil {
		return nil, fmt.Errorf("sig: %w", err)
	}
	return &pptypes.PulseRevokeRequestEC{ConsentCid: ccid, EncryptedData: *encData, Signature: sig}, nil
}

// ── PulseConsentRequestPQ ─────────────────────────────────────────────────────

// MarshalConsentRequestPQ encodes a PulseConsentRequestPQ as a DAG-CBOR map:
// {"t":"consent-pq","v":1,"ed":<bytes>,"sigs":[<bytes>,...]}
func MarshalConsentRequestPQ(p *pptypes.PulseConsentRequestPQ) ([]byte, error) {
	edBytes, err := MarshalConsentPQ(&p.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(4)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("consent-pq")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("ed")
	_ = ma.AssembleValue().AssignBytes(edBytes)
	_ = ma.AssembleKey().AssignString("sigs")
	la, err := ma.AssembleValue().BeginList(int64(len(p.Signatures)))
	if err != nil {
		return nil, err
	}
	for _, sig := range p.Signatures {
		if err := la.AssembleValue().AssignBytes(sig); err != nil {
			return nil, err
		}
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

// UnmarshalConsentRequestPQ decodes a DAG-CBOR block into a PulseConsentRequestPQ.
func UnmarshalConsentRequestPQ(block []byte) (*pptypes.PulseConsentRequestPQ, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "consent-pq" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected consent-pq version: %d", ver)
	}
	edBytes, err := MustBytes(node, "ed")
	if err != nil {
		return nil, fmt.Errorf("ed: %w", err)
	}
	encData, err := UnmarshalConsentPQ(edBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted data: %w", err)
	}
	sigs, err := decodeBytesList(node, "sigs")
	if err != nil {
		return nil, err
	}
	return &pptypes.PulseConsentRequestPQ{EncryptedData: *encData, Signatures: sigs}, nil
}

// ── PulseRevokeRequestPQ ──────────────────────────────────────────────────────

// MarshalRevokeRequestPQ encodes a PulseRevokeRequestPQ as a DAG-CBOR map:
// {"t":"revoke-pq","v":1,"ccid":<string>,"ed":<bytes>,"sig":<bytes>}
func MarshalRevokeRequestPQ(p *pptypes.PulseRevokeRequestPQ) ([]byte, error) {
	edBytes, err := MarshalConsentPQ(&p.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(5)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("revoke-pq")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("ccid")
	_ = ma.AssembleValue().AssignString(p.ConsentCid)
	_ = ma.AssembleKey().AssignString("ed")
	_ = ma.AssembleValue().AssignBytes(edBytes)
	_ = ma.AssembleKey().AssignString("sig")
	_ = ma.AssembleValue().AssignBytes(p.Signature)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalRevokeRequestPQ decodes a DAG-CBOR block into a PulseRevokeRequestPQ.
func UnmarshalRevokeRequestPQ(block []byte) (*pptypes.PulseRevokeRequestPQ, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "revoke-pq" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected revoke-pq version: %d", ver)
	}
	ccid, err := MustString(node, "ccid")
	if err != nil {
		return nil, fmt.Errorf("ccid: %w", err)
	}
	edBytes, err := MustBytes(node, "ed")
	if err != nil {
		return nil, fmt.Errorf("ed: %w", err)
	}
	encData, err := UnmarshalConsentPQ(edBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted data: %w", err)
	}
	sig, err := MustBytes(node, "sig")
	if err != nil {
		return nil, fmt.Errorf("sig: %w", err)
	}
	return &pptypes.PulseRevokeRequestPQ{ConsentCid: ccid, EncryptedData: *encData, Signature: sig}, nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

// decodeBytesList reads a named IPLD list node and returns each element as []byte.
func decodeBytesList(node ipld.Node, key string) ([][]byte, error) {
	listNode, err := node.LookupByString(key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	it := listNode.ListIterator()
	var out [][]byte
	for !it.Done() {
		_, sn, err := it.Next()
		if err != nil {
			return nil, err
		}
		b, err := sn.AsBytes()
		if err != nil {
			return nil, fmt.Errorf("%s element: %w", key, err)
		}
		out = append(out, b)
	}
	return out, nil
}
