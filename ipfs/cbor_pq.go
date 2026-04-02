package ipfs

import (
	"bytes"
	"fmt"

	ipld "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
)

// MarshalConsentPQ encodes a PulsePQEncryptionResult as a DAG-CBOR map:
// {"t":"pq","v":1,"sd":<bytes>,"keys":[{"fp":<bytes32>,"ekk":<bytes>,"edk":<bytes>},...]}
func MarshalConsentPQ(r *pptypes.PulsePQEncryptionResult) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(4)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("pq")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("sd")
	_ = ma.AssembleValue().AssignBytes(r.SealedData)
	_ = ma.AssembleKey().AssignString("keys")
	la, err := ma.AssembleValue().BeginList(int64(len(r.Keys)))
	if err != nil {
		return nil, err
	}
	for _, k := range r.Keys {
		if err := appendPQKey(la, k); err != nil {
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

// UnmarshalConsentPQ decodes a DAG-CBOR block into a PulsePQEncryptionResult.
func UnmarshalConsentPQ(block []byte) (*pptypes.PulsePQEncryptionResult, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding block to IPLD node: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "pq" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected pq structure version: %d", ver)
	}
	sd, err := MustBytes(node, "sd")
	if err != nil {
		return nil, fmt.Errorf("sd: %w", err)
	}
	keys, err := decodePQKeys(node)
	if err != nil {
		return nil, err
	}
	return &pptypes.PulsePQEncryptionResult{SealedData: sd, Keys: keys}, nil
}

// MarshalRevokePQ encodes a RevokeStructureMulti as a DAG-CBOR map:
// {"t":"rev-pq","v":1,"sd":<bytes>,"keys":[...],"gr":<string>}
func MarshalRevokePQ(r *pptypes.RevokeStructureMulti) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(5)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("rev-pq")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("sd")
	_ = ma.AssembleValue().AssignBytes(r.SealedData)
	_ = ma.AssembleKey().AssignString("keys")
	la, err := ma.AssembleValue().BeginList(int64(len(r.Keys)))
	if err != nil {
		return nil, err
	}
	for _, k := range r.Keys {
		if err := appendPQKey(la, k); err != nil {
			return nil, err
		}
	}
	if err := la.Finish(); err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("gr")
	_ = ma.AssembleValue().AssignString(r.Grant)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalRevokePQ decodes a DAG-CBOR block into a RevokeStructureMulti.
func UnmarshalRevokePQ(block []byte) (*pptypes.RevokeStructureMulti, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "rev-pq" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected rev-pq version: %d", ver)
	}
	sd, err := MustBytes(node, "sd")
	if err != nil {
		return nil, fmt.Errorf("sd: %w", err)
	}
	keys, err := decodePQKeys(node)
	if err != nil {
		return nil, err
	}
	gr, err := MustString(node, "gr")
	if err != nil {
		return nil, fmt.Errorf("gr: %w", err)
	}
	return &pptypes.RevokeStructureMulti{
		PulsePQEncryptionResult: pptypes.PulsePQEncryptionResult{SealedData: sd, Keys: keys},
		Grant:                   gr,
	}, nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

// appendPQKey serialises a single PulsePQEncryptionKey into the list assembler.
func appendPQKey(la interface {
	AssembleValue() ipld.NodeAssembler
}, k *pptypes.PulsePQEncryptionKey) error {
	kb := basicnode.Prototype.Map.NewBuilder()
	kma, err := kb.BeginMap(3)
	if err != nil {
		return err
	}
	fp := make([]byte, 32)
	copy(fp, k.KeyFingerPrint[:])
	_ = kma.AssembleKey().AssignString("fp")
	_ = kma.AssembleValue().AssignBytes(fp)
	_ = kma.AssembleKey().AssignString("ekk")
	_ = kma.AssembleValue().AssignBytes(k.EncapsulatedKeyKey)
	_ = kma.AssembleKey().AssignString("edk")
	_ = kma.AssembleValue().AssignBytes(k.EncapsulatedDataKey)
	if err := kma.Finish(); err != nil {
		return err
	}
	return la.AssembleValue().AssignNode(kb.Build())
}

// decodePQKeys reads the "keys" list from an IPLD node.
func decodePQKeys(node ipld.Node) ([]*pptypes.PulsePQEncryptionKey, error) {
	keysNode, err := node.LookupByString("keys")
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	it := keysNode.ListIterator()
	var keys []*pptypes.PulsePQEncryptionKey
	for !it.Done() {
		_, kn, err := it.Next()
		if err != nil {
			return nil, err
		}
		fpBytes, err := MustBytes(kn, "fp")
		if err != nil {
			return nil, fmt.Errorf("fp: %w", err)
		}
		if len(fpBytes) != 32 {
			return nil, fmt.Errorf("fp must be 32 bytes, got %d", len(fpBytes))
		}
		var fp [32]byte
		copy(fp[:], fpBytes)
		ekk, err := MustBytes(kn, "ekk")
		if err != nil {
			return nil, fmt.Errorf("ekk: %w", err)
		}
		edk, err := MustBytes(kn, "edk")
		if err != nil {
			return nil, fmt.Errorf("edk: %w", err)
		}
		keys = append(keys, &pptypes.PulsePQEncryptionKey{
			KeyFingerPrint:      fp,
			EncapsulatedKeyKey:  ekk,
			EncapsulatedDataKey: edk,
		})
	}
	return keys, nil
}
