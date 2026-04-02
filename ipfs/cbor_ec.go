package ipfs

import (
	"bytes"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
)

// MarshalConsentEC encodes a PulseECEncryptionResult as a DAG-CBOR map:
// {"t":"ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>}
func MarshalConsentEC(r *pptypes.PulseECEncryptionResult) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(5)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("ec")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("sd")
	_ = ma.AssembleValue().AssignBytes(r.SealedData)
	_ = ma.AssembleKey().AssignString("k1")
	_ = ma.AssembleValue().AssignBytes(r.Key1)
	_ = ma.AssembleKey().AssignString("k2")
	_ = ma.AssembleValue().AssignBytes(r.Key2)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalConsentEC decodes a DAG-CBOR block into a PulseECEncryptionResult.
func UnmarshalConsentEC(block []byte) (*pptypes.PulseECEncryptionResult, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding block to IPLD node: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "ec" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected ec structure version: %d", ver)
	}
	sd, err := MustBytes(node, "sd")
	if err != nil {
		return nil, fmt.Errorf("sd: %w", err)
	}
	k1, err := MustBytes(node, "k1")
	if err != nil {
		return nil, fmt.Errorf("k1: %w", err)
	}
	k2, err := MustBytes(node, "k2")
	if err != nil {
		return nil, fmt.Errorf("k2: %w", err)
	}
	return &pptypes.PulseECEncryptionResult{SealedData: sd, Key1: k1, Key2: k2}, nil
}

// MarshalRevokeEC encodes a RevokeStructure as a DAG-CBOR map:
// {"t":"rev-ec","v":1,"sd":<bytes>,"k1":<bytes>,"k2":<bytes>,"gr":<string>}
func MarshalRevokeEC(r *pptypes.RevokeStructure) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(6)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("rev-ec")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("sd")
	_ = ma.AssembleValue().AssignBytes(r.SealedData)
	_ = ma.AssembleKey().AssignString("k1")
	_ = ma.AssembleValue().AssignBytes(r.Key1)
	_ = ma.AssembleKey().AssignString("k2")
	_ = ma.AssembleValue().AssignBytes(r.Key2)
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

// UnmarshalRevokeEC decodes a DAG-CBOR block into a RevokeStructure.
func UnmarshalRevokeEC(block []byte) (*pptypes.RevokeStructure, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "rev-ec" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected rev-ec version: %d", ver)
	}
	sd, err := MustBytes(node, "sd")
	if err != nil {
		return nil, fmt.Errorf("sd: %w", err)
	}
	k1, err := MustBytes(node, "k1")
	if err != nil {
		return nil, fmt.Errorf("k1: %w", err)
	}
	k2, err := MustBytes(node, "k2")
	if err != nil {
		return nil, fmt.Errorf("k2: %w", err)
	}
	gr, err := MustString(node, "gr")
	if err != nil {
		return nil, fmt.Errorf("gr: %w", err)
	}
	return &pptypes.RevokeStructure{
		PulseECEncryptionResult: pptypes.PulseECEncryptionResult{SealedData: sd, Key1: k1, Key2: k2},
		Grant:                   gr,
	}, nil
}
