package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
)

// PulseECEncryptionResult is a struct for holding the result of an encryption
// operation. It contains the sealed data, the two public keys involved in the
// exchange, for embedding in a consent record (Notary) or a Consent/Revoke/Update
// request.
type PulseECEncryptionResult struct {
	SealedData []byte `json:"sealedData"` // Encrypted data
	Key1       []byte `json:"key1"      ` // My public key, 33-byte compressed format
	Key2       []byte `json:"key2"      ` // Public key of the other party, 33-byte compressed format
}

func (result *PulseECEncryptionResult) MarshalCBOR() ([]byte, error) {
	// {"t":"ec","v":1,"sd":bytes,"k1":bytes,"k2":bytes}
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
	_ = ma.AssembleValue().AssignBytes(result.SealedData)

	_ = ma.AssembleKey().AssignString("k1")
	_ = ma.AssembleValue().AssignBytes(result.Key1)

	_ = ma.AssembleKey().AssignString("k2")
	_ = ma.AssembleValue().AssignBytes(result.Key2)

	if err := ma.Finish(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mustBytes(n ipld.Node, key string) ([]byte, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return nil, err
	}
	return v.AsBytes()
}

func mustString(n ipld.Node, key string) (string, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return "", err
	}
	return v.AsString()
}

func mustInt(n ipld.Node, key string) (int64, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return 0, err
	}
	return v.AsInt()
}

func (p *PulseECEncryptionResult) UnmarshalCBOR(node ipld.Node) error {
	ty, err := mustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "ec" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := mustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected ec structure version: %d", ver)
	}

	sd, err := mustBytes(node, "sd")
	if err != nil {
		return fmt.Errorf("sd: %w", err)
	}
	k1, err := mustBytes(node, "k1")
	if err != nil {
		return fmt.Errorf("k1: %w", err)
	}
	k2, err := mustBytes(node, "k2")
	if err != nil {
		return fmt.Errorf("k2: %w", err)
	}
	p.SealedData = sd
	p.Key2 = k2
	p.Key1 = k1
	return nil
}

func (p *PulseECEncryptionResult) MarshalJSON() ([]byte, error) {
	type Alias PulseECEncryptionResult
	return json.Marshal((*Alias)(p))
}

func (p *PulseECEncryptionResult) UnmarshalJSON(bytes []byte) error {
	type Alias PulseECEncryptionResult
	return json.Unmarshal(bytes, (*Alias)(p))
}
