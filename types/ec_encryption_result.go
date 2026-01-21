package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
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

func (p *PulseECEncryptionResult) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	err := dagcbor.Decode(na, bytes.NewReader(block))
	if err != nil {
		return fmt.Errorf("decoding block to IPLD node: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "ec" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected ec structure version: %d", ver)
	}

	sd, err := ipfs.MustBytes(node, "sd")
	if err != nil {
		return fmt.Errorf("sd: %w", err)
	}
	k1, err := ipfs.MustBytes(node, "k1")
	if err != nil {
		return fmt.Errorf("k1: %w", err)
	}
	k2, err := ipfs.MustBytes(node, "k2")
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
