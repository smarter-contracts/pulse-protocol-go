package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

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

// ── RevokeStructure — DAG-CBOR ────────────────────────────────────────────────────────

// MarshalCBOR encodes the revoke structure as a DAG-CBOR map.
func (r *RevokeStructure) MarshalCBOR() ([]byte, error) {
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

// UnmarshalCBOR decodes a DAG-CBOR block into the revoke structure.
func (r *RevokeStructure) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "rev-ec" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}

	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected rev-ec version: %d", ver)
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
	gr, err := ipfs.MustString(node, "gr")
	if err != nil {
		return fmt.Errorf("gr: %w", err)
	}

	r.SealedData = sd
	r.Key1 = k1
	r.Key2 = k2
	r.Grant = gr
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

// ── RevokeStructureMulti — DAG-CBOR ──────────────────────────────────────────────────

// MarshalCBOR encodes the multi-party revoke structure as a DAG-CBOR map.
func (r *RevokeStructureMulti) MarshalCBOR() ([]byte, error) {
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
		kb := basicnode.Prototype.Map.NewBuilder()
		kma, err := kb.BeginMap(3)
		if err != nil {
			return nil, err
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
			return nil, err
		}
		if err := la.AssembleValue().AssignNode(kb.Build()); err != nil {
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

// UnmarshalCBOR decodes a DAG-CBOR block into the multi-party revoke structure.
func (r *RevokeStructureMulti) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "rev-pq" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}

	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected rev-pq version: %d", ver)
	}

	sd, err := ipfs.MustBytes(node, "sd")
	if err != nil {
		return fmt.Errorf("sd: %w", err)
	}

	keysNode, err := node.LookupByString("keys")
	if err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	it := keysNode.ListIterator()
	var keys []*PulsePQEncryptionKey
	for !it.Done() {
		_, kn, err := it.Next()
		if err != nil {
			return err
		}
		fpBytes, err := ipfs.MustBytes(kn, "fp")
		if err != nil {
			return fmt.Errorf("fp: %w", err)
		}
		if len(fpBytes) != 32 {
			return fmt.Errorf("fp must be 32 bytes, got %d", len(fpBytes))
		}
		var fp [32]byte
		copy(fp[:], fpBytes)
		ekk, err := ipfs.MustBytes(kn, "ekk")
		if err != nil {
			return fmt.Errorf("ekk: %w", err)
		}
		edk, err := ipfs.MustBytes(kn, "edk")
		if err != nil {
			return fmt.Errorf("edk: %w", err)
		}
		keys = append(keys, &PulsePQEncryptionKey{
			KeyFingerPrint:      fp,
			EncapsulatedKeyKey:  ekk,
			EncapsulatedDataKey: edk,
		})
	}

	gr, err := ipfs.MustString(node, "gr")
	if err != nil {
		return fmt.Errorf("gr: %w", err)
	}

	r.SealedData = sd
	r.Keys = keys
	r.Grant = gr
	return nil
}
