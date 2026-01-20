package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
)

// PulsePQEncryptionKey is a struct for holding the encapsulated key for a
// recipient. It combines the encrypted AES key with an fingerprint of the public MLKEMS key used to encrypt it.
type PulsePQEncryptionKey struct {
	KeyFingerPrint      [32]byte `json:"keyFingerPrint"  cbor:"0,keyasint"`     // Hash of public key
	EncapsulatedKeyKey  []byte   `json:"encapsulatedKeyKey" cbor:"1,keyasint"`  // Encapsulated/Encrypted AES EncryptionKey
	EncapsulatedDataKey []byte   `json:"encapsulatedDataKey" cbor:"2,keyasint"` // Encapsulated/Encrypted AES Ciphertext
}

// PulsePQEncryptionResult is a struct for holding the result of an encryption
// operation. It contains the sealed data and the public keys for recipients,
// for embedding in a consent record (Notary) or a Consent/Revoke/Update
// request.
type PulsePQEncryptionResult struct {
	SealedData []byte                  `json:"sealedData" cbor:"0,keyasint"` // Encrypted data
	Keys       []*PulsePQEncryptionKey `json:"keys"       cbor:"1,keyasint"` // Public keys of parties that may be able to decrypt the data
}

func (result *PulsePQEncryptionResult) MarshalCBOR() ([]byte, error) {
	// {"t":"pq","v":1,"sd":bytes,"keys":[{"fp":bytes32,"ekk":bytes,"edk":bytes}, ...]}
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
	_ = ma.AssembleValue().AssignBytes(result.SealedData)

	_ = ma.AssembleKey().AssignString("keys")
	la, err := ma.AssembleValue().BeginList(int64(len(result.Keys)))
	if err != nil {
		return nil, err
	}

	for _, k := range result.Keys {
		// key object: {"fp": <32 bytes>, "ekk": <bytes>, "edk": <bytes>}
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

	if err := ma.Finish(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PulsePQEncryptionResult) UnmarshalCBOR(node ipld.Node) error {
	ty, err := mustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "pq" {
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

		fpBytes, err := mustBytes(kn, "fp")
		if err != nil {
			return fmt.Errorf("fp: %w", err)
		}
		if len(fpBytes) != 32 {
			return fmt.Errorf("fp must be 32 bytes, got %d", len(fpBytes))
		}
		var fp [32]byte
		copy(fp[:], fpBytes)

		ekk, err := mustBytes(kn, "ekk")
		if err != nil {
			return fmt.Errorf("ekk: %w", err)
		}
		edk, err := mustBytes(kn, "edk")
		if err != nil {
			return fmt.Errorf("edk: %w", err)
		}

		keys = append(keys, &PulsePQEncryptionKey{
			KeyFingerPrint:      fp,
			EncapsulatedKeyKey:  ekk,
			EncapsulatedDataKey: edk,
		})
	}

	p.SealedData = sd
	p.Keys = keys
	return nil
}

func (p *PulsePQEncryptionResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(p)
}

func (p *PulsePQEncryptionResult) UnmarshalJSON(bytes []byte) error {
	return json.Unmarshal(bytes, p)
}
