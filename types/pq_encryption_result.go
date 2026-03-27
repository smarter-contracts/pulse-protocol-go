package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
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

// MarshalCBOR encodes the PQ encryption result as a DAG-CBOR map:
// {"t":"pq","v":1,"sd":<bytes>,"keys":[{"fp":<bytes32>,"ekk":<bytes>,"edk":<bytes>}, ...]}.
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

// UnmarshalCBOR decodes a DAG-CBOR block into the PQ encryption result.
func (p *PulsePQEncryptionResult) UnmarshalCBOR(block []byte) error {
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
	if ty != "pq" {
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

	p.SealedData = sd
	p.Keys = keys
	return nil
}

// MarshalJSON implements json.Marshaler for PulsePQEncryptionResult.
func (p *PulsePQEncryptionResult) MarshalJSON() ([]byte, error) {
	type Alias PulsePQEncryptionResult
	return json.Marshal((*Alias)(p))
}

// UnmarshalJSON implements json.Unmarshaler for PulsePQEncryptionResult.
func (p *PulsePQEncryptionResult) UnmarshalJSON(bytes []byte) error {
	type Alias PulsePQEncryptionResult
	return json.Unmarshal(bytes, (*Alias)(p))
}

// ── PulsePQEncryptionKey — JSON ───────────────────────────────────────────────

// MarshalJSON implements json.Marshaler, encoding KeyFingerPrint as a base64
// string (matching []byte behaviour) rather than Go's default int-array encoding
// for fixed-size arrays.
func (k *PulsePQEncryptionKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		KeyFingerPrint      []byte `json:"keyFingerPrint"`
		EncapsulatedKeyKey  []byte `json:"encapsulatedKeyKey"`
		EncapsulatedDataKey []byte `json:"encapsulatedDataKey"`
	}{
		KeyFingerPrint:      k.KeyFingerPrint[:],
		EncapsulatedKeyKey:  k.EncapsulatedKeyKey,
		EncapsulatedDataKey: k.EncapsulatedDataKey,
	})
}

// UnmarshalJSON implements json.Unmarshaler, decoding a base64-encoded
// keyFingerPrint into the fixed-size [32]byte field.
func (k *PulsePQEncryptionKey) UnmarshalJSON(data []byte) error {
	var v struct {
		KeyFingerPrint      []byte `json:"keyFingerPrint"`
		EncapsulatedKeyKey  []byte `json:"encapsulatedKeyKey"`
		EncapsulatedDataKey []byte `json:"encapsulatedDataKey"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if len(v.KeyFingerPrint) != 32 {
		return fmt.Errorf("keyFingerPrint must be 32 bytes, got %d", len(v.KeyFingerPrint))
	}
	copy(k.KeyFingerPrint[:], v.KeyFingerPrint)
	k.EncapsulatedKeyKey = v.EncapsulatedKeyKey
	k.EncapsulatedDataKey = v.EncapsulatedDataKey
	return nil
}
