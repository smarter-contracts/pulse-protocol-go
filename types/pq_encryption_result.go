package types

import (
	"encoding/json"
	"fmt"
)

// PulsePQEncryptionKey is a struct for holding the encapsulated key for a
// recipient. It combines the encrypted AES key with a fingerprint of the public MLKEMS key used to encrypt it.
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
