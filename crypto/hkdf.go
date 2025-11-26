package crypto

import (
	"errors"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// TODO: Handle Seed values
// TODO: Handle Info values
// TODO: Test pack
// TODO: Known Value Test pack

// PulseHKDF provides a Hash Key Derivation Function (HKDF). We use an RFC 5869 HKDF, with the following parameters:
//
// Hash Algorithm: keccak256 (consistent with the rest of the Pulse Protocol)
// Seed: nil (translates to all 0 bytes)
// Info:
//
// The algorithm output is a 32-byte AES-256 key.
type PulseHKDF struct {
	sharedSecret []byte
	generatedKey []byte
}

// NewPulseHKDF creates a new HKDF instance.
func NewPulseHKDF() *PulseHKDF {
	return &PulseHKDF{}
}

// SetSharedSecret sets the shared secret to be used in the HKDF.
func (h *PulseHKDF) SetSharedSecret(sharedSecret []byte) *PulseHKDF {
	h.sharedSecret = sharedSecret
	return h
}

// GeneratedKey returns the generated key.
func (h *PulseHKDF) GeneratedKey() []byte {
	return h.generatedKey
}

// DeriveKey derives a new key from the shared secret.
func (h *PulseHKDF) DeriveKey() error {
	if err := h.validateHKDF(); err != nil {
		return err
	}

	keyReader := hkdf.New(sha3.NewLegacyKeccak256, h.sharedSecret, nil, nil)
	newKey := make([]byte, AESGCMKeySize)

	if _, err := keyReader.Read(newKey); err != nil {
		return err
	}
	h.generatedKey = newKey
	return nil
}

func (h *PulseHKDF) validateHKDF() error {
	if h.sharedSecret == nil {
		return errors.New("shared secret must be set")
	}
	return nil
}
