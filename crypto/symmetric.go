package crypto

import (
	"errors"
)

// This file contains cryptographic functions for symmetric encryption used in the Pulse Protocol.
// We have (strong) opinions about which algorithms to use, and so abstract them away here. The
// protocol mandates using AES-256-GCM for symmetric encryption.
//
// Symmetric encryption is used for two purposes:
// 1. Consent record encryption (by both ECDH and Kyber)
// 2. Consent record AES key encryption (by Kyber only)
//
// This file contains the common functions for both purposes.

//TODO: Reunify?
//TODO: Update known values
//TODO: Review Nonce usage -- should we random it
//TODO: Pack Nonce/Ciphertext together in a struct (CBOR)

const (
	AESGCMKeySize    = 32 // AES-256
	AESGCMNonceSize  = 12 // GCM standard nonce size
	EthAddressLength = 20
)

type PulseSymmetricPurpose byte

const (
	PulseNoSymmetricPurpose PulseSymmetricPurpose = iota
	PulseSymmetricConsent
	PulseSymmetricRevoke
	PulseSymmetricUpdate
)

var (
	ErrBadContractAddress = errors.New("contract address must be 40 hex characters")
	ErrNoPlaintext        = errors.New("no plaintext to sealPlaintext")
	ErrNoCiphertext       = errors.New("no ciphertext to sealPlaintext")
	ErrNoKey              = errors.New("missing key for decryption")
	ErrNoContractAddress  = errors.New("no contract address, chainId or purpose")
)

type PulseSymmetricEncryption struct {
	key        []byte                // AES EncryptionKey used for AES-256-GCM
	hasKey     bool                  // True if key is set
	nonce      [AESGCMNonceSize]byte // Encryption nonce
	plaintext  []byte
	ciphertext []byte
}

// SetEncryptionKey sets the key for the encryption process.
func (e *PulseSymmetricEncryption) SetEncryptionKey(key []byte) *PulseSymmetricEncryption {
	e.key = key
	e.hasKey = true
	return e
}

// EncryptionKey returns the key for the encryption process.
func (e *PulseSymmetricEncryption) EncryptionKey() []byte {
	return e.key
}

// SetCiphertext sets the ciphertext for the decryption process.
func (e *PulseSymmetricEncryption) SetCiphertext(ciphertext []byte) *PulseSymmetricEncryption {
	e.ciphertext = ciphertext
	return e
}

// Ciphertext returns the ciphertext from the encryption process.
func (e *PulseSymmetricEncryption) Ciphertext() []byte {
	return e.ciphertext
}
