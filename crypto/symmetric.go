package crypto

// This file contains cryptographic functions for symmetric encryption used in the Pulse Protocol.
// We have (strong) opinions about which algorithms to use, and so abstract them away here. The
// protocol mandates using AES-256-GCM for symmetric encryption.
//
// There are two encryption functions specified: essentially with a key specified, or without. The
// use depends on whether the higher level key exchange is ECDH (key specified by the ECDH exchange)
// or Kyber (ephemeral key encapsulation). Decryption is the same either way, and you'll need a key.
//
// In addition to the Encrypt/Decrypt functions, there are helper functions to serialise the results
// to strings suitable for transmission over the wire.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
)

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

// PulseSymmetricNonce represents a nonce used for symmetric encryption.
// It's defined as a 12 byte array to match GCM requirements.'
//type PulseSymmetricNonce [AESGCMNonceSize]byte

// A Fixed base nonce that we derive the encryption nonce from.
var PulseAESBaseNonce = []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78}

// PulseSymmetricEncryption is a struct used to encapsulate the symmetric encryption process for the Pulse Protocol.
// The object is opaque to the user, with all fields manipulated by function calls.
//
// Internally, the struct wraps around an AEAD cipher ( AES-256-GCM ). Encryption can be performed in two ways:
// 1. With a key specified by the user (ECDH exchange)
// 2. With an ephemeral key (Kyber)
//
// The Nonce is generated deterministically using the contract address, chainId and purpose. We set AAD for the
// algorithm to be the nonce.
type PulseSymmetricEncryption struct {
	key                   []byte // key for AES-256-GCM
	hasKey                bool
	nonce                 [AESGCMNonceSize]byte // nonce for GCM
	purpose               PulseSymmetricPurpose // consent, revoke, update, for nonce generation
	plaintext             []byte
	ciphertext            []byte
	contractAddressString *string
	contractAddress       *[EthAddressLength]byte // For nonce generation
	chainId               byte                    // For nonce generation
}

// NewPulseSymmetricEncryption creates a new PulseSymmetricEncryption object with no fields
// set
func NewPulseSymmetricEncryption() *PulseSymmetricEncryption {
	return &PulseSymmetricEncryption{
		purpose: PulseNoSymmetricPurpose,
	}
}

// SetKey sets the key for the encryption process.
func (e *PulseSymmetricEncryption) SetKey(key []byte) *PulseSymmetricEncryption {
	e.key = key
	e.hasKey = true
	return e
}

// Key returns the key for the encryption process.
func (e *PulseSymmetricEncryption) Key() []byte {
	return e.key
}

// SetChainId sets the chain ID for the encryption process.
func (e *PulseSymmetricEncryption) SetChainId(chainId byte) *PulseSymmetricEncryption {
	e.chainId = chainId
	return e
}

// SetContractAddress sets the contract address for the encryption process.
// The contract address should be a 40 character hex string.
func (e *PulseSymmetricEncryption) SetContractAddress(contractAddress *string) *PulseSymmetricEncryption {
	e.contractAddressString = contractAddress
	return e
}

func (e *PulseSymmetricEncryption) decodeContractAddress() error {
	*e.contractAddressString = strings.TrimPrefix(*e.contractAddressString, "0x")
	if hex.DecodedLen(len(*e.contractAddressString)) != EthAddressLength {
		return ErrBadContractAddress
	}
	dstContractAddress := make([]byte, EthAddressLength)
	decode, err := hex.Decode(dstContractAddress, []byte(*e.contractAddressString))
	if err != nil || decode != EthAddressLength {
		return errors.New("failed to decode contract address ")
	}
	e.contractAddress = (*[EthAddressLength]byte)(dstContractAddress)
	return nil
}

// generateNonce deterministically generates the nonce for the encryption process.
//
// Algorithm:
//
//	Start with the fixed base nonce
//	XOR the first 12 bytes of the contract address
//	XOR the last 8 bytes of the contract address with the first 8 bytes
//	XOR chainId with byte 8
//	XOR purpose with byte 9
func (e *PulseSymmetricEncryption) generateNonce() {
	fmt.Printf("Contract Address: %x\n", e.contractAddress)
	leftContractAddress := e.contractAddress[:AESGCMNonceSize]
	rightContractAddress := e.contractAddress[AESGCMNonceSize:]

	for j := range e.nonce {
		e.nonce[j] = PulseAESBaseNonce[j] ^ leftContractAddress[j]
		if j < len(rightContractAddress) {
			e.nonce[j] ^= rightContractAddress[j]
		}
		if j == 8 {
			e.nonce[j] ^= e.chainId
		}
		if j == 9 {
			e.nonce[j] ^= byte(e.purpose)
		}
	}
}

// SetPlaintext sets the plaintext for the encryption process.
func (e *PulseSymmetricEncryption) SetPlaintext(plaintext []byte) *PulseSymmetricEncryption {
	e.plaintext = plaintext
	return e
}

// Plaintext returns the plaintext from the decryption process.
func (e *PulseSymmetricEncryption) Plaintext() []byte {
	return e.plaintext
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

// SetPurpose sets the purpose for the encryption process.
func (e *PulseSymmetricEncryption) SetPurpose(purpose PulseSymmetricPurpose) *PulseSymmetricEncryption {
	e.purpose = purpose
	return e
}

// SealPlaintext encrypts the plaintext using AES-256-GCM
//
//		The following fields must be set:
//		  - ContractAddress
//		  - ChainId
//		  - Plaintext
//	   - Purpose
//
//		The following things are optional:
//		  - Key
//
// If key is not set, a random new key will be generated.
//
// For the AES-GCM encryption we have:
//   - plaintext : user supplied
//   - key: user supplied or generated
//   - nonce: deterministically generated using contract address, chainId and purpose
//   - associated data: nonce
//
// Encrypted data is returned in Ciphertext(). Key() will return the generated key.
func (e *PulseSymmetricEncryption) SealPlaintext() error {
	if e.plaintext == nil || len(e.plaintext) == 0 {
		return ErrNoPlaintext
	}
	if e.contractAddressString == nil ||
		*e.contractAddressString == "" ||
		e.purpose == PulseNoSymmetricPurpose ||
		e.chainId == 0 {
		return ErrNoContractAddress
	}
	if err := e.decodeContractAddress(); err != nil {
		return errors.New("failed to decode contract address: " + err.Error())
	}

	if !e.hasKey {
		err := e.generateAES256Key()
		if err != nil {
			return errors.New("failed to generate AES256 key: " + err.Error())
		}
	}

	e.generateNonce()

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return errors.New("failed to generate AES Cipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("failed to generate GCM Cipher: " + err.Error())
	}

	e.ciphertext = gcm.Seal(nil, e.nonce[:], e.plaintext, e.nonce[:])

	return nil
}

// OpenCiphertext decrypts the ciphertext using AES-256-GCM
//
//		The following fields must be set:
//		  - ContractAddress
//		  - ChainId
//		  - Plaintext
//	   - Purpose
//	   - Key
//
// For the AES-GCM encryption we have:
//   - ciphertext : user supplied
//   - key: user supplied
//   - nonce: deterministically generated using contract address, chainId and purpose, must match encryption values
//   - associated data: nonce
//
// Encrypted data is returned in Plaintext().
func (e *PulseSymmetricEncryption) OpenCiphertext() error {
	if e.ciphertext == nil || len(e.ciphertext) == 0 {
		return ErrNoCiphertext
	}
	if e.contractAddressString == nil ||
		*e.contractAddressString == "" ||
		e.purpose == PulseNoSymmetricPurpose ||
		e.chainId == 0 {
		return ErrNoContractAddress
	}
	if err := e.decodeContractAddress(); err != nil {
		return errors.New("failed to decode contract address: " + err.Error())
	}
	if e.key == nil {
		return ErrNoKey
	}

	e.generateNonce()

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return errors.New("failed to generate AES Cipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("failed to generate GCM Cipher: " + err.Error())
	}

	e.plaintext, err = gcm.Open(nil, e.nonce[:], e.ciphertext, e.nonce[:])

	return err
}

func (e *PulseSymmetricEncryption) generateAES256Key() error {
	key, err := randutil.Bytes(AESGCMKeySize)
	e.key = key
	e.hasKey = true
	return err
}
