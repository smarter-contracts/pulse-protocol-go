package crypto

// This file contains cryptographic functions for symmetric encryption used in the Pulse Protocol.
// We have (strong) opinions about which algorithms to use, and so abstract them away here. The
// protocol mandates using AES-256-GCM for symmetric encryption.
//
// This file contains the code for encrypting and decrypting data (consent, revoke & notary records)
// using AES-256-GCM. EncryptionKey features:
//
//  - Deterministic nonce generation ( based on a fixed base, contract address, chainId and purpose )
//  - Associated Data = nonce
//  - AES EncryptionKey is optional -- we generate a random one if not specified ( for Kyber )
//
// In addition to the Encrypt/Decrypt functions, there are helper functions to serialise the results
// to strings suitable for transmission over the wire.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
)

// PulseAESBaseNonce is a fixed base nonce that we derive the encryption nonce from.
var PulseAESBaseNonce = []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78}

// PulseSymmetricConsentEncryption is a struct used to encapsulate the symmetric encryption process for the Pulse Protocol.
// The object is opaque to the user, with all fields manipulated by function calls.
//
// Internally, the struct wraps around an AEAD cipher ( AES-256-GCM ). Encryption can be performed in two ways:
// 1. With a key specified by the user (ECDH exchange)
// 2. With an ephemeral key (Kyber)
//
// Within the protocol, we may use two levels of AES Encryption:
//  1. Encryption of the consent record ( used by both EC and PQ key exchange )
//  2. Encryption of the consent record AES EncryptionKey ( used by PQ key exchange only )
//
// The key is generated randomly if not specified by the user.
//
// For the consent record, the nonce is generated deterministically using the contract address, chainId and purpose. We set AAD for the
// algorithm to be the nonce.
type PulseSymmetricConsentEncryption struct {
	PulseSymmetricEncryption
	purpose               PulseSymmetricPurpose // consent, revoke, update, for nonce generation
	contractAddressString *string
	contractAddress       *[EthAddressLength]byte // For deterministic nonce generation
	chainId               byte                    // For deterministic nonce generation
}

// NewPulseSymmetricEncryption creates a new PulseSymmetricConsentEncryption object with no fields
// set
func NewPulseSymmetricEncryption() *PulseSymmetricConsentEncryption {
	return &PulseSymmetricConsentEncryption{
		purpose: PulseNoSymmetricPurpose,
	}
}

func (e *PulseSymmetricConsentEncryption) SetEncryptionKey(key []byte) *PulseSymmetricConsentEncryption {
	e.PulseSymmetricEncryption.SetEncryptionKey(key)
	return e
}

func (e *PulseSymmetricConsentEncryption) SetCiphertext(key []byte) *PulseSymmetricConsentEncryption {
	e.PulseSymmetricEncryption.SetCiphertext(key)
	return e
}

// SetChainId sets the chain ID for the encryption process.
func (e *PulseSymmetricConsentEncryption) SetChainId(chainId byte) *PulseSymmetricConsentEncryption {
	e.chainId = chainId
	return e
}

// SetContractAddress sets the contract address for the encryption process.
// The contract address should be a 40 character hex string.
func (e *PulseSymmetricConsentEncryption) SetContractAddress(contractAddress *string) *PulseSymmetricConsentEncryption {
	e.contractAddressString = contractAddress
	return e
}

func (e *PulseSymmetricConsentEncryption) decodeContractAddress() error {
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
func (e *PulseSymmetricConsentEncryption) generateNonce() {
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
func (e *PulseSymmetricConsentEncryption) SetPlaintext(plaintext []byte) *PulseSymmetricConsentEncryption {
	e.plaintext = plaintext
	return e
}

// Plaintext returns the plaintext from the decryption process.
func (e *PulseSymmetricConsentEncryption) Plaintext() []byte {
	return e.plaintext
}

// SetPurpose sets the purpose for the encryption process.
func (e *PulseSymmetricConsentEncryption) SetPurpose(purpose PulseSymmetricPurpose) *PulseSymmetricConsentEncryption {
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
//		  - EncryptionKey
//
// If key is not set, a random new key will be generated.
//
// For the AES-GCM encryption we have:
//   - plaintext : user supplied
//   - key: user supplied or generated
//   - nonce: deterministically generated using contract address, chainId and purpose
//   - associated data: nonce
//
// Encrypted data is returned in Ciphertext(). EncryptionKey() will return the generated key.
func (e *PulseSymmetricConsentEncryption) SealPlaintext() error {
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
//	   - EncryptionKey
//
// For the AES-GCM encryption we have:
//   - ciphertext : user supplied
//   - key: user supplied
//   - nonce: deterministically generated using contract address, chainId and purpose, must match encryption values
//   - associated data: nonce
//
// Encrypted data is returned in Plaintext().
func (e *PulseSymmetricConsentEncryption) OpenCiphertext() error {
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

func (e *PulseSymmetricConsentEncryption) generateAES256Key() error {
	key, err := randutil.Bytes(AESGCMKeySize)
	e.key = key
	e.hasKey = true
	return err
}
