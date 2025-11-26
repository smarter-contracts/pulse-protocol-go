package crypto

// This file contains cryptographic functions for symmetric encryption used in the Pulse Protocol.
// We have (strong) opinions about which algorithms to use, and so abstract them away here. The
// protocol mandates using AES-256-GCM for symmetric encryption.
//
// This file contains the code for encrypting and decrypting other AES keys, and is used by the Kyber
// key encapsulation mechanism in a two stage AES encryption process.
// EncryptionKey features:
//
//  - Random nonce generation ( except for internal known value testing )
//  - Associated Data = "key-wrap" || recipientID || contractAddress || chainId || purpose
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

// PulseSymmetricKeyEncryption is a struct used to encapsulate the symmetric encryption process for the Pulse Protocol.
// The object is opaque to the user, with all fields manipulated by function calls.
//
// This class is used for encrypting/decrypting another AES key, and is used by the Kyber key encapsultation
// mechanism in a two stage AES encryption process.
//
// The nonce is random, but the AAD is based on an identifier for the recipient.
type PulseSymmetricKeyEncryption struct {
	PulseSymmetricEncryption
	purpose               PulseSymmetricPurpose // consent, revoke, update, for nonce generation
	contractAddressString *string
	contractAddress       *[EthAddressLength]byte // For deterministic nonce generation
	chainId               byte                    // For deterministic nonce generation
}

// NewPulseSymmetricEncryption creates a new PulseSymmetricConsentEncryption object with no fields
// set
func NewPulseSymmetricKeyEncryption() *PulseSymmetricConsentEncryption {
	return &PulseSymmetricConsentEncryption{
		purpose: PulseNoSymmetricPurpose,
	}
}

func (e *PulseSymmetricKeyEncryption) SetEncryptionKey(key []byte) *PulseSymmetricKeyEncryption {
	e.PulseSymmetricEncryption.SetEncryptionKey(key)
	return e
}

func (e *PulseSymmetricKeyEncryption) SetCiphertext(key []byte) *PulseSymmetricKeyEncryption {
	e.PulseSymmetricEncryption.SetCiphertext(key)
	return e
}

// SetChainId sets the chain ID for the encryption process.
func (e *PulseSymmetricKeyEncryption) SetChainId(chainId byte) *PulseSymmetricKeyEncryption {
	e.chainId = chainId
	return e
}

// SetContractAddress sets the contract address for the encryption process.
// The contract address should be a 40 character hex string.
func (e *PulseSymmetricKeyEncryption) SetContractAddress(contractAddress *string) *PulseSymmetricKeyEncryption {
	e.contractAddressString = contractAddress
	return e
}

func (e *PulseSymmetricKeyEncryption) decodeContractAddress() error {
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
func (e *PulseSymmetricKeyEncryption) generateNonce() {
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
func (e *PulseSymmetricKeyEncryption) SetPlaintext(plaintext []byte) *PulseSymmetricKeyEncryption {
	e.plaintext = plaintext
	return e
}

// Plaintext returns the plaintext from the decryption process.
func (e *PulseSymmetricKeyEncryption) Plaintext() []byte {
	return e.plaintext
}

// SetPurpose sets the purpose for the encryption process.
func (e *PulseSymmetricKeyEncryption) SetPurpose(purpose PulseSymmetricPurpose) *PulseSymmetricKeyEncryption {
	e.purpose = purpose
	return e
}

// WrapAESKey encrypts the plaintext using AES-256-GCM
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
func (e *PulseSymmetricConsentEncryption) WrapAESKey() error {
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

// UnwrapAESKey decrypts the ciphertext using AES-256-GCM
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
func (e *PulseSymmetricConsentEncryption) UnwrapAESKey() error {
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

func (e *PulseSymmetricKeyEncryption) generateAES256Key() error {
	key, err := randutil.Bytes(AESGCMKeySize)
	e.key = key
	e.hasKey = true
	return err
}

func (e *PulseSymmetricKeyEncryption) generateRandomNonce() error {
	nonce, err := randutil.Bytes(AESGCMNonceSize)
	e.nonce = [AESGCMNonceSize]byte(nonce)
	return err
}
