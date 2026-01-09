package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"golang.org/x/crypto/sha3"
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

//TODO: Update known values

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
	PulseSymmetricKeyWrap = 255
)

func (p PulseSymmetricPurpose) String() string {
	switch p {
	case PulseSymmetricConsent:
		return "consent"
	case PulseSymmetricRevoke:
		return "revoke"
	case PulseSymmetricUpdate:
		return "update"
	case PulseSymmetricKeyWrap:
		return "keywrap"
	default:
		panic("unhandled default case")
	}
}

var (
	ErrBadContractAddress = errors.New("contract address must be 40 hex characters")
	ErrNoPlaintext        = errors.New("no plaintext to sealPlaintext")
	ErrNoCiphertext       = errors.New("no ciphertext to sealPlaintext")
	ErrNoKey              = errors.New("missing key for decryption")
	ErrNoContractAddress  = errors.New("no contract address, chainId or purpose")
)

func buildAAD(purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipientHash []byte,
	nonce []byte,
	contextHash []byte,
	transcriptHash []byte,
) []byte {
	aad := fmt.Sprintf("pulse|%s|v1|%s|rid=%s|ctx=%s|th=%s|nonce=%s",
		purpose.String(),
		cipherSuite,
		textformat.FormatHex(recipientHash),
		textformat.FormatHex(contextHash),
		textformat.FormatHex(transcriptHash),
		textformat.FormatHex(nonce))

	return []byte(aad)
}

func PulseSealWithNewKey(
	plaintext []byte,
	purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipient []byte,
	contextHash []byte,
) ([]byte, []byte, []byte, error) {
	aesKey, err := randutil.Bytes(AESGCMKeySize)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate AES256 key: " + err.Error())
	}
	nonce, err := randutil.Bytes(AESGCMNonceSize)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate AES256 nonce: " + err.Error())
	}
	hash := sha3.NewLegacyKeccak256()
	transcriptHash := hash.Sum(nonce)
	ciphertext, err := PulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipient, contextHash, transcriptHash)
	if err != nil {
		return nil, nil, nil, err
	}
	return ciphertext, aesKey, nonce, nil
}

func PulseSeal(
	plaintext []byte,
	aesKey []byte,
	nonce []byte,
	purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipient []byte,
	contextHash []byte,
	transcriptHash []byte,
) ([]byte, error) {

	aad := buildAAD(purpose, cipherSuite, recipient, nonce, contextHash, transcriptHash)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.New("failed to generate AES Cipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to generate GCM Cipher: " + err.Error())
	}

	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func PulseOpen(
	ciphertext []byte,
	aesKey []byte,
	nonce []byte,
	purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipient []byte,
	contextHash []byte,
	transcriptHash []byte,
) ([]byte, error) {
	aad := buildAAD(purpose, cipherSuite, recipient, nonce, contextHash, transcriptHash)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.New("failed to generate AES Cipher: " + err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to generate GCM Cipher: " + err.Error())
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
