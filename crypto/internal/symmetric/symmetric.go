package symmetric

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
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
	PulseSymmetricKeyWrap = 255
)

var (
	ErrBadContractAddress = errors.New("contract address must be 40 hex characters")
	ErrNoPlaintext        = errors.New("no plaintext to sealPlaintext")
	ErrNoCiphertext       = errors.New("no ciphertext to sealPlaintext")
	ErrNoKey              = errors.New("missing key for decryption")
	ErrNoContractAddress  = errors.New("no contract address, chainId or purpose")
)

type PulseSymmetricEncryption struct {
	key                   []byte                // AES EncryptionKey used for AES-256-GCM
	hasKey                bool                  // True if key is set
	nonce                 [AESGCMNonceSize]byte // Encryption nonce
	plaintext             []byte
	ciphertext            []byte
	purpose               PulseSymmetricPurpose // consent, revoke, update, for nonce generation
	contractAddressString *string
	contractAddress       *[EthAddressLength]byte // For deterministic nonce generation
	chainId               byte                    // For deterministic nonce generation
}

func buildAAD(purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipient []byte,
	nonce []byte,
	context []byte,
) []byte {
	aadBuf := bytes.Buffer{}
	aadBuf.WriteString("pulse|")
	switch purpose {
	case PulseSymmetricConsent:
		aadBuf.WriteString("consent|")
	case PulseSymmetricRevoke:
		aadBuf.WriteString("revoke|")
	case PulseSymmetricUpdate:
		aadBuf.WriteString("update|")
	case PulseSymmetricKeyWrap:
		aadBuf.WriteString("keywrap|")
	}
	aadBuf.WriteString("v1|")
	aadBuf.WriteString(cipherSuite)
	aadBuf.WriteString("|")
	aadBuf.WriteString(hex.EncodeToString(recipient))
	aadBuf.WriteString("|")
	aadBuf.WriteString(hex.EncodeToString(nonce))
	aadBuf.WriteString("|")
	aadBuf.WriteString(hex.EncodeToString(context))
	aadBuf.WriteString("|")

	return aadBuf.Bytes()
}

func PulseSealWithNewKey(
	plaintext []byte,
	purpose PulseSymmetricPurpose,
	recipient []byte,
	context []byte,
) ([]byte, []byte, []byte, error) {
	aesKey, err := randutil.Bytes(AESGCMKeySize)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate AES256 key: " + err.Error())
	}
	nonce, err := randutil.Bytes(AESGCMNonceSize)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate AES256 nonce: " + err.Error())
	}
	ciphertext, err := PulseSeal(plaintext, aesKey, nonce, purpose, recipient, context)
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
	recipient []byte,
	context []byte,
) ([]byte, error) {

	aad := buildAAD(purpose, "aes-gcm", recipient, nonce, context)

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
	recipient []byte,
	context []byte) ([]byte, error) {
	aad := buildAAD(purpose, "aes-gcm", recipient, nonce, context)

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
