package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
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

// buildAAD constructs the Additional Authenticated Data (AAD) for AES-GCM encryption.
// It combines the purpose, cipher suite, recipient hash, nonce, context, and transcript
// into a single string for cryptographic domain separation.
//
// Arguments:
//   - purpose: The intended use of the encryption (consent, revoke, update, or keywrap).
//   - cipherSuite: A string identifier for the cryptographic algorithms used.
//   - recipientHash: A binary hash/identifier for the recipient(s).
//   - nonce: The 12-byte GCM nonce.
//   - contextHash: A hash of the context (chainId, contract address, etc.).
//   - transcriptHash: A hash of the exchange transcript.
//
// Returns:
//   - A byte slice containing the formatted AAD string.
func buildAAD(purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipientHash []byte,
	nonce []byte,
	contextHash []byte,
	transcriptHash []byte,
) []byte {
	aad := fmt.Sprintf("|pulse|%s|v1|%s|rid=%s|ctx=%s|th=%s|nonce=%s|",
		purpose.String(),
		cipherSuite,
		textformat.FormatHex(recipientHash),
		textformat.FormatHex(contextHash),
		textformat.FormatHex(transcriptHash),
		textformat.FormatHex(nonce))

	return []byte(aad)
}

// PulseSealWithNewKey generates a new random AES key and nonce, then seals the plaintext.
// It uses AES-256-GCM and derives a transcript hash from the generated nonce.
//
// Arguments:
//   - entropy: Optional source of randomness (if nil, uses crypto/rand.Reader).
//   - plaintext: The data to be encrypted.
//   - purpose: The intended purpose of the encryption.
//   - cipherSuite: Identifier for the cryptographic suite.
//   - recipient: Identifier/hash of the recipient.
//   - contextHash: Hash of the encryption context.
//
// Returns:
//   - The resulting ciphertext.
//   - The generated 32-byte AES key.
//   - The generated 12-byte nonce.
//   - An error if key generation or encryption fails.
func PulseSealWithNewKey(
	entropy io.Reader,
	plaintext []byte,
	purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipientHash []byte,
	contextHash []byte,
) ([]byte, []byte, []byte, error) {
	aesKey, err := randutil.Bytes(entropy, AESGCMKeySize)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate AES256 key: " + err.Error())
	}
	nonce, err := randutil.Bytes(entropy, AESGCMNonceSize)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate AES256 nonce: " + err.Error())
	}
	transcriptHash := hash.PulseHashBytes(nonce)
	ciphertext, err := PulseSeal(plaintext, aesKey, nonce, purpose, cipherSuite, recipientHash, contextHash, transcriptHash)
	if err != nil {
		return nil, nil, nil, err
	}
	return ciphertext, aesKey, nonce, nil
}

// PulseSeal encrypts the plaintext using AES-256-GCM with the provided key and nonce.
// It incorporates Additional Authenticated Data (AAD) for improved security and domain separation.
//
// Arguments:
//   - plaintext: The data to be encrypted.
//   - aesKey: The 32-byte AES key.
//   - nonce: The 12-byte GCM nonce.
//   - purpose: The intended purpose of the encryption.
//   - cipherSuite: Identifier for the cryptographic suite.
//   - recipient: Identifier/hash of the recipient.
//   - contextHash: Hash of the encryption context.
//   - transcriptHash: Hash of the exchange transcript.
//
// Returns:
//   - The authenticated ciphertext (including the 16-byte GCM tag).
//   - An error if encryption setup fails.
func PulseSeal(
	plaintext []byte,
	aesKey []byte,
	nonce []byte,
	purpose PulseSymmetricPurpose,
	cipherSuite string,
	recipientHash []byte,
	contextHash []byte,
	transcriptHash []byte,
) ([]byte, error) {

	aad := buildAAD(purpose, cipherSuite, recipientHash, nonce, contextHash, transcriptHash)

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

// PulseOpen decrypts and authenticates the ciphertext using AES-256-GCM.
// It verifies that the Additional Authenticated Data (AAD) matches the one used during encryption.
//
// Arguments:
//   - ciphertext: The encrypted data (including the 16-byte GCM tag).
//   - aesKey: The 32-byte AES key.
//   - nonce: The 12-byte GCM nonce.
//   - purpose: The intended purpose of the encryption.
//   - cipherSuite: Identifier for the cryptographic suite.
//   - recipient: Identifier/hash of the recipient.
//   - contextHash: Hash of the encryption context.
//   - transcriptHash: Hash of the exchange transcript.
//
// Returns:
//   - The original plaintext if authentication succeeds.
//   - An error if decryption or authentication fails.
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
