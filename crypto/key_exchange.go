package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/wipe"
	"golang.org/x/crypto/sha3"
)

//TODO: Update known values testpack
//TODO: Review test pack coverage

// PulseECEncryptionResult is a struct for holding the result of an encryption
// operation. It contains the sealed data, the two public keys involved in the
// exchange, for embedding in a consent record (Notary) or a Consent/Revoke/Update
// request.
type PulseECEncryptionResult struct {
	_          struct{} `json:"-"          cbor:",toarray"`   // Enable CBOR array encoding for this type.
	SealedData []byte   `json:"sealedData" cbor:"0,keyasint"` // Encrypted data
	Key1       []byte   `json:"key1"       cbor:"1,keyasint"` // My public key, 33-byte compressed format
	Key2       []byte   `json:"key2"       cbor:"2,keyasint"` // Public key of the other party, 33-byte compressed format
}

var ECDHCipherSuite = "ecdh-secp256k1+hkdf-keccak256+aes-gcm-256"

// EncryptECDH performs a hybrid encryption using Elliptic Curve Diffie-Hellman (ECDH).
// It derives a shared secret using SECP256K1, generates an AES-256 key via HKDF,
// and seals the plaintext using AES-GCM.
//
// Arguments:
//   - plaintext: The data to be encrypted.
//   - contractAddress: Pointer to the contract address hex string.
//   - myPrivateKey: The sender's SECP256K1 private key.
//   - otherPublicKey: The recipient's SECP256K1 public key.
//   - purpose: The intended purpose for the encryption (e.g., PulseSymmetricConsent).
//   - chainId: The blockchain network identifier.
//   - consentNumber: The sequence number for the consent record.
//
// Returns:
//   - A PulseECEncryptionResult containing the ciphertext and involved public keys.
//   - An error if encryption setup or execution fails.
func EncryptECDH(plaintext []byte,
	contractAddress *string,
	myPrivateKey *secp.PrivateKey,
	otherPublicKey *secp.PublicKey,
	purpose symmetric.PulseSymmetricPurpose,
	chainId int32,
	consentNumber int32,
) (*PulseECEncryptionResult, error) {
	if myPrivateKey == nil || otherPublicKey == nil {
		return nil, errors.New("must provide both private and public keys to encrypt")
	}
	contextHash := context.ContextHash(chainId, *contractAddress, consentNumber)
	transcriptHash := generateTranscriptHash(textformat.FormatHex(myPrivateKey.PubKey().SerializeCompressed()),
		textformat.FormatHex(otherPublicKey.SerializeCompressed()))
	aesKey, nonce, err := generateAESKey(myPrivateKey, otherPublicKey, transcriptHash, contextHash)
	defer wipe.SliceWipe(aesKey)
	defer wipe.SliceWipe(nonce)
	if err != nil {
		return nil, errors.New("Failed to generate aes key and nonce: " + err.Error())
	}

	ciphertext, err := symmetric.PulseSeal(plaintext, aesKey, nonce, purpose, ECDHCipherSuite, nil, contextHash, transcriptHash)
	if err != nil {
		return nil, errors.New("Failed to seal plaintext: " + err.Error())
	}

	return &PulseECEncryptionResult{
		SealedData: ciphertext,
		Key1:       myPrivateKey.PubKey().SerializeCompressed(),
		Key2:       otherPublicKey.SerializeCompressed(),
	}, nil

}

// DecryptEC decrypts a message that was encrypted using ECDH.
// It identifies the other party's public key from the result, derives the shared secret,
// and opens the AES-GCM ciphertext.
//
// Arguments:
//   - encryptionResult: The struct containing the ciphertext and public keys.
//   - contractAddress: Pointer to the contract address hex string.
//   - myPrivateKey: The recipient's SECP256K1 private key.
//   - purpose: The intended purpose of the encryption.
//   - chainId: The blockchain network identifier.
//   - consentNumber: The sequence number for the consent record.
//
// Returns:
//   - The original plaintext.
//   - An error if decryption or authentication fails.
func DecryptEC(encryptionResult *PulseECEncryptionResult,
	contractAddress *string,
	myPrivateKey *secp.PrivateKey,
	purpose symmetric.PulseSymmetricPurpose,
	chainId int32,
	consentNumber int32,
) ([]byte, error) {
	myPublicKey := myPrivateKey.PubKey().SerializeCompressed()

	// Figure out which public key is the other party's
	var otherPublicKey *secp.PublicKey
	if bytes.Equal(encryptionResult.Key1, myPublicKey) {
		opk, err := secp.ParsePubKey(encryptionResult.Key2)
		if err != nil {
			return nil, errors.New("Failed to parse other public key: " + err.Error())
		}
		otherPublicKey = opk
	} else if bytes.Equal(encryptionResult.Key2, myPublicKey) {
		opk, err := secp.ParsePubKey(encryptionResult.Key1)
		if err != nil {
			return nil, errors.New("Failed to parse other public key: " + err.Error())
		}
		otherPublicKey = opk
	} else {
		return nil, errors.New("No matching public key found in encryption result")
	}

	// Get the AES key and nonce from the ECDH exchange
	transcriptHash := generateTranscriptHash(textformat.FormatHex(encryptionResult.Key1),
		textformat.FormatHex(encryptionResult.Key2))
	contextHash := context.ContextHash(chainId, *contractAddress, consentNumber)
	aesKey, nonce, err := generateAESKey(myPrivateKey, otherPublicKey, transcriptHash, contextHash)
	if err != nil {
		return nil, errors.New("Failed to generate aes key: " + err.Error())
	}

	// Decrypt the ciphertext
	plaintext, err := symmetric.PulseOpen(encryptionResult.SealedData, aesKey, nonce, purpose, ECDHCipherSuite, nil, contextHash, transcriptHash)
	if err != nil {
		return nil, errors.New("Failed to open Ciphertext: " + err.Error())
	}

	return plaintext, nil
}

// generateAESKey computes a shared secret between two ECDH key pairs and derives a
// 32-byte AES-256 key and 12-byte nonce using an RFC 5869 HKDF.
//
// Arguments:
//   - me: My SECP256K1 private key.
//   - other: The other party's SECP256K1 public key.
//   - transcriptHash: Hash of the exchange transcript for domain separation.
//   - contextHash: Hash of the encryption context.
//
// Returns:
//   - Derived AES key.
//   - Derived AES nonce.
//   - An error if keys are missing or derivation fails.
func generateAESKey(me *secp.PrivateKey, other *secp.PublicKey, transcriptHash []byte, contextHash []byte) ([]byte, []byte, error) {
	if me == nil || other == nil {
		return nil, nil, errors.New("must provide both private and public keys to derive a shared secret")
	}
	sharedSecret := secp.GenerateSharedSecret(me, other)
	return hkdf.PulseHKDFECDH(sharedSecret, transcriptHash, nil, contextHash)
}

// generateTranscriptHash creates a deterministic Keccak-256 hash of the involved public keys.
// This ensures that the encryption is bound to the specific pair of participants.
//
// Arguments:
//   - key1: Hex-encoded string of the first compressed public key.
//   - key2: Hex-encoded string of the second compressed public key.
//
// Returns:
//   - A 32-byte Keccak-256 hash of the sorted public keys and protocol identifier.
func generateTranscriptHash(key1 string, key2 string) []byte {
	keys := [2]string{key1, key2}
	slices.Sort(keys[:])

	transcriptString := fmt.Sprintf("|pulse|group|v1|%s|%s|%s|", keys[0], keys[1], ECDHCipherSuite)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(transcriptString))
	return hash.Sum(nil)
}
