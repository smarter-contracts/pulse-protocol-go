package key_exchange

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/wipe"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

var ECDHCipherSuite = "ecdh-secp256k1+hkdf-keccak256+aes-gcm-256"

// EncryptECDH performs hybrid encryption using Elliptic Curve Diffie-Hellman (ECDH).
// It derives a shared secret using SECP256K1, generates an AES-256 key via HKDF,
// and seals the plaintext using AES-GCM.
func EncryptECDH(plaintext []byte,
	contractAddress *string,
	myPrivateKey *secp.PrivateKey,
	otherPublicKey *secp.PublicKey,
	purpose purposes.PulsePurpose,
	chainId uint32,
	consentNumber uint32,
) (*types.PulseECEncryptionResult, error) {
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

	return &types.PulseECEncryptionResult{
		SealedData: ciphertext,
		Key1:       myPrivateKey.PubKey().SerializeCompressed(),
		Key2:       otherPublicKey.SerializeCompressed(),
	}, nil

}

// DecryptEC decrypts a message encrypted using ECDH.
// It identifies the other party's public key from the result, derives the shared secret,
// and opens the AES-GCM ciphertext.
func DecryptEC(encryptionResult *types.PulseECEncryptionResult,
	contractAddress *string,
	myPrivateKey *secp.PrivateKey,
	purpose purposes.PulsePurpose,
	chainId uint32,
	consentNumber uint32,
) ([]byte, error) {
	myPublicKey := myPrivateKey.PubKey().SerializeCompressed()

	// Figure out which public key is the other party's
	var otherPublicKey *secp.PublicKey
	if bytes.Equal(encryptionResult.Key1, myPublicKey) {
		opk, err := secp.ParsePubKey(encryptionResult.Key2)
		if err != nil {
			return nil, errors.New("failed to parse other public key: " + err.Error())
		}
		otherPublicKey = opk
	} else if bytes.Equal(encryptionResult.Key2, myPublicKey) {
		opk, err := secp.ParsePubKey(encryptionResult.Key1)
		if err != nil {
			return nil, errors.New("failed to parse other public key: " + err.Error())
		}
		otherPublicKey = opk
	} else {
		return nil, errors.New("no matching public key found in encryption result")
	}

	// Get the AES key and nonce from the ECDH exchange
	transcriptHash := generateTranscriptHash(textformat.FormatHex(encryptionResult.Key1),
		textformat.FormatHex(encryptionResult.Key2))
	contextHash := context.ContextHash(chainId, *contractAddress, consentNumber)
	aesKey, nonce, err := generateAESKey(myPrivateKey, otherPublicKey, transcriptHash, contextHash)
	if err != nil {
		return nil, errors.New("failed to generate aes key: " + err.Error())
	}

	// Decrypt the ciphertext
	plaintext, err := symmetric.PulseOpen(encryptionResult.SealedData, aesKey, nonce, purpose, ECDHCipherSuite, nil, contextHash, transcriptHash)
	if err != nil {
		return nil, errors.New("failed to open Ciphertext: " + err.Error())
	}

	return plaintext, nil
}

// generateAESKey computes a shared secret between two ECDH key pairs and derives a
// 32-byte AES-256 key and 12-byte nonce using an RFC 5869 HKDF.
func generateAESKey(me *secp.PrivateKey, other *secp.PublicKey, transcriptHash []byte, contextHash []byte) ([]byte, []byte, error) {
	if me == nil || other == nil {
		return nil, nil, errors.New("must provide both private and public keys to derive a shared secret")
	}
	sharedSecret := secp.GenerateSharedSecret(me, other)
	key, nonce, err := hkdf.PulseHKDFECDH(sharedSecret, transcriptHash, nil, contextHash)
	return key, nonce, err
}

func generateTranscriptString(key1 string, key2 string) string {
	keys := [2]string{key1, key2}
	slices.Sort(keys[:])

	return fmt.Sprintf("|pulse|group|v1|%s|%s|%s|", keys[0], keys[1], ECDHCipherSuite)
}

// generateTranscriptHash creates a deterministic Keccak-256 hash of the involved public keys.
func generateTranscriptHash(key1 string, key2 string) []byte {
	transcriptString := generateTranscriptString(key1, key2)
	return hash.PulseHashString(transcriptString)
}
