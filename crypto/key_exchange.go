package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
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

func EncryptECDH(plaintext []byte,
	contractAddress *string,
	myPrivateKey *secp.PrivateKey,
	otherPublicKey *secp.PublicKey,
	purpose symmetric.PulseSymmetricPurpose,
	chainId int32,
	consentNumber int32,
) (*PulseECEncryptionResult, error) {
	aesKey, nonce, err := generateAESKey(myPrivateKey, otherPublicKey)
	defer wipe.SliceWipe(aesKey)
	defer wipe.SliceWipe(nonce)
	if err != nil {
		return nil, errors.New("Failed to generate aes key and nonce: " + err.Error())
	}

	recipientIdHash := generateRecipientIdHash(textformat.FormatHex(myPrivateKey.PubKey().SerializeCompressed()),
		textformat.FormatHex(otherPublicKey.SerializeCompressed()))
	ciphertext, err := symmetric.PulseSeal(plaintext, aesKey, nonce, purpose, ECDHCipherSuite, recipientIdHash, []byte("context"), []byte("transcript"))
	if err != nil {
		return nil, errors.New("Failed to seal plaintext: " + err.Error())
	}

	return &PulseECEncryptionResult{
		SealedData: ciphertext,
		Key1:       myPrivateKey.PubKey().SerializeCompressed(),
		Key2:       otherPublicKey.SerializeCompressed(),
	}, nil

}

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
	aesKey, nonce, err := generateAESKey(myPrivateKey, otherPublicKey)
	if err != nil {
		return nil, errors.New("Failed to generate aes key: " + err.Error())
	}

	// Decrypt the ciphertext
	// TODO: Arguments
	recipientIdHash := generateRecipientIdHash(textformat.FormatHex(encryptionResult.Key1),
		textformat.FormatHex(encryptionResult.Key2))
	plaintext, err := symmetric.PulseOpen(encryptionResult.SealedData, aesKey, nonce, purpose, ECDHCipherSuite, recipientIdHash, []byte("context"), []byte("transcript"))
	if err != nil {
		return nil, errors.New("Failed to open Ciphertext: " + err.Error())
	}

	return plaintext, nil
}

// generateAESKey computes a shared secret between two ECDH key pairs and derives a
// 32-byte AES-256 key using an RFC 5869 HKDF. The result is suitable for use
// with AES-GCM symmetric encryption.
func generateAESKey(me *secp.PrivateKey, other *secp.PublicKey) ([]byte, []byte, error) {
	if me == nil || other == nil {
		return nil, nil, errors.New("must provide both private and public keys to derive a shared secret")
	}
	sharedSecret := secp.GenerateSharedSecret(me, other)

	// TODO : Function arguments
	return hkdf.PulseHKDFECDH(sharedSecret, []byte("transcript"), []byte("recipientid"), []byte("context"))
}

func generateRecipientIdHash(key1 string, key2 string) []byte {
	keys := [2]string{key1, key2}
	slices.Sort(keys[:])

	recipientString := fmt.Sprintf("|pulse|group|v1|%s|%s|", keys[0], keys[1])
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(recipientString))
	return hash.Sum(nil)
}
