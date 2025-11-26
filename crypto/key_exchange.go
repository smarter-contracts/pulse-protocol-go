package crypto

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const PulseHKDFInfoStr = "ctx: v1 | AES-256-GCM session | Pulse Protocol"

func PulseHKDFInfo() []byte { return []byte(PulseHKDFInfoStr) }

//TODO: Split out types into new module
//TODO: Use new HKDF function
//TODO: Update known values testpack
//TODO: Review test pack coverage

// PulseECEncryption is a struct for encrypting data using ECDH key exchange to generate a symmetric key.
type PulseECEncryption struct {
	plaintext        []byte
	ciphertext       []byte
	contractAddress  *string
	myPrivateKey     *secp.PrivateKey
	myPublicKey      *secp.PublicKey
	otherPublicKey   *secp.PublicKey
	purpose          PulseSymmetricPurpose
	chainId          byte
	encryptionResult *PulseECEncryptionResult
}

// NewPulseECEncryption constructs a new PulseECEncryption with zero values.
// Configure it using the setter methods before calling Encrypt or Decrypt.
func NewPulseECEncryption() *PulseECEncryption {
	return &PulseECEncryption{}
}

// SetPlaintext sets the plaintext bytes to be encrypted.
// Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetPlaintext(plaintext []byte) *PulseECEncryption {
	e.plaintext = plaintext
	return e
}

// Plaintext returns the currently set plaintext. This will be populated after
// a successful call to Decrypt, or whatever was set via SetPlaintext.
func (e *PulseECEncryption) Plaintext() []byte {
	return e.plaintext
}

// SetContractAddress sets the contract address context used in the symmetric
// encryption/decryption process. This value must match on both sides.
// Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetContractAddress(contractAddress *string) *PulseECEncryption {
	e.contractAddress = contractAddress
	return e
}

// SetMyPrivateKey sets my (local) ECDH private key and derives the corresponding
// public key. Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetMyPrivateKey(myPrivateKey *secp.PrivateKey) *PulseECEncryption {
	e.myPrivateKey = myPrivateKey
	e.myPublicKey = myPrivateKey.PubKey()
	return e
}

// SetOtherPublicKey sets the peer's ECDH public key used to derive the
// shared secret. Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetOtherPublicKey(otherPublicKey *secp.PublicKey) *PulseECEncryption {
	e.otherPublicKey = otherPublicKey
	return e
}

// SetPurpose sets the purpose/context for symmetric encryption. This is used
// as associated data and must match on encryption and decryption.
// Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetPurpose(purpose PulseSymmetricPurpose) *PulseECEncryption {
	e.purpose = purpose
	return e
}

// SetChainId sets the blockchain network identifier used in the symmetric
// encryption context. Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetChainId(chainId byte) *PulseECEncryption {
	e.chainId = chainId
	return e
}

// SetEncryptionResult provides a previously produced encryption result that
// contains the sealed data and the two public keys. This is a convenient way
// to set Ciphertext and the peer public key before calling Decrypt.
// Returns the receiver to allow method chaining.
func (e *PulseECEncryption) SetEncryptionResult(result *PulseECEncryptionResult) *PulseECEncryption {
	e.encryptionResult = result
	return e
}

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

// Encrypt encrypts the plaintext, using a key generated from the supplied ECDH keypair.
//
// The following fields must be set:
//   - Plaintext
//   - ContractAddress
//   - MyPrivateKey
//   - OtherPublicKey
//   - Purpose
//   - ChainId
func (e *PulseECEncryption) Encrypt() error {
	if e.plaintext == nil || len(e.plaintext) == 0 {
		return errors.New("must provide plaintext")
	}
	err := e.verifyReady()
	if err != nil {
		return err
	}

	aesKey, err := generateAESKey(e.myPrivateKey, e.otherPublicKey)
	if err != nil {
		return errors.New("Failed to generate aes key: " + err.Error())
	}

	symmetricEncryption := NewPulseSymmetricEncryption().
		SetEncryptionKey(aesKey).
		SetContractAddress(e.contractAddress).
		SetPlaintext(e.plaintext).
		SetChainId(e.chainId).
		SetPurpose(e.purpose)

	err = symmetricEncryption.SealPlaintext()
	if err != nil {
		return errors.New("Failed to seal plaintext: " + err.Error())
	}

	e.ciphertext = symmetricEncryption.Ciphertext()

	return nil
}

// GetEncryptionResult returns the sealed data and the two compressed public
// keys involved in the exchange. The order of keys is (myPublicKey, otherPublicKey).
func (e *PulseECEncryption) GetEncryptionResult() *PulseECEncryptionResult {
	return &PulseECEncryptionResult{
		SealedData: e.ciphertext,
		Key1:       e.myPublicKey.SerializeCompressed(),
		Key2:       e.otherPublicKey.SerializeCompressed(),
	}
}

// Decrypt encrypts the plaintext, using a key generated from the supplied ECDH keypair.
//
// The following fields must be set:
//   - Ciphertext
//   - ContractAddress
//   - MyPrivateKey
//   - OtherPublicKey
//   - Purpose
//   - ChainId
//
// CipherText and OtherPublicKey can be set by passing in a PulseECEncryptionResult.
func (e *PulseECEncryption) Decrypt() error {
	err := e.unpackECEncryptionResult()
	if err != nil {
		return errors.New("problem deciphering encryption result: " + err.Error())
	}
	err = e.verifyReady()
	if err != nil {
		return err
	}
	if e.ciphertext == nil || len(e.ciphertext) == 0 {
		return errors.New("must provide ciphertext")
	}

	aesKey, err := generateAESKey(e.myPrivateKey, e.otherPublicKey)
	if err != nil {
		return errors.New("Failed to generate aes key: " + err.Error())
	}

	symmetricEncryption := NewPulseSymmetricEncryption().
		SetEncryptionKey(aesKey).
		SetContractAddress(e.contractAddress).
		SetCiphertext(e.ciphertext).
		SetChainId(e.chainId).
		SetPurpose(e.purpose)

	err = symmetricEncryption.OpenCiphertext()
	if err != nil {
		return errors.New("Failed to open Ciphertext: " + err.Error())
	}

	e.plaintext = symmetricEncryption.Plaintext()
	return nil
}

// verifyReady checks that all fields required for encryption or decryption are
// non-nil. Returns an error if any are missing.
func (e *PulseECEncryption) verifyReady() error {
	if e.contractAddress == nil {
		return errors.New("must provide contract address")
	}
	if e.purpose == PulseNoSymmetricPurpose {
		return errors.New("must provide purpose")
	}
	if e.chainId == 0 {
		return errors.New("must provide chainId")
	}
	if e.myPrivateKey == nil {
		return errors.New("must provide private key")
	}
	if e.otherPublicKey == nil {
		return errors.New("must provide public key")
	}
	return nil
}

// unpackECEncryptionResult interprets an attached PulseECEncryptionResult and
// populates the ciphertext and other party's public key on the receiver. If no
// result is present, it verifies that Ciphertext and OtherPublicKey are already
// populated. Returns an error if the result does not contain a key matching our public
// key, or if required data is missing.
func (e *PulseECEncryption) unpackECEncryptionResult() error {
	if e.myPrivateKey == nil {
		return errors.New("must provide private key")
	}
	// If there's nothing to unpack, return no error, but the caller should have set ciphertext/otherPublicKey
	// directly.
	if e.encryptionResult == nil {
		if e.ciphertext != nil &&
			len(e.ciphertext) > 0 &&
			e.otherPublicKey != nil &&
			len(e.otherPublicKey.SerializeCompressed()) > 0 {
			return nil
		}
		return errors.New("missing encryption result structure, and no ciphertext or otherPublicKey provided")
	}

	// myPublicKey will already be set when we set myPrivateKey. Let's see which of the keys in the result
	// structure match myPublicKey. We use Bytes.Equal() to compare the two byte arrays rather than
	// subtle.ConstantTimeCompare() because we want to avoid the overhead of the latter, and public keys are
	// not secret.
	pubkeyString := e.myPublicKey.SerializeCompressed()
	var pk *secp.PublicKey
	var err error

	if bytes.Equal(pubkeyString, e.encryptionResult.Key1) {
		// Key1 is ours
		pk, err = secp.ParsePubKey(e.encryptionResult.Key2)
	} else if bytes.Equal(pubkeyString, e.encryptionResult.Key2) {
		// Key2 is ours
		pk, err = secp.ParsePubKey(e.encryptionResult.Key1)
	} else {
		// None of these keys match ours. We have a problem.
		return errors.New("no matching public key found in encryption result")
	}
	if err != nil {
		return errors.New("failed to parse other public key: " + err.Error())
	}

	e.otherPublicKey = pk
	e.ciphertext = e.encryptionResult.SealedData
	return nil
}

// generateAESKey computes a shared secret between two ECDH key pairs and derives a
// 32-byte AES-256 key using an RFC 5869 HKDF. The result is suitable for use
// with AES-GCM symmetric encryption.
func generateAESKey(me *secp.PrivateKey, other *secp.PublicKey) ([]byte, error) {
	if me == nil || other == nil {
		return nil, errors.New("must provide both private and public keys to derive a shared secret")
	}
	sharedSecret := secp.GenerateSharedSecret(me, other)

	return deriveKey(sharedSecret)
}

// deriveKey expands the shared secret into a key of length n using HKDF with
// Keccak-256 as the hash function. The salt and info parameters provide context
// per RFC 5869. Salt is nil (translates to all 0 bytes), and info is the
// constant PulseHKDFInfo. We use Keccak-256 to be consistent with the rest of
// the Pulse Protocol.
func deriveKey(shared []byte) ([]byte, error) {
	h := hkdf.New(sha3.NewLegacyKeccak256, shared, nil, PulseHKDFInfo())
	key := make([]byte, AESGCMKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}
