package crypto

import (
	"bytes"
	"errors"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"

	"golang.org/x/crypto/sha3"
)

//TODO: Zero Sensitive Data
//TODO: Update Known values post HKDF completion
//TODO: Packing encryption result into single CBOR/byte array
//TODO: Split Encrypt/Decrypt into smaller functions
//TODO: Review test pack coverage

// PulsePQEncryption is a struct for encrypting data using a post-quantum
// key encapsulation mechanism (KEM) to derive a symmetric key.
type PulsePQEncryption struct {
	plaintext              []byte
	ciphertext             []byte
	contractAddress        *string
	myPrivateKey           *kyberKEM.PrivateKey
	myPublicKey            *kyberKEM.PublicKey
	myPublicKeyFingerPrint [32]byte
	otherPublicKeys        map[[32]byte]*kyberKEM.PublicKey
	encapsulatedKeys       []*PulsePQEncryptionKey
	purpose                symmetric.PulseSymmetricPurpose
	chainId                byte
	encryptionResult       *PulsePQEncryptionResult
	aesKey                 []byte
	hasKey                 bool
	seed                   []byte
	hasSeed                bool
}

// NewPulsePQEncryption constructs a new PulsePQEncryption with zero values.
// Configure it using the setter methods before calling Encrypt or Decrypt.
func NewPulsePQEncryption() *PulsePQEncryption {
	e := &PulsePQEncryption{}
	e.otherPublicKeys = make(map[[32]byte]*kyberKEM.PublicKey)
	return e
}

// SetPlaintext sets the plaintext bytes to be encrypted.
// Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) SetPlaintext(plaintext []byte) *PulsePQEncryption {
	e.plaintext = plaintext
	return e
}

// Plaintext returns the currently set plaintext. This will be populated after
// a successful call to Decrypt, or whatever was set via SetPlaintext.
func (e *PulsePQEncryption) Plaintext() []byte {
	return e.plaintext
}

// SetContractAddress sets the contract address context used in the symmetric
// encryption/decryption process. This value must match on both sides.
// Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) SetContractAddress(contractAddress *string) *PulsePQEncryption {
	e.contractAddress = contractAddress
	return e
}

// SetMyPrivateKey sets my (local) KEM private key. Some schemes allow deriving
// the public key from the private key; if available, the public key field may
// be populated by the caller using a dedicated setter in future. For now we
// only store the private key. Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) SetMyPrivateKey(myPrivateKey *kyberKEM.PrivateKey) *PulsePQEncryption {
	e.myPrivateKey = myPrivateKey
	pubKey := myPrivateKey.Public()
	e.myPublicKey = pubKey.(*kyberKEM.PublicKey)

	e.myPublicKeyFingerPrint = getPubKeyFingerprint(e.myPublicKey)
	e.otherPublicKeys[e.myPublicKeyFingerPrint] = e.myPublicKey
	return e
}

// AddOtherPublicKey sets the list of recipient public keys that should be able
// to decrypt the sealed data. Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) AddOtherPublicKey(otherPublicKey *kyberKEM.PublicKey) *PulsePQEncryption {
	fp := getPubKeyFingerprint(otherPublicKey)
	e.otherPublicKeys[fp] = otherPublicKey
	return e
}

// SetPurpose sets the purpose/context for symmetric encryption. This is used
// as associated data and must match on encryption and decryption.
// Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) SetPurpose(purpose symmetric.PulseSymmetricPurpose) *PulsePQEncryption {
	e.purpose = purpose
	return e
}

// SetChainId sets the blockchain network identifier used in the symmetric
// encryption context. Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) SetChainId(chainId byte) *PulsePQEncryption {
	e.chainId = chainId
	return e
}

// SetEncryptionResult provides a previously produced encryption result that
// contains the sealed data and the public keys of the parties that may decrypt
// it. This is a convenient way to set Ciphertext and the peer public keys
// before calling Decrypt. Returns the receiver to allow method chaining.
func (e *PulsePQEncryption) SetEncryptionResult(result *PulsePQEncryptionResult) *PulsePQEncryption {
	e.encryptionResult = result
	return e
}

// setAESKey sets the AES key used for encryption. Returns the receiver to allow method chaining.
// Not for general use, but useful for testing.
func (e *PulsePQEncryption) setAESKey(key []byte) *PulsePQEncryption {
	e.aesKey = key
	e.hasKey = true
	return e
}

// setSeed sets the seed used for encryption. Returns the receiver to allow method chaining.
// Not for general use (hence private), but useful for testing.
func (e *PulsePQEncryption) setSeed(seed []byte) *PulsePQEncryption {
	e.seed = seed
	e.hasSeed = true
	return e
}

// PulsePQEncryptionKey is a struct for holding the encapsulated key for a
// recipient. It combines the encrypted AES key with an fingerprint of the public MLKEMS key used to encrypt it.
type PulsePQEncryptionKey struct {
	_                   struct{} `json:"-"               cbor:",toarray"`       // Enable CBOR array encoding for this type.
	KeyFingerPrint      [32]byte `json:"keyFingerPrint"  cbor:"0,keyasint"`     // Hash of public key
	EncapsulatedKeyKey  []byte   `json:"encapsulatedKeyKey" cbor:"1,keyasint"`  // Encapsulated/Encrypted AES EncryptionKey
	EncapsulatedDataKey []byte   `json:"encapsulatedDataKey" cbor:"2,keyasint"` // Encapsulated/Encrypted AES Ciphertext
}

// PulsePQEncryptionResult is a struct for holding the result of an encryption
// operation. It contains the sealed data and the public keys for recipients,
// for embedding in a consent record (Notary) or a Consent/Revoke/Update
// request.
type PulsePQEncryptionResult struct {
	_          struct{}                `json:"-"          cbor:",toarray"`   // Enable CBOR array encoding for this type.
	SealedData []byte                  `json:"sealedData" cbor:"0,keyasint"` // Encrypted data
	Keys       []*PulsePQEncryptionKey `json:"keys"       cbor:"1,keyasint"` // Public keys of parties that may be able to decrypt the data
}

// GetEncryptionResult returns the sealed data and the recipient public keys
// involved in the encapsulation. The first key MAY be the sender's public key
// if set, followed by all other recipient keys.
func (e *PulsePQEncryption) GetEncryptionResult() *PulsePQEncryptionResult {
	keys := make([]*PulsePQEncryptionKey, 0, 1+len(e.encapsulatedKeys))
	for _, k := range e.encapsulatedKeys {
		if k == nil {
			continue
		}
		keys = append(keys, k)
	}
	return &PulsePQEncryptionResult{
		SealedData: e.ciphertext,
		Keys:       keys,
	}
}

// Encrypt encrypts the plaintext using AEAD with a random AES key, then encapsulates the key for each recipient using
// a post-quantum Kyber768/MLKEMS scheme.
//
// The following fields must be set:
//   - Plaintext
//   - ContractAddress
//   - OtherPublicKeys
//   - Purpose
//   - ChainId
//
// If MyPrivateKey is set, the corresponding public key will be added to OtherPublicKeys.
//
// Use GetEncryptionResult() to get the result of the encryption operation.
// Will return an error if there is a problem.
func (e *PulsePQEncryption) Encrypt() error {
	if err := e.verifyEncryptReady(); err != nil {
		return err
	}
	context := e.getContext()

	var cipherText, aesKey, nonce []byte
	var err error
	if e.hasKey {
		aesKey = e.aesKey[:symmetric.AESGCMKeySize]
		nonce = e.aesKey[symmetric.AESGCMKeySize:]
		cipherText, err = symmetric.PulseSeal(e.plaintext, aesKey, nonce, e.purpose, []byte("all-recipients"), context)
	} else {
		cipherText, aesKey, nonce, err = symmetric.PulseSealWithNewKey(e.plaintext, e.purpose, []byte("all-recipients"), context)
	}
	if err != nil {
		return errors.New("Failed to seal plaintext: " + err.Error())
	}
	keyBuffer := bytes.Buffer{}
	keyBuffer.Write(aesKey)
	keyBuffer.Write(nonce)
	dataAESKey := keyBuffer.Bytes()

	e.ciphertext = cipherText

	scheme := kyberKEM.Scheme()
	for fingerPrint, kemPK := range e.otherPublicKeys {
		if kemPK == nil {
			continue
		}

		var encapsulatedSecret, sharedSecret []byte
		var err error
		// Generally hasSeed == false, but true for some test cases.
		if e.hasSeed {
			encapsulatedSecret, sharedSecret, err = scheme.EncapsulateDeterministically(kemPK, e.seed)
		} else {
			encapsulatedSecret, sharedSecret, err = scheme.Encapsulate(kemPK)
		}
		if err != nil {
			return err
		}

		keyAESKey, keyNonce, err := hkdf.PulseHKDFKyber(sharedSecret, encapsulatedSecret, fingerPrint[:], context)
		if err != nil {
			return err
		}

		// TODO: Arguments
		encryptedKey, err := symmetric.PulseSeal(dataAESKey, keyAESKey, keyNonce, e.purpose, fingerPrint[:], context)
		if err != nil {
			return err
		}

		// TODO: Zero sensitive data
		e.encapsulatedKeys = append(e.encapsulatedKeys, &PulsePQEncryptionKey{
			KeyFingerPrint:      fingerPrint,
			EncapsulatedKeyKey:  encapsulatedSecret,
			EncapsulatedDataKey: encryptedKey,
		})
	}

	return nil
}

// Decrypt recovers the plaintext previously encrypted using Encrypt.
//
// The following fields must be set:
//   - EncryptionResult (Contains the ciphertext and the AEAD key encrypted for each recipient)
//   - ContractAddress
//   - MyPrivateKey
//   - Purpose
//   - ChainId
//
// Use GetPlainText() to get the result of the operation. Will return an error if there is a problem.
func (e *PulsePQEncryption) Decrypt() error {
	if err := e.verifyDecryptReady(); err != nil {
		return err
	}

	// Find the EncapsulatedKey assigned to my public key. Decrypt it using my private key to get the AES key.
	foundKey := false
	sharedSecret := make([]byte, kyberKEM.SharedKeySize)
	keyIndex := 0
	for i, key := range e.encryptionResult.Keys {
		if bytes.Equal(key.KeyFingerPrint[:], e.myPublicKeyFingerPrint[:]) {
			foundKey = true
			keyIndex = i
			e.myPrivateKey.DecapsulateTo(sharedSecret, key.EncapsulatedKeyKey)
			break
		}
	}
	if !foundKey {
		return errors.New("no key found for this party")
	}

	k := e.encryptionResult.Keys[keyIndex]
	keyAESKey, keyNonce, err := hkdf.PulseHKDFKyber(sharedSecret, k.EncapsulatedKeyKey, k.KeyFingerPrint[:], e.getContext())
	if err != nil {
		return err
	}

	// First AES Open -- Get the internal AES Key
	// TODO: Arguments
	dataAESKey, err := symmetric.PulseOpen(e.encryptionResult.Keys[keyIndex].EncapsulatedDataKey, keyAESKey, keyNonce, e.purpose, k.KeyFingerPrint[:], e.getContext())
	if err != nil {
		return errors.New("Failed to open encrypted key: " + err.Error())
	}

	dataKey := dataAESKey[:symmetric.AESGCMKeySize]
	dataNonce := dataAESKey[symmetric.AESGCMKeySize:]
	// Now unseal the data
	// TODO: Arguments
	plainText, err := symmetric.PulseOpen(e.encryptionResult.SealedData, dataKey, dataNonce, e.purpose, []byte("all-recipients"), e.getContext())
	if err != nil {
		return errors.New("Failed to open encrypted data: " + err.Error())
	}
	e.plaintext = plainText

	//TODO: Zero sensitive data
	return nil
}

// verifyReady checks that all fields required for both encryption or decryption are
// non-nil. Returns an error if any are missing.
func (e *PulsePQEncryption) verifyReady() error {
	if e.contractAddress == nil {
		return errors.New("must provide contract address")
	}
	if e.purpose == symmetric.PulseNoSymmetricPurpose {
		return errors.New("must provide purpose")
	}
	if e.chainId == 0 {
		return errors.New("must provide chainId")
	}
	return nil
}

// verifyEncryptReady checks that all fields required for encryption are set.
func (e *PulsePQEncryption) verifyEncryptReady() error {
	if e.plaintext == nil || len(e.plaintext) == 0 {
		return errors.New("must provide plaintext")
	}
	// otherPublicKeys must have at least two elements, but one could be set when we add a private key.
	if len(e.otherPublicKeys) < 2 {
		return errors.New("must provide another public key")
	}
	return e.verifyReady()
}

// verifyDecryptReady checks that all fields required for decryption are set.
func (e *PulsePQEncryption) verifyDecryptReady() error {
	if e.myPrivateKey == nil {
		return errors.New("must provide private key")
	}
	if e.encryptionResult == nil {
		return errors.New("must provide encryption result")
	}
	if e.encryptionResult.SealedData == nil || len(e.encryptionResult.SealedData) == 0 {
		return errors.New("must provide ciphertext in encryption result")
	}
	return e.verifyReady()
}

// Returns a hash of a MLKEMS/Kyber-768 public key, which we can use to identify the key later.
func getPubKeyFingerprint(pk *kyberKEM.PublicKey) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	buf := make([]byte, kyberKEM.PublicKeySize)
	pk.Pack(buf)
	hash.Write(buf)
	return [32]byte(hash.Sum(nil))
}

func (e *PulsePQEncryption) getContext() []byte {
	contextBuffer := bytes.Buffer{}
	contextBuffer.WriteByte(e.chainId)
	contextBuffer.WriteString(*e.contractAddress)
	return contextBuffer.Bytes()
}
