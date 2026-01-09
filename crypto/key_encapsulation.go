package crypto

import (
	"bytes"
	"errors"
	"slices"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/wipe"

	"golang.org/x/crypto/sha3"
)

//TODO: Update Known values post HKDF completion
//TODO: Packing encryption result into single CBOR/byte array
//TODO: Split Encrypt/Decrypt into smaller functions
//TODO: Review test pack coverage

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

var PQDataCipherSuite = "rng+aes-gcm-256"
var PQKeyCipherSuite = "kyber768+hkdf-keccak256+aes-gcm-256"

func EncryptPQ(plaintext []byte,
	contractAddress *string,
	publicKeys []*kyberKEM.PublicKey,
	purpose symmetric.PulseSymmetricPurpose,
	chainId int32,
	consentNumber int32,
) (*PulsePQEncryptionResult, error) {
	var result PulsePQEncryptionResult

	// Encrypt the plaintext (consent data) using a random AES key
	recipientIDHash := getAllRecipientIDHashFromKeys(publicKeys)
	contextHash := textformat.ContextHash(chainId, *contractAddress, consentNumber)

	cipherText, aesKey, nonce, err := symmetric.PulseSealWithNewKey(plaintext, purpose, PQDataCipherSuite, recipientIDHash, contextHash)
	if err != nil {
		return nil, errors.New("Failed to seal plaintext: " + err.Error())
	}
	defer wipe.SliceWipe(aesKey)
	defer wipe.SliceWipe(nonce)

	// Pack Key/Nonce together for encrypting to other parties
	dataAESKey := make([]byte, symmetric.AESGCMKeySize+symmetric.AESGCMNonceSize)
	defer wipe.SliceWipe(dataAESKey)
	copy(dataAESKey[:symmetric.AESGCMKeySize], aesKey)
	copy(dataAESKey[symmetric.AESGCMKeySize:], nonce)

	result.SealedData = cipherText

	// Kyber stuff now -- lets encapsulate the AES key for each recipient
	for idx := range publicKeys {
		kemPK := publicKeys[idx]

		encKey, err := encapsulateKey(kemPK, dataAESKey, purpose, contextHash)
		if err != nil {
			return nil, err
		}
		result.Keys = append(result.Keys, encKey)

	}
	return &result, nil
}

func encapsulateKey(kemPK *kyberKEM.PublicKey, dataAESKey []byte, purpose symmetric.PulseSymmetricPurpose, contextHash []byte) (*PulsePQEncryptionKey, error) {
	scheme := kyberKEM.Scheme()
	fingerPrint := getPubKeyFingerprint(kemPK)

	// Generate a shared secret and encapsulated secret for this recipient
	encapsulatedSecret, sharedSecret, err := scheme.Encapsulate(kemPK)
	defer wipe.SliceWipe(sharedSecret)
	if err != nil {
		return nil, err
	}

	// TODO: Arguments
	// Derive AES key/nonce from shared secret for encrypting our data key
	keyAESKey, keyNonce, err := hkdf.PulseHKDFKyber(sharedSecret, encapsulatedSecret, fingerPrint[:], []byte("context"))
	defer wipe.SliceWipe(keyAESKey)
	defer wipe.SliceWipe(keyNonce)
	if err != nil {
		return nil, err
	}

	// Encrypt our data key using the derived AES key/nonce
	hash := sha3.NewLegacyKeccak256()
	transcriptHash := hash.Sum(encapsulatedSecret)
	encryptedKey, err := symmetric.PulseSeal(dataAESKey, keyAESKey, keyNonce, purpose, PQKeyCipherSuite, fingerPrint[:], contextHash, transcriptHash)
	if err != nil {
		return nil, err
	}

	// Pack result
	return &PulsePQEncryptionKey{
		KeyFingerPrint:      fingerPrint,
		EncapsulatedKeyKey:  encapsulatedSecret,
		EncapsulatedDataKey: encryptedKey,
	}, nil
}

func DecryptPQ(encryptionResult *PulsePQEncryptionResult,
	contractAddress *string,
	myPrivateKey *kyberKEM.PrivateKey,
	purpose symmetric.PulseSymmetricPurpose,
	chainId int32,
	consentNumber int32,
) ([]byte, error) {
	contextHash := textformat.ContextHash(chainId, *contractAddress, consentNumber)

	// Scan the encryptionResult for my public key fingerprint, and get the shared secret.
	myKeyFingerprint := getPubKeyFingerprint(myPrivateKey.Public().(*kyberKEM.PublicKey))

	foundKey := false
	sharedSecret := make([]byte, kyberKEM.SharedKeySize)
	defer wipe.SliceWipe(sharedSecret)
	fingerPrints := make([]string, len(encryptionResult.Keys))
	keyIndex := 0
	for i, key := range encryptionResult.Keys {
		fingerPrints[i] = textformat.FormatHex(key.KeyFingerPrint[:])
		if !foundKey && bytes.Equal(key.KeyFingerPrint[:], myKeyFingerprint[:]) {
			foundKey = true
			keyIndex = i
			myPrivateKey.DecapsulateTo(sharedSecret, key.EncapsulatedKeyKey)
		}
	}
	if !foundKey {
		return nil, errors.New("no key found for this party")
	}

	// Derive AES key from shared secret using HKDF
	k := encryptionResult.Keys[keyIndex]
	// TODO: Arguments
	keyAESKey, keyNonce, err := hkdf.PulseHKDFKyber(sharedSecret, k.EncapsulatedKeyKey, k.KeyFingerPrint[:], []byte("context"))
	if err != nil {
		return nil, err
	}

	// First AES Open -- Get the internal AES Key
	tHash := sha3.NewLegacyKeccak256()
	transcriptHash := tHash.Sum(k.EncapsulatedKeyKey)
	dataAESKey, err := symmetric.PulseOpen(k.EncapsulatedDataKey, keyAESKey, keyNonce, purpose, PQKeyCipherSuite, k.KeyFingerPrint[:], contextHash, transcriptHash)
	defer wipe.SliceWipe(dataAESKey)
	if err != nil {
		return nil, errors.New("Failed to open encrypted key: " + err.Error())
	}

	dataKey := dataAESKey[:symmetric.AESGCMKeySize]
	dataNonce := dataAESKey[symmetric.AESGCMKeySize:]
	defer wipe.SliceWipe(dataKey)
	defer wipe.SliceWipe(dataNonce)

	// Now unseal the consent data
	recipientIdHash := getAllRecipientIDHashFromFingerPrints(fingerPrints)
	nHash := sha3.NewLegacyKeccak256()
	dataTranscript := nHash.Sum(dataNonce)
	plainText, err := symmetric.PulseOpen(encryptionResult.SealedData, dataKey, dataNonce, purpose, PQDataCipherSuite, recipientIdHash, contextHash, dataTranscript)
	if err != nil {
		return nil, errors.New("Failed to open encrypted data: " + err.Error())
	}

	return plainText, nil

}

// Returns a hash of a MLKEMS/Kyber-768 public key, which we can use to identify the key later.
func getPubKeyFingerprint(pk *kyberKEM.PublicKey) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	buf := make([]byte, kyberKEM.PublicKeySize)
	pk.Pack(buf)
	hash.Write(buf)
	return [32]byte(hash.Sum(nil))
}

func getAllRecipientIDHashFromKeys(keys []*kyberKEM.PublicKey) []byte {
	var fingerPrints []string
	for _, pk := range keys {
		fingerPrint := getPubKeyFingerprint(pk)
		fingerPrints = append(fingerPrints, textformat.FormatHex(fingerPrint[:]))
	}

	return getAllRecipientIDHashFromFingerPrints(fingerPrints)
}

func getAllRecipientIDHashFromFingerPrints(fingerPrints []string) []byte {
	slices.Sort(fingerPrints)
	output := bytes.Buffer{}
	output.WriteString("|pulse|group|v1|")
	for _, fp := range fingerPrints {
		output.WriteString(fp)
		output.WriteString("|")
	}

	hash := sha3.NewLegacyKeccak256()
	hash.Write(output.Bytes())
	return hash.Sum(nil)
}

func buildContext(chainId byte, contractAddress string) []byte {
	contextBuffer := bytes.Buffer{}
	contextBuffer.WriteByte(chainId)
	contextBuffer.WriteString(contractAddress)
	return contextBuffer.Bytes()
}
