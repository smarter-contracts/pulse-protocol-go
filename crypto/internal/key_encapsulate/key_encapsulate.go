// Package key_encapsulate implements post-quantum hybrid encryption and
// decryption using ML-KEM-768 (Kyber768).  It generates a random AES-256-GCM
// key to seal the plaintext, then encapsulates that key for each recipient
// using Kyber768 key encapsulation.
package key_encapsulate

import (
	"bytes"
	"errors"
	"io"
	"slices"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/wipe"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// PQDataCipherSuite is the cipher suite identifier for the outer data encryption
// (random AES key, no key agreement).
var PQDataCipherSuite = "rng+aes-gcm-256"

// PQKeyCipherSuite is the cipher suite identifier for the per-recipient key
// encapsulation layer (Kyber768 KEM + HKDF + AES-GCM key wrap).
var PQKeyCipherSuite = "kyber768+hkdf-keccak256+aes-gcm-256"

func packKey(key, nonce []byte) []byte {
	packed := make([]byte, symmetric.AESGCMKeySize+symmetric.AESGCMNonceSize)
	copy(packed[:symmetric.AESGCMKeySize], key)
	copy(packed[symmetric.AESGCMKeySize:], nonce)
	return packed
}

// EncryptPQ performs post-quantum hybrid encryption for multiple recipients.
// It generates a random AES-256 key to seal the plaintext, then encapsulates that AES key
// for each recipient using Kyber768 (ML-KEM).
func EncryptPQ(entropy io.Reader,
	plaintext []byte,
	contractAddress *string,
	publicKeys []*kyberKEM.PublicKey,
	purpose purposes.PulsePurpose,
	chainId uint32,
	consentNumber uint32,
) (*types.PulsePQEncryptionResult, error) {
	var result types.PulsePQEncryptionResult
	if contractAddress == nil || *contractAddress == "" {
		return nil, errors.New("contract address must be provided")
	}
	if len(publicKeys) < 1 {
		return nil, errors.New("must provide at least one public key to encrypt")
	}

	// Encrypt the plaintext (consent data) using a random AES key
	recipientIDHash := getAllRecipientIDHashFromKeys(publicKeys)
	contextHash := context.ContextHash(chainId, *contractAddress, consentNumber)

	cipherText, aesKey, nonce, err := symmetric.PulseSealWithNewKey(entropy, plaintext, purpose, PQDataCipherSuite, recipientIDHash, contextHash)
	if err != nil {
		return nil, errors.New("Failed to seal plaintext: " + err.Error())
	}
	defer wipe.SliceWipe(aesKey)
	defer wipe.SliceWipe(nonce)

	// Pack Key/Nonce together for encrypting to other parties
	dataAESKey := packKey(aesKey, nonce)
	defer wipe.SliceWipe(dataAESKey)

	result.SealedData = cipherText

	// Kyber stuff now -- lets encapsulate the AES key for each recipient
	for idx := range publicKeys {
		kemPK := publicKeys[idx]

		encKey, err := encapsulateKey(entropy, kemPK, dataAESKey, purpose, contextHash)
		if err != nil {
			return nil, err
		}
		result.Keys = append(result.Keys, encKey)

	}
	return &result, nil
}

// encapsulateKey handles the per-recipient key encapsulation process.
func encapsulateKey(entropy io.Reader, kemPK *kyberKEM.PublicKey, dataAESKey []byte, purpose purposes.PulsePurpose, contextHash []byte) (*types.PulsePQEncryptionKey, error) {
	scheme := kyberKEM.Scheme()
	fingerPrint := getPubKeyFingerprint(kemPK)

	// Generate a shared secret and encapsulated secret for this recipient
	var encapsulatedSecret, sharedSecret []byte
	var err error
	if entropy != nil {
		seed := make([]byte, scheme.EncapsulationSeedSize())
		if _, err := io.ReadFull(entropy, seed); err != nil {
			return nil, err
		}
		encapsulatedSecret, sharedSecret, err = scheme.EncapsulateDeterministically(kemPK, seed)
	} else {
		encapsulatedSecret, sharedSecret, err = scheme.Encapsulate(kemPK)
	}
	defer wipe.SliceWipe(sharedSecret)
	if err != nil {
		return nil, err
	}

	// Derive AES key/nonce from shared secret for encrypting our data key
	keyAESKey, keyNonce, err := hkdf.PulseHKDFKyber(sharedSecret, encapsulatedSecret, fingerPrint[:], contextHash)
	defer wipe.SliceWipe(keyAESKey)
	defer wipe.SliceWipe(keyNonce)
	if err != nil {
		return nil, err
	}

	// Encrypt our data key using the derived AES key/nonce
	transcriptHash := hash.PulseHashBytes(encapsulatedSecret)
	encryptedKey, err := symmetric.PulseSeal(dataAESKey, keyAESKey, keyNonce, purpose, PQKeyCipherSuite, fingerPrint[:], contextHash, transcriptHash)
	if err != nil {
		return nil, err
	}

	// Pack result
	return &types.PulsePQEncryptionKey{
		KeyFingerPrint:      fingerPrint,
		EncapsulatedKeyKey:  encapsulatedSecret,
		EncapsulatedDataKey: encryptedKey,
	}, nil
}

// DecryptPQ decrypts a message that was encrypted using the post-quantum hybrid scheme.
func DecryptPQ(encryptionResult *types.PulsePQEncryptionResult,
	contractAddress *string,
	myPrivateKey *kyberKEM.PrivateKey,
	purpose purposes.PulsePurpose,
	chainId uint32,
	consentNumber uint32,
) ([]byte, error) {
	if contractAddress == nil || *contractAddress == "" {
		return nil, errors.New("contract address must be provided")
	}
	contextHash := context.ContextHash(chainId, *contractAddress, consentNumber)

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
	keyAESKey, keyNonce, err := hkdf.PulseHKDFKyber(sharedSecret, k.EncapsulatedKeyKey, k.KeyFingerPrint[:], contextHash)
	defer wipe.SliceWipe(keyAESKey)
	defer wipe.SliceWipe(keyNonce)
	if err != nil {
		return nil, err
	}

	// First AES Open -- Get the internal AES Key
	transcriptHash := hash.PulseHashBytes(k.EncapsulatedKeyKey)
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
	dataTranscriptHash := hash.PulseHashBytes(dataNonce)
	plainText, err := symmetric.PulseOpen(encryptionResult.SealedData, dataKey, dataNonce, purpose, PQDataCipherSuite, recipientIdHash, contextHash, dataTranscriptHash)
	if err != nil {
		return nil, errors.New("Failed to open encrypted data: " + err.Error())
	}

	return plainText, nil

}

// getPubKeyFingerprint computes a Keccak-256 fingerprint of a Kyber public key.
func getPubKeyFingerprint(pk *kyberKEM.PublicKey) [32]byte {
	buf := make([]byte, kyberKEM.PublicKeySize)
	pk.Pack(buf)
	return [32]byte(hash.PulseHashBytes(buf))
}

func getAllRecipientIDHashFromKeys(keys []*kyberKEM.PublicKey) []byte {
	return hash.PulseHashBytes(getAllRecipientIDStringFromKeys(keys))
}

func getAllRecipientIDHashFromFingerPrints(fingerPrints []string) []byte {
	return hash.PulseHashBytes(getAllRecipientIDStringFromFingerPrints(fingerPrints))
}

func getAllRecipientIDStringFromKeys(keys []*kyberKEM.PublicKey) []byte {
	var fingerPrints []string
	for _, pk := range keys {
		fingerPrint := getPubKeyFingerprint(pk)
		fingerPrints = append(fingerPrints, textformat.FormatHex(fingerPrint[:]))
	}

	return getAllRecipientIDStringFromFingerPrints(fingerPrints)
}

func getAllRecipientIDStringFromFingerPrints(fingerPrints []string) []byte {
	slices.Sort(fingerPrints)
	output := bytes.Buffer{}
	output.WriteString("|pulse|group|v1|")
	for _, fp := range fingerPrints {
		output.WriteString(fp)
		output.WriteString("|")
	}
	return output.Bytes()
}
