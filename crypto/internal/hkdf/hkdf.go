package hkdf

import (
	"bytes"
	"fmt"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/wipe"

	//"github.com/smarter-contracts/pulse-protocol-go/crypto"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// This file implements the HKDF functions used by Pulse. We use an industry standard
// RFC5869 HMAC based HKDF. This wrapper handles:
//
// * Populating the Salt & Info values for Expand/Extract operations.
// * Extracts a 32 byte AES-256 key from the shared secret.
// * Extracts a 12 byte nonce from the shared secret.
//
// Hash Algorithm: keccak256 (consistent with the rest of the Pulse Protocol)
// Salt: Keccak256("pulse|kdf|v1|salt|" + exchangeAlgo + "|" + Keccak256(transcript) )
//   - exchangeAlgo is either "kyber768" for kyber exchanges, or "secp256k1" for ECDH
//   - transcript is passed in from the calling function, but will be either
//     "secp256k1|keccak256(myPublicKey^theirPublicKey)"   OR
//     "kyber768|<EncapsulatedSharedSecret>|keccak256(PubKey)"
//
// Info: "pulse|kdf|v1|aes-gcm|" + keyOrNonce + "|v1|" + recipientID + "|" + ctkHash
//   - keyOrNonce is "key-wrap" for key derivation, or "nonce" for nonce derivation
//   - recipientID
//   - ctkHash
//
// PulseHKDFKyber derives a 32-byte AES-256 key and a 12-byte nonce from a Kyber shared secret.
// It uses the RFC 5869 HKDF algorithm with Keccak-256 as the underlying hash function.
//
// Arguments:
//   - sharedSecret: The raw shared secret derived from Kyber decapsulation.
//   - transcript: A byte slice representing the exchange transcript for domain separation.
//   - recipientId: The identifier (fingerprint) of the recipient.
//   - context: The binary context (chainId, contract address, etc.) for the encryption.
//
// Returns:
//   - A 32-byte AES key.
//   - A 12-byte AES nonce.
//   - A 32-byte Pseudo-Random Key (PRK).
//   - An error if the derivation fails.
func PulseHKDFKyber(sharedSecret []byte,
	transcript []byte,
	recipientId []byte,
	context []byte,
) ([]byte, []byte, error) {
	parentAlgo, purpose, suite := getSettings("Kyber")

	// fmt.Printf("DEBUG: PulseHKDFKyber sharedSecret=%x, transcript=%x, recipientId=%x, context=%x\n", sharedSecret, transcript, recipientId, context)

	return pulseHKDFImp(sharedSecret, parentAlgo, transcript, purpose, suite, recipientId, context)
}

// PulseHKDFECDH derives a 32-byte AES-256 key and a 12-byte nonce from an ECDH shared secret.
// It uses the RFC 5869 HKDF algorithm with Keccak-256 as the underlying hash function.
//
// Arguments:
//   - sharedSecret: The raw shared secret derived from ECDH (X-coordinate).
//   - transcript: A byte slice representing the exchange transcript for domain separation.
//   - recipientId: The identifier of the recipient (not used for ECDH salt but used in Info).
//   - context: The binary context for the encryption.
//
// Returns:
//   - A 32-byte AES key.
//   - A 12-byte AES nonce.
//   - A 32-byte Pseudo-Random Key (PRK).
//   - An error if the derivation fails.
// PulseHKDFPQSeed derives a fixed-length seed for ML-KEM key pair generation from
// an HD wallet node key.  It uses HKDF-Extract with a domain-separation salt and
// HKDF-Expand with a purpose-specific info string to produce `length` bytes of
// deterministic key material.
//
// Arguments:
//   - nodeKey: The raw private key bytes from the BIP-32 node (32 bytes).
//   - infoSuffix: Domain-separation label, e.g. "|pulse|pq|consent|v1|".
//   - length: Number of output bytes (64 for ML-KEM-768).
//
// Returns:
//   - A byte slice of the requested length.
//   - An error if derivation fails.
func PulseHKDFPQSeed(nodeKey []byte, infoSuffix string, length int) ([]byte, error) {
	// Extract step: use a fixed domain-separated salt
	salt := hash.PulseHashString("|pulse|pq|v1|seed-salt|")
	prk := hkdf.Extract(sha3.NewLegacyKeccak256, nodeKey, salt)

	// Expand step: info includes the domain label
	info := []byte(infoSuffix)
	seed := make([]byte, length)
	r := hkdf.Expand(sha3.NewLegacyKeccak256, prk, info)
	if _, err := r.Read(seed); err != nil {
		return nil, fmt.Errorf("HKDF expand for PQ seed: %w", err)
	}
	return seed, nil
}

func PulseHKDFECDH(sharedSecret []byte,
	transcript []byte,
	recipientId []byte,
	context []byte,
) ([]byte, []byte, error) {
	parentAlgo, purpose, suite := getSettings("ECDH")
	return pulseHKDFImp(sharedSecret, parentAlgo, transcript, purpose, suite, recipientId, context)
}

func getSettings(mode string) (string, string, string) {
	if mode == "Kyber" {
		return "kyber768", "keywrap-aes", "kyber768+hkdf-keccak256"
	}
	return "secp256k1", "aead:channel:", "ecdh-secp256k1+hkdf-keccak256"
}

// pulseHKDFImp is the internal implementation of the Pulse HKDF flow.
// It performs both the Extract and Expand steps of RFC 5869.
//
// Arguments:
//   - sharedSecret: The input keying material.
//   - parentAlgo: String identifying the exchange algorithm ("kyber768" or "secp256k1").
//   - transcript: Byte slice of the exchange transcript.
//   - purpose: String identifying the purpose of the key (e.g., "keywrap-aes").
//   - suite: String identifying the full cryptographic suite.
//   - recipientId: Binary identifier for the recipient.
//   - context: Binary context for the encryption.
//
// Returns:
//   - Derived AES key and nonce.
//   - Derived Pseudo-Random Key (PRK).
func pulseHKDFImp(sharedSecret []byte,
	parentAlgo string,
	transcript []byte,
	purpose string,
	suite string,
	recipientId []byte,
	context []byte) ([]byte, []byte, error) {

	keyInfo := createInfo(purpose, false, suite, recipientId, context)
	nonceInfo := createInfo(purpose, true, suite, recipientId, context)

	aesKey := make([]byte, symmetric.AESGCMKeySize)
	aesNonce := make([]byte, symmetric.AESGCMNonceSize)

	prk := pulseExtract(sharedSecret, parentAlgo, transcript)
	defer wipe.SliceWipe(prk)

	keyReader := hkdf.Expand(sha3.NewLegacyKeccak256, prk, keyInfo)
	nonceReader := hkdf.Expand(sha3.NewLegacyKeccak256, prk, nonceInfo)
	if _, err := keyReader.Read(aesKey); err != nil {

		return nil, nil, err
	}
	if _, err := nonceReader.Read(aesNonce); err != nil {
		wipe.SliceWipe(prk)
		return nil, nil, err
	}

	return aesKey, aesNonce, nil
}

func pulseExtract(sharedSecret []byte, parentAlgo string, transcript []byte) []byte {
	salt := createSalt(parentAlgo, transcript)
	return hkdf.Extract(sha3.NewLegacyKeccak256, sharedSecret, salt)
}

// createSalt constructs the salt for the HKDF Extract step.
// The salt is a Keccak-256 hash of a formatted string including the algorithm and transcript.
//
// Arguments:
//   - exchangeAlgo: The algorithm name.
//   - transcript: The transcript bytes.
//
// Returns:
//   - A 32-byte salt.
func createSalt(
	exchangeAlgo string,
	transcript []byte,
) []byte {
	return hash.PulseHashString(createSaltString(exchangeAlgo, transcript))
}

func createSaltString(exchangeAlgo string, transcript []byte) string {
	// TOOD: Add leading "|" for consistency
	return fmt.Sprintf("|pulse|kdf|v1|salt|%s|%s|", exchangeAlgo, textformat.FormatHex(transcript))
}

// createInfo constructs the info parameter for the HKDF Expand step.
// It ensures domain separation between key and nonce derivation.
//
// Arguments:
//   - purpose: String identifying the purpose.
//   - isNonce: Boolean indicating if this is for nonce derivation.
//   - suite: String identifying the cryptographic suite.
//   - recipientID: Identifier for the recipient.
//   - context: Binary context.
//
// Returns:
//   - Formatted info bytes.
func createInfo(purpose string,
	isNonce bool,
	suite string,
	recipientID []byte,
	context []byte,
) []byte {
	keyOrNonce := "key"
	if isNonce {
		keyOrNonce = "nonce"
	}
	contextHash := hash.PulseHashBytes(context)
	output := bytes.Buffer{}
	output.WriteString(fmt.Sprintf("|pulse|kdf|v1|%s%s|%s|rid=%s|ctx=", purpose, keyOrNonce, suite, textformat.FormatHex(recipientID)))
	output.WriteString(textformat.FormatHex(contextHash))
	output.WriteByte('|')

	return output.Bytes()
}
