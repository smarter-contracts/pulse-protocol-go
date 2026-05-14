// Package hkdf implements the Pulse Protocol's HKDF key derivation functions
// using RFC 5869 HMAC-based Extract-and-Expand with Keccak-256.  It supports
// three modes: ECDH (AES key + nonce from shared secret), Kyber (AES key +
// nonce from KEM shared secret), and PQSeed (64-byte ML-KEM seed from an HD
// wallet node key).
package hkdf

import (
	"bytes"
	"fmt"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/wipe"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// MLKEMSeedSize is the number of bytes required to deterministically derive an
// ML-KEM-768 key pair via scheme.DeriveKeyPair.  The seed is produced by a
// single HKDF-Expand call in PulseHKDFPQSeed.
const MLKEMSeedSize = 64

// This file implements the HKDF functions used by Pulse. We use an industry standard
// RFC5869 HMAC based HKDF. This wrapper handles:
//
// * Populating the Salt & Info values for Expand/Extract operations.
// * For AES mode: extracts a 32-byte AES-256 key and a 12-byte nonce.
// * For Seed mode: extracts a single block of key material (e.g. 64 bytes for ML-KEM).
//
// Hash Algorithm: keccak256 (consistent with the rest of the Pulse Protocol)
//
// Salt: Keccak256("|pulse|<function>|v1|salt|<algo>|<keccak256(transcript)>|")
//   - function is "kdf" for AES key derivation, or "seed" for PQ key pair generation
//   - algo is the key agreement algorithm ("kyber768" or "secp256k1")
//   - transcript binds the salt to the exchange context:
//     ECDH:   keccak256(sorted public keys)
//     Kyber:  encapsulated shared secret
//     PQSeed: compressed secp256k1 public key of the HD node
//
// Info: "|pulse|<function>|v1|<purpose><suffix>|<suite>|rid=<recipientId>|ctx=<keccak256(context)>|"
//   - For AES mode: suffix is "key" or "nonce" to domain-separate the two expansions
//   - For Seed mode: suffix is empty (single expansion)

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
//   - An error if the derivation fails.
func PulseHKDFKyber(sharedSecret []byte,
	transcript []byte,
	recipientId []byte,
	context []byte,
) ([]byte, []byte, error) {
	function, parentAlgo, purpose, suite := getSettings("Kyber")
	recipientIdStr := textformat.FormatHex(recipientId)
	return pulseHKDFImp(sharedSecret, function, parentAlgo, transcript, purpose, suite, recipientIdStr, context, symmetric.AESGCMKeySize, symmetric.AESGCMNonceSize)
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
//   - An error if the derivation fails.
func PulseHKDFECDH(sharedSecret []byte,
	transcript []byte,
	recipientId []byte,
	context []byte,
) ([]byte, []byte, error) {
	function, parentAlgo, purpose, suite := getSettings("ECDH")
	recipientIdStr := textformat.FormatHex(recipientId)
	return pulseHKDFImp(sharedSecret, function, parentAlgo, transcript, purpose, suite, recipientIdStr, context, symmetric.AESGCMKeySize, symmetric.AESGCMNonceSize)
}

// PulseHKDFPQSeed derives a 64-byte seed for ML-KEM-768 key pair generation from
// an HD wallet node key.  It follows the same Extract+Expand pattern as the AES
// derivation functions but produces a single block of key material instead of a
// separate key and nonce.
//
// Consent/revoke domain separation is not needed at the HKDF level because the
// HD wallet path already binds the purpose (9 or 10), so the nodeKey input is
// different for consent and revoke derivations.
//
// Arguments:
//   - nodeKey: The raw private key bytes from the BIP-32 node (32 bytes).
//   - transcript: The compressed secp256k1 public key of the HD node (33 bytes).
//   - recipientIdStr: The other party number as a decimal string (e.g. "2").
//   - context: The binary context (chainId, contract address, consent number).
//
// Returns:
//   - A 64-byte seed suitable for scheme.DeriveKeyPair.
//   - An error if derivation fails.
func PulseHKDFPQSeed(nodeKey []byte,
	transcript []byte,
	recipientIdStr string,
	context []byte,
) ([]byte, error) {
	function, parentAlgo, purpose, suite := getSettings("PQSeed")
	seed, _, err := pulseHKDFImp(nodeKey, function, parentAlgo, transcript, purpose, suite, recipientIdStr, context, MLKEMSeedSize, 0)
	return seed, err
}

// getSettings returns the protocol parameters for each HKDF mode.
//
// Returns: (function, parentAlgo, purpose, suite)
//   - function: "kdf" for AES key derivation, "seed" for PQ key pair generation
//   - parentAlgo: The key agreement algorithm name used in the salt
//   - purpose: The purpose label used in the info string
//   - suite: The full cryptographic suite identifier
func getSettings(mode string) (string, string, string, string) {
	switch mode {
	case "Kyber":
		return "kdf", "kyber768", "keywrap-aes", "kyber768+hkdf-keccak256"
	case "PQSeed":
		return "seed", "kyber768", "kyber-keygen", "kyber768+hkdf-keccak256"
	default: // ECDH
		return "kdf", "secp256k1", "aead:channel:", "ecdh-secp256k1+hkdf-keccak256"
	}
}

// pulseHKDFImp is the internal implementation of the Pulse HKDF flow.
// It performs both the Extract and Expand steps of RFC 5869.
//
// outputLength specifies the size of the first (or only) output block.
// output2Length controls whether a second block is produced:
//   - output2Length == 0: single expansion — returns (output1, nil, nil).
//     The info suffix is empty.
//   - output2Length > 0: dual expansion — returns (output1, output2, nil).
//     The first expansion uses suffix "key"; the second uses suffix "nonce".
func pulseHKDFImp(ikm []byte,
	function string,
	parentAlgo string,
	transcript []byte,
	purpose string,
	suite string,
	recipientIdStr string,
	context []byte,
	outputLength int,
	output2Length int,
) ([]byte, []byte, error) {

	prk := pulseExtract(ikm, function, parentAlgo, transcript)
	defer wipe.SliceWipe(prk)

	// Determine info suffix for the first expansion
	var suffix string
	if output2Length > 0 {
		suffix = "key"
	}

	info := createInfo(function, purpose, suffix, suite, recipientIdStr, context)
	output1 := make([]byte, outputLength)
	r := hkdf.Expand(sha3.NewLegacyKeccak256, prk, info)
	if _, err := r.Read(output1); err != nil {
		return nil, nil, fmt.Errorf("HKDF expand: %w", err)
	}

	if output2Length == 0 {
		return output1, nil, nil
	}

	// Second expansion with "nonce" suffix
	nonceInfo := createInfo(function, purpose, "nonce", suite, recipientIdStr, context)
	output2 := make([]byte, output2Length)
	nonceReader := hkdf.Expand(sha3.NewLegacyKeccak256, prk, nonceInfo)
	if _, err := nonceReader.Read(output2); err != nil {
		wipe.SliceWipe(output1)
		return nil, nil, err
	}

	return output1, output2, nil
}

func pulseExtract(ikm []byte, function string, parentAlgo string, transcript []byte) []byte {
	salt := createSalt(function, parentAlgo, transcript)
	return hkdf.Extract(sha3.NewLegacyKeccak256, ikm, salt)
}

// createSalt constructs the salt for the HKDF Extract step.
// The salt is a Keccak-256 hash of a formatted string including the function,
// algorithm, and transcript.
func createSalt(function string, exchangeAlgo string, transcript []byte) []byte {
	return hash.PulseHashString(createSaltString(function, exchangeAlgo, transcript))
}

func createSaltString(function string, exchangeAlgo string, transcript []byte) string {
	return fmt.Sprintf("|pulse|%s|v1|salt|%s|%s|", function, exchangeAlgo, textformat.FormatHex(transcript))
}

// createInfo constructs the info parameter for the HKDF Expand step.
// It ensures domain separation between different derivation contexts.
//
// For AES mode, suffix is "key" or "nonce" to separate the two expansions.
// For Seed mode, suffix is empty (single expansion).
func createInfo(function string,
	purpose string,
	suffix string,
	suite string,
	recipientIdStr string,
	context []byte,
) []byte {
	contextHash := hash.PulseHashBytes(context)
	output := bytes.Buffer{}
	output.WriteString(fmt.Sprintf("|pulse|%s|v1|%s%s|%s|rid=%s|ctx=", function, purpose, suffix, suite, recipientIdStr))
	output.WriteString(textformat.FormatHex(contextHash))
	output.WriteByte('|')

	return output.Bytes()
}
