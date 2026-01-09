package hkdf

import (
	"bytes"
	"fmt"

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
// The algorithm output is a 32-byte AES-256 key.
func PulseHKDFKyber(sharedSecret []byte,
	transcriptHash []byte,
	recipientId []byte,
	context []byte,
) ([]byte, []byte, error) {
	parentAlgo := "kyber768"
	purpose := "keywrap-aes"
	suite := "kyber768+hkdf-keccak256"

	return pulseHKDFImp(sharedSecret, parentAlgo, transcriptHash, purpose, suite, recipientId, context)
}

func PulseHKDFECDH(sharedSecret []byte,
	transcriptHash []byte,
	recipientId []byte,
	context []byte,
) ([]byte, []byte, error) {
	parentAlgo := "secp256k1"
	purpose := "aead:channel:"
	suite := "ecdh-secp256k1+hkdf-keccak256"

	return pulseHKDFImp(sharedSecret, parentAlgo, transcriptHash, purpose, suite, recipientId, context)
}

func pulseHKDFImp(sharedSecret []byte,
	parentAlgo string,
	transcriptHash []byte,
	purpose string,
	suite string,
	recipientId []byte,
	context []byte) ([]byte, []byte, error) {

	salt := createSalt(parentAlgo, transcriptHash)

	keyInfo := createInfo(purpose, false, suite, recipientId, context)
	nonceInfo := createInfo(purpose, true, suite, recipientId, context)

	aesKey := make([]byte, symmetric.AESGCMKeySize)
	aesNonce := make([]byte, symmetric.AESGCMNonceSize)

	prk := hkdf.Extract(sha3.NewLegacyKeccak256, sharedSecret, salt)
	defer wipe.SliceWipe(prk)
	keyReader := hkdf.Expand(sha3.NewLegacyKeccak256, prk, keyInfo)
	nonceReader := hkdf.Expand(sha3.NewLegacyKeccak256, prk, nonceInfo)
	if _, err := keyReader.Read(aesKey); err != nil {
		return nil, nil, err
	}
	if _, err := nonceReader.Read(aesNonce); err != nil {
		return nil, nil, err
	}

	return aesKey, aesNonce, nil
}

func createSalt(
	exchangeAlgo string,
	transcriptHash []byte,
) []byte {
	saltString := fmt.Sprintf("pulse|kdf|v1|salt|%s|%s", exchangeAlgo, textformat.FormatHex(transcriptHash))
	outputHash := sha3.NewLegacyKeccak256()
	return outputHash.Sum([]byte(saltString))
}

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
	contextHash := sha3.NewLegacyKeccak256().Sum(context)
	output := bytes.Buffer{}
	output.WriteString(fmt.Sprintf("pulse|kdf|v1|%s%s|%s|rid=%x|ctx=", purpose, keyOrNonce, suite, recipientID))
	output.Write(contextHash[:])

	return output.Bytes()
}
