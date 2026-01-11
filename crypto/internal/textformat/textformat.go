package textformat

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// textformat contains common functions for formatting components of AES AAD, HKDF Info and Salt strings.
//
// We want the strings to be human readable, so the general approach is:
//
//  -- Long blocks of data are hashed ( with Keccak ) to shorten down to 32 bytes of data
//  -- All binary data is hex encoded using no 0x, and all lowercase letters.
//
// Yes, hex encoding binary data is not the most space efficient approach, but it is easier to read/debug,
// and we shouldn't be sending any of these strings over the wire...

// FormatHex converts a byte slice into a lowercase hexadecimal string without the "0x" prefix.
// This is used for human-readable domain separation in AAD and HKDF info strings.
//
// Arguments:
//   - b: The byte slice to encode.
//
// Returns:
//   - A hexadecimal string representation of the input.
func FormatHex(b []byte) string {
	return hex.EncodeToString(b)
}

// ContextString builds a human-readable string representing the encryption context.
// It includes the chain ID, contract address, and consent number.
//
// Arguments:
//   - chainId: The blockchain network identifier.
//   - contractAddress: The Ethereum-style hex address of the contract.
//   - consentNumber: The sequence number or identifier for the specific consent record.
//
// Returns:
//   - A formatted context string.
func ContextString(chainId int32,
	contractAddress string,
	consentNumber int32,
) string {
	return fmt.Sprintf("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d",
		chainId, contractAddress, consentNumber)
}

// ContextHash computes a Keccak-256 hash of the context string.
// This hash is used in AAD and HKDF salt/info for domain separation.
//
// Arguments:
//   - chainId: The blockchain network identifier.
//   - contractAddress: The Ethereum-style hex address of the contract.
//   - consentNumber: The sequence number for the specific consent record.
//
// Returns:
//   - A 32-byte Keccak-256 hash of the context string.
func ContextHash(chainId int32,
	contractAddress string,
	consentNumber int32,
) []byte {

	hash := sha3.NewLegacyKeccak256()
	return hash.Sum([]byte(ContextString(chainId, contractAddress, consentNumber)))
}
