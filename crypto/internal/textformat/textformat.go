// Package textformat provides common functions for formatting components of
// AES AAD, HKDF Info and Salt strings.
//
// The strings are designed to be human-readable, so the general approach is:
//
//   - Long blocks of data are hashed (with Keccak) to shorten down to 32 bytes
//   - All binary data is hex encoded using no 0x prefix, and all lowercase letters
//
// Hex encoding binary data is not the most space-efficient approach, but it is
// easier to read and debug, and these strings are not sent over the wire.
package textformat

import (
	"encoding/hex"
)

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
