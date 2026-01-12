package textformat

import (
	"encoding/hex"
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
