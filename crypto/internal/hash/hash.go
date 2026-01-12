package hash

// hash contains functions that carry out a Keecak256 hash on the given data.

import "golang.org/x/crypto/sha3"

// PulseHashBytes computes a Keccak-256 hash of the provided byte slice.
// This is a standard hashing function used across the Pulse Protocol for data integrity
// and identifier generation.
//
// Arguments:
//   - data: The byte slice to be hashed.
//
// Returns:
//   - A 32-byte Keccak-256 hash.
func PulseHashBytes(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// PulseHashString computes a Keccak-256 hash of the provided string.
// It converts the string to bytes and delegates to PulseHashBytes.
//
// Arguments:
//   - data: The string to be hashed.
//
// Returns:
//   - A 32-byte Keccak-256 hash.
func PulseHashString(data string) []byte {
	return PulseHashBytes([]byte(data))
}
