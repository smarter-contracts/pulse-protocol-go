package randutil

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
)

// Read fills the provided byte slice with cryptographically secure random bytes.
// It uses crypto/rand.Reader as the source of entropy.
//
// Arguments:
//   - b: The byte slice to fill.
//
// Returns:
//   - An error if the read operation fails.
func Read(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}

// Bytes generates and returns a slice of n cryptographically secure random bytes.
//
// Arguments:
//   - n: The number of bytes to generate.
//
// Returns:
//   - A slice containing the random bytes.
//   - An error if the generation fails.
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	return b, Read(b)
}

// MustBytes is a wrapper around Bytes that panics if an error occurs.
// It is intended for use in tests or during initialization where failure is not expected.
//
// Arguments:
//   - n: The number of bytes to generate.
//
// Returns:
//   - A slice containing the random bytes.
func MustBytes(n int) []byte {
	b, err := Bytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

// Uint64 returns a uniformly distributed, cryptographically secure random uint64.
//
// Returns:
//   - A random uint64 value.
//   - An error if the generation fails.
func Uint64() (uint64, error) {
	var b [8]byte
	if err := Read(b[:]); err != nil {
		return 0, err
	}
	// Little-endian decode
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56, nil
}

// BigInt returns a uniform random integer in the range [0, max).
// It uses crypto/rand.Int for generation.
//
// Arguments:
//   - max: The upper bound (exclusive), must be > 0.
//
// Returns:
//   - A pointer to the generated random big.Int.
//   - An error if the generation fails.
func BigInt(max *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}

// StringURLSafe generates n random bytes and returns them as a URL-safe base64 string without padding.
// This is suitable for generating tokens, session IDs, or other identifiers.
//
// Arguments:
//   - n: The number of random bytes to generate before encoding.
//
// Returns:
//   - A base64raw-URL encoded string.
//   - An error if byte generation fails.
func StringURLSafe(n int) (string, error) {
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
