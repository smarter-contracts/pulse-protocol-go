package randutil

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
)

// Read fills the provided byte slice with cryptographically secure random bytes.
// It uses the provided reader as the source of entropy. If the reader is nil,
// it defaults to crypto/rand.Reader.
//
// Arguments:
//   - r: The entropy source (if nil, uses crypto/rand.Reader).
//   - b: The byte slice to fill.
//
// Returns:
//   - An error if the read operation fails.
func Read(r io.Reader, b []byte) error {
	if r == nil {
		r = rand.Reader
	}
	_, err := io.ReadFull(r, b)
	return err
}

// Bytes generates and returns a slice of n random bytes using the provided reader.
// If the reader is nil, it defaults to crypto/rand.Reader.
//
// Arguments:
//   - r: The entropy source (if nil, uses crypto/rand.Reader).
//   - n: The number of bytes to generate.
//
// Returns:
//   - A slice containing the random bytes.
//   - An error if the generation fails.
func Bytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	return b, Read(r, b)
}

// MustBytes is a wrapper around Bytes that panics if an error occurs.
//
// Arguments:
//   - r: The entropy source (if nil, uses crypto/rand.Reader).
//   - n: The number of bytes to generate.
//
// Returns:
//   - A slice containing the random bytes.
func MustBytes(r io.Reader, n int) []byte {
	b, err := Bytes(r, n)
	if err != nil {
		panic(err)
	}
	return b
}

// Uint64 returns a uniformly distributed, cryptographically secure random uint64.
//
// Arguments:
//   - r: The entropy source (if nil, uses crypto/rand.Reader).
//
// Returns:
//   - A random uint64 value.
//   - An error if the generation fails.
func Uint64(r io.Reader) (uint64, error) {
	var b [8]byte
	if err := Read(r, b[:]); err != nil {
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
// It uses the provided reader for generation.
//
// Arguments:
//   - r: The entropy source (if nil, uses crypto/rand.Reader).
//   - max: The upper bound (exclusive), must be > 0.
//
// Returns:
//   - A pointer to the generated random big.Int.
//   - An error if the generation fails.
func BigInt(r io.Reader, max *big.Int) (*big.Int, error) {
	if r == nil {
		r = rand.Reader
	}
	return rand.Int(r, max)
}

// StringURLSafe generates n random bytes and returns them as a URL-safe base64 string without padding.
//
// Arguments:
//   - r: The entropy source (if nil, uses crypto/rand.Reader).
//   - n: The number of random bytes to generate before encoding.
//
// Returns:
//   - A base64raw-URL encoded string.
//   - An error if byte generation fails.
func StringURLSafe(r io.Reader, n int) (string, error) {
	b, err := Bytes(r, n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
