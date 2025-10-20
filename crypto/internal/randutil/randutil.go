package randutil

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
)

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}

// Bytes returns n random bytes.
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	return b, Read(b)
}

// MustBytes panics on error. Handy in tests or init paths.
func MustBytes(n int) []byte {
	b, err := Bytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

// Uint64 returns a uniformly random uint64.
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

// BigInt returns a uniform random integer in [0, max) using crypto/rand.Int.
// max must be > 0.
func BigInt(max *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}

// StringURLSafe returns n random bytes, base64url (no padding) encoded.
// Good for tokens/IDs.
func StringURLSafe(n int) (string, error) {
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
