package randutil

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestRead_ZeroLenOK(t *testing.T) {
	var b []byte
	if err := Read(b); err != nil {
		t.Fatalf("Read(0) error: %v", err)
	}
}

func TestBytes_LengthAndUniqueness(t *testing.T) {
	const n = 32
	b1, err := Bytes(n)
	if err != nil {
		t.Fatalf("Bytes(%d) error: %v", n, err)
	}
	if len(b1) != n {
		t.Fatalf("Bytes length: want %d got %d", n, len(b1))
	}
	b2, err := Bytes(n)
	if err != nil {
		t.Fatalf("Bytes(%d) 2nd error: %v", n, err)
	}
	if len(b2) != n {
		t.Fatalf("Bytes length 2nd: want %d got %d", n, len(b2))
	}
	// Extremely unlikely to be equal if randomness is working.
	if string(b1) == string(b2) {
		t.Fatalf("two random byte slices unexpectedly equal")
	}
}

func TestMustBytes_Length(t *testing.T) {
	const n = 16
	b := MustBytes(n)
	if len(b) != n {
		t.Fatalf("MustBytes length: want %d got %d", n, len(b))
	}
}

func TestUint64_Uniqueness(t *testing.T) {
	u1, err := Uint64()
	if err != nil {
		t.Fatalf("Uint64 error: %v", err)
	}
	u2, err := Uint64()
	if err != nil {
		t.Fatalf("Uint64 2nd error: %v", err)
	}
	if u1 == u2 {
		t.Fatalf("two random uint64 values unexpectedly equal: %d", u1)
	}
}

func TestBigInt_Range(t *testing.T) {
	max := big.NewInt(1000)
	for i := 0; i < 100; i++ {
		v, err := BigInt(max)
		if err != nil {
			t.Fatalf("BigInt error: %v", err)
		}
		if v.Sign() < 0 || v.Cmp(max) >= 0 {
			t.Fatalf("BigInt out of range: got %v, want in [0,%v)", v, max)
		}
	}
}

func TestStringURLSafe_LengthAndAlphabet(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 15, 16, 32} {
		s, err := StringURLSafe(n)
		if err != nil {
			t.Fatalf("StringURLSafe(%d) error: %v", n, err)
		}
		wantLen := base64.RawURLEncoding.EncodedLen(n)
		if len(s) != wantLen {
			t.Fatalf("StringURLSafe len for n=%d: want %d got %d", n, wantLen, len(s))
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !isB64URLChar(c) {
				t.Fatalf("StringURLSafe produced non-URL-safe char %q (0x%x) at pos %d", c, c, i)
			}
		}
	}
}

func isB64URLChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	}
	return false
}
