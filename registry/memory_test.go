package registry

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── LookupOrCreate ────────────────────────────────────────────────────────────

func TestMemoryRegistry_LookupOrCreate_AllocatesSequentially(t *testing.T) {
	r := NewMemoryRegistry()

	n0, err := r.LookupOrCreate("did:example:alice")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), n0)

	n1, err := r.LookupOrCreate("did:example:bob")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), n1)

	n2, err := r.LookupOrCreate("did:example:carol")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), n2)
}

func TestMemoryRegistry_LookupOrCreate_Idempotent(t *testing.T) {
	r := NewMemoryRegistry()

	n1, err := r.LookupOrCreate("did:example:alice")
	require.NoError(t, err)

	n2, err := r.LookupOrCreate("did:example:alice")
	require.NoError(t, err)

	assert.Equal(t, n1, n2)
	// Counter must not have advanced
	n3, err := r.LookupOrCreate("did:example:bob")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), n3)
}

func TestMemoryRegistry_LookupOrCreate_EmptyIdentifier(t *testing.T) {
	r := NewMemoryRegistry()
	_, err := r.LookupOrCreate("")
	assert.Error(t, err)
}

func TestMemoryRegistry_LookupOrCreate_NumberBelowHardenedBoundary(t *testing.T) {
	r := NewMemoryRegistry()
	n, err := r.LookupOrCreate("did:example:alice")
	require.NoError(t, err)
	assert.Less(t, n, uint32(0x80000000))
}

// ── Lookup ────────────────────────────────────────────────────────────────────

func TestMemoryRegistry_Lookup_ReturnsCorrectNumber(t *testing.T) {
	r := NewMemoryRegistry()
	expected, err := r.LookupOrCreate("did:example:alice")
	require.NoError(t, err)

	got, err := r.Lookup("did:example:alice")
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestMemoryRegistry_Lookup_NotFound(t *testing.T) {
	r := NewMemoryRegistry()
	_, err := r.Lookup("did:example:unknown")
	assert.True(t, errors.Is(err, ErrNotFound))
}

// ── NextConsentNumber ─────────────────────────────────────────────────────────

func TestMemoryRegistry_NextConsentNumber_StartsAtZero(t *testing.T) {
	r := NewMemoryRegistry()
	n, err := r.NextConsentNumber(0, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), n)
}

func TestMemoryRegistry_NextConsentNumber_Increments(t *testing.T) {
	r := NewMemoryRegistry()
	for i := uint32(0); i < 5; i++ {
		n, err := r.NextConsentNumber(0, 1)
		require.NoError(t, err)
		assert.Equal(t, i, n)
	}
}

func TestMemoryRegistry_NextConsentNumber_IndependentPerChain(t *testing.T) {
	r := NewMemoryRegistry()

	// Advance chain 1 twice
	_, _ = r.NextConsentNumber(0, 1)
	_, _ = r.NextConsentNumber(0, 1)
	n1, err := r.NextConsentNumber(0, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), n1)

	// Chain 2 should still start at 0
	n2, err := r.NextConsentNumber(0, 137)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), n2)
}

func TestMemoryRegistry_NextConsentNumber_IndependentPerOtherParty(t *testing.T) {
	r := NewMemoryRegistry()

	// Advance otherParty 0, chain 1 three times
	_, _ = r.NextConsentNumber(0, 1)
	_, _ = r.NextConsentNumber(0, 1)
	_, _ = r.NextConsentNumber(0, 1)

	// otherParty 1, same chain should start at 0
	n, err := r.NextConsentNumber(1, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), n)
}

func TestMemoryRegistry_NextConsentNumber_BelowHardenedBoundary(t *testing.T) {
	r := NewMemoryRegistry()
	n, err := r.NextConsentNumber(0, 1)
	require.NoError(t, err)
	assert.Less(t, n, uint32(0x80000000))
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestMemoryRegistry_Concurrent_LookupOrCreate(t *testing.T) {
	r := NewMemoryRegistry()
	const goroutines = 50
	identifiers := make([]string, goroutines)
	for i := range identifiers {
		identifiers[i] = "did:example:party" + string(rune('A'+i%26))
	}

	var wg sync.WaitGroup
	results := make([]uint32, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = r.LookupOrCreate(identifiers[idx])
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}
}

func TestMemoryRegistry_Concurrent_NextConsentNumber(t *testing.T) {
	r := NewMemoryRegistry()
	const goroutines = 100

	var wg sync.WaitGroup
	results := make([]uint32, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = r.NextConsentNumber(0, 1)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d", i)
	}

	// All 100 numbers must be distinct and in [0, 99]
	seen := make(map[uint32]bool)
	for _, n := range results {
		assert.False(t, seen[n], "duplicate consent number %d", n)
		seen[n] = true
	}
	assert.Len(t, seen, goroutines)
}

// ── Interface satisfaction ────────────────────────────────────────────────────

func TestMemoryRegistry_ImplementsInterface(t *testing.T) {
	var _ OtherPartyRegistry = (*MemoryRegistry)(nil)
}
