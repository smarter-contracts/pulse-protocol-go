package registry

import (
	"fmt"
	"sync"
)

// maxNormalIndex is the largest valid non-hardened BIP-32 child index.
const maxNormalIndex uint32 = 0x7fffffff

type consentKey struct {
	otherPartyNo uint32
	chainId      uint32
}

// MemoryRegistry is a thread-safe in-memory reference implementation of
// OtherPartyRegistry.  It is intended for testing and development; production
// deployments should use a persistent backend.
type MemoryRegistry struct {
	mu              sync.Mutex
	identifiers     map[string]uint32
	nextPartyNo     uint32
	consentCounters map[consentKey]uint32
}

// NewMemoryRegistry returns a new, empty MemoryRegistry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{
		identifiers:     make(map[string]uint32),
		consentCounters: make(map[consentKey]uint32),
	}
}

// LookupOrCreate returns the uint32 number for identifier, allocating a new
// sequential number if the identifier has not been seen before.
func (r *MemoryRegistry) LookupOrCreate(identifier string) (uint32, error) {
	if identifier == "" {
		return 0, fmt.Errorf("identifier must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if n, ok := r.identifiers[identifier]; ok {
		return n, nil
	}
	if r.nextPartyNo > maxNormalIndex {
		return 0, fmt.Errorf("other party number space exhausted (max %d)", maxNormalIndex)
	}
	n := r.nextPartyNo
	r.nextPartyNo++
	r.identifiers[identifier] = n
	return n, nil
}

// Lookup returns the uint32 number for identifier.
// Returns ErrNotFound if identifier has not been registered.
func (r *MemoryRegistry) Lookup(identifier string) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if n, ok := r.identifiers[identifier]; ok {
		return n, nil
	}
	return 0, ErrNotFound
}

// NextConsentNumber returns the next consent sequence number for the
// (otherPartyNo, chainId) pair and increments the internal counter.
// Sequence numbers start at 0.
func (r *MemoryRegistry) NextConsentNumber(otherPartyNo uint32, chainId uint32) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	k := consentKey{otherPartyNo, chainId}
	n := r.consentCounters[k]
	if n > maxNormalIndex {
		return 0, fmt.Errorf("consent number space exhausted for otherParty=%d chain=%d", otherPartyNo, chainId)
	}
	r.consentCounters[k] = n + 1
	return n, nil
}
