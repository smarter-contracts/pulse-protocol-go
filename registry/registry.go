// Package registry defines the OtherPartyRegistry interface used by the Pulse
// Protocol crypto library.
//
// An OtherPartyRegistry maps human-readable identifiers (DIDs, Ethereum
// addresses, etc.) to the stable uint32 numbers used in Pulse HD wallet
// derivation paths, and tracks per-(otherPartyNo, chainId) consent sequence
// numbers.
package registry

import "errors"

// ErrNotFound is returned by Lookup when the identifier is not registered.
var ErrNotFound = errors.New("other party not found")

// OtherPartyRegistry maps human-readable other-party identifiers to the stable
// uint32 numbers used in Pulse HD wallet derivation, and tracks per-
// (otherPartyNo, chainId) consent sequence numbers.
//
// All methods must be safe for concurrent use.
type OtherPartyRegistry interface {
	// LookupOrCreate returns the stable uint32 number for identifier,
	// allocating a new sequential number if the identifier is not yet known.
	// The allocated number is guaranteed to be a valid non-hardened BIP-32
	// child index (< 0x80000000).
	LookupOrCreate(identifier string) (uint32, error)

	// Lookup returns the uint32 number for identifier.
	// Returns ErrNotFound if identifier has not been registered.
	Lookup(identifier string) (uint32, error)

	// NextConsentNumber returns the next consent sequence number for the
	// (otherPartyNo, chainId) pair and increments the internal counter.
	// Sequence numbers start at 0 and are non-hardened BIP-32 child indices
	// (< 0x80000000).
	NextConsentNumber(otherPartyNo uint32, chainId uint32) (uint32, error)
}
