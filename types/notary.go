package types

import "time"

// NotaryBlock contains metadata about the context in which a consent or revocation was given.
// It is encrypted alongside the consent payload and provides an auditable record of the
// circumstances of the transaction (IP address, timestamp, etc.).
//
// The NotaryBlock is encrypted using ECDH between the Grantor's key and the Mid-Tier's
// Notary Public Key, so only the Mid-Tier can decrypt it. The encrypted block is embedded
// in the consent or revoke record before the outer participant encryption is applied.
//
// All fields are optional — the parties decide which contextual fields to include.
//
// Note: this is a stub implementation. Fields will be expanded in a later phase once the
// full notary requirements are defined.
type NotaryBlock struct {
	Timestamp time.Time `json:"timestamp" cbor:"ts"`
	IPAddress string    `json:"ipAddress" cbor:"ip"`
	UserAgent string    `json:"userAgent" cbor:"ua"`
	Location  string    `json:"location"  cbor:"loc"`
}
