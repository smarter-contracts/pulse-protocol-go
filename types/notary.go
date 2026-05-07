package types

import "time"

// NotaryBlock contains metadata about the context in which a consent or revocation was given.
// It is encrypted alongside the consent payload and provides an auditable record of the
// circumstances of the transaction (IP address, timestamp, etc.).
//
// The NotaryBlock is encrypted using ECDH between the grantor's purpose-2 key and the
// Mid-Tier notary public key, so only Mid-Tier can decrypt it. The encrypted bytes are
// embedded in the consent record before the outer participant encryption is applied.
type NotaryBlock struct {
	// Timestamp is the moment consent was given (UTC).
	Timestamp time.Time `json:"timestamp" cbor:"ts"`
	// IPAddress is the client IP address at the time of consent.
	IPAddress string    `json:"ipAddress" cbor:"ip"`
	// UserAgent is the HTTP User-Agent string of the client at the time of consent.
	UserAgent string    `json:"userAgent" cbor:"ua"`
	// Location is a geographic hint such as an ISO 3166-1 alpha-2 country code (e.g. "GB").
	Location  string    `json:"location"  cbor:"loc"`
}
