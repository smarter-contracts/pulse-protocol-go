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
	Timestamp time.Time `json:"timestamp" cbor:"ts"`
	IPAddress string    `json:"ipAddress" cbor:"ip"`
	UserAgent string    `json:"userAgent" cbor:"ua"`
	Location  string    `json:"location"  cbor:"loc"`
}
