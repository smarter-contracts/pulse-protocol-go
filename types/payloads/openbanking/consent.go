// Package openbanking defines consent payload types for Open Banking use cases.
package openbanking

import "github.com/smarter-contracts/pulse-protocol-go/types/payloads"

// Type is the payload type discriminator for Open Banking consents.
const Type = "openbanking"

// OpenBankingConsentPayload is the unencrypted consent payload for Open Banking
// data sharing permissions. It embeds ConsentPayloadHeader so that Type and Version
// are always present and readable after decryption.
//
// Note: field definitions are a stub. Open Banking specific fields (account IDs,
// permissions, expiry, etc.) will be added in a later phase.
type OpenBankingConsentPayload struct {
	payloads.ConsentPayloadHeader

	// TODO: define Open Banking specific fields, e.g.:
	// AccountIDs          []string  `json:"accountIds"`
	// Permissions         []string  `json:"permissions"`
	// ExpirationDateTime  time.Time `json:"expirationDateTime"`
	// TransactionFromDate time.Time `json:"transactionFromDate"`
	// TransactionToDate   time.Time `json:"transactionToDate"`
}
