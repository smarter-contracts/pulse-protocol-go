// Package feedpermission defines the consent payload type for Feed Permission consents.
package feedpermission

// Type is the payload type discriminator for Feed Permission consents.
const Type = "feed-permission"

// FeedPermissionPayload is the unencrypted consent payload that grants an external
// feed service permission to write data to a specific container in the grantor's
// Solid pod.
//
// The pod container path is constrained to "pulse/feeds/{feedType}/" to ensure
// that external services can only write to designated feed containers.
//
// The type and version discriminators are written to CBOR by the marshaller rather
// than stored as struct fields; any party that decrypts the record can read "t"
// and "v" before deserialising the remaining fields.
type FeedPermissionPayload struct {
	// ConsentNo is the sequence number assigned by the grantor's proxy for this consent
	// within the grantor–counterparty pair. Used as part of the HD key derivation path.
	ConsentNo        uint32   `json:"consentNo"        cbor:"cn"`
	// WalletId identifies the grantor's wallet that issued this consent.
	WalletId         string   `json:"walletId"         cbor:"wid"`
	// GrantorWebId is the WebID URI of the data owner granting consent.
	GrantorWebId     string   `json:"grantorWebId"     cbor:"gwid"`
	// CounterpartyDid is the DID of the grantee receiving permission.
	CounterpartyDid  string   `json:"counterpartyDid"  cbor:"cpd"`
	// FeedType identifies the category of data feed being granted (e.g. "open-banking").
	FeedType         string   `json:"feedType"         cbor:"ft"`
	// PodContainerPath is the Solid pod container the grantee may write to.
	// Must be "pulse/feeds/{feedType}/".
	PodContainerPath string   `json:"podContainerPath" cbor:"pcp"`
	// Permissions lists the access modes granted (e.g. ["read", "write"]).
	Permissions      []string `json:"permissions"      cbor:"pm"`
	// DataCategories lists the data categories covered by this consent (e.g. ["transaction-history"]).
	DataCategories   []string `json:"dataCategories"   cbor:"dc"`
	// IssuedAt is the Unix timestamp (seconds) when this consent was created.
	IssuedAt         int64    `json:"issuedAt"         cbor:"iat"`
	// ExpiresAt is the Unix timestamp (seconds) when this consent expires. 0 means no expiry.
	ExpiresAt        int64    `json:"expiresAt"        cbor:"exp"`
	// EncryptedNotary is the AES-256-GCM ciphertext of the NotaryBlock (nonce prepended),
	// sealed for the Mid-Tier notary key using ECDH with the grantor's purpose-2 key.
	EncryptedNotary  []byte   `json:"encryptedNotary"  cbor:"en"`
	// NotaryKey1 is the 33-byte compressed secp256k1 public key of the grantor's ephemeral
	// purpose-2 key used to seal the NotaryBlock.
	NotaryKey1       []byte   `json:"notaryKey1"       cbor:"nk1"`
	// NotaryKey2 is the 33-byte compressed secp256k1 public key of the Mid-Tier notary,
	// used as the recipient key when sealing the NotaryBlock.
	NotaryKey2       []byte   `json:"notaryKey2"       cbor:"nk2"`
}
