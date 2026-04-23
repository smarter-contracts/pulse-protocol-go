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
	ConsentNo        uint32   `json:"consentNo"        cbor:"cn"`
	WalletId         string   `json:"walletId"         cbor:"wid"`
	GrantorWebId     string   `json:"grantorWebId"     cbor:"gwid"`
	CounterpartyDid  string   `json:"counterpartyDid"  cbor:"cpd"`
	FeedType         string   `json:"feedType"         cbor:"ft"`
	PodContainerPath string   `json:"podContainerPath" cbor:"pcp"` // must be "pulse/feeds/{feedType}/"
	Permissions      []string `json:"permissions"      cbor:"pm"`
	DataCategories   []string `json:"dataCategories"   cbor:"dc"`
	IssuedAt         int64    `json:"issuedAt"         cbor:"iat"` // Unix seconds
	ExpiresAt        int64    `json:"expiresAt"        cbor:"exp"` // Unix seconds; 0 = no expiry
	EncryptedNotary  []byte   `json:"encryptedNotary"  cbor:"en"`
	NotaryKey1       []byte   `json:"notaryKey1"       cbor:"nk1"` // 33-byte compressed secp256k1
	NotaryKey2       []byte   `json:"notaryKey2"       cbor:"nk2"` // 33-byte compressed secp256k1
}
