// Package feedrevocation defines the revoke payload type for Feed Permission consents.
package feedrevocation

// Type is the payload type discriminator for Feed Permission revocations.
const Type = "feed-revocation"

// FeedRevocationPayload is the unencrypted revoke payload that signals the
// withdrawal of a previously granted Feed Permission consent.
//
// It is encrypted to the grantor using the grantee's HD purpose-5 key and
// signed (binding the revoke CID to the original grant CID) before submission
// to mid-tier.
//
// The type and version discriminators are written to CBOR by the marshaller
// rather than stored as struct fields.
type FeedRevocationPayload struct {
	// GrantCID is the IPFS CID of the original consent's encrypted-data CBOR,
	// binding this revocation to a specific grant.
	GrantCID string `json:"grantCid"        cbor:"gcid"`

	// RevokerId is the DID or WebID of the party initiating the revocation.
	RevokerId string `json:"revokerId"       cbor:"rid"`

	// IssuedAt is the Unix timestamp (seconds) when this revocation was created.
	IssuedAt int64 `json:"issuedAt"        cbor:"iat"`

	// EncryptedNotary is the AES-256-GCM ciphertext of the NotaryBlock (nonce
	// prepended), sealed for the Mid-Tier notary key using ECDH with the
	// grantee's purpose-4 key.
	EncryptedNotary []byte `json:"encryptedNotary" cbor:"en"`

	// NotaryKey1 is the 33-byte compressed secp256k1 public key of the grantee's
	// ephemeral purpose-4 key used to seal the NotaryBlock.
	NotaryKey1 []byte `json:"notaryKey1"      cbor:"nk1"`

	// NotaryKey2 is the 33-byte compressed secp256k1 public key of the Mid-Tier
	// notary, used as the recipient key when sealing the NotaryBlock.
	NotaryKey2 []byte `json:"notaryKey2"      cbor:"nk2"`
}
