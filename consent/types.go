package consent

import (
	"time"

	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// TransactionStatus represents the status string sent by mid-tier in a callback.
// Grant and revoke transactions use distinct prefixes so the type can be inferred
// from the status alone; the CallbackRequest.Type field confirms it.
type TransactionStatus string

const (
	// Grant transaction statuses (no prefix).
	TransactionStatusPending   TransactionStatus = "pending"
	TransactionStatusIPFSLive  TransactionStatus = "ipfs_live"
	TransactionStatusSubmitted TransactionStatus = "submitted"
	TransactionStatusConfirmed TransactionStatus = "confirmed"
	TransactionStatusRejected  TransactionStatus = "rejected"
	TransactionStatusDelayed   TransactionStatus = "delayed"

	// Revoke transaction statuses (rev_ prefix).
	TransactionStatusRevPending   TransactionStatus = "rev_pending"
	TransactionStatusRevIPFSLive  TransactionStatus = "rev_ipfs_live"
	TransactionStatusRevSubmitted TransactionStatus = "rev_submitted"
	TransactionStatusRevConfirmed TransactionStatus = "rev_confirmed"
)

// TransactionType distinguishes grant from revoke callbacks.
type TransactionType string

const (
	TransactionTypeGrant  TransactionType = "grant"
	TransactionTypeRevoke TransactionType = "revoke"
)

// ConsentStatus is the lifecycle state of a ConsentRecord.
type ConsentStatus string

const (
	// ConsentStatusPendingReview is set when the ConsentReviewer returns Defer.
	// The record awaits a call to ApproveConsent or RejectConsent.
	ConsentStatusPendingReview ConsentStatus = "pending-review"

	// ConsentStatusPending is set once the consent is approved and submitted to
	// mid-tier, but the on-chain transaction has not yet confirmed.
	ConsentStatusPending ConsentStatus = "pending"

	// ConsentStatusActive is set when mid-tier confirms the on-chain transaction.
	ConsentStatusActive ConsentStatus = "active"

	// ConsentStatusRevoked is terminal: the consent has been revoked and confirmed on-chain.
	// Set when HandleTransactionCallback receives a rev_confirmed callback.
	ConsentStatusRevoked ConsentStatus = "revoked"

	// ConsentStatusRejected is terminal: the ConsentReviewer or app rejected the consent.
	ConsentStatusRejected ConsentStatus = "rejected"

	// ConsentStatusExpired is returned by CheckConsent when the record is Active but
	// ExpiresAt has passed. It is not stored; expiry is evaluated at read time.
	ConsentStatusExpired ConsentStatus = "expired"

	// ConsentStatusNotFound is returned by CheckConsent when no matching record exists.
	ConsentStatusNotFound ConsentStatus = "not-found"
)

// ReviewDecision is the outcome returned by ConsentReviewer.Review.
type ReviewDecision string

const (
	ReviewDecisionAccept ReviewDecision = "accept"
	ReviewDecisionReject ReviewDecision = "reject"
	// ReviewDecisionDefer stores the record as pending-review for later approval.
	ReviewDecisionDefer ReviewDecision = "defer"
)

// ConsentRecord is the primary entity managed by the library. It holds both the
// decrypted payload (for fast reads) and the sealed bytes (for IPFS submission).
type ConsentRecord struct {
	ID          string
	PartyKey    string // DID, WebID, or future multi-party concat key
	FeedType    string
	Status      ConsentStatus
	ConsentNo   int
	ChainID     int
	CID         string     // grant IPFS CID; empty until grant ipfs_live callback
	RevokeCID   string     // revoke IPFS CID; empty until rev_ipfs_live callback
	ExpiresAt   *time.Time // nil means no expiry
	Payload     *feedpermission.FeedPermissionPayload // decrypted; nil until ingest succeeds
	SealedBytes []byte   // DAG-CBOR wrapper of {SealedData, Key1, Key2}; used for CID computation
	SealedData  []byte   // raw AES-256-GCM ciphertext sent to mid-tier in the grant body
	Keys        [][]byte // EC: [Key1, Key2]; ordered for correct array reconstruction
	Signatures  [][]byte // EIP-191 signatures over the consent CID; ordered by signer
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RevokeRecord carries the signed revocation payload for SubmitRevoke.
type RevokeRecord struct {
	ConsentID   string
	PartyKey    string
	GrantCID    string // IPFS CID of the grant being revoked
	SealedBytes []byte // outer-encrypted revoke record
	Signature   []byte // EIP-191 signature over the revoke payload
}

// ConsentEvent is a single entry returned by MidTierClient.GetConsentsSince.
// It represents either a grant or a revoke transaction at a particular pipeline stage.
type ConsentEvent struct {
	ConsentID   string
	PartyKey    string
	Type        TransactionType
	Status      TransactionStatus
	CID         string
	BlockNumber uint64
	TxIndex     uint
	Cursor      string // opaque; becomes the new sync cursor after processing
}

// TransactionUpdateEvent is delivered to EventHandler.OnTransactionUpdate at each
// pipeline stage for both grant and revoke transactions.
type TransactionUpdateEvent struct {
	ConsentID string
	Type      TransactionType
	Status    TransactionStatus
	CID       string
}

// ConsentRevokedEvent is delivered to EventHandler.OnConsentRevoked once when a
// revoke transaction reaches Confirmed.
type ConsentRevokedEvent struct {
	ConsentID string
	PartyKey  string
	CID       string // CID of the revoke record on IPFS
}

// ConsentCheckResult is returned by ConsentEngine.CheckConsent.
type ConsentCheckResult struct {
	Status    ConsentStatus
	Payload   *feedpermission.FeedPermissionPayload // non-nil only when Status is Active
	ExpiresAt *time.Time
}

// InboundConsentRequest carries the sealed record received from the network
// alongside the routing context required to locate the correct decryption keys.
type InboundConsentRequest struct {
	PartyKey   string   // counterparty identifier
	ChainID    int
	ConsentNo  int
	SealedData []byte   // raw AES-256-GCM ciphertext
	Key1       []byte   // grantor ephemeral public key (purpose 3)
	Key2       []byte   // recipient public key (purpose 3)
	Signatures [][]byte // EIP-191 signatures from the initiating party
}

// InboundConsentResponse is returned by ConsentEngine.HandleInboundConsent.
type InboundConsentResponse struct {
	ConsentID string
	Decision  ReviewDecision
}

// XpubResponse is returned by ConsentEngine.HandleXpubRequest.
type XpubResponse struct {
	Xpub         string
	OtherpartyId int
}

// CallbackRequest is passed to ConsentEngine.HandleTransactionCallback by the
// application's HTTP handler when mid-tier delivers a progress update.
type CallbackRequest struct {
	ConsentID string
	Type      TransactionType
	Status    TransactionStatus
	CID       string
}
