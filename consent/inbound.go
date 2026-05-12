package consent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// HandleInboundConsent decrypts, validates, reviews, and stores an inbound
// consent request received from a counterparty via mid-tier.
//
// Sequence:
//  1. CounterpartyDirectory.GetOrAssignIndex(req.PartyKey) → otherpartyId
//  2. ppcrypto.DecryptConsentEC(wallet, consentReq, ...) → raw CBOR bytes
//  3. UnmarshalFeedPermission(cbor) → FeedPermissionPayload
//  4. Validate (expiry)
//  5. ConsentReviewer.Review → decision
//  6. Store record at appropriate status; if Accept → MidTierClient.SubmitGrant
func (e *ConsentEngine) HandleInboundConsent(ctx context.Context, req InboundConsentRequest) (InboundConsentResponse, error) {
	otherpartyId, err := e.cpDir.GetOrAssignIndex(req.PartyKey)
	if err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: GetOrAssignIndex: %w", err)
	}

	consentReq := &types.PulseConsentRequestEC{
		EncryptedData: types.PulseECEncryptionResult{
			SealedData: req.SealedData,
			Key1:       req.Key1,
			Key2:       req.Key2,
		},
	}
	cbor, err := ppcrypto.DecryptConsentEC(e.wallet, consentReq, uint32(otherpartyId), uint32(req.ConsentNo), e.config.contractAddress, uint32(req.ChainID))
	if err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: ECDH open: %w", err)
	}

	payload, err := ipfs.UnmarshalFeedPermission(cbor)
	if err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: unmarshal payload: %w", err)
	}

	if payload.ExpiresAt != 0 && time.Unix(payload.ExpiresAt, 0).Before(time.Now()) {
		return InboundConsentResponse{}, fmt.Errorf("consent: payload has expired")
	}

	decision, err := e.config.reviewer.Review(ctx, payload)
	if err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: reviewer: %w", err)
	}

	sealedBytes, err := marshalSealedRecord(req)
	if err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: marshal sealed record: %w", err)
	}

	now := time.Now().UTC()
	record := &ConsentRecord{
		ID:          newConsentID(),
		PartyKey:    req.PartyKey,
		FeedType:    payload.FeedType,
		ConsentNo:   req.ConsentNo,
		ChainID:     req.ChainID,
		Payload:     payload,
		SealedBytes: sealedBytes,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if payload.ExpiresAt != 0 {
		t := time.Unix(payload.ExpiresAt, 0).UTC()
		record.ExpiresAt = &t
	}

	switch decision {
	case ReviewDecisionAccept:
		record.Status = ConsentStatusPending
	case ReviewDecisionReject:
		record.Status = ConsentStatusRejected
	case ReviewDecisionDefer:
		record.Status = ConsentStatusPendingReview
	default:
		return InboundConsentResponse{}, fmt.Errorf("consent: unknown decision %q", decision)
	}

	if err := e.store.Set(record); err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: store: %w", err)
	}

	if decision == ReviewDecisionAccept {
		if err := e.mt.SubmitGrant(ctx, *record, "", nil); err != nil {
			return InboundConsentResponse{}, fmt.Errorf("consent: SubmitGrant: %w", err)
		}
	}

	return InboundConsentResponse{ConsentID: record.ID, Decision: decision}, nil
}

// ApproveConsent transitions a pending-review record to pending and submits it
// to mid-tier. Called by the application after a deferred review decision.
func (e *ConsentEngine) ApproveConsent(ctx context.Context, consentID string) error {
	record, err := e.store.Get(consentID)
	if err != nil {
		return fmt.Errorf("consent: ApproveConsent Get: %w", err)
	}
	if record == nil {
		return fmt.Errorf("consent: ApproveConsent: consent %q not found", consentID)
	}
	if record.Status != ConsentStatusPendingReview {
		return fmt.Errorf("consent: ApproveConsent: expected pending-review, got %q", record.Status)
	}

	record.Status = ConsentStatusPending
	record.UpdatedAt = time.Now().UTC()
	if err := e.store.Set(record); err != nil {
		return fmt.Errorf("consent: ApproveConsent Set: %w", err)
	}
	if err := e.mt.SubmitGrant(ctx, *record, "", nil); err != nil {
		return fmt.Errorf("consent: ApproveConsent SubmitGrant: %w", err)
	}
	return nil
}

// RejectConsent transitions a pending-review record to rejected.
// Called by the application after a deferred review decision.
func (e *ConsentEngine) RejectConsent(ctx context.Context, consentID string) error {
	record, err := e.store.Get(consentID)
	if err != nil {
		return fmt.Errorf("consent: RejectConsent Get: %w", err)
	}
	if record == nil {
		return fmt.Errorf("consent: RejectConsent: consent %q not found", consentID)
	}
	if record.Status != ConsentStatusPendingReview {
		return fmt.Errorf("consent: RejectConsent: expected pending-review, got %q", record.Status)
	}

	record.Status = ConsentStatusRejected
	record.UpdatedAt = time.Now().UTC()
	if err := e.store.Set(record); err != nil {
		return fmt.Errorf("consent: RejectConsent Set: %w", err)
	}
	return nil
}

// marshalSealedRecord CBOR-encodes the ConsentStructure from the request fields
// so the sealed bytes can be submitted to IPFS via MidTierClient.SubmitGrant.
func marshalSealedRecord(req InboundConsentRequest) ([]byte, error) {
	result := &types.PulseECEncryptionResult{
		SealedData: req.SealedData,
		Key1:       req.Key1,
		Key2:       req.Key2,
	}
	b, err := ipfs.MarshalConsentEC(result)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// newConsentID returns a random 16-byte hex string suitable for use as a
// ConsentRecord.ID within a single node's store.
func newConsentID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
