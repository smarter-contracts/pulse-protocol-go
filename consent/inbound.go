package consent

import (
	"context"
	"fmt"
	"time"

	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto/v2"
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

	cid, err := ipfs.ComputeCID(sealedBytes)
	if err != nil {
		return InboundConsentResponse{}, fmt.Errorf("consent: compute CID: %w", err)
	}

	now := time.Now().UTC()
	record := &ConsentRecord{
		ID:          cid,
		PartyKey:    req.PartyKey,
		FeedType:    payload.FeedType,
		ConsentNo:   req.ConsentNo,
		ChainID:     req.ChainID,
		Payload:     payload,
		SealedBytes: sealedBytes,
		SealedData:  req.SealedData,
		Keys:        [][]byte{req.Key1, req.Key2},
		Signatures:  req.Signatures,
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
		// Counter-sign before storing and submitting so the record in the store
		// already carries the engine's signature.
		if err := e.counterSign(record, uint32(otherpartyId)); err != nil {
			return InboundConsentResponse{}, fmt.Errorf("consent: counter-sign: %w", err)
		}
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

	otherPartyNo, err := e.cpDir.GetOrAssignIndex(record.PartyKey)
	if err != nil {
		return fmt.Errorf("consent: ApproveConsent GetOrAssignIndex: %w", err)
	}
	if err := e.counterSign(record, uint32(otherPartyNo)); err != nil {
		return fmt.Errorf("consent: ApproveConsent sign: %w", err)
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

// counterSign appends the engine's EIP-191 signature over the consent CID to
// record.Signatures. The CBOR bytes in record.SealedBytes are used to compute
// the CID (they are the canonical DAG-CBOR encoding of the consent structure).
func (e *ConsentEngine) counterSign(record *ConsentRecord, otherPartyNo uint32) error {
	consentReq := &types.PulseConsentRequestEC{
		EncryptedData: types.PulseECEncryptionResult{
			SealedData: record.SealedData,
			Key1:       keyAt(record.Keys, 0),
			Key2:       keyAt(record.Keys, 1),
		},
		Signatures: record.Signatures,
	}
	if err := ppcrypto.SignConsentRequest(
		e.wallet, consentReq, record.SealedBytes,
		otherPartyNo, uint32(record.ConsentNo),
		e.config.contractAddress, uint32(record.ChainID),
	); err != nil {
		return err
	}
	record.Signatures = consentReq.Signatures
	return nil
}

// keyAt returns keys[i] or nil if i is out of range.
func keyAt(keys [][]byte, i int) []byte {
	if i < len(keys) {
		return keys[i]
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

