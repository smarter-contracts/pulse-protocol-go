package consent

import (
	"context"
	"fmt"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	bip32 "github.com/jamesradley/go-bip32"
	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedrevocation"
)

// RevokeConsent initiates a revocation for an existing consent. The consent must
// be in pending or active status — pending-review consents should be rejected via
// RejectConsent instead.
//
// The flow:
//  1. The grantor's xpub is retrieved from CounterpartyDirectory (hard fail if absent).
//  2. A NotaryBlock is encrypted to the mid-tier notary key (purpose 4).
//  3. A FeedRevocationPayload is built from the notary result, the revoker identity,
//     and the original grant CID.
//  4. The payload is encrypted to the grantor's purpose-5 key and signed (EncryptSignRevokeEC).
//  5. The sealed record is submitted to mid-tier via MidTierClient.SubmitRevoke.
//
// RevokeConsent does NOT change the ConsentRecord status. State transitions are
// driven by subsequent HandleTransactionCallback calls (rev_pending through
// rev_confirmed).
func (e *ConsentEngine) RevokeConsent(ctx context.Context, consentID string) error {
	record, err := e.store.Get(consentID)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent Get: %w", err)
	}
	if record == nil {
		return fmt.Errorf("consent: RevokeConsent: consent %q not found", consentID)
	}
	if record.Status != ConsentStatusPending && record.Status != ConsentStatusActive {
		return fmt.Errorf("consent: RevokeConsent: cannot revoke consent in status %q (want pending or active)", record.Status)
	}
	if record.Payload == nil {
		return fmt.Errorf("consent: RevokeConsent: no decrypted payload on record %q; cannot build notary block", consentID)
	}

	otherPartyIdx, err := e.cpDir.GetOrAssignIndex(record.PartyKey)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent GetOrAssignIndex: %w", err)
	}

	// Retrieve the grantor's xpub — required to derive their encryption public key.
	grantorXpub, ok, err := e.cpDir.GetXpub(record.PartyKey)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent GetXpub: %w", err)
	}
	if !ok {
		return fmt.Errorf("consent: RevokeConsent: no xpub stored for counterparty %q; cannot derive encryption key", record.PartyKey)
	}

	grantorParent, err := bip32.B58Deserialize(grantorXpub)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent: parse grantor xpub: %w", err)
	}

	// Derive the grantor's purpose-5 public key for encrypting the revoke structure.
	grantorStructPub, err := ppcrypto.DerivePublicKeyFromParent(
		grantorParent,
		uint32(record.ChainID),
		uint32(record.ConsentNo),
		purposes.PulsePurposeEncryptRevokeStructure,
	)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent: derive grantor structure key: %w", err)
	}

	// Parse the mid-tier notary public key from the stored payload.
	notaryPubKey, err := secp.ParsePubKey(record.Payload.NotaryKey2)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent: parse notary key: %w", err)
	}

	// Build and encrypt the NotaryBlock (purpose 4).
	notaryBlock := &pptypes.NotaryBlock{
		Timestamp: time.Now().UTC(),
	}
	notaryCBOR, err := ipfs.MarshalNotaryBlock(notaryBlock)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent MarshalNotaryBlock: %w", err)
	}
	notaryResult, err := ppcrypto.EncryptRevokeNotaryEC(
		e.wallet, notaryCBOR,
		uint32(otherPartyIdx), uint32(record.ConsentNo),
		notaryPubKey,
		e.config.contractAddress, uint32(record.ChainID),
	)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent EncryptRevokeNotaryEC: %w", err)
	}

	// Build the revocation payload.
	revokePayload := &feedrevocation.FeedRevocationPayload{
		GrantCID:        record.CID,
		RevokerId:       record.Payload.CounterpartyDid,
		IssuedAt:        time.Now().Unix(),
		EncryptedNotary: notaryResult.SealedData,
		NotaryKey1:      notaryResult.Key1,
		NotaryKey2:      notaryResult.Key2,
	}
	revokeCBOR, err := ipfs.MarshalFeedRevocation(revokePayload)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent MarshalFeedRevocation: %w", err)
	}

	// Encrypt the revoke payload to the grantor and sign, binding the revoke CID
	// to the original grant CID.
	revokeRequest, err := ppcrypto.EncryptSignRevokeEC(
		e.wallet, revokeCBOR,
		uint32(otherPartyIdx), uint32(record.ConsentNo),
		grantorStructPub,
		e.config.contractAddress, uint32(record.ChainID),
		record.CID,
	)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent EncryptSignRevokeEC: %w", err)
	}

	// Marshal the encrypted data CBOR for IPFS pinning by mid-tier.
	sealedBytes, err := ipfs.MarshalConsentEC(&revokeRequest.EncryptedData)
	if err != nil {
		return fmt.Errorf("consent: RevokeConsent MarshalConsentEC: %w", err)
	}

	revokeRec := RevokeRecord{
		ConsentID:   record.ID,
		PartyKey:    record.PartyKey,
		GrantCID:    record.CID,
		SealedBytes: sealedBytes,
		Signature:   revokeRequest.Signature,
	}

	if err := e.mt.SubmitRevoke(ctx, revokeRec); err != nil {
		return fmt.Errorf("consent: RevokeConsent SubmitRevoke: %w", err)
	}

	return nil
}
