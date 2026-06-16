package consent

import (
	"context"
	"fmt"

	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto/v2"
)

// ConsentEngine orchestrates the consent lifecycle on the grantee side.
// Construct one with NewConsentEngine and wire its methods into the application's
// HTTP handlers and startup sequence.
//
// ConsentEngine holds no internal goroutines. All scheduling (e.g. periodic
// re-sync) is the application's responsibility.
type ConsentEngine struct {
	wallet  ppcrypto.WalletStore
	cpDir   CounterpartyDirectory
	store   ConsentStore
	mt      MidTierClient
	config  *ConsentEngineConfig
}

// NewConsentEngine constructs a ConsentEngine with the four required dependencies.
// Optional behaviour (reviewer, event handler) is configured via Option values.
func NewConsentEngine(
	wallet ppcrypto.WalletStore,
	cpDir CounterpartyDirectory,
	store ConsentStore,
	mt MidTierClient,
	opts ...Option,
) *ConsentEngine {
	cfg := defaultConfig()
	for _, o := range opts {
		o(cfg)
	}
	return &ConsentEngine{
		wallet: wallet,
		cpDir:  cpDir,
		store:  store,
		mt:     mt,
		config: cfg,
	}
}

// HandleXpubRequest returns the local party's extended public key at
// m/4410704'/{otherpartyId}. Applications expose this as GET /xpub/{otherpartyId}
// so counterparties can derive consent encryption keys without a round-trip
// through the Trust Directory.
func (e *ConsentEngine) HandleXpubRequest(_ context.Context, otherpartyId int) (XpubResponse, error) {
	xpub, err := ppcrypto.DeriveOtherPartyXpub(e.wallet, uint32(otherpartyId))
	if err != nil {
		return XpubResponse{}, err
	}
	return XpubResponse{Xpub: xpub, OtherpartyId: otherpartyId}, nil
}

// HandleXpubRequestByDID resolves or assigns a counterparty slot for the given
// DID, then returns the local party's xpub at that slot. Used by POST /api/v3/xpub
// where the caller identifies itself by DID rather than a pre-known integer slot.
func (e *ConsentEngine) HandleXpubRequestByDID(ctx context.Context, requestorDID string) (XpubResponse, error) {
	slot, err := e.cpDir.GetOrAssignIndex(requestorDID)
	if err != nil {
		return XpubResponse{}, fmt.Errorf("xpub by DID: assign slot for %q: %w", requestorDID, err)
	}
	return e.HandleXpubRequest(ctx, slot)
}
