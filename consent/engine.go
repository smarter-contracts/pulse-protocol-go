package consent

import (
	"context"

	ppcrypto "github.com/smarter-contracts/pulse-protocol-go/crypto"
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
