package consent

import (
	"context"

	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// ConsentEngineConfig holds the optional dependencies for a ConsentEngine.
// Use functional Option values to override the defaults.
type ConsentEngineConfig struct {
	reviewer        ConsentReviewer
	handler         EventHandler
	contractAddress string
}

// Option is a functional option for configuring a ConsentEngine.
type Option func(*ConsentEngineConfig)

// WithReviewer sets a custom ConsentReviewer. Without this option every inbound
// consent is automatically accepted.
func WithReviewer(r ConsentReviewer) Option {
	return func(c *ConsentEngineConfig) { c.reviewer = r }
}

// WithEventHandler sets a custom EventHandler. Without this option all lifecycle
// events are silently discarded.
func WithEventHandler(h EventHandler) Option {
	return func(c *ConsentEngineConfig) { c.handler = h }
}

// WithContractAddress sets the on-chain contract address used as a context binding
// in the ECDH key derivation.  Required for production; defaults to empty string
// which the crypto layer will reject.
func WithContractAddress(addr string) Option {
	return func(c *ConsentEngineConfig) { c.contractAddress = addr }
}

func defaultConfig() *ConsentEngineConfig {
	return &ConsentEngineConfig{
		reviewer: acceptAllReviewer{},
		handler:  noopEventHandler{},
	}
}

// acceptAllReviewer is the default ConsentReviewer: every inbound consent is accepted.
type acceptAllReviewer struct{}

func (acceptAllReviewer) Review(_ context.Context, _ *feedpermission.FeedPermissionPayload) (ReviewDecision, error) {
	return ReviewDecisionAccept, nil
}

// noopEventHandler is the default EventHandler: all events are silently discarded.
type noopEventHandler struct{}

func (noopEventHandler) OnTransactionUpdate(_ context.Context, _ TransactionUpdateEvent) error {
	return nil
}

func (noopEventHandler) OnConsentRevoked(_ context.Context, _ ConsentRevokedEvent) error {
	return nil
}
