package crypto

import bip32 "github.com/jamesradley/go-bip32"

// WalletStore is the key-store abstraction used by all HD wallet functions in
// this package.  Implementations hold the BIP-32 master key (typically derived
// from a BIP-39 mnemonic via bip32.NewMasterKey) and return it on demand.
//
// The interface is intentionally minimal: storage, caching, and access control
// are application concerns.  The crypto package only needs the key itself.
type WalletStore interface {
	GetMasterKey() (*bip32.Key, error)
}
