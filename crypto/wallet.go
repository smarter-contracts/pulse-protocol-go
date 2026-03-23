package crypto

import bip32 "github.com/jamesradley/go-bip32"

// Wallet is the source of the BIP-32 master key used for all Pulse HD
// derivations.  Implementations are responsible for secure key storage;
// the crypto library never stores or exports key material.
type Wallet interface {
	// GetMasterKey returns the BIP-32 master private key.
	// The caller must not retain the key beyond its immediate use.
	GetMasterKey() (*bip32.Key, error)
}
