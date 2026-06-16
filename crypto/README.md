# pulse-protocol-go/crypto

HD wallet derivation, ECDH encryption, ML-KEM-768 post-quantum encryption, and EIP-191 signing for the Pulse Permissions Protocol. All operations are driven through a `WalletStore` interface so key material never needs to leave a secure enclave or vault.

```
go get github.com/smarter-contracts/pulse-protocol-go/crypto/v2
```

## WalletStore

Every function in this package accepts a `WalletStore` rather than a raw key. Implement the single-method interface with whatever storage is appropriate for your deployment:

```go
type WalletStore interface {
    GetMasterKey() (*bip32.Key, error)
}
```

A simple in-memory implementation for tests and development:

```go
type memWallet struct{ key *bip32.Key }
func (w *memWallet) GetMasterKey() (*bip32.Key, error) { return w.key, nil }

seed := bip39.NewSeed(mnemonic, "")
master, _ := bip32.NewMasterKey(seed)
wallet := &memWallet{key: master}
```

## HD derivation path

The Pulse Protocol uses the path `m/4410704'/{otherParty}/{chain}/{consent}/{purpose}`. Only the root index `4410704'` is hardened, which allows BIP-32 extended public keys (xpubs) to be derived at `m/4410704'/{otherParty}` and shared with counterparties for per-consent key derivation.

The `purpose` leaf selects the key role:

| Purpose | Usage |
|---|---|
| 1 | Signing (EIP-191) |
| 2 | Notary ECDH |
| 3 | Consent/revoke ECDH |
| 4 | Post-quantum ML-KEM-768 |

## Key functions

### Xpub derivation

```go
// Returns the xpub at m/4410704'/{otherParty}.
// Pass otherParty=0 to get the root protocol xpub at m/4410704' — used
// when querying mid-tier for all consents via address enumeration.
xpub, err := crypto.DeriveOtherPartyXpub(wallet, slot)

// Returns the raw *bip32.Key instead of the base58-encoded xpub string.
key, err := crypto.DeriveOtherPartyGenerator(wallet, slot)

// Derives a per-consent public key from a stored counterparty xpub.
// Non-hardened derivation at /{chain}/{consent}/{purpose}.
pubKey, err := crypto.DerivePublicKeyFromParent(parentKey, chain, consent, purpose)
```

### Consent encryption (EC)

```go
// Encrypt and sign a consent payload.
// Returns a PulseConsentPayload and EIP-191 signature.
result, sig, err := crypto.EncryptSignConsentEC(wallet, payload, otherParty, consentNo, chainId, contractAddr)

// Decrypt a consent payload received from a counterparty.
plain, err := crypto.DecryptConsentEC(wallet, result, otherParty, consentNo, chainId)
```

### Revoke encryption (EC)

```go
result, sig, err := crypto.EncryptSignRevokeEC(wallet, payload, grantCID, otherParty, consentNo, chainId, contractAddr)
plain, err := crypto.DecryptRevokeEC(wallet, result, otherParty, consentNo, chainId)
```

### Post-quantum encryption (ML-KEM-768)

```go
// Derive the ML-KEM-768 key pair for a consent slot.
encapKey, decapKey, err := crypto.DerivePQKeyPair(wallet, otherParty, consentNo, chainId)

// Encrypt for multiple ML-KEM-768 recipients.
result, sig, err := crypto.EncryptSignConsentPQ(wallet, payload, recipients, consentNo, chainId, contractAddr)
plain, err := crypto.DecryptConsentPQ(wallet, result, otherParty, consentNo, chainId)
```

### Notary block encryption

```go
// Encrypt the NotaryBlock for the mid-tier notary key (purpose 2).
sealed, err := crypto.EncryptConsentNotaryEC(wallet, block, notaryPubKey, otherParty, consentNo, chainId)

// Decrypt as the notary (using the notary's own private key).
block, err := crypto.DecryptConsentNotaryECAsNotary(notaryPrivKey, sealed, granterPurpose2PubKey)
```

### EIP-191 signing

```go
// Sign a consent CID for submission to mid-tier.
sig, err := crypto.SignConsentRequest(wallet, request, sealedCBOR, otherParty, consentNo, contractAddr, chainId)

// Sign a revoke CID.
sig, err := crypto.SignRevokeRequest(wallet, request, sealedCBOR, otherParty, consentNo, contractAddr, chainId)

// Recover the signer address from a consent signature.
addr, err := crypto.GetConsentAddress(sig, contractAddr, consentCID)
```

## Post-quantum readiness

This module implements NIST ML-KEM-768 (FIPS 203) via [Cloudflare Circl](https://github.com/cloudflare/circl). The TypeScript counterpart (`@pulse-protocol/crypto`) uses `@noble/post-quantum ml_kem768`, producing byte-identical key material and ciphertexts.
