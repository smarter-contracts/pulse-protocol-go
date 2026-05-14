// Package crypto implements the Pulse Protocol's cryptographic operations for
// consent record management.  It provides HD wallet key derivation (BIP-32),
// ECDH and ML-KEM-768 (post-quantum) encryption, EIP-191 signing, and
// signature verification.
//
// The primary entry points are the Encrypt/Decrypt/Sign functions for consent
// and revoke records (both EC and PQ variants), and [DerivePQKeyPair] for
// ML-KEM key generation.  All key derivation follows the Pulse HD path:
//
//	m/4410704'/otherParty/chain/consent/purpose
//
// See the examples/ directory for complete EC and PQ workflows.
package crypto

import (
	"errors"
	"fmt"

	kyberKEM "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	bip32 "github.com/jamesradley/go-bip32"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/key_encapsulate"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/key_exchange"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/wipe"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ── HD path ─────────────────────────────────────────────────────────────────

// Pulse Protocol BIP-43 identifier: 0x80434d50 ('CMP' in ASCII)
const pulseProtocolIdentifier = 0x80434d50 // 2152046672 decimal, or 4410704' in BIP-32 notation

// pulseHDPath represents a Pulse Protocol HD wallet derivation path
// Path format: m/protocol'/otherparty/chain/consent/purpose
type pulseHDPath struct {
	Protocol   uint32                // BIP-43 Protocol identifier (hardened): 0x80434d50
	OtherParty uint32                // Identifier for the other party (normal): 0x0 - 0x7fffffff
	Chain      uint32                // Blockchain backend (normal): 0x1 - 0x7fffffff (1 = Polygon)
	Consent    uint32                // Sequential consent number (normal): 0x0 - 0x7fffffff
	Purpose    purposes.PulsePurpose // Purpose of the key (normal): 1-5
}

// newpulseHDPath creates a new Pulse HD wallet path
func newpulseHDPath(otherParty uint32, chain uint32, consent uint32, p purposes.PulsePurpose) (*pulseHDPath, error) {
	if otherParty >= 0x80000000 {
		return nil, errors.New("otherParty must be less than 0x80000000 (hardening applied automatically)")
	}
	if chain >= 0x80000000 {
		return nil, errors.New("chain must be a normal (non-hardened) key index")
	}
	if consent >= 0x80000000 {
		return nil, errors.New("consent must be a normal (non-hardened) key index")
	}
	if p < purposes.PulsePurposeSignTx ||
		(p > purposes.PulsePurposeEncryptRevokeStructure &&
			p != purposes.PulseSymmetricConsent &&
			p != purposes.PulseSymmetricRevoke &&
			p != purposes.PulseSymmetricUpdate &&
			p != purposes.PulsePurposePQDeriveConsent &&
			p != purposes.PulsePurposePQDeriveRevoke &&
			p != purposes.PulseSymmetricKeyWrap) {
		return nil, fmt.Errorf("invalid purpose: %d", p)
	}

	return &pulseHDPath{
		Protocol:   pulseProtocolIdentifier,
		OtherParty: otherParty,
		Chain:      chain,
		Consent:    consent,
		Purpose:    p,
	}, nil
}

// String returns the path in BIP-32 notation (e.g., "m/4410704'/2/1/62/1")
func (p *pulseHDPath) String() string {
	return fmt.Sprintf("m/%d'/%d/%d/%d/%d",
		p.Protocol-bip32.FirstHardenedChild,
		p.OtherParty,
		p.Chain,
		p.Consent,
		uint32(p.Purpose))
}

// ── Key derivation ──────────────────────────────────────────────────────────

// deriveKeyFromMaster derives a private key from a master key following the Pulse HD path.
// Returns a secp256k1 private key suitable for ECDSA signing and ECDH.
func deriveKeyFromMaster(masterKey *bip32.Key, path *pulseHDPath) (*secp.PrivateKey, error) {
	if masterKey == nil {
		return nil, errors.New("masterKey cannot be nil")
	}
	if path == nil {
		return nil, errors.New("path cannot be nil")
	}

	// Derive: m/protocol'
	key, err := masterKey.NewChildKey(path.Protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to derive protocol key: %w", err)
	}

	// Derive: m/protocol'/otherparty
	key, err = key.NewChildKey(path.OtherParty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive otherparty key: %w", err)
	}

	// Derive: m/protocol'/otherparty'/chain
	key, err = key.NewChildKey(path.Chain)
	if err != nil {
		return nil, fmt.Errorf("failed to derive chain key: %w", err)
	}

	// Derive: m/protocol'/otherparty'/chain/consent
	key, err = key.NewChildKey(path.Consent)
	if err != nil {
		return nil, fmt.Errorf("failed to derive consent key: %w", err)
	}

	// Derive: m/protocol'/otherparty'/chain/consent/purpose
	key, err = key.NewChildKey(uint32(path.Purpose))
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose key: %w", err)
	}

	// Convert to secp256k1 private key
	privKey := secp.PrivKeyFromBytes(key.Key)
	return privKey, nil
}

// deriveOtherPartyKey derives the extended public key at m/4410704'/otherParty.
// This key can be shared with the counterparty so they can derive all child public
// keys for this slot without access to private key material.
//
// otherParty == 0 is a sentinel: the function returns the root protocol xpub at
// m/4410704' without an additional child derivation. This root xpub is passed to
// mid-tier for consent lookup via address enumeration (Synchronize flow).
func deriveOtherPartyKey(masterKey *bip32.Key, otherParty uint32) (*bip32.Key, error) {
	if masterKey == nil {
		return nil, errors.New("masterKey cannot be nil")
	}
	if otherParty >= 0x80000000 {
		return nil, errors.New("otherParty must be a normal (non-hardened) key index")
	}

	key, err := masterKey.NewChildKey(pulseProtocolIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to derive protocol key: %w", err)
	}
	if otherParty == 0 {
		return key.PublicKey(), nil
	}
	key, err = key.NewChildKey(otherParty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive otherparty key: %w", err)
	}
	return key.PublicKey(), nil
}

// DerivePublicKeyFromParent derives a public key from an extended public key returned
// by DeriveOtherPartyGenerator.  It follows the non-hardened portion of the Pulse HD
// path (chain/consent/purpose), allowing one party to compute the other party's
// public key for a specific consent without access to private key material.
//
// Typical use: Alice calls DeriveOtherPartyGenerator on Bob's master key (or uses a
// generator Bob has shared with her), then calls DerivePublicKeyFromParent to obtain
// the public key she should encrypt to for a particular (chain, consent, purpose).
func DerivePublicKeyFromParent(parentKey *bip32.Key, chain uint32, consent uint32, p purposes.PulsePurpose) (*secp.PublicKey, error) {
	return derivePublicKeyFromParent(parentKey, chain, consent, p)
}

// derivePublicKeyFromParent is the unexported implementation.
func derivePublicKeyFromParent(parentKey *bip32.Key, chain uint32, consent uint32, p purposes.PulsePurpose) (*secp.PublicKey, error) {
	if parentKey == nil {
		return nil, errors.New("parentKey cannot be nil")
	}
	if chain >= 0x80000000 {
		return nil, errors.New("chain must be a normal (non-hardened) key index")
	}
	if consent >= 0x80000000 {
		return nil, errors.New("consent must be a normal (non-hardened) key index")
	}
	if p < purposes.PulsePurposeSignTx || p > purposes.PulsePurposeEncryptRevokeStructure {
		return nil, fmt.Errorf("invalid purpose: %d (must be 1-5)", p)
	}

	// Derive: parent/chain
	key, err := parentKey.NewChildKey(chain)
	if err != nil {
		return nil, fmt.Errorf("failed to derive chain key: %w", err)
	}

	// Derive: parent/chain/consent
	key, err = key.NewChildKey(consent)
	if err != nil {
		return nil, fmt.Errorf("failed to derive consent key: %w", err)
	}

	// Derive: parent/chain/consent/purpose
	key, err = key.NewChildKey(uint32(p))
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose key: %w", err)
	}

	// Convert to secp256k1 public key
	pubKey, err := secp.ParsePubKey(key.PublicKey().Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}

// DeriveOtherPartyGenerator derives the extended public key at m/4410704'/otherParty.
// This key can be shared with the counterparty to allow them to derive all child public
// keys for this slot without access to private key material.
func DeriveOtherPartyGenerator(wallet WalletStore, otherParty uint32) (*bip32.Key, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DeriveOtherPartyGenerator: get master key: %w", err)
	}
	return deriveOtherPartyKey(masterKey, otherParty)
}

// DeriveOtherPartyXpub returns the base58-encoded extended public key at
// m/4410704'/otherParty.  This xpub is shared during counterparty pairing so
// the other party can derive all child public keys for this slot without access
// to private key material.  otherParty 0 is the root index used for mid-tier routing.
func DeriveOtherPartyXpub(wallet WalletStore, otherParty uint32) (string, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return "", fmt.Errorf("DeriveOtherPartyXpub: get master key: %w", err)
	}
	gen, err := deriveOtherPartyKey(masterKey, otherParty)
	if err != nil {
		return "", fmt.Errorf("DeriveOtherPartyXpub: %w", err)
	}
	return gen.String(), nil
}

// DerivePQKeyPair deterministically derives an ML-KEM-768 key pair from the wallet's
// master key.  The derivation follows the standard Pulse HD path:
//
//	m/4410704'/otherPartyNo/chainId/consentNumber/purpose
//
// where purpose is either PulsePurposePQDeriveConsent (9) or
// PulsePurposePQDeriveRevoke (10).  The 32-byte node private key is then
// expanded to a 64-byte ML-KEM seed via HKDF-Keccak256.
//
// HKDF inputs:
//   - IKM:        the secp256k1 node private key (32 bytes)
//   - Salt:       Keccak256("|pulse|seed|v1|salt|kyber768|<compressed public key>|")
//   - Info:       "|pulse|seed|v1|kyber-keygen|kyber768+hkdf-keccak256|rid=<otherPartyNo>|ctx=<contextHash>|"
//
// Returns the private key (decapsulation key) and the public key (encapsulation
// key).  The private key must be kept secret; the public key may be shared with
// other parties so they can encrypt to this wallet.
func DerivePQKeyPair(
	wallet WalletStore,
	otherPartyNo uint32,
	consentNumber uint32,
	chainId uint32,
	purpose purposes.PulsePurpose,
) (*kyberKEM.PrivateKey, *kyberKEM.PublicKey, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, nil, fmt.Errorf("DerivePQKeyPair: get master key: %w", err)
	}
	return derivePQKeyPair(masterKey, otherPartyNo, consentNumber, chainId, purpose)
}

// derivePQKeyPair is the internal implementation of DerivePQKeyPair.
func derivePQKeyPair(
	masterKey *bip32.Key,
	otherPartyNo uint32,
	consentNumber uint32,
	chainId uint32,
	purpose purposes.PulsePurpose,
) (*kyberKEM.PrivateKey, *kyberKEM.PublicKey, error) {
	if purpose != purposes.PulsePurposePQDeriveConsent && purpose != purposes.PulsePurposePQDeriveRevoke {
		return nil, nil, errors.New("purpose must be PulsePurposePQDeriveConsent or PulsePurposePQDeriveRevoke")
	}

	keyPath, err := newpulseHDPath(otherPartyNo, chainId, consentNumber, purpose)
	if err != nil {
		return nil, nil, errors.New("failed to create PQ HD path: " + err.Error())
	}

	nodePrivKey, err := deriveKeyFromMaster(masterKey, keyPath)
	if err != nil {
		return nil, nil, errors.New("failed to derive PQ node key from master: " + err.Error())
	}

	scheme := kyberKEM.Scheme()
	nodeKeyBytes := nodePrivKey.Serialize()
	defer wipe.SliceWipe(nodeKeyBytes)

	// Transcript: the compressed secp256k1 public key of this HD node
	transcript := nodePrivKey.PubKey().SerializeCompressed()

	// Recipient ID: the other party number in the clear
	recipientIdStr := fmt.Sprintf("%d", otherPartyNo)

	// Context: same context hash used elsewhere (chainId, contractAddress, consentNumber)
	// For seed derivation we don't have a contract address at this level,
	// so we use the HD path parameters as the context binding.
	contextHash := context.ContextHash(chainId, "", consentNumber)

	seed, err := hkdf.PulseHKDFPQSeed(nodeKeyBytes, transcript, recipientIdStr, contextHash)
	if err != nil {
		return nil, nil, errors.New("failed to derive PQ seed: " + err.Error())
	}
	defer wipe.SliceWipe(seed)

	pubKey, privKey := scheme.DeriveKeyPair(seed)
	return privKey.(*kyberKEM.PrivateKey), pubKey.(*kyberKEM.PublicKey), nil
}

// ── EC consent ──────────────────────────────────────────────────────────────

// EncryptSignConsentEC encrypts consent data to the other party using ECDH and
// appends an EIP-191 signature over the CID of the encrypted payload.
func EncryptSignConsentEC(wallet WalletStore,
	consentData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	otherPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
) (*types.PulseConsentRequestEC, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("EncryptSignConsentEC: get master key: %w", err)
	}
	encryptedConsentData, err := encryptEC(masterKey, consentData, otherPartyNo, consentNumber, otherPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptConsentStructure)
	if err != nil {
		return nil, errors.New("failed to encrypt consent data: " + err.Error())
	}

	cbor, err := ipfs.MarshalConsentEC(encryptedConsentData)
	if err != nil {
		return nil, errors.New("failed to marshal consent CBOR: " + err.Error())
	}

	returnValue := &types.PulseConsentRequestEC{EncryptedData: *encryptedConsentData}
	if err := SignConsentRequest(wallet, returnValue, cbor, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return returnValue, nil
}

// EncryptConsentNotaryEC encrypts consent notary data to the notary's public key
// using ECDH at purpose 2 (EncryptConsentNotaryBlock).
func EncryptConsentNotaryEC(
	wallet WalletStore,
	notaryData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	notaryPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
) (*types.PulseECEncryptionResult, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("EncryptConsentNotaryEC: get master key: %w", err)
	}
	return encryptEC(masterKey, notaryData, otherPartyNo, consentNumber, notaryPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptConsentNotaryBlock)
}

// DecryptConsentNotaryEC derives the consent notary encryption key from the HD wallet
// and decrypts a notary block produced by EncryptConsentNotaryEC.
func DecryptConsentNotaryEC(wallet WalletStore,
	encryptedData *types.PulseECEncryptionResult,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DecryptConsentNotaryEC: get master key: %w", err)
	}
	return decryptHDEC(masterKey, encryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposeEncryptConsentNotaryBlock)
}

// DecryptConsentEC derives the consent encryption key from the HD wallet and decrypts
// the consent payload.  The caller must have been one of the two parties to the
// original encryption (Key1 or Key2 in the EncryptedData).
func DecryptConsentEC(wallet WalletStore,
	request *types.PulseConsentRequestEC,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DecryptConsentEC: get master key: %w", err)
	}
	return decryptHDEC(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposeEncryptConsentStructure)
}

// ── PQ consent ──────────────────────────────────────────────────────────────

// EncryptSignConsentPQ encrypts consent data for one or more ML-KEM-768
// recipients, then appends an EIP-191 secp256k1 signature over the CID of
// the encrypted payload.  The signing key is the same Pulse HD path as for
// the EC variant (purpose 1 — SignTx), so the two schemes share signing
// infrastructure.
//
// recipientPubKeys must contain the ML-KEM encapsulation keys of all parties
// that should be able to decrypt the record.  Typically this is [alicePubKey,
// bobPubKey] derived via DerivePQKeyPair on each wallet.
func EncryptSignConsentPQ(
	wallet WalletStore,
	consentData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	recipientPubKeys []*kyberKEM.PublicKey,
	contractAddress string,
	chainId uint32,
) (*types.PulseConsentRequestPQ, error) {
	encryptedData, err := key_encapsulate.EncryptPQ(nil, consentData, &contractAddress, recipientPubKeys, purposes.PulseSymmetricConsent, chainId, consentNumber)
	if err != nil {
		return nil, errors.New("failed to PQ-encrypt consent data: " + err.Error())
	}

	cbor, err := ipfs.MarshalConsentPQ(encryptedData)
	if err != nil {
		return nil, errors.New("failed to marshal PQ consent CBOR: " + err.Error())
	}

	req := &types.PulseConsentRequestPQ{EncryptedData: *encryptedData}
	if err := SignConsentRequest(wallet, req, cbor, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return req, nil
}

// DecryptConsentPQ derives the caller's ML-KEM private key from the HD wallet
// and decrypts the consent payload.
func DecryptConsentPQ(
	wallet WalletStore,
	request *types.PulseConsentRequestPQ,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DecryptConsentPQ: get master key: %w", err)
	}
	return decryptHDPQ(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposePQDeriveConsent, purposes.PulseSymmetricConsent)
}

// ── EC revoke ───────────────────────────────────────────────────────────────

// EncryptSignRevokeEC encrypts revoke data and produces a signed PulseRevokeRequestEC.
// consentCid is the CID of the original consent's encrypted-data CBOR (stored in
// PulseConsentRequestEC.EncryptedData after marshalling).
func EncryptSignRevokeEC(wallet WalletStore,
	revokeData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	otherPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
	consentCid string,
) (*types.PulseRevokeRequestEC, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("EncryptSignRevokeEC: get master key: %w", err)
	}
	encryptedRevokeData, err := encryptEC(masterKey, revokeData, otherPartyNo, consentNumber, otherPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeStructure)
	if err != nil {
		return nil, errors.New("failed to encrypt revoke data: " + err.Error())
	}

	cbor, err := ipfs.MarshalConsentEC(encryptedRevokeData)
	if err != nil {
		return nil, errors.New("failed to marshal revoke CBOR: " + err.Error())
	}

	returnValue := &types.PulseRevokeRequestEC{
		ConsentCid:    consentCid,
		EncryptedData: *encryptedRevokeData,
	}
	if err := SignRevokeRequest(wallet, returnValue, cbor, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return returnValue, nil
}

// EncryptRevokeNotaryEC encrypts revoke notary data to the notary's public key
// using ECDH at purpose 4 (EncryptRevokeNotaryBlock).
func EncryptRevokeNotaryEC(
	wallet WalletStore,
	notaryData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	notaryPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
) (*types.PulseECEncryptionResult, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("EncryptRevokeNotaryEC: get master key: %w", err)
	}
	return encryptEC(masterKey, notaryData, otherPartyNo, consentNumber, notaryPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeNotaryBlock)
}

// DecryptRevokeNotaryEC derives the revoke notary encryption key from the HD wallet
// and decrypts a notary block produced by EncryptRevokeNotaryEC.
func DecryptRevokeNotaryEC(wallet WalletStore,
	encryptedData *types.PulseECEncryptionResult,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DecryptRevokeNotaryEC: get master key: %w", err)
	}
	return decryptHDEC(masterKey, encryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeNotaryBlock)
}

// DecryptRevokeEC derives the revoke encryption key from the HD wallet and decrypts
// the revoke payload.
func DecryptRevokeEC(wallet WalletStore,
	request *types.PulseRevokeRequestEC,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DecryptRevokeEC: get master key: %w", err)
	}
	return decryptHDEC(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeStructure)
}

// ── PQ revoke ───────────────────────────────────────────────────────────────

// EncryptSignRevokePQ encrypts revoke data for one or more ML-KEM-768
// recipients, then appends an EIP-191 secp256k1 signature that binds the
// revoke to the original consent CID.
func EncryptSignRevokePQ(
	wallet WalletStore,
	revokeData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	recipientPubKeys []*kyberKEM.PublicKey,
	contractAddress string,
	chainId uint32,
	consentCid string,
) (*types.PulseRevokeRequestPQ, error) {
	encryptedData, err := key_encapsulate.EncryptPQ(nil, revokeData, &contractAddress, recipientPubKeys, purposes.PulseSymmetricRevoke, chainId, consentNumber)
	if err != nil {
		return nil, errors.New("failed to PQ-encrypt revoke data: " + err.Error())
	}

	cbor, err := ipfs.MarshalConsentPQ(encryptedData)
	if err != nil {
		return nil, errors.New("failed to marshal PQ revoke CBOR: " + err.Error())
	}

	req := &types.PulseRevokeRequestPQ{
		ConsentCid:    consentCid,
		EncryptedData: *encryptedData,
	}
	if err := SignRevokeRequest(wallet, req, cbor, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return req, nil
}

// DecryptRevokePQ derives the caller's ML-KEM private key from the HD wallet
// and decrypts the revoke payload.
func DecryptRevokePQ(
	wallet WalletStore,
	request *types.PulseRevokeRequestPQ,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return nil, fmt.Errorf("DecryptRevokePQ: get master key: %w", err)
	}
	return decryptHDPQ(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposePQDeriveRevoke, purposes.PulseSymmetricRevoke)
}

// ── Signing ─────────────────────────────────────────────────────────────────

// SignConsentRequest derives the HD signing key and appends a signature to any
// consent request type (EC or PQ).  encryptedDataCBOR must be the DAG-CBOR
// encoding of the encrypted payload (e.g. from ipfs.MarshalConsentEC); its CID
// is what gets signed.
func SignConsentRequest(wallet WalletStore,
	request SignableConsent,
	encryptedDataCBOR []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) error {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return fmt.Errorf("SignConsentRequest: get master key: %w", err)
	}
	cid, err := ipfs.GetCid(encryptedDataCBOR)
	if err != nil {
		return errors.New("failed to get cid: " + err.Error())
	}

	signingKeyPath, err := newpulseHDPath(otherPartyNo, chainId, consentNumber, purposes.PulsePurposeSignTx)
	if err != nil {
		return errors.New("failed to create HD path: " + err.Error())
	}
	signingKey, err := deriveKeyFromMaster(masterKey, signingKeyPath)
	if err != nil {
		return errors.New("failed to derive signing key from master: " + err.Error())
	}
	signature, err := SignConsent(signingKey.ToECDSA(), contractAddress, cid.String())
	if err != nil {
		return errors.New("failed to sign consent: " + err.Error())
	}
	request.AppendSignature(signature)
	return nil
}

// SignRevokeRequest derives the HD signing key and sets the signature on any
// revoke request type (EC or PQ).  encryptedDataCBOR must be the DAG-CBOR
// encoding of the revoke structure (e.g. from ipfs.MarshalRevokeEC); its CID,
// together with the original consent CID from request.GetConsentCid(), is what
// gets signed, binding the revocation cryptographically to both records.
func SignRevokeRequest(wallet WalletStore,
	request SignableRevoke,
	encryptedDataCBOR []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) error {
	masterKey, err := wallet.GetMasterKey()
	if err != nil {
		return fmt.Errorf("SignRevokeRequest: get master key: %w", err)
	}
	revokeCid, err := ipfs.GetCid(encryptedDataCBOR)
	if err != nil {
		return errors.New("failed to get revoke cid: " + err.Error())
	}

	signingKeyPath, err := newpulseHDPath(otherPartyNo, chainId, consentNumber, purposes.PulsePurposeSignTx)
	if err != nil {
		return errors.New("failed to create HD path: " + err.Error())
	}
	signingKey, err := deriveKeyFromMaster(masterKey, signingKeyPath)
	if err != nil {
		return errors.New("failed to derive signing key from master: " + err.Error())
	}
	signature, err := SignRevoke(signingKey.ToECDSA(), contractAddress, request.GetConsentCid(), revokeCid.String())
	if err != nil {
		return errors.New("failed to sign revoke: " + err.Error())
	}
	request.AppendSignature(signature)
	return nil
}

// ── Internal helpers ────────────────────────────────────────────────────────

func encryptEC(
	masterKey *bip32.Key,
	notaryData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	notaryPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
	purpose purposes.PulsePurpose,
) (*types.PulseECEncryptionResult, error) {
	keyPath, err := newpulseHDPath(otherPartyNo, chainId, consentNumber, purpose)
	if err != nil {
		return nil, errors.New("failed to create HD path: " + err.Error())
	}

	privKey, err := deriveKeyFromMaster(masterKey, keyPath)
	if err != nil {
		return nil, errors.New("failed to derive notary encryption key from master: " + err.Error())
	}

	return key_exchange.EncryptECDH(notaryData, &contractAddress, privKey, notaryPubKey, purpose, chainId, consentNumber)
}

// decryptHDEC derives the encryption private key at the given purpose and decrypts.
func decryptHDEC(masterKey *bip32.Key,
	encryptedData *types.PulseECEncryptionResult,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
	purpose purposes.PulsePurpose,
) ([]byte, error) {
	keyPath, err := newpulseHDPath(otherPartyNo, chainId, consentNumber, purpose)
	if err != nil {
		return nil, errors.New("failed to create HD path: " + err.Error())
	}
	privKey, err := deriveKeyFromMaster(masterKey, keyPath)
	if err != nil {
		return nil, errors.New("failed to derive encryption key from master: " + err.Error())
	}
	return key_exchange.DecryptEC(encryptedData, &contractAddress, privKey, purpose, chainId, consentNumber)
}

// decryptHDPQ derives the ML-KEM private key for the given derive purpose and
// calls DecryptPQ with the symmetric purpose used during encryption.
func decryptHDPQ(
	masterKey *bip32.Key,
	encryptedData *types.PulsePQEncryptionResult,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
	derivePurpose purposes.PulsePurpose,
	symPurpose purposes.PulsePurpose,
) ([]byte, error) {
	privKey, _, err := derivePQKeyPair(masterKey, otherPartyNo, consentNumber, chainId, derivePurpose)
	if err != nil {
		return nil, errors.New("failed to derive PQ decryption key: " + err.Error())
	}
	return key_encapsulate.DecryptPQ(encryptedData, &contractAddress, privKey, symPurpose, chainId, consentNumber)
}
