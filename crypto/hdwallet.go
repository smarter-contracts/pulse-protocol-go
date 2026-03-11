package crypto

import (
	"errors"
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	bip32 "github.com/jamesradley/go-bip32"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// Pulse Protocol BIP-43 identifier: 0x80434d50 ('CMP' in ASCII)
const PulseProtocolIdentifier = 0x80434d50 // 2152046672 decimal, or 4410704' in BIP-32 notation

// PulseHDPath represents a Pulse Protocol HD wallet derivation path
// Path format: m/protocol'/otherparty/chain/consent/purpose
type PulseHDPath struct {
	Protocol   uint32                // BIP-43 Protocol identifier (hardened): 0x80434d50
	OtherParty uint32                // Identifier for the other party (normal): 0x0 - 0x7fffffff
	Chain      uint32                // Blockchain backend (normal): 0x1 - 0x7fffffff (1 = Polygon)
	Consent    uint32                // Sequential consent number (normal): 0x0 - 0x7fffffff
	Purpose    purposes.PulsePurpose // Purpose of the key (normal): 1-5
}

// NewPulseHDPath creates a new Pulse HD wallet path
func NewPulseHDPath(otherParty uint32, chain uint32, consent uint32, p purposes.PulsePurpose) (*PulseHDPath, error) {
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

	return &PulseHDPath{
		Protocol:   PulseProtocolIdentifier,
		OtherParty: otherParty,
		Chain:      chain,
		Consent:    consent,
		Purpose:    p,
	}, nil
}

// String returns the path in BIP-32 notation (e.g., "m/4410704'/2/1/62/1")
func (p *PulseHDPath) String() string {
	return fmt.Sprintf("m/%d'/%d/%d/%d/%d",
		p.Protocol-bip32.FirstHardenedChild,
		p.OtherParty,
		p.Chain,
		p.Consent,
		uint32(p.Purpose))
}

func EncryptSignConsentEC(masterKey *bip32.Key,
	consentData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	otherPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
) (*types.PulseConsentRequestEC, error) {
	encryptedConsentData, err := encryptEC(masterKey, consentData, otherPartyNo, consentNumber, otherPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptConsentStructure)
	if err != nil {
		return nil, errors.New("failed to encrypt consent data: " + err.Error())
	}

	returnValue := &types.PulseConsentRequestEC{EncryptedData: *encryptedConsentData}
	if err := SignConsentRequest(masterKey, returnValue, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return returnValue, nil
}

// SignConsentRequest derives the HD signing key and appends a signature to any
// consent request type (EC or PQ).  It replaces the former type-specific
// SignConsentEC function.
func SignConsentRequest(masterKey *bip32.Key,
	request SignableConsent,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) error {
	signingCBOR, err := request.EncryptedDataCBOR()
	if err != nil {
		return errors.New("failed to marshal consent CBOR: " + err.Error())
	}
	cid, err := ipfs.GetCid(signingCBOR)
	if err != nil {
		return errors.New("failed to get cid: " + err.Error())
	}

	signingKeyPath, err := NewPulseHDPath(otherPartyNo, chainId, consentNumber, purposes.PulsePurposeSignTx)
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

func EncryptConsentNotaryEC(
	masterKey *bip32.Key,
	notaryData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	notaryPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
) (*PulseECEncryptionResult, error) {
	return encryptEC(masterKey, notaryData, otherPartyNo, consentNumber, notaryPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptConsentStructure)
}

func EncryptRevokeNotaryEC(
	masterKey *bip32.Key,
	notaryData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	notaryPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
) (*PulseECEncryptionResult, error) {
	return encryptEC(masterKey, notaryData, otherPartyNo, consentNumber, notaryPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeStructure)
}

func encryptEC(
	masterKey *bip32.Key,
	notaryData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	notaryPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
	purpose purposes.PulsePurpose,
) (*PulseECEncryptionResult, error) {
	keyPath, err := NewPulseHDPath(otherPartyNo, chainId, consentNumber, purpose)
	if err != nil {
		return nil, errors.New("failed to create HD path: " + err.Error())
	}

	privKey, err := deriveKeyFromMaster(masterKey, keyPath)
	if err != nil {
		return nil, errors.New("failed to derive notary encryption key from master: " + err.Error())
	}

	return EncryptECDH(notaryData, &contractAddress, privKey, notaryPubKey, purpose, chainId, consentNumber)
}

// DeriveKeyFromMaster derives a private key from a master key following the Pulse HD path
// Returns a secp256k1 private key suitable for ECDSA signing and ECDH
func deriveKeyFromMaster(masterKey *bip32.Key, path *PulseHDPath) (*secp.PrivateKey, error) {
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

// EncryptSignRevokeEC encrypts revoke data and produces a signed PulseRevokeRequestEC.
// consentCid is the CID of the original consent's encrypted-data CBOR (stored in
// PulseConsentRequestEC.EncryptedData after marshalling).
func EncryptSignRevokeEC(masterKey *bip32.Key,
	revokeData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	otherPubKey *secp.PublicKey,
	contractAddress string,
	chainId uint32,
	consentCid string,
) (*types.PulseRevokeRequestEC, error) {
	encryptedRevokeData, err := encryptEC(masterKey, revokeData, otherPartyNo, consentNumber, otherPubKey, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeStructure)
	if err != nil {
		return nil, errors.New("failed to encrypt revoke data: " + err.Error())
	}

	returnValue := &types.PulseRevokeRequestEC{
		ConsentCid:    consentCid,
		EncryptedData: *encryptedRevokeData,
	}
	if err := SignRevokeRequest(masterKey, returnValue, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return returnValue, nil
}

// SignRevokeRequest derives the HD signing key and sets the signature on any
// revoke request type (EC or PQ).  The signature covers the contract address,
// the original consent CID, and the CID of the revoke encrypted data —
// binding the revocation cryptographically to both records.
func SignRevokeRequest(masterKey *bip32.Key,
	request SignableRevoke,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) error {
	revokeCBOR, err := request.EncryptedDataCBOR()
	if err != nil {
		return errors.New("failed to marshal revoke CBOR: " + err.Error())
	}
	revokeCid, err := ipfs.GetCid(revokeCBOR)
	if err != nil {
		return errors.New("failed to get revoke cid: " + err.Error())
	}

	signingKeyPath, err := NewPulseHDPath(otherPartyNo, chainId, consentNumber, purposes.PulsePurposeSignTx)
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

// DecryptConsentEC derives the consent encryption key from the HD wallet and decrypts
// the consent payload.  The caller must have been one of the two parties to the
// original encryption (Key1 or Key2 in the EncryptedData).
func DecryptConsentEC(masterKey *bip32.Key,
	request *types.PulseConsentRequestEC,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	return decryptHDEC(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposeEncryptConsentStructure)
}

// DecryptRevokeEC derives the revoke encryption key from the HD wallet and decrypts
// the revoke payload.
func DecryptRevokeEC(masterKey *bip32.Key,
	request *types.PulseRevokeRequestEC,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	return decryptHDEC(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposeEncryptRevokeStructure)
}

// decryptHDEC derives the encryption private key at the given purpose and decrypts.
func decryptHDEC(masterKey *bip32.Key,
	encryptedData *PulseECEncryptionResult,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
	purpose purposes.PulsePurpose,
) ([]byte, error) {
	keyPath, err := NewPulseHDPath(otherPartyNo, chainId, consentNumber, purpose)
	if err != nil {
		return nil, errors.New("failed to create HD path: " + err.Error())
	}
	privKey, err := deriveKeyFromMaster(masterKey, keyPath)
	if err != nil {
		return nil, errors.New("failed to derive encryption key from master: " + err.Error())
	}
	return DecryptEC(encryptedData, &contractAddress, privKey, purpose, chainId, consentNumber)
}

// DeriveOtherPartyGenerator derives the public key generator for a specific other party
// This is the key at path m/protocol'/otherparty which can be used to derive
// public keys for that party without knowing their private keys
func DeriveOtherPartyGenerator(masterKey *bip32.Key, otherParty uint32) (*bip32.Key, error) {
	if masterKey == nil {
		return nil, errors.New("masterKey cannot be nil")
	}
	if otherParty >= 0x80000000 {
		return nil, errors.New("otherParty must be a normal (non-hardened) key index")
	}

	// Derive: m/protocol'
	key, err := masterKey.NewChildKey(PulseProtocolIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to derive protocol key: %w", err)
	}

	// Derive: m/protocol'/otherparty
	key, err = key.NewChildKey(otherParty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive otherparty key: %w", err)
	}

	return key.PublicKey(), nil
}
