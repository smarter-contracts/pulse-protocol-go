package crypto

import (
	"errors"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	bip32 "github.com/jamesradley/go-bip32"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/wipe"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// PQ seed HKDF info strings — kept here so they are part of the protocol spec.
const (
	pqConsentSeedInfo = "|pulse|pq|consent|v1|"
	pqRevokeSeedInfo  = "|pulse|pq|revoke|v1|"
)

// DerivePQKeyPair deterministically derives an ML-KEM-768 key pair from a BIP-32
// master key.  The derivation follows the standard Pulse HD path:
//
//	m/4410704'/otherPartyNo/chainId/consentNumber/purpose
//
// where purpose is either PulsePurposePQDeriveConsent (9) or
// PulsePurposePQDeriveRevoke (10).  The 32-byte node private key is then
// expanded to a 64-byte ML-KEM seed via HKDF-Keccak256 with a
// purpose-specific info string, so the chain code is never used directly as
// key material.
//
// Returns the private key (decapsulation key) and the public key (encapsulation
// key).  The private key must be kept secret; the public key (EncapsulationKey())
// may be shared with other parties so they can encrypt to this wallet.
func DerivePQKeyPair(
	masterKey *bip32.Key,
	otherPartyNo uint32,
	consentNumber uint32,
	chainId uint32,
	purpose purposes.PulsePurpose,
) (*kyberKEM.PrivateKey, *kyberKEM.PublicKey, error) {
	if purpose != purposes.PulsePurposePQDeriveConsent && purpose != purposes.PulsePurposePQDeriveRevoke {
		return nil, nil, errors.New("purpose must be PulsePurposePQDeriveConsent or PulsePurposePQDeriveRevoke")
	}

	keyPath, err := NewPulseHDPath(otherPartyNo, chainId, consentNumber, purpose)
	if err != nil {
		return nil, nil, errors.New("failed to create PQ HD path: " + err.Error())
	}

	nodePrivKey, err := deriveKeyFromMaster(masterKey, keyPath)
	if err != nil {
		return nil, nil, errors.New("failed to derive PQ node key from master: " + err.Error())
	}

	// Expand the 32-byte secp256k1 node key to 64 bytes for the ML-KEM seed.
	var infoSuffix string
	if purpose == purposes.PulsePurposePQDeriveConsent {
		infoSuffix = pqConsentSeedInfo
	} else {
		infoSuffix = pqRevokeSeedInfo
	}

	scheme := kyberKEM.Scheme()
	nodeKeyBytes := nodePrivKey.Serialize()
	defer wipe.SliceWipe(nodeKeyBytes)

	seed, err := hkdf.PulseHKDFPQSeed(nodeKeyBytes, infoSuffix, scheme.SeedSize())
	if err != nil {
		return nil, nil, errors.New("failed to derive PQ seed: " + err.Error())
	}
	defer wipe.SliceWipe(seed)

	pubKey, privKey := scheme.DeriveKeyPair(seed)
	return privKey.(*kyberKEM.PrivateKey), pubKey.(*kyberKEM.PublicKey), nil
}

// ── Consent ───────────────────────────────────────────────────────────────────

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
	masterKey *bip32.Key,
	consentData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	recipientPubKeys []*kyberKEM.PublicKey,
	contractAddress string,
	chainId uint32,
) (*types.PulseConsentRequestPQ, error) {
	encryptedData, err := EncryptPQ(nil, consentData, &contractAddress, recipientPubKeys, purposes.PulseSymmetricConsent, chainId, consentNumber)
	if err != nil {
		return nil, errors.New("failed to PQ-encrypt consent data: " + err.Error())
	}

	req := &types.PulseConsentRequestPQ{EncryptedData: *encryptedData}
	if err := SignConsentRequest(masterKey, req, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return req, nil
}

// DecryptConsentPQ derives the caller's ML-KEM private key from the HD wallet
// and decrypts the consent payload.
func DecryptConsentPQ(
	masterKey *bip32.Key,
	request *types.PulseConsentRequestPQ,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	return decryptHDPQ(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposePQDeriveConsent, purposes.PulseSymmetricConsent)
}

// ── Revoke ────────────────────────────────────────────────────────────────────

// EncryptSignRevokePQ encrypts revoke data for one or more ML-KEM-768
// recipients, then appends an EIP-191 secp256k1 signature that binds the
// revoke to the original consent CID.
func EncryptSignRevokePQ(
	masterKey *bip32.Key,
	revokeData []byte,
	otherPartyNo uint32,
	consentNumber uint32,
	recipientPubKeys []*kyberKEM.PublicKey,
	contractAddress string,
	chainId uint32,
	consentCid string,
) (*types.PulseRevokeRequestPQ, error) {
	encryptedData, err := EncryptPQ(nil, revokeData, &contractAddress, recipientPubKeys, purposes.PulseSymmetricRevoke, chainId, consentNumber)
	if err != nil {
		return nil, errors.New("failed to PQ-encrypt revoke data: " + err.Error())
	}

	req := &types.PulseRevokeRequestPQ{
		ConsentCid:    consentCid,
		EncryptedData: *encryptedData,
	}
	if err := SignRevokeRequest(masterKey, req, otherPartyNo, consentNumber, contractAddress, chainId); err != nil {
		return nil, err
	}
	return req, nil
}

// DecryptRevokePQ derives the caller's ML-KEM private key from the HD wallet
// and decrypts the revoke payload.
func DecryptRevokePQ(
	masterKey *bip32.Key,
	request *types.PulseRevokeRequestPQ,
	otherPartyNo uint32,
	consentNumber uint32,
	contractAddress string,
	chainId uint32,
) ([]byte, error) {
	return decryptHDPQ(masterKey, &request.EncryptedData, otherPartyNo, consentNumber, contractAddress, chainId, purposes.PulsePurposePQDeriveRevoke, purposes.PulseSymmetricRevoke)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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
	privKey, _, err := DerivePQKeyPair(masterKey, otherPartyNo, consentNumber, chainId, derivePurpose)
	if err != nil {
		return nil, errors.New("failed to derive PQ decryption key: " + err.Error())
	}
	return DecryptPQ(encryptedData, &contractAddress, privKey, symPurpose, chainId, consentNumber)
}
