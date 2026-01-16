package crypto

import (
	"crypto/ecdsa"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
)

// SignConsent signs a consent request for a given CID and contract address using the provided private key.
// It returns the EIP-191 formatted signature.
func SignConsent(key *ecdsa.PrivateKey, contractAddressString string, cid string) ([]byte, error) {
	return signRequest(key, contractAddressString, cid)
}

// SignRevoke signs a revocation request for a given CID and revocation CID (rcid) using the provided private key.
// It returns the EIP-191 formatted signature.
func SignRevoke(key *ecdsa.PrivateKey, contractAddressString string, cid string, rcid string) ([]byte, error) {
	return signRequest(key, contractAddressString, cid, rcid)
}

// SignUpdate signs an update request for a given CID and new CID using the provided private key.
// It returns the EIP-191 formatted signature.
func SignUpdate(key *ecdsa.PrivateKey, contractAddressString string, cid string, newCid string) ([]byte, error) {
	return signRequest(key, contractAddressString, cid, newCid)
}

// signRequest is a helper function that hashes the provided CIDs and contract address,
// and signs the resulting hash using the provided private key.
func signRequest(key *ecdsa.PrivateKey, contractAddressString string, cids ...string) ([]byte, error) {
	hMessage := buildMessage(contractAddressString, cids...)
	signingHash := accounts.TextHash(hMessage)
	signature, err := crypto.Sign(signingHash, key)
	// Convert the Recovery Parameter to EIP-191 format ( [0,1] -> [27,28] )
	if err == nil {
		signature[64] += 27
	}
	return signature, err
}

// GetConsentAddress recovers the Ethereum address that signed the consent request from the signature,
// contract address, and CID.
func GetConsentAddress(signature []byte, contractAddressString string, cid string) (common.Address, error) {
	return getSigningAddress(signature, contractAddressString, cid)
}

// GetRevokeAddress recovers the Ethereum address that signed the revocation request from the signature,
// contract address, CID, and rcid.
func GetRevokeAddress(signature []byte, contractAddressString string, cid string, rcid string) (common.Address, error) {
	return getSigningAddress(signature, contractAddressString, cid, rcid)
}

// GetUpdateAddress recovers the Ethereum address that signed the update request from the signature,
// contract address, CID, and newCid.
func GetUpdateAddress(signature []byte, contractAddressString string, cid string, newCid string) (common.Address, error) {
	return getSigningAddress(signature, contractAddressString, cid, newCid)
}

// getSigningAddress is a helper function that recovers the signer's address from a signature
// and the message components (contract address and CIDs).
func getSigningAddress(signature []byte, contractAddressString string, cids ...string) (common.Address, error) {
	hMessage := buildMessage(contractAddressString, cids...)
	signingHash := accounts.TextHash(hMessage)

	// Convert the signature from EIP-191 format ( [27,28] -> [0,1] ) if needed
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27
	}
	publicKey, err := crypto.SigToPub(signingHash, signature)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*publicKey), err
}

// buildMessage builds the message we are going to sign. We pack the message manually, rather than using
// the ABI encoder, because the Smart Contract expects us to use the "Packed" format (i.e. no 0 padding to 32 byte
// boundaries).
//
// Packed format for consent is:
//
//	[Contract Address] + [Consent CID]
//
// in binary form -- i.e., 20 bytes for contract address, 51 bytes for CID.
//
// For Revokes and Updates, a second CID is expected on the end of the message (rcid or newCid).
func buildMessage(contractAddressString string, cids ...string) []byte {
	contractAddress := parseContractAddress(contractAddressString)
	packedMessage := packMessage(contractAddress, cids...)
	return hash.PulseHashBytes(packedMessage)
}

// packMessage concatenates the contract address and the provided CIDs into a single byte slice.
func packMessage(contractAddress common.Address, cids ...string) []byte {
	packedMessage := contractAddress[:]
	for _, cid := range cids {
		packedMessage = append(packedMessage, []byte(cid)...)
	}
	return packedMessage
}

// parseContractAddress converts a hex-encoded contract address string into a common.Address.
// It handles addresses with or without the "0x" prefix.
func parseContractAddress(contractAddressString string) common.Address {
	rawString := strings.TrimPrefix(contractAddressString, "0x")
	return common.HexToAddress(rawString)
}
