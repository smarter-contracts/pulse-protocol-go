package crypto

import (
	"crypto/ecdsa"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
)

func SignConsent(key *ecdsa.PrivateKey, contractAddressString string, cid string) ([]byte, error) {
	message := buildConsentMessage(cid, contractAddressString)
	signingHash := accounts.TextHash(message)
	signature, err := crypto.Sign(signingHash, key)
	// Convert the Recovery Parameter to EIP-191 format ( [0,1] -> [27,28] )
	if err == nil {
		signature[64] += 27
	}
	return signature, err
}

func SignRevoke(key *ecdsa.PrivateKey, contractAddressString string, cid string, rcid string) ([]byte, error) {
	message := buildRevokeMessage(cid, rcid, contractAddressString)
	signingHash := accounts.TextHash(message)
	signature, err := crypto.Sign(signingHash, key)
	// Convert the Recovery Parameter to EIP-191 format ( [0,1] -> [27,28] )
	if err == nil {
		signature[64] += 27
	}
	return signature, err
}

func SignUpdate(key *ecdsa.PrivateKey, contractAddressString string, cid string, newCid string) ([]byte, error) {
	message := buildRevokeMessage(cid, newCid, contractAddressString)
	signingHash := accounts.TextHash(message)
	signature, err := crypto.Sign(signingHash, key)
	// Convert the Recovery Parameter to EIP-191 format ( [0,1] -> [27,28] )
	if err == nil {
		signature[64] += 27
	}
	return signature, err
}

func ConsentAddress(signature []byte, contractAddressString string, cid string) (common.Address, error) {
	message := buildConsentMessage(cid, contractAddressString)
	signingHash := accounts.TextHash(message)

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

func RevokeAddress(signature []byte, contractAddressString string, cid string, rcid string) (common.Address, error) {
	message := buildRevokeMessage(cid, rcid, contractAddressString)
	signingHash := accounts.TextHash(message)

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

func UpdateAddress(signature []byte, contractAddressString string, cid string, newCid string) (common.Address, error) {
	message := buildRevokeMessage(cid, newCid, contractAddressString)
	signingHash := accounts.TextHash(message)

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

// buildConsentMessage builds the message we are going to sign. We pack the message manually, rather than using
// the ABI encoder, because the Smart Contract expects us to use the "Packed" format (i.e. no 0 padding to 32 byte
// boundaries. )
//
// Packed format for consent is
//
//	[Contract Address] + [Consent CID]
//
// in binary form -- ie. 20 bytes for contract address, 51 bytes for CID.
func buildConsentMessage(cid string, contractAddressString string) []byte {
	contractAddress := parseContractAddress(contractAddressString)
	packedMessage := packMessage(contractAddress, cid)
	return hash.PulseHashBytes(packedMessage)
}

func buildRevokeMessage(cid string, rcid string, contractAddressString string) []byte {
	contractAddress := parseContractAddress(contractAddressString)
	packedMessage := packMessage(contractAddress, cid, rcid)
	return hash.PulseHashBytes(packedMessage)
}

func buildUpdateMessage(cid string, newCid string, contractAddressString string) []byte {
	contractAddress := parseContractAddress(contractAddressString)
	packedMessage := packMessage(contractAddress, cid, newCid)
	return hash.PulseHashBytes(packedMessage)
}

func packMessage(contractAddress common.Address, cids ...string) []byte {
	packedMessage := contractAddress[:]
	for _, cid := range cids {
		packedMessage = append(packedMessage, []byte(cid)...)
	}
	return packedMessage
}

func parseContractAddress(contractAddressString string) common.Address {
	rawString := strings.TrimPrefix(contractAddressString, "0x")
	return common.HexToAddress(rawString)

}
