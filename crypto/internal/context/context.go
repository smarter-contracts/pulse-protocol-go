package context

import (
	"fmt"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
)

// ContextString builds a human-readable string representing the encryption context.
// It includes the chain ID, contract address, and consent number.
//
// Arguments:
//   - chainId: The blockchain network identifier.
//   - contractAddress: The Ethereum-style hex address of the contract.
//   - consentNumber: The sequence number or identifier for the specific consent record.
//
// Returns:
//   - A formatted context string.
func ContextString(chainId uint32,
	contractAddress string,
	consentNumber uint32,
) string {
	return fmt.Sprintf("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d",
		chainId, contractAddress, consentNumber)
}

// ContextHash computes a Keccak-256 hash of the context string.
// This hash is used in AAD and HKDF salt/info for domain separation.
//
// Arguments:
//   - chainId: The blockchain network identifier.
//   - contractAddress: The Ethereum-style hex address of the contract.
//   - consentNumber: The sequence number for the specific consent record.
//
// Returns:
//   - A 32-byte Keccak-256 hash of the context string.
func ContextHash(chainId uint32,
	contractAddress string,
	consentNumber uint32,
) []byte {
	return hash.PulseHashString(ContextString(chainId, contractAddress, consentNumber))
}
