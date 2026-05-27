package crypto

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
	"github.com/smarter-contracts/pulse-protocol-go/types"
)

// ConsentSigners recovers the Ethereum address for each signature in a
// PulseConsentRequestEC.  The returned slice is in the same order as
// request.Signatures.
func ConsentSigners(request *types.PulseConsentRequestEC, contractAddress string) ([]common.Address, error) {
	if request == nil {
		return nil, errors.New("request must not be nil")
	}
	if len(request.Signatures) == 0 {
		return nil, errors.New("request has no signatures")
	}

	cbor, err := ipfs.MarshalConsentEC(&request.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}
	cid, err := ipfs.GetCid(cbor)
	if err != nil {
		return nil, fmt.Errorf("computing consent CID: %w", err)
	}
	cidStr := cid.String()

	addrs := make([]common.Address, len(request.Signatures))
	for i, sig := range request.Signatures {
		addr, err := GetConsentAddress(sig, contractAddress, cidStr)
		if err != nil {
			return nil, fmt.Errorf("recovering address for signature %d: %w", i, err)
		}
		addrs[i] = addr
	}
	return addrs, nil
}

// RevokeSignerWasConsentSigner verifies that the signer of a PulseRevokeRequestEC
// was one of the signers of the original PulseConsentRequestEC.
//
// Both the revoke and consent records must have been signed using the same
// contractAddress.  The revoke.ConsentCid must match the CID of the consent's
// encrypted data (it is not re-verified here; the caller is responsible for
// confirming the chain of CIDs).
func RevokeSignerWasConsentSigner(
	revoke *types.PulseRevokeRequestEC,
	consent *types.PulseConsentRequestEC,
	contractAddress string,
) (bool, error) {
	if revoke == nil {
		return false, errors.New("revoke must not be nil")
	}
	if consent == nil {
		return false, errors.New("consent must not be nil")
	}
	if len(revoke.Signature) == 0 {
		return false, errors.New("revoke has no signature")
	}

	// Recover the revoke signer — the CID must include the GrantRef so it
	// matches what EncryptSignRevokeEC signs and what the mid-tier verifies.
	revokeCBOR, err := ipfs.MarshalRevokeEC(&types.RevokeStructure{
		PulseECEncryptionResult: revoke.EncryptedData,
		Grant:                   revoke.ConsentCid,
	})
	if err != nil {
		return false, fmt.Errorf("marshalling revoke encrypted data: %w", err)
	}
	revokeCid, err := ipfs.GetCid(revokeCBOR)
	if err != nil {
		return false, fmt.Errorf("computing revoke CID: %w", err)
	}
	revokeSignerAddr, err := GetRevokeAddress(revoke.Signature, contractAddress, revoke.ConsentCid, revokeCid.String())
	if err != nil {
		return false, fmt.Errorf("recovering revoke signer address: %w", err)
	}

	// Recover all consent signers and check for a match
	consentSigners, err := ConsentSigners(consent, contractAddress)
	if err != nil {
		return false, fmt.Errorf("recovering consent signers: %w", err)
	}
	for _, addr := range consentSigners {
		if addr == revokeSignerAddr {
			return true, nil
		}
	}
	return false, nil
}
