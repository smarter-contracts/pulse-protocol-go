package crypto

// SignableConsent is implemented by any consent request type (EC or PQ).
// It abstracts over the encrypted payload and signature list so that
// SignConsentRequest can sign any consent record without knowing whether
// the underlying encryption is EC or post-quantum.
type SignableConsent interface {
	// EncryptedDataCBOR returns the DAG-CBOR encoding of the encrypted payload.
	// The CID of this encoding is what gets signed.
	EncryptedDataCBOR() ([]byte, error)

	// AppendSignature appends an EIP-191 signature to the request.
	AppendSignature(sig []byte)
}

// SignableRevoke is implemented by any revoke request type (EC or PQ).
type SignableRevoke interface {
	// EncryptedDataCBOR returns the DAG-CBOR encoding of the encrypted payload.
	EncryptedDataCBOR() ([]byte, error)

	// GetConsentCid returns the CID of the original consent's encrypted data.
	// This is included in the revoke signing message to bind the revocation
	// to a specific consent record.
	GetConsentCid() string

	// AppendSignature sets the revoke signature.
	AppendSignature(sig []byte)
}
