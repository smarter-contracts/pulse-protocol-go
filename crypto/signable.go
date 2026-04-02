package crypto

// SignableConsent is implemented by any consent request type (EC or PQ).
// It abstracts over the signature list so that SignConsentRequest can sign
// any consent record without knowing whether the underlying encryption is
// EC or post-quantum.  The CBOR bytes of the encrypted payload are now
// passed as an explicit argument rather than obtained via an interface method.
type SignableConsent interface {
	// AppendSignature appends an EIP-191 signature to the request.
	AppendSignature(sig []byte)
}

// SignableRevoke is implemented by any revoke request type (EC or PQ).
type SignableRevoke interface {
	// GetConsentCid returns the CID of the original consent's encrypted data.
	// This is included in the revoke signing message to bind the revocation
	// to a specific consent record.
	GetConsentCid() string

	// AppendSignature sets the revoke signature.
	AppendSignature(sig []byte)
}
