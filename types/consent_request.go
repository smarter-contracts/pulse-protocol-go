package types

type PulseConsentRequestEC struct {
	EncryptedData PulseECEncryptionResult `json:"consent"`
	Signatures    [][]byte                `json:"signatures"`
}

// Embed Grant Ref into EncryptedData - just add a new field?
type PulseRevokeRequestEC struct {
	EncryptedData PulseECEncryptionResult `json:"revoke"`
	Signature     []byte                  `json:"signature"`
}
