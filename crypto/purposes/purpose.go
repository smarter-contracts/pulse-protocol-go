package purposes

import "fmt"

// PulsePurpose represents the purpose field in the HD wallet path or the purpose of symmetric encryption
type PulsePurpose uint32

const (
	// HD Wallet purposes
	PulsePurposeSignTx                    PulsePurpose = 0x1
	PulsePurposeEncryptConsentNotaryBlock PulsePurpose = 0x2
	PulsePurposeEncryptConsentStructure   PulsePurpose = 0x3
	PulsePurposeEncryptRevokeNotaryBlock  PulsePurpose = 0x4
	PulsePurposeEncryptRevokeStructure    PulsePurpose = 0x5

	// PQ (post-quantum) HD wallet purposes — used only for HKDF seed derivation,
	// not for encryption purposes passed to EncryptPQ/DecryptPQ.
	PulsePurposePQDeriveConsent PulsePurpose = 9
	PulsePurposePQDeriveRevoke  PulsePurpose = 10

	// Symmetric encryption purposes (originally from internal/symmetric)
	PulseNoSymmetricPurpose PulsePurpose = 0
	PulseSymmetricConsent   PulsePurpose = 6
	PulseSymmetricRevoke    PulsePurpose = 7
	PulseSymmetricUpdate    PulsePurpose = 8
	PulseSymmetricKeyWrap   PulsePurpose = 255
)

func (p PulsePurpose) String() string {
	switch p {
	case PulsePurposeSignTx:
		return "signtx"
	case PulsePurposeEncryptConsentNotaryBlock:
		return "encrypt-consent-notary-block"
	case PulsePurposeEncryptConsentStructure:
		return "consent"
	case PulsePurposeEncryptRevokeNotaryBlock:
		return "encrypt-revoke-notary-block"
	case PulsePurposeEncryptRevokeStructure:
		return "revoke"
	case PulsePurposePQDeriveConsent:
		return "pq-derive-consent"
	case PulsePurposePQDeriveRevoke:
		return "pq-derive-revoke"
	case PulseSymmetricConsent:
		return "consent"
	case PulseSymmetricRevoke:
		return "revoke"
	case PulseSymmetricUpdate:
		return "update"
	case PulseSymmetricKeyWrap:
		return "keywrap"
	default:
		return fmt.Sprintf("unknown-%d", p)
	}
}
