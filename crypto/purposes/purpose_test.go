package purposes

import (
	"fmt"
	"testing"
)

func TestPulsePurpose_String(t *testing.T) {
	tests := []struct {
		purpose PulsePurpose
		want    string
	}{
		{PulsePurposeSignTx, "signtx"},
		{PulsePurposeEncryptConsentNotaryBlock, "encrypt-consent-notary-block"},
		{PulsePurposeEncryptConsentStructure, "consent"},
		{PulsePurposeEncryptRevokeNotaryBlock, "encrypt-revoke-notary-block"},
		{PulsePurposeEncryptRevokeStructure, "revoke"},
		{PulseSymmetricConsent, "consent"},
		{PulseSymmetricRevoke, "revoke"},
		{PulseSymmetricUpdate, "update"},
		{PulseSymmetricKeyWrap, "keywrap"},
		{PulseNoSymmetricPurpose, "unknown-0"},
		{PulsePurpose(999), "unknown-999"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("Purpose_%d", tt.purpose), func(t *testing.T) {
			if got := tt.purpose.String(); got != tt.want {
				t.Errorf("PulsePurpose.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPulsePurpose_Values(t *testing.T) {
	// Verify that the values haven't changed accidentally
	if PulsePurposeSignTx != 0x1 {
		t.Errorf("PulsePurposeSignTx = %d, want 1", PulsePurposeSignTx)
	}
	if PulseSymmetricKeyWrap != 255 {
		t.Errorf("PulseSymmetricKeyWrap = %d, want 255", PulseSymmetricKeyWrap)
	}
	if PulseNoSymmetricPurpose != 0 {
		t.Errorf("PulseNoSymmetricPurpose = %d, want 0", PulseNoSymmetricPurpose)
	}
}
