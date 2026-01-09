package crypto

import (
	"bytes"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
)

/* Test pack for the signing code. This consists of a set of known value tests which can be copied to other
* implementations for ease of development, plus some internal tests that are implementation-specific. We start
* the pack with the known values and mark below where we switch to the internal tests.
*
* If you are developing your own code, it's important to replicate the message structure and packing because the
* smart contract only works one way. You must match this otherwise your consents won't validate properly, (or,
* they will validate, but you'll be unable to find or revoke them later)
*
* With the following inputs:
*  ContractAddress = 0x0102030405060708090a0b0c0d0e0f1011121314 ( 20 bytes )
*  Cid = bafyreihd744kp3ua6svk5t3chwlqicnzag22zmcohrwowvyqawjqogr65i
*
* We should have the following outputs:
*   PackedConsentMessage Bytes: 0x0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b35
*                                 74336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569
*   ConsentMessage Bytes: 0x48bf046023b71d67f433eb418347863959a5f02716b7c9dcb2b471c9d42b721d
 */

const KnownCid = "bafyreihd744kp3ua6svk5t3chwlqicnzag22zmcohrwowvyqawjqogr65i"

// helperContractAddressPQ duplicates the helper used in EC tests to avoid import cycles.
func helperContractAddressBytes() *[20]byte {
	var b [symmetric.EthAddressLength]byte
	for i := 0; i < symmetric.EthAddressLength; i++ {
		b[i] = byte(i + 1)
	}
	return &b
}

func helperContractAddressSign() *string {
	b := helperContractAddressBytes()
	hexLocal := func(x byte) string {
		const hexDigits = "0123456789abcdef"
		return string([]byte{hexDigits[x>>4], hexDigits[x&0x0f]})
	}
	s := "0x"
	for i := 0; i < len(b); i++ {
		s += hexLocal(b[i])
	}
	return &s
}

func TestPulseSigning_PackingValues(t *testing.T) {
	s := NewPulseSigning().
		SetContractAddress(helperContractAddressSign()).
		SetConsentCid(KnownCid)

	if err := s.parseContractAddress(); err != nil {
		t.Fatalf("parseContractAddress: %v", err)
	}
	if !bytes.Equal(s.contractAddress[:], helperContractAddressBytes()[:]) {
		t.Fatalf("contract address mismatch")
	}

	if err := s.buildConsentMessage(); err != nil {
		t.Fatalf("buildConsentMessage: %v", err)
	}

	expectedPackedMessage := mustHexDecode("0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569")
	if !bytes.Equal(s.packed, expectedPackedMessage) {
		t.Fatalf("packed message mismatch expected: %x got: %x", expectedPackedMessage, s.packed)
	}

	expectedConsentMessage := mustHexDecode("48bf046023b71d67f433eb418347863959a5f02716b7c9dcb2b471c9d42b721d")
	if !bytes.Equal(s.message, expectedConsentMessage) {
		t.Fatalf("consent message mismatch expected: %x got: %x", expectedConsentMessage, s.message)
	}

}
