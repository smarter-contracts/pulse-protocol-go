package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/textformat"
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
	contractAddress := parseContractAddress(*helperContractAddressSign())

	if !bytes.Equal(contractAddress[:], helperContractAddressBytes()[:]) {
		t.Fatalf("contract address mismatch")
	}

	packedMessage := packMessage(contractAddress, KnownCid)
	msg := buildMessage(*helperContractAddressSign(), KnownCid)

	expectedPackedMessage := mustHexDecode("0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569")
	if !bytes.Equal(packedMessage, expectedPackedMessage) {
		t.Fatalf("packed message mismatch expected: %x got: %x", expectedPackedMessage, packedMessage)
	}

	expectedConsentMessage := mustHexDecode("48bf046023b71d67f433eb418347863959a5f02716b7c9dcb2b471c9d42b721d")
	if !bytes.Equal(msg, expectedConsentMessage) {
		t.Fatalf("consent message mismatch expected: %x got: %x", expectedConsentMessage, msg)
	}

}

func TestSignConsent_Table(t *testing.T) {
	tests := []struct {
		name                string
		privateKeyHex       string
		publicKeyHex        string
		addressHex          string
		contractAddress     string
		cid                 string
		expectedPacked      string
		expectedPackedHash  string
		expectedSigningHash string
		expectedSignature   string
	}{
		{
			name:                "send_test_consent EC grantee",
			privateKeyHex:       "89b58da1002bdd02ea9972c3c64c050f9a5236e430e030c18406035ca2be1856",
			publicKeyHex:        "04badd8074a5f44f7311552f5709e49c438d5940f7d8bb8be578c187caf40ff669e8b2d2ec4d2459c928c586dd3f62dc3b441431235eb06b646a359731032c9cb6",
			addressHex:          "fc3a23dade5b5a5c6b1790f9ac4256aed8ee8993",
			contractAddress:     "0x9b980288ae5F7a1aca113faec133e765879a5fab",
			cid:                 "bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm",
			expectedPacked:      "9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d",
			expectedPackedHash:  "e70594616cdcabad2c33930134d92dd152d138de679cb4f21fcadf0db30d07b2",
			expectedSigningHash: "a30638332e2051a57faa61224ef3920ed2cdb216c4c7b3b38b02a05a391c6140",
			expectedSignature:   "b60d499d54b1a73eb9bb69c7289d5dcdd32e9893bc7e4f72df32fa75f395a1800cfa4eb49bf3a87bad7fc69b476ef5d5bea56883d2b9d0348963fcad34e5542e1b",
		},
		{
			name:                "send_test_consent EC grantor",
			privateKeyHex:       "da4782769625a2cfe4c5ab998f71e19892d0769ed42c0551b2efab5eceae884c",
			publicKeyHex:        "04cadc6350aae69f23b9807a3462e72602914cebdd39dfa1b22d585730ca69c617d0c6e3644605da370694bb30172a9838fd1cb6c2e4d446021cc9bfaf982e7f11",
			addressHex:          "33a1debbe882df214f96a2b92b4062ee8fbb9c2f",
			contractAddress:     "0x9b980288ae5F7a1aca113faec133e765879a5fab",
			cid:                 "bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm",
			expectedPacked:      "9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d",
			expectedPackedHash:  "e70594616cdcabad2c33930134d92dd152d138de679cb4f21fcadf0db30d07b2",
			expectedSigningHash: "a30638332e2051a57faa61224ef3920ed2cdb216c4c7b3b38b02a05a391c6140",
			expectedSignature:   "83dc442a0a67d27cccf8c57357f06b35b6f5b33082a81616fa0b0c4d144d572a0ca95431fe5262a41c83a04473b13c0cd5611bf6b5f1b560283ebceb88a295ff1b",
		},
		{
			name:                "Known Values Test",
			privateKeyHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			publicKeyHex:        "046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab",
			addressHex:          "ede35562d3555e61120a151b3c8e8e91d83a378a",
			contractAddress:     "0x0102030405060708090a0b0c0d0e0f1011121314",
			cid:                 KnownCid,
			expectedPacked:      "0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569",
			expectedPackedHash:  "48bf046023b71d67f433eb418347863959a5f02716b7c9dcb2b471c9d42b721d",
			expectedSigningHash: "64920461bf4a9d15b68cf83b139ea4b941544ca9e4e52f4cf529f9b499abb967",
			expectedSignature:   "83507ee48e57e629554080fb8c812119938c7e852451d54cd1dacf6688d10ab3672b5602ca24af6597da87c397b52769b5ba8ce30dae866f44c09fbaf4a951c91b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := crypto.HexToECDSA(tt.privateKeyHex)
			if err != nil {
				t.Fatalf("failed to parse private key: %v", err)
			}

			publicKey := key.Public()
			publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("failed to cast public key to ECDSA")
			}
			pubBytes := crypto.FromECDSAPub(publicKeyECDSA)
			if hex.EncodeToString(pubBytes) != tt.publicKeyHex {
				t.Errorf("public key mismatch\ngot:  %x\nwant: %s", pubBytes, tt.publicKeyHex)
			}

			address := crypto.PubkeyToAddress(*publicKeyECDSA)
			if textformat.FormatHex(address[:]) != tt.addressHex {
				t.Errorf("address mismatch\ngot:  %s\nwant: %s", textformat.FormatHex(address[:]), tt.addressHex)
			}

			// 1. Check Packed Message
			addr := parseContractAddress(tt.contractAddress)
			packed := packMessage(addr, tt.cid)
			if hex.EncodeToString(packed) != tt.expectedPacked {
				t.Errorf("packed message mismatch\ngot:  %x\nwant: %s", packed, tt.expectedPacked)
			}

			// 2. Check Packed Message Hash (PulseHash)
			packedHash := buildMessage(tt.contractAddress, tt.cid)
			if hex.EncodeToString(packedHash) != tt.expectedPackedHash {
				t.Errorf("packed hash mismatch\ngot:  %x\nwant: %s", packedHash, tt.expectedPackedHash)
			}

			// 3. Check Signing Hash (Ethereum TextHash)
			signingHash := accounts.TextHash(packedHash)
			if hex.EncodeToString(signingHash) != tt.expectedSigningHash {
				t.Errorf("signing hash mismatch\ngot:  %x\nwant: %s", signingHash, tt.expectedSigningHash)
			}

			// 4. Check Signature Bytes
			sig, err := SignConsent(key, tt.contractAddress, tt.cid)
			if err != nil {
				t.Fatalf("SignConsent failed: %v", err)
			}
			if hex.EncodeToString(sig) != tt.expectedSignature {
				t.Errorf("signature mismatch\ngot:  %x\nwant: %s", sig, tt.expectedSignature)
			}

			// 5. Check Recovery of signature
			recoveredAddress, err := GetConsentAddress(sig, tt.contractAddress, tt.cid)
			if err != nil {
				t.Fatalf("ConsentAddress failed: %v", err)
			}
			if textformat.FormatHex(recoveredAddress[:]) != tt.addressHex {
				t.Errorf("address mismatch\ngot:  %s\nwant: %s", textformat.FormatHex(address[:]), tt.addressHex)
			}
		})
	}
}

func TestSignRevoke_Table(t *testing.T) {
	tests := []struct {
		name                string
		privateKeyHex       string
		publicKeyHex        string
		addressHex          string
		contractAddress     string
		cid                 string
		rcid                string
		expectedPacked      string
		expectedPackedHash  string
		expectedSigningHash string
		expectedSignature   string
	}{
		{
			name:                "send_test_revoke EC grantee",
			privateKeyHex:       "89b58da1002bdd02ea9972c3c64c050f9a5236e430e030c18406035ca2be1856",
			publicKeyHex:        "04badd8074a5f44f7311552f5709e49c438d5940f7d8bb8be578c187caf40ff669e8b2d2ec4d2459c928c586dd3f62dc3b441431235eb06b646a359731032c9cb6",
			addressHex:          "fc3a23dade5b5a5c6b1790f9ac4256aed8ee8993",
			contractAddress:     "0x9b980288ae5F7a1aca113faec133e765879a5fab",
			cid:                 "bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm",
			rcid:                "bafyreidxxmeu4hn46zhbwclzwykj7vdbixj5boduhql7ihm4i2djqt4dmq",
			expectedPacked:      "9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d626166797265696478786d657534686e34367a686277636c7a77796b6a3776646269786a35626f647568716c3769686d346932646a717434646d71",
			expectedPackedHash:  "cc506c53243fe75efed2a8407f9507d9741435ce35ba038c8dc7fcf7ded772d2",
			expectedSigningHash: "268c86604e8c4b1925b4ab12fc9c6ac5d0a974c0e8b70466678319a69ab76b88",
			expectedSignature:   "380309be5b333ee98a842eba5243d6ea12df1460242b945852b80066dd14f3b06dadac3afe2acdfcc5762ef8fa6eff0df71cbc17eee4e83ed8911e8a577162721b",
		},
		{
			name:                "send_test_revoke EC grantor",
			privateKeyHex:       "da4782769625a2cfe4c5ab998f71e19892d0769ed42c0551b2efab5eceae884c",
			publicKeyHex:        "04cadc6350aae69f23b9807a3462e72602914cebdd39dfa1b22d585730ca69c617d0c6e3644605da370694bb30172a9838fd1cb6c2e4d446021cc9bfaf982e7f11",
			addressHex:          "33a1debbe882df214f96a2b92b4062ee8fbb9c2f",
			contractAddress:     "0x9b980288ae5F7a1aca113faec133e765879a5fab",
			cid:                 "bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm",
			rcid:                "bafyreidxxmeu4hn46zhbwclzwykj7vdbixj5boduhql7ihm4i2djqt4dmq",
			expectedPacked:      "9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d626166797265696478786d657534686e34367a686277636c7a77796b6a3776646269786a35626f647568716c3769686d346932646a717434646d71",
			expectedPackedHash:  "cc506c53243fe75efed2a8407f9507d9741435ce35ba038c8dc7fcf7ded772d2",
			expectedSigningHash: "268c86604e8c4b1925b4ab12fc9c6ac5d0a974c0e8b70466678319a69ab76b88",
			expectedSignature:   "07c1b03984ca30b557638a808768de4a992fc0a82290d2d8a9af8130ae3e4ec1365d0952bea16f671a71a8b8b0ff9c65370761a44b1a53518d66ac78e493e4d61c",
		},
		{
			name:                "Known Values Test",
			privateKeyHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			publicKeyHex:        "046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab",
			addressHex:          "ede35562d3555e61120a151b3c8e8e91d83a378a",
			contractAddress:     "0x0102030405060708090a0b0c0d0e0f1011121314",
			cid:                 KnownCid,
			rcid:                "bafyreidxxmeu4hn46zhbwclzwykj7vdbixj5boduhql7ihm4i2djqt4dmq",
			expectedPacked:      "0102030405060708090a0b0c0d0e0f10111213146261667972656968643734346b703375613673766b3574336368776c7169636e7a616732327a6d636f6872776f7776797161776a716f6772363569626166797265696478786d657534686e34367a686277636c7a77796b6a3776646269786a35626f647568716c3769686d346932646a717434646d71",
			expectedPackedHash:  "26f90118453374476e6d1c9462e6dbc16e17fa88974ef780c385a3e66847757d",
			expectedSigningHash: "01eae01192709113c2bebbf955e237757a8d2a9e6e30f147bcf61f44abced572",
			expectedSignature:   "eb2ccdade157f21e4a790f0acaa1aa1f74222754e88004bbc94f8829a7b039cb04270295d7cf72a52d2003830e09cac7a14f03b301834937e92ff8f600c0171d1b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := crypto.HexToECDSA(tt.privateKeyHex)
			if err != nil {
				t.Fatalf("failed to parse private key: %v", err)
			}

			publicKey := key.Public()
			publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("failed to cast public key to ECDSA")
			}
			pubBytes := crypto.FromECDSAPub(publicKeyECDSA)
			if hex.EncodeToString(pubBytes) != tt.publicKeyHex {
				t.Errorf("public key mismatch\ngot:  %x\nwant: %s", pubBytes, tt.publicKeyHex)
			}

			address := crypto.PubkeyToAddress(*publicKeyECDSA)
			if textformat.FormatHex(address[:]) != tt.addressHex {
				t.Errorf("address mismatch\ngot:  %s\nwant: %s", textformat.FormatHex(address[:]), tt.addressHex)
			}

			// 1. Check Packed Message
			addr := parseContractAddress(tt.contractAddress)
			packed := packMessage(addr, tt.cid, tt.rcid)
			if hex.EncodeToString(packed) != tt.expectedPacked {
				t.Errorf("packed message mismatch\ngot:  %x\nwant: %s", packed, tt.expectedPacked)
			}

			// 2. Check Packed Message Hash (PulseHash)
			packedHash := buildMessage(tt.contractAddress, tt.cid, tt.rcid)
			if hex.EncodeToString(packedHash) != tt.expectedPackedHash {
				t.Errorf("packed hash mismatch\ngot:  %x\nwant: %s", packedHash, tt.expectedPackedHash)
			}

			// 3. Check Signing Hash (Ethereum TextHash)
			signingHash := accounts.TextHash(packedHash)
			if hex.EncodeToString(signingHash) != tt.expectedSigningHash {
				t.Errorf("signing hash mismatch\ngot:  %x\nwant: %s", signingHash, tt.expectedSigningHash)
			}

			// 4. Check Signature Bytes
			sig, err := SignRevoke(key, tt.contractAddress, tt.cid, tt.rcid)
			if err != nil {
				t.Fatalf("SignConsent failed: %v", err)
			}
			if hex.EncodeToString(sig) != tt.expectedSignature {
				t.Errorf("signature mismatch\ngot:  %x\nwant: %s", sig, tt.expectedSignature)
			}

			// 5. Check Recovery of signature
			recoveredAddress, err := GetRevokeAddress(sig, tt.contractAddress, tt.cid, tt.rcid)
			if err != nil {
				t.Fatalf("ConsentAddress failed: %v", err)
			}
			if textformat.FormatHex(recoveredAddress[:]) != tt.addressHex {
				t.Errorf("address mismatch\ngot:  %s\nwant: %s", textformat.FormatHex(address[:]), tt.addressHex)
			}
		})
	}
}

