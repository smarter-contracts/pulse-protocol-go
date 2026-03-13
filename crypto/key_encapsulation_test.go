package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/key_encapsulate"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
)

/*
 * Test pack for ML-KEMS/Crystals-Kyber key encapsulation. If you are trying to build your own test pack/implementation,
 * the public tests should be replicated in your code to ensure that your results are consistent with the reference
 * implementation.
 *
 * Further down are tests that are specific to this Go implementation, which are not essential to replicate. The cutover
 * point is marked
 *
 * EncryptionKey values for the tests (binary/byte arrays coded as hex strings):
 * Alice Private EncryptionKey: <contents of alice_private.hex>
 * Bob Public EncryptionKey: <contents of bob_public.hex>
 *
 * Note that the stored keys are ML-KEM standard PrivateKey format ( 2400 bytes ) which includes the public key.
 * In the 2400 byte format, we have
 *      - First 1152 bytes -> 'Actual' Private EncryptionKey
 *      - Next 1184 bytes -> Public EncryptionKey
 *      - Next 32 bytes -> Hash of Public EncryptionKey
 *      - Last 32 bytes -> "Z"
*
 *    ChainId = 0x1
 *    Purpose = 1  ( Consent )
 *    ContractAddress = 0x0102030405060708090a0b0c0d0e0f1011121314 ( 20 bytes )
 *    Plaintext = "pulse test"
 *    AES EncryptionKey =  0x75ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a
 *    Seed for MLKEMS Encryption: "76ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a"
 *
 *  Note that in ordinary usage AESKey should not be passed into the Symmetric encryption, but we do it here
 *  for deterministic test results.
 *
 *  Outputs:
 *    expectedSealedData = 0x643fc6221df02dc72dc4f9381993d1682d252ce0838742ab19b5
 *	  expectedKey1FingerPrint = 0x01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd
 *	  expectedKey2FingerPrint = 70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde
*/

// helperContractAddressPQ duplicates the helper used in EC tests to avoid import cycles.
func helperContractAddressPQ() *string {
	var b [symmetric.EthAddressLength]byte
	for i := 0; i < symmetric.EthAddressLength; i++ {
		b[i] = byte(i + 1)
	}
	hexLocal := func(x byte) string {
		const hexdigits = "0123456789abcdef"
		return string([]byte{hexdigits[x>>4], hexdigits[x&0x0f]})
	}
	s := "0x"
	for i := 0; i < len(b); i++ {
		s += hexLocal(b[i])
	}
	return &s
}

func keyFromFile(filename string) (*kyberKEM.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	returnVal := new(kyberKEM.PrivateKey)
	err = unpackHexToPrivateKey(data, returnVal)
	return returnVal, err
}

func unpackHexToPrivateKey(hexString []byte, sk *kyberKEM.PrivateKey) error {
	buf := make([]byte, kyberKEM.PrivateKeySize)
	_, err := hex.Decode(buf, []byte(hexString))
	sk.Unpack(buf)
	return err
}

func makeKeySeed(offset byte) []byte {
	seed := make([]byte, kyberKEM.KeySeedSize)
	var i byte
	for i = 0; i < kyberKEM.KeySeedSize; i++ {
		seed[i] = i + offset
	}
	return seed
}

func makeKeyFile(filename string, offset byte) error {
	seed := makeKeySeed(offset)
	_, privateKey := kyberKEM.NewKeyFromSeed(seed)

	keyBytes := make([]byte, kyberKEM.PrivateKeySize)
	privateKey.Pack(keyBytes)
	return os.WriteFile(filename, []byte(fmt.Sprintf("%x", keyBytes)), 0644)
}

func TestPulsePQ_EncryptDecrypt_Success(t *testing.T) {
	plainText := []byte("pulse text")
	contractAddress := helperContractAddressPQ()
	purpose := purposes.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)

	alicePrivate, _ := keyFromFile("alice_private.hex")
	_ = alicePrivate
	bobPrivate, _ := keyFromFile("bob_private.hex")
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)

	// EncryptPQ for Bob
	result, err := key_encapsulate.EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{bobPublic}, purpose, chainId, 0)
	if err != nil {
		t.Fatalf("EncryptPQ: %v", err)
	}

	// DecryptPQ for Bob
	decrypted, err := key_encapsulate.DecryptPQ(result, contractAddress, bobPrivate, purpose, chainId, 0)
	if err != nil {
		t.Fatalf("DecryptPQ (Bob): %v", err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", decrypted, plainText)
	}
}

func TestPulsePQ_Decrypt_Errors(t *testing.T) {
	plainText := []byte("data")
	contractAddress := helperContractAddressPQ()
	purpose := purposes.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)
	pk, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, _ := key_encapsulate.EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk}, purpose, chainId, 0)

	// Decrypt with wrong private key
	pkWrong, wrongSK, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	_ = pkWrong
	_, err := key_encapsulate.DecryptPQ(result, contractAddress, wrongSK, purpose, chainId, 0)
	if err == nil || err.Error() != "no key found for this party" {
		t.Fatalf("expected 'no key found for this party', got %v", err)
	}
}
