package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	kyberPKE "github.com/cloudflare/circl/pke/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal"
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
 *    expectedKey1Key =
 * a0486c6ac85b6c6ccd4fecdad70ba7399957f447bd10249c941d51ec368392f2c0019c283d7c440bece27d7851a0712e5b1f3c813f419ce8d36c
 * cdc56518625e463cbc9451ecd354f9a93de317ee4778e0c5911858d315f317e0ff195c482830105a1e568f4ebc4732afc13406b4ff50d5112334
 * e018545122246988e0c752d3ac85f6cf7f40e80f70fb7453269adf11a774fe863872547761bad3e9ec13cb5c334bad8443c815decc0764cc6afb
 * 38a8ba4b96184d87370728ec8a58191a4d7718e3d866160ba9aac28e42ec2920c1ffe8b5023031bdae56926cf0c01337831ef0edf264022dea57
 * b4a5e1fc01c6505f91b5f4f1f625fc0f86b8f5990fd0e6ece51cc1f51dd33b16b9bf18faebe90fa3a70b3bb2eca37b029d00662e2f9cbdcc8b11
 * 09caf8380ae318cee21c62e4030d4c56ab7cd3950281d5f1b161be1d80dc0f7666bd72831b94159b00b68cdaa8501bee1bd7180db1ef33af5811
 * d602e7064608487eded03bcd43506a27686b06d37e4fb1e865e9be895541d9a0e17e1c591996577331f8ca8c6decc08c3fe631e405efdb9ac377
 * f7fdc1328138b9c5256cc588ca9d71fd78d11219bcd2b429cfe2b7df286e33b4aabe56537dd7b3cb816b039d1f38f7eef2036cbaba6070c8b8a0
 * 45e538b5230093a9965e4f5c39345b8ecc29b16414d34fd7df07456a8f0842738ab0ac6ad0b4ef1f817baf704a682e737eaa99920dbdffd23a28
 * fd176b1f6ef584ade796030962d0dce33d21367d9676c7071314e5197834f66847ec11fa6b1a4d920fc5c5a10ffdaf163140e5887647a543da23
 * 53fffbf602a4f67edf3e2b5fdad7dd2276a1ecc67b43227d96865a82155bca135b8c96cc8290b0e9156fe13f5a5c895337b70a0e0794b49be05f
 * 8a08f1ea50f4641e7311369ac0467710fede2e89ebdf8e85ca6bc87aa2087d529d97f3c131a7b9d3bb7b6f304425c0ffe9469d950141fd7439e4
 * af8c8f94f4a20e0899d690bc0be933f703570c51bf553a466c23c7339ac651573233509b9d9f601e9677b61c2d4afba1341060a1b0f71e20aefb
 * 7dd4bcb82ea7ea8e5d493871b9e15f86978b660e64aa9aa5c8c16cedd48556c1e3f1332d4937b4e35f8aae70ce59ec759fede4004e6e3052f326
 * 414556b8499ecc5e3667c4ec5fcbcc7dea795b32b2a11797f8be94ac9ed68588690b001be0e276bfa0f6a3549c5de63f161ac6d88df01aabbc13
 * 334e0be4cf58662300bfa879805b5761b2e07e00c0e6a1796f67981199859e4c96f6084b3afab7cc34f77880aea970a0b7b638d0765f333b0bfc
 * 4f9b2e7a10485b23d3fd73ab65f351e536e08d77b01455a65b63e0d3afe53bfbdedc2bb87a35c8ef2db343b5701605dce04e87ce1a64cc70e9c3
 * a4d72f92432dec511b0cfb91df528157955d9241ce28dc1779189e6f3ef9d41267d6b6b6f1b22767d807409c1b1f9deabe9bf103d112f99b71ec
 * 4680fce708828a726413a1ed253fca685fd4f8d338633234a8a9f2a734f91c44915b2d24bb6fae1036b18398
 *	expectedKey2Key =
 * a34d045829f83bee80109bcc057d3e0b25e9773f50bad45a7b8deadb16d823c0ee830cc2fe6b03cbf4caf6b1ac09f6bc5dc44e58c32ba35e37dd
 * e9c570f6724275074daf78b2625e067945eb03e676c2c267ef2e0a9cd2ba7865290320e1d7466dc593a1d9fc5508ddc61b1b0e2c1aa4413a689b
 * dfdb47214346fc94472f94d6292929f25bd54498ed1bfeb5621044182d2dff320c04e311d8545be8c05f436cf4fb64bc55bcab8c6a413886e598
 * 175b93cc5e5121c55b90a834d559395101fdca654310224156c1b59ecd2289ea1a1904def962d617aa010be5aca1aa4e8aa2b694cc0a779de0b1
 * e53d4a6abcfc0b11294099c4bd44964e5a59bc1a317a3f7ad228b913639ac47ce888f6aa81b98693e484b90e1f80a0ebabfaf2afe0f3022782c8
 * 1dd0c6d7b55386d25ef75100d0e4d2a7c638da19bcf37729b2a19e82c1a4967fab6d336b71379e951b5fc51b55991dab302a74e3348ad3a6bb9a
 * 80a7f1cae3991e15c66762cc58bcc18c7f580d9416bb01aa915f38aa3fe615c5dc66848903f523df89944a16706b5e9d0a329edff74691d7d171
 * 23f1c6bb986b9a4c8d61f7b428aaf372f6a24dea1436e61568497c8ea2abb7dfa3c220a3ae8098d3f39c3d4d026552f577190a9a7f01916985ec
 * 6e56c0e43f59e6a7b39c98bc2fd58e2f8fbdd996cdca43e60c54a1c1b6bd8957fbfaa20ee3edb84f7c7b358941f6289916c737504aec8066a744
 * 7c77a8ae838bd7c4d6c5a658d691c387d952ecc53dec1b1af09670351bab11cb960d05f3010ae62c7d011a18c1c8d7abb4b9ab4f3be462c9aebf
 * 45dd196edeb77878355c1348fa336efad79b97ebb06f70acf10e3b8bd74779ea772ab68a54845bf3f21b2ebb34400a5da51286589fd58cfdd264
 * 1f8264a1a6ed25350099bbb440e98c7f5248e1bd7f809f1f40b1e8bb8f1c31144580452b05116941593cddbfcee177e57949c031882ddb60b8e0
 * 9fed2f6513ea55923a1a4b46204fe293c7eac9d671434eb7ce3c3ce7ec93180fbc1aed42eb0229be1a0ac0b65433e0c9a03bde4f8afe2a6dafb6
 * bc857ed4aa905b09c65b3df00d9de583ea08e00edc0146c66f64b09b3923433ec127fac129d45807b9a0d4ed8303e689661381b12de75777d2a1
 * 5421076eeee9aa227fc3fe92e566128425b499803fbb20164eaf7494ac9208beedd5c95a978af2dd279ad9ac193e30b34afbd78d142e308855d2
 * 190537cc126afcfe88604c9fc1deaec21564104226cf600919ad9d6e36614d21f0056f980a01f30bbd062ebacaa4344265a96531c593b4ba252c
 * ac96a4b4df8055a1714626ee876dae2cf2afb03095e29e8af4295322248c5d73f6d5c54cc4e084441ee3c7f434a7364b114a88b8dadebcbe820b
 * a0ec885a4c152ffc6aba770c4704e6680e761b312fa3e5554f3f5b3bc587a61c444ff0d6e22e739f62d4674d5105c521cfbd38ac5449cafe1ddc
 * e92b0a6de2b3bc03bcdc28fbc58524a33674ff51cd1ea9d2a81f225b2545fef30b567efeab8297f8d4223911

*/

// helperContractAddressPQ duplicates the helper used in EC tests to avoid import cycles.
func helperContractAddressPQ() *string {
	var b [internal.EthAddressLength]byte
	for i := 0; i < internal.EthAddressLength; i++ {
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

func unpackHexToPublicKey(hexString string, pk *kyberKEM.PublicKey) error {
	buf := make([]byte, kyberKEM.PublicKeySize)
	_, err := hex.Decode(buf, []byte(hexString))
	pk.Unpack(buf)
	return err
}

func TestPulsePQ_KnownValues(t *testing.T) {
	plainText := []byte("pulse text")
	contractAddress := helperContractAddressPQ()
	purpose := internal.PulseSymmetricConsent
	chainId := uint8(0x01)

	alicePrivate, err := keyFromFile("alice_private.hex")
	if err != nil {
		t.Fatalf("Alice read from file: %v", err)
	}

	bobPrivate, err := keyFromFile("bob_private.hex")
	if err != nil {
		t.Fatalf("Bob read from file: %v", err)
	}

	// alicePublicIface := alicePrivate.Public()
	// alicePublic := alicePublicIface.(*kyberKEM.PublicKey)

	bobPublicIface := bobPrivate.Public()
	bobPublic := bobPublicIface.(*kyberKEM.PublicKey)

	aesKey := mustHexDecode("75ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a" + "000102030405060708090a0b")
	seed := mustHexDecode("76ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a")

	enc := NewPulsePQEncryption().
		SetPlaintext(plainText).
		SetContractAddress(contractAddress).
		SetPurpose(purpose).
		SetChainId(chainId).
		SetMyPrivateKey(alicePrivate).
		AddOtherPublicKey(bobPublic).
		setAESKey(aesKey).
		setSeed(seed)

	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result := enc.GetEncryptionResult()
	if result == nil {
		t.Fatalf("result is nil")
	}
	expectedSealedData := mustHexDecode("e0584e6c16bcf1b2e20959e084b6bbcc67dfcea96462d0c21d63")
	expectedKey1FingerPrint := mustHexDecode("01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd")
	expectedKey2FingerPrint := mustHexDecode("70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde")

	if !bytes.Equal(result.SealedData, expectedSealedData) {
		t.Fatalf("expected sealed data mismatch: got %x want %x", result.SealedData, expectedSealedData)
	}
	if len(result.Keys) != 2 {
		t.Fatalf("expected 2 keys in result, got %d", len(result.Keys))
	}

	// The order of the keys is not deterministic, so we need to compare the fingerprints to work out which is which
	if bytes.Equal(result.Keys[0].KeyFingerPrint[:], expectedKey1FingerPrint[:]) {
		// expected1 == Keys[0] !
		if !bytes.Equal(result.Keys[1].KeyFingerPrint[:], expectedKey2FingerPrint) {
			t.Fatalf("second key fingerprint mismatch: got %x want %x", result.Keys[1].KeyFingerPrint, expectedKey2FingerPrint)
		}
	} else if bytes.Equal(result.Keys[0].KeyFingerPrint[:], expectedKey2FingerPrint) {
		// expected2 == Keys[0] !
		if !bytes.Equal(result.Keys[1].KeyFingerPrint[:], expectedKey1FingerPrint) {
			t.Fatalf("second key fingerprint mismatch: got %x want %x", result.Keys[1].KeyFingerPrint, expectedKey1FingerPrint)
		}
	} else {
		// Neither expected1 nor expected2 == Keys[0] !
		t.Fatalf("neither keyFingerPrint1 nor keyFingerPrint2 found in result")
	}

	// Verify we can decrypt it back
	dec := NewPulsePQEncryption().
		SetContractAddress(contractAddress).
		SetPurpose(purpose).
		SetChainId(chainId).
		SetEncryptionResult(result).
		SetMyPrivateKey(alicePrivate)

	if err := dec.Decrypt(); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(dec.Plaintext(), plainText) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", dec.Plaintext(), plainText)
	}
}

func TestPulsePQ_SettersAndGetEncryptionResult(t *testing.T) {
	pt := []byte("hello pq")
	cipher := []byte{1, 2, 3, 4, 5}

	e := NewPulsePQEncryption().
		SetPlaintext(pt).
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01)

	// Sanity: Plaintext getter
	if !bytes.Equal(e.Plaintext(), pt) {
		t.Fatalf("plaintext getter mismatch: got %q want %q", e.Plaintext(), pt)
	}

	// Pre-populate encapsulated keys and ciphertext directly (package-private fields)
	finger1 := [32]byte{0xAA}
	finger2 := [32]byte{0xBB}
	enc1 := []byte{9, 9, 9}
	enc2 := []byte{8, 8, 8}
	enc3 := []byte{7, 7, 7}
	enc4 := []byte{6, 6, 6}
	e.encapsulatedKeys = []*PulsePQEncryptionKey{
		{KeyFingerPrint: finger1, EncapsulatedKeyKey: enc1, EncapsulatedDataKey: enc3},
		{KeyFingerPrint: finger2, EncapsulatedKeyKey: enc2, EncapsulatedDataKey: enc4},
	}
	e.ciphertext = cipher

	res := e.GetEncryptionResult()
	if !bytes.Equal(res.SealedData, cipher) {
		t.Fatalf("sealed data mismatch: got %x want %x", res.SealedData, cipher)
	}
	if len(res.Keys) != 2 {
		t.Fatalf("expected 2 keys in result, got %d", len(res.Keys))
	}
	if !bytes.Equal(res.Keys[0].KeyFingerPrint[:], finger1[:]) ||
		!bytes.Equal(res.Keys[0].EncapsulatedKeyKey, enc1) ||
		!bytes.Equal(res.Keys[0].EncapsulatedDataKey, enc3) {
		t.Fatalf("first key key mismatch")
	}
	if !bytes.Equal(res.Keys[1].KeyFingerPrint[:], finger2[:]) ||
		!bytes.Equal(res.Keys[1].EncapsulatedKeyKey, enc2) ||
		!bytes.Equal(res.Keys[1].EncapsulatedDataKey, enc4) {
		t.Fatalf("second key key mismatch")
	}
}

func TestPulsePQ_Encrypt_Errors(t *testing.T) {
	// Missing plaintext
	{
		e := NewPulsePQEncryption().
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01)
		if err := e.Encrypt(); err == nil || err.Error() != "must provide plaintext" {
			t.Fatalf("expected missing plaintext error, got %v", err)
		}
	}

	pk1, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pk2, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Missing contract address
	{
		e := NewPulsePQEncryption().
			SetPlaintext([]byte("data")).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01).
			AddOtherPublicKey(pk1).
			AddOtherPublicKey(pk2)
		if err := e.Encrypt(); err == nil || err.Error() != "must provide contract address" {
			t.Fatalf("expected missing contract address error, got %v", err)
		}
	}

	// Missing purpose
	{
		e := NewPulsePQEncryption().
			SetPlaintext([]byte("data")).
			SetContractAddress(helperContractAddressPQ()).
			SetChainId(0x01).
			AddOtherPublicKey(pk1).
			AddOtherPublicKey(pk2)
		if err := e.Encrypt(); err == nil || err.Error() != "must provide purpose" {
			t.Fatalf("expected missing purpose error, got %v", err)
		}
	}

	// Missing chainId
	{
		e := NewPulsePQEncryption().
			SetPlaintext([]byte("data")).
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			AddOtherPublicKey(pk1).
			AddOtherPublicKey(pk2)
		if err := e.Encrypt(); err == nil || err.Error() != "must provide chainId" {
			t.Fatalf("expected missing chainId error, got %v", err)
		}
	}

	// Not enough recipients (<2)
	{
		e := NewPulsePQEncryption().
			SetPlaintext([]byte("data")).
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01).
			AddOtherPublicKey(pk1)
		if err := e.Encrypt(); err == nil || err.Error() != "must provide another public key" {
			t.Fatalf("expected not-enough-recipients error, got %v", err)
		}
	}
}

func TestPulsePQ_Decrypt_Errors(t *testing.T) {
	// Missing private key
	{
		e := NewPulsePQEncryption().
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01)
		if err := e.Decrypt(); err == nil || err.Error() != "must provide private key" {
			t.Fatalf("expected missing private key error, got %v", err)
		}
	}

	// Missing encryption result
	{
		e := NewPulsePQEncryption().
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01)
		// Provide a non-nil private key to get past first check
		e.myPrivateKey = new(kyberKEM.PrivateKey)
		if err := e.Decrypt(); err == nil || err.Error() != "must provide encryption result" {
			t.Fatalf("expected missing encryption result error, got %v", err)
		}
	}

	// Missing ciphertext in encryption result
	{
		e := NewPulsePQEncryption().
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01)
		e.myPrivateKey = new(kyberKEM.PrivateKey)
		e.encryptionResult = &PulsePQEncryptionResult{SealedData: nil}
		if err := e.Decrypt(); err == nil || err.Error() != "must provide ciphertext in encryption result" {
			t.Fatalf("expected missing ciphertext error, got %v", err)
		}
	}

	// No matching encapsulated key for my fingerprint
	{
		e := NewPulsePQEncryption().
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01)
		// Set a dummy private key to pass verify, but do not set myPublicKeyFingerPrint so it won't match
		e.myPrivateKey = new(kyberKEM.PrivateKey)
		e.encryptionResult = &PulsePQEncryptionResult{
			SealedData: []byte{1, 2, 3},
			Keys: []*PulsePQEncryptionKey{
				{KeyFingerPrint: [32]byte{0x01}, EncapsulatedKeyKey: []byte{0x02}, EncapsulatedDataKey: []byte{0x03}},
			},
		}
		if err := e.Decrypt(); err == nil || err.Error() != "no key found for this party" {
			t.Fatalf("expected no matching key error, got %v", err)
		}
	}
}

// --- Additional tests for Kyber KEM flow ---

func TestPulsePQ_Encrypt_Success_WithRecipients(t *testing.T) {
	// Generate two KEM keypairs for recipients
	pk1, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pk2, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	enc := NewPulsePQEncryption().
		SetPlaintext([]byte("top secret pq data")).
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01)

	enc.AddOtherPublicKey(pk1)
	enc.AddOtherPublicKey(pk2)

	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if len(enc.ciphertext) == 0 {
		t.Fatalf("ciphertext should not be empty")
	}

	// Build expected fingerprints for both recipients
	fp1 := getPubKeyFingerprint(pk1)
	fp2 := getPubKeyFingerprint(pk2)

	res := enc.GetEncryptionResult()
	if len(res.Keys) != 2 {
		t.Fatalf("expected 2 encapsulated keys, got %d", len(res.Keys))
	}
	// Check that both fingerprints are present and encapsulated keys have expected size
	seen1, seen2 := false, false
	for _, k := range res.Keys {
		if len(k.EncapsulatedKeyKey) == 0 || len(k.EncapsulatedDataKey) == 0 {
			t.Fatalf("encapsulated key should not be empty")
		}
		if bytes.Equal(k.KeyFingerPrint[:], fp1[:]) {
			seen1 = true
		}
		if bytes.Equal(k.KeyFingerPrint[:], fp2[:]) {
			seen2 = true
		}
	}
	if !seen1 || !seen2 {
		t.Fatalf("did not see all expected recipient fingerprints: seen1=%v seen2=%v", seen1, seen2)
	}
}

func TestPulsePQ_GetEncryptionResult_SkipsNil(t *testing.T) {
	e := NewPulsePQEncryption()
	cipher := []byte{7, 7, 7}
	e.ciphertext = cipher
	e.encapsulatedKeys = []*PulsePQEncryptionKey{
		nil,
		{KeyFingerPrint: [32]byte{0x01}, EncapsulatedKeyKey: []byte{0x02}, EncapsulatedDataKey: []byte{0x03}},
		nil,
	}
	res := e.GetEncryptionResult()
	if !bytes.Equal(res.SealedData, cipher) {
		t.Fatalf("sealed data mismatch")
	}
	if len(res.Keys) != 1 {
		t.Fatalf("expected 1 non-nil key, got %d", len(res.Keys))
	}
	if res.Keys[0] == nil ||
		len(res.Keys[0].KeyFingerPrint) == 0 ||
		len(res.Keys[0].EncapsulatedKeyKey) == 0 ||
		len(res.Keys[0].EncapsulatedDataKey) == 0 {
		t.Fatalf("unexpected nil or empty key fields")
	}
}

func TestPulsePQ_EncryptDecrypt_Success(t *testing.T) {
	alicePub, alicePriv, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	bobPub, bobPriv, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	plainText := []byte("top secret pq data")

	enc := NewPulsePQEncryption().
		SetPlaintext(plainText).
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01)

	enc.AddOtherPublicKey(alicePub)
	enc.AddOtherPublicKey(bobPub)

	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if len(enc.ciphertext) == 0 {
		t.Fatalf("ciphertext should not be empty")
	}

	encResult := enc.GetEncryptionResult()
	if len(encResult.Keys) != 2 {
		t.Fatalf("expected 2 encapsulated keys, got %d", len(encResult.Keys))
	}

	decAlice := NewPulsePQEncryption().
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(encResult).
		SetMyPrivateKey(alicePriv)

	if err := decAlice.Decrypt(); err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(decAlice.Plaintext(), plainText) {
		t.Fatalf("plaintext mismatch: got %q want %q", decAlice.Plaintext(), plainText)
	}

	decBob := NewPulsePQEncryption().
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(encResult).
		SetMyPrivateKey(bobPriv)
	if err := decBob.Decrypt(); err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(decBob.Plaintext(), plainText) {
		t.Fatalf("plaintext mismatch: got %q want %q", decBob.Plaintext(), plainText)
	}
}

func TestPulsePQ_SetPrivateKey_AddsPublicKey(t *testing.T) {
	_, sk, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	e := NewPulsePQEncryption().
		SetMyPrivateKey(sk)

	if len(e.otherPublicKeys) != 1 {
		t.Fatalf("expected 1 other public key, got %d", len(e.otherPublicKeys))
	}
}

func TestPulsePQ_SingleParty_Fails(t *testing.T) {
	_, sk, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	e := NewPulsePQEncryption().
		SetMyPrivateKey(sk).
		SetChainId(1).
		SetPurpose(internal.PulseSymmetricConsent).
		SetContractAddress(helperContractAddressPQ()).
		SetPlaintext([]byte("hello pq"))

	err = e.verifyEncryptReady()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "must provide another public key" {
		t.Fatalf("expected error message, got %v", err)
	}
}

func TestDuplicate_OtherKey(t *testing.T) {
	pk, sk, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	e := NewPulsePQEncryption().
		SetChainId(1).
		SetPurpose(internal.PulseSymmetricConsent).
		SetContractAddress(helperContractAddressPQ()).
		SetPlaintext([]byte("hello pq")).
		AddOtherPublicKey(pk).
		AddOtherPublicKey(pk)

	if len(e.otherPublicKeys) != 1 {
		t.Fatalf("duplicate pub: expected 1 otherpublickey, got %d", len(e.otherPublicKeys))
	}

	e2 := NewPulsePQEncryption().
		SetChainId(1).
		SetPurpose(internal.PulseSymmetricConsent).
		SetContractAddress(helperContractAddressPQ()).
		SetPlaintext([]byte("hello pq")).
		AddOtherPublicKey(pk).
		SetMyPrivateKey(sk)

	if len(e2.otherPublicKeys) != 1 {
		t.Fatalf("add myPublic and private: expected 1 otherpublickey, got %d", len(e2.otherPublicKeys))
	}
}

func TestPulsePQ_Decrypt_TamperedEncapsulatedKey_Fails(t *testing.T) {
	// Generate recipients
	pk1, sk1, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pk2, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Encrypt for two recipients
	enc := NewPulsePQEncryption().
		SetPlaintext([]byte("secret")).
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01)
	enc.AddOtherPublicKey(pk1)
	enc.AddOtherPublicKey(pk2)
	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	res := enc.GetEncryptionResult()
	if len(res.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(res.Keys))
	}

	// Find entry for recipient1 by fingerprint and tamper the encapsulated key
	// Build recipient1 fingerprint from pk1
	fp1 := getPubKeyFingerprint(pk1)

	found := false
	for _, k := range res.Keys {
		if bytes.Equal(k.KeyFingerPrint[:], fp1[:]) {
			if len(k.EncapsulatedKeyKey) > 0 {
				k.EncapsulatedKeyKey[0] ^= 0xFF // flip a bit
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("failed to locate recipient key to tamper")
	}

	// Attempt decrypt as recipient1
	dec := NewPulsePQEncryption().
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(res).
		SetMyPrivateKey(sk1)
	if err := dec.Decrypt(); err == nil {
		t.Fatalf("expected decrypt failure with tampered encapsulated key: plaintext=%q", dec.Plaintext())
	}
}

func TestPulsePQ_Decrypt_NoMatchingFingerprint_Fails(t *testing.T) {
	// Two recipients for encryption
	pk1, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pk2, _, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// Third party trying to decrypt
	_, sk3, err := kyberKEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	enc := NewPulsePQEncryption().
		SetPlaintext([]byte("secret")).
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01)
	enc.AddOtherPublicKey(pk1)
	enc.AddOtherPublicKey(pk2)
	if err := enc.Encrypt(); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	res := enc.GetEncryptionResult()

	dec := NewPulsePQEncryption().
		SetContractAddress(helperContractAddressPQ()).
		SetPurpose(internal.PulseSymmetricConsent).
		SetChainId(0x01).
		SetEncryptionResult(res).
		SetMyPrivateKey(sk3)
	if err := dec.Decrypt(); err == nil || err.Error() != "no key found for this party" {
		t.Fatalf("expected 'no key found for this party', got %v", err)
	}
}

func TestPulsePQ_Encrypt_DeterministicWithSeed(t *testing.T) {
	pk1, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	pk2, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	seed := bytes.Repeat([]byte{0x42}, kyberPKE.EncryptionSeedSize)
	aesKey := mustHexDecode("75ab8bc72f3e2b201e0d0146dff8dfdcbc0c9581ba729cf39145ad459bea745a" + "000102030405060708090a0b")

	mkEnc := func() *PulsePQEncryption {
		return NewPulsePQEncryption().
			SetPlaintext([]byte("msg")).
			SetContractAddress(helperContractAddressPQ()).
			SetPurpose(internal.PulseSymmetricConsent).
			SetChainId(0x01).
			setAESKey(aesKey)
	}

	e1 := mkEnc().AddOtherPublicKey(pk1).AddOtherPublicKey(pk2).setSeed(seed)
	if err := e1.Encrypt(); err != nil {
		t.Fatal(err)
	}
	r1 := e1.GetEncryptionResult()

	e2 := mkEnc().AddOtherPublicKey(pk1).AddOtherPublicKey(pk2).setSeed(seed)
	if err := e2.Encrypt(); err != nil {
		t.Fatal(err)
	}
	r2 := e2.GetEncryptionResult()

	sortKeys := func(res *PulsePQEncryptionResult) {
		sort.Slice(res.Keys, func(i, j int) bool {
			return bytes.Compare(res.Keys[i].KeyFingerPrint[:], res.Keys[j].KeyFingerPrint[:]) < 0
		})
	}
	sortKeys(r1)
	sortKeys(r2)

	if !bytes.Equal(r1.Keys[0].EncapsulatedKeyKey, r2.Keys[0].EncapsulatedKeyKey) ||
		!bytes.Equal(r1.Keys[1].EncapsulatedKeyKey, r2.Keys[1].EncapsulatedKeyKey) {
		t.Fatalf("encapsulated AES keys should be identical with fixed seed and AESkey")
	}
	if !bytes.Equal(r1.Keys[0].EncapsulatedDataKey, r2.Keys[0].EncapsulatedDataKey) ||
		!bytes.Equal(r1.Keys[1].EncapsulatedDataKey, r2.Keys[1].EncapsulatedDataKey) {
		t.Fatalf("encapsulated AES keys should be identical with fixed seed and AESkey")
	}
	if !bytes.Equal(r1.Keys[0].KeyFingerPrint[:], r2.Keys[0].KeyFingerPrint[:]) ||
		!bytes.Equal(r1.Keys[1].KeyFingerPrint[:], r2.Keys[1].KeyFingerPrint[:]) {
		t.Fatalf("fingerprints should be identical across deterministic runs")
	}

	// Converse without a seed
	e3 := mkEnc().AddOtherPublicKey(pk1).AddOtherPublicKey(pk2)
	if err := e3.Encrypt(); err != nil {
		t.Fatal(err)
	}
	r3 := e3.GetEncryptionResult()
	if bytes.Equal(r1.Keys[0].EncapsulatedKeyKey, r3.Keys[0].EncapsulatedKeyKey) ||
		bytes.Equal(r1.Keys[1].EncapsulatedKeyKey, r3.Keys[1].EncapsulatedKeyKey) {
		t.Fatalf("encapsulated keys should be different without fixed seed")
	}
	if bytes.Equal(r1.Keys[0].EncapsulatedDataKey, r3.Keys[0].EncapsulatedDataKey) ||
		bytes.Equal(r1.Keys[1].EncapsulatedDataKey, r3.Keys[1].EncapsulatedDataKey) {
		t.Fatalf("encapsulated keys should be different without fixed seed")
	}
}
