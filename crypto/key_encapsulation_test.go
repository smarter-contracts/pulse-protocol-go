package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
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

func unpackHexToPublicKey(hexString string, pk *kyberKEM.PublicKey) error {
	buf := make([]byte, kyberKEM.PublicKeySize)
	_, err := hex.Decode(buf, []byte(hexString))
	pk.Unpack(buf)
	return err
}

func TestPulsePQ_EncryptDecrypt_Success(t *testing.T) {
	plainText := []byte("pulse text")
	contractAddress := helperContractAddressPQ()
	purpose := symmetric.PulseSymmetricConsent
	chainId := uint8(0x01)

	alicePrivate, _ := keyFromFile("alice_private.hex")
	_ = alicePrivate
	bobPrivate, _ := keyFromFile("bob_private.hex")
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)

	// EncryptPQ for Bob
	result, err := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{bobPublic}, purpose, int32(chainId), 0)
	if err != nil {
		t.Fatalf("EncryptPQ: %v", err)
	}

	// DecryptPQ for Bob
	decrypted, err := DecryptPQ(result, contractAddress, bobPrivate, purpose, int32(chainId), 0)
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
	purpose := symmetric.PulseSymmetricConsent
	chainId := uint8(0x01)
	pk, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, _ := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk}, purpose, int32(chainId), 0)

	// Decrypt with wrong private key
	pkWrong, wrongSK, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	_ = pkWrong
	_, err := DecryptPQ(result, contractAddress, wrongSK, purpose, int32(chainId), 0)
	if err == nil || err.Error() != "no key found for this party" {
		t.Fatalf("expected 'no key found for this party', got %v", err)
	}
}

func TestPulsePQ_Encrypt_Success_WithRecipients(t *testing.T) {
	plainText := []byte("top secret pq data")
	contractAddress := helperContractAddressPQ()
	purpose := symmetric.PulseSymmetricConsent
	chainId := uint8(0x01)

	pk1, sk1, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	_ = sk1
	pk2, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, err := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk1, pk2}, purpose, int32(chainId), 0)
	if err != nil {
		t.Fatalf("EncryptPQ: %v", err)
	}

	if len(result.SealedData) == 0 {
		t.Fatalf("sealed data should not be empty")
	}

	if len(result.Keys) != 2 {
		t.Fatalf("expected 2 encapsulated keys, got %d", len(result.Keys))
	}

	// Build expected fingerprints for both recipients
	fp1 := getPubKeyFingerprint(pk1)
	fp2 := getPubKeyFingerprint(pk2)

	// Check that both fingerprints are present
	seen1, seen2 := false, false
	for _, k := range result.Keys {
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

func TestPulsePQ_Decrypt_TamperedEncapsulatedKey_Fails(t *testing.T) {
	plainText := []byte("secret")
	contractAddress := helperContractAddressPQ()
	purpose := symmetric.PulseSymmetricConsent
	chainId := uint8(0x01)

	pk1, sk1, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	pk2, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, _ := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk1, pk2}, purpose, int32(chainId), 0)

	// Find entry for recipient1 by fingerprint and tamper the encapsulated key
	fp1 := getPubKeyFingerprint(pk1)

	found := false
	for _, k := range result.Keys {
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
	_, err := DecryptPQ(result, contractAddress, sk1, purpose, int32(chainId), 0)
	if err == nil {
		t.Fatal("expected decrypt failure with tampered encapsulated key")
	}
}

func TestGetAllRecipientIDHash(t *testing.T) {
	// Use some fixed fingerprints for testing
	fp1 := "01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd"
	fp2 := "70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"

	// fingerprints sorted: fp1, fp2
	// recipientString := "|pulse|group|v1|01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd|70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|"

	hash1 := getAllRecipientIDHashFromFingerPrints([]string{fp1, fp2})
	hash2 := getAllRecipientIDHashFromFingerPrints([]string{fp2, fp1})

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("getAllRecipientIDHashFromFingerPrints is not deterministic: %x != %x", hash1, hash2)
	}

	// Known hash for these fingerprints (Keccak256)
	expectedHash := mustHexDecode("9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922")
	if !bytes.Equal(hash1, expectedHash) {
		t.Errorf("getAllRecipientIDHashFromFingerPrints mismatch: got %x, want %x", hash1, expectedHash)
	}
}

func TestEncryptPQ_KnownValues(t *testing.T) {
	// Setup fixed entropy source
	seed := make([]byte, 1024)
	entropy := bytes.NewReader(seed) // All zeros entropy

	plaintext := []byte("pulse test")
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"
	purpose := symmetric.PulseSymmetricConsent
	chainId := int32(1)
	consentNumber := int32(0)

	// Use Bob's key from file (deterministic as well)
	bobPrivate, _ := keyFromFile("bob_private.hex")
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)

	// Calculate expected intermediate values
	recipientIDHash := getAllRecipientIDHashFromKeys([]*kyberKEM.PublicKey{bobPublic})
	contextHash := context.ContextHash(chainId, contractAddress, consentNumber)

	// For dataAESKey and nonce, we need to know how they are generated in PulseSealWithNewKey
	// PulseSealWithNewKey(entropy, ...) calls randutil.Bytes(entropy, 32) then randutil.Bytes(entropy, 12)
	entropyClone := bytes.NewReader(seed)
	dataAESKeyGenerated, _ := randutil.Bytes(entropyClone, 32)
	nonceGenerated, _ := randutil.Bytes(entropyClone, 12)

	result, err := EncryptPQ(entropy, plaintext, &contractAddress, []*kyberKEM.PublicKey{bobPublic}, purpose, chainId, consentNumber)
	if err != nil {
		t.Fatalf("EncryptPQ failed: %v", err)
	}

	// Verify all requested "known values"
	expectedRecipientIDHash := "defb6b9c9ee90833454eff2c033843bbd6070e6fceb8d2cbd095a88b4956e2fc"
	if hex.EncodeToString(recipientIDHash) != expectedRecipientIDHash {
		t.Errorf("recipientIDHash mismatch: got %x, want %s", recipientIDHash, expectedRecipientIDHash)
	}

	expectedContextHash := "7c70756c73657c6374787c76317c636861696e3d317c636f6e74726163743d3078303130323033303430353036303730383039306130623063306430653066313031313132313331347c636f6e73656e744e756d6265723d30c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if hex.EncodeToString(contextHash) != expectedContextHash {
		t.Errorf("contextHash mismatch: got %x, want %s", contextHash, expectedContextHash)
	}

	expectedDataAESKey := "0000000000000000000000000000000000000000000000000000000000000000"
	if hex.EncodeToString(dataAESKeyGenerated) != expectedDataAESKey {
		t.Errorf("dataAESKey mismatch: got %x, want %s", dataAESKeyGenerated, expectedDataAESKey)
	}

	expectedNonce := "000000000000000000000000"
	if hex.EncodeToString(nonceGenerated) != expectedNonce {
		t.Errorf("nonce mismatch: got %x, want %s", nonceGenerated, expectedNonce)
	}

	expectedSealedData := "bed22c4e28401f0b743a2555e29abfc7f2ff4e0212ddf02f4bb6"
	if hex.EncodeToString(result.SealedData) != expectedSealedData {
		t.Errorf("SealedData mismatch: got %x, want %s", result.SealedData, expectedSealedData)
	}

	expectedFingerprint := "70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"
	if hex.EncodeToString(result.Keys[0].KeyFingerPrint[:]) != expectedFingerprint {
		t.Errorf("KeyFingerPrint mismatch: got %x, want %s", result.Keys[0].KeyFingerPrint, expectedFingerprint)
	}

	expectedEncapsulatedKey := "a69fc428d306085ef8f79ccbe3d99b5070366a1264b7425e36a048e0119d620f885a2cda5d811a0c18beed14bde0a8bb8e069e16a826250bab2dbd547d4de0ff4de75b9014ad8bdb55628037141fb1e749d97e3db95b1c533e168e7974f4acf18048e93f4931e73f7d865af62d7552c4455c1ec7baeb86b696ee7ebf350c452f82242392f92bfd131564e305370c2c87be4cb4538b5325afd7d989e8850e0d76e63bc55cebed61e123752a455b9f04f022c53845c16ffe384a1b2f3369a1647b35164737b54d2dc7caa6363669a9a9efe33384777750677577a58bea494752ceba6e40b9d99cd9d843d40710ba313acff881218e241d2241a58391a53ebf3ec6e2f751fc5851e039a875953961782245f798fd43f567bc0d9d8663fad091590ca737606f5f651e74d2cbe2b10e14278a954f4192d2d1f612b43adc92a5cdd3498615e7689377a04c271a3b3ab8cd4eb0db8d5768666aa5e61b2a60649ffe8df5e775fa7b45c31b8dad5a1e73b17af9400b9b4f5f954fef18e2151a563337a43cc448690f8075a808efd1c13a11f5d6fc30f2ede542c3b9a54d033b3eb9b11f44c4be6fd20f8a6d1f928b4cede47259b2f54c40752d9ad4f7b3588c283a655638f497a6b03544273a292f501d59b21697309164f84d7344bc227d50590b810fce1ae0d81a996e9a0d279be62720818fce3f1b0ebcec5d0c392ec4c1e05108e48246099f8e87f66e983b1913422d46b6853de0e1c7056a6fe481aafc82439512741f58ad030ff567567eafa3650393b3156fa7620aee89002ddfa291e8bf0e3c9d1293cbce8d0eec4ff1eb613f4327acf114e0864f5d78373172af24ced15aac6d889f4c34713c905db1eb5fb75cdea3d96c3b3775efebfba3f8f3a15a3ce5169f007cfbf9e876976539d91858274a3d85dd07147f276fb0375b431317845d84308e283735cbea65a97df6a9798d4b2c447535e77e20204bcd8780f745734a6c8e8af441be9c9f6889a014b27226631d9af39e075bf53a6d83aa97e9d0e3602ba7ece204836d66e354ff03343d5d4fbd271fe4d4603d9eaf121b777d7e32cc832dd3500cfc9336d3ec04487f338b3a2057323738dd06534a316e2746abdb647b98a2b2fa1b62ab41d5aff7cb03d6dda768e6d045cca7394edf518b023aba6e65d34543b91ee616957765644ae2542bb704190fce9702d6af7415b2ab4cfc7a7c7e2d6c91bcc1c7834e3b01735fc12d2d27047f21a30138de09fcacff9df05b8b0b989853ab66003af5406542d79c32eab287bff9f412189da377dde08c28ad42e88d0789be6a3acf5cce43393b1142ed78f04cc2fb251490a506a9c4cbc16dd9ec8febba8f4a5a9624c962091ae54904b1e70d7bd47ae7f8f26ad92aa9ae52458da23e8f8076a34f89257fe7934b4df1ce188dfab4dd53032cf8fbb9a90f22b829bea68389be81c016cf6311df599e07946f891e6937c0230ced6767f478ef6b106d8debe7eccf58bf4b77279a083f3f5a73cdf0f28102d18e7b1f64bd393c6b73"
	if hex.EncodeToString(result.Keys[0].EncapsulatedKeyKey) != expectedEncapsulatedKey {
		t.Errorf("EncapsulatedKeyKey mismatch: got %x, want %s", result.Keys[0].EncapsulatedKeyKey, expectedEncapsulatedKey)
	}

	expectedEncapsulatedDataKey := "007ff672f889559e1af7b3b2b73c8ce602fd1d97d7262e261585bf4a139d1027bb1ff69026308bf46a85112f1d0e5d54548a9bcde88ed19468868242"
	if hex.EncodeToString(result.Keys[0].EncapsulatedDataKey) != expectedEncapsulatedDataKey {
		t.Errorf("EncapsulatedDataKey mismatch: got %x, want %s", result.Keys[0].EncapsulatedDataKey, expectedEncapsulatedDataKey)
	}

	// Round-trip check
	decrypted, err := DecryptPQ(result, &contractAddress, bobPrivate, purpose, chainId, consentNumber)
	if err != nil {
		t.Fatalf("DecryptPQ failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}
