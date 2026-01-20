package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/randutil"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/types"
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
	purpose := types.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)

	alicePrivate, _ := keyFromFile("alice_private.hex")
	_ = alicePrivate
	bobPrivate, _ := keyFromFile("bob_private.hex")
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)

	// EncryptPQ for Bob
	result, err := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{bobPublic}, purpose, chainId, 0)
	if err != nil {
		t.Fatalf("EncryptPQ: %v", err)
	}

	// DecryptPQ for Bob
	decrypted, err := DecryptPQ(result, contractAddress, bobPrivate, purpose, chainId, 0)
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
	purpose := types.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)
	pk, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, _ := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk}, purpose, chainId, 0)

	// Decrypt with wrong private key
	pkWrong, wrongSK, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	_ = pkWrong
	_, err := DecryptPQ(result, contractAddress, wrongSK, purpose, chainId, 0)
	if err == nil || err.Error() != "no key found for this party" {
		t.Fatalf("expected 'no key found for this party', got %v", err)
	}
}

func TestPulsePQ_Encrypt_Success_WithRecipients(t *testing.T) {
	plainText := []byte("top secret pq data")
	contractAddress := helperContractAddressPQ()
	purpose := types.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)

	pk1, sk1, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	_ = sk1
	pk2, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, err := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk1, pk2}, purpose, chainId, 0)
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

func stringCompare(t *testing.T, name, expected, actual string) {
	if expected != actual {
		t.Errorf("%s mismatch: got %s, want %s", name, actual, expected)
	}
}

func TestEncapsulateKey_KnownValues(t *testing.T) {
	alicePrivate, err := keyFromFile("alice_private.hex")
	if err != nil {
		t.Fatalf("Alice keyFromFile failed: %v", err)
	}
	alicePublic := alicePrivate.Public().(*kyberKEM.PublicKey)

	bobPrivate, err := keyFromFile("bob_private.hex")
	if err != nil {
		t.Fatalf("Bob keyFromFile failed: %v", err)
	}
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)

	// Since encapsulateKey is tested with suitable entropy, it consumes some bytes from it.
	// We need to skip the bytes already consumed by PulseSealWithNewKey in a full EncryptPQ run
	// if we want to match those values, but here we just test encapsulateKey in isolation.
	// encapsulateKey consumes scheme.EncapsulationSeedSize() = 32 bytes for seed.

	tests := []struct {
		name                 string
		seed                 []byte
		publicKey            *kyberKEM.PublicKey
		aesKeyPacked         []byte
		purpose              types.PulsePurpose
		contextHash          []byte
		expectedFingerPrint  string
		expectedSharedSecret string
		expectedEncapsulated string // encapsulatedSecret
		expectedKeyAESKey    string
		expectedKeyNonce     string
		expectedEncryptedKey string // encryptedKey (EncapsulatedDataKey)
		expectedResultCBOR   []byte
	}{
		{
			name:                 "Alice Isolation",
			seed:                 mustHexDecode("2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b"),
			publicKey:            alicePublic,
			aesKeyPacked:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"),
			purpose:              types.PulsePurposeEncryptConsentStructure,
			contextHash:          mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			expectedFingerPrint:  "01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd",
			expectedSharedSecret: "5c1db08a4db86a2f26964f53c2911e8ab029f0087732e76bd5e1842dbac50777",
			expectedEncapsulated: "b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9",
			expectedKeyAESKey:    "8c00e2528428927b81befef1022cf7de7aae639b8f714a90c1c6106237000822",
			expectedKeyNonce:     "504f2d28709e2db670a59cc4",
			expectedEncryptedKey: "b500e45683a54614d13c6c239dda4829089657ce965b5d28ab8920f3a87d96cf69bf85893de9c1a938caf63cf48ec3f0c29f30045b8ec1249f046812",
			expectedResultCBOR:   mustHexDecode("83582001b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd590440b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9583cb500e45683a54614d13c6c239dda4829089657ce965b5d28ab8920f3a87d96cf69bf85893de9c1a938caf63cf48ec3f0c29f30045b8ec1249f046812"),
		},
		{
			name:                 "Bob Isolation",
			seed:                 mustHexDecode("4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b"),
			publicKey:            bobPublic,
			aesKeyPacked:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"),
			purpose:              types.PulsePurposeEncryptConsentStructure,
			contextHash:          mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			expectedFingerPrint:  "70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde",
			expectedSharedSecret: "49666a8941873a339c07299b0aea6941ad420dd0df8ebd9fc5160154153caea3",
			expectedEncapsulated: "ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02",
			expectedKeyAESKey:    "ec144bc3e77f9d68782131775750e9e53d76ccc8186e1846a146d5e37c48f3ca",
			expectedKeyNonce:     "2e00a1a119f54375f5a75416",
			expectedEncryptedKey: "4614dfed6eac84edbd00618bc1a681de48043dde02b187df803812427e59070ce716b3b3cf0033bab49cfb7568c9dbf5788b8b4f078cdd3fcb56ad76",
			expectedResultCBOR:   mustHexDecode("83582070e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde590440ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02583c4614dfed6eac84edbd00618bc1a681de48043dde02b187df803812427e59070ce716b3b3cf0033bab49cfb7568c9dbf5788b8b4f078cdd3fcb56ad76"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We need to capture intermediate values. Since we cannot easily modify encapsulateKey to return them
			// without breaking EncryptPQ (unless we return a lot of values), we will replicate the logic here
			// and compare with the result of encapsulateKey.

			// Actually, let's just use the known values from a successful run if possible.
			// I will run the test once to get the values, then fix them.
			entropy := bytes.NewReader(tt.seed)

			res, err := encapsulateKey(entropy, tt.publicKey, tt.aesKeyPacked, tt.purpose, tt.contextHash)
			if err != nil {
				t.Fatalf("encapsulateKey failed: %v", err)
			}

			// Verify result matches expected
			stringCompare(t, tt.name+" fingerPrint", tt.expectedFingerPrint, textformat.FormatHex(res.KeyFingerPrint[:]))
			stringCompare(t, tt.name+" encapsulatedSecret", tt.expectedEncapsulated, textformat.FormatHex(res.EncapsulatedKeyKey))
			stringCompare(t, tt.name+" encryptedKey", tt.expectedEncryptedKey, textformat.FormatHex(res.EncapsulatedDataKey))

			// To verify sharedSecret, keyAESKey, keyNonce, we MUST either return them from encapsulateKey
			// or re-derive them here using the same seed.

			// Let's re-derive using the same logic as encapsulateKey to verify intermediate steps.
			scheme := kyberKEM.Scheme()
			entropyClone := bytes.NewReader(tt.seed) // reset entropy
			seedForIsolation := make([]byte, scheme.EncapsulationSeedSize())
			io.ReadFull(entropyClone, seedForIsolation)

			encapsulatedSecret, sharedSecret, _ := scheme.EncapsulateDeterministically(tt.publicKey, seedForIsolation)
			if textformat.FormatHex(sharedSecret) != tt.expectedSharedSecret {
				t.Errorf(tt.name+" sharedSecret mismatch: got %x, want %s", sharedSecret, tt.expectedSharedSecret)
			}
			if textformat.FormatHex(encapsulatedSecret) != tt.expectedEncapsulated {
				t.Errorf(tt.name+" output encapsulatedSecret mismatch: got %x, want %s", encapsulatedSecret, tt.expectedEncapsulated)
			}

			keyAESKey, keyNonce, _ := hkdf.PulseHKDFKyber(sharedSecret, encapsulatedSecret, res.KeyFingerPrint[:], tt.contextHash)
			if textformat.FormatHex(keyAESKey) != tt.expectedKeyAESKey {
				t.Errorf(tt.name+" keyAESKey mismatch: got %x, want %s", keyAESKey, tt.expectedKeyAESKey)
			}
			if textformat.FormatHex(keyNonce) != tt.expectedKeyNonce {
				t.Errorf(tt.name+" keyNonce mismatch: got %x, want %s", keyNonce, tt.expectedKeyNonce)
			}

			resCBOR, err := res.CBOR()
			if err != nil {
				t.Fatalf("res.CBOR() failed: %v", err)
			}
			if !bytes.Equal(tt.expectedResultCBOR, resCBOR) {
				t.Errorf(tt.name+" resultCBOR mismatch: got %x, want %x", resCBOR, tt.expectedResultCBOR)
			}
		})
	}
}

func TestEncryptPQ_KnownValues(t *testing.T) {
	// Setup fixed entropy source
	seed := make([]byte, 1024)
	for i := range seed {
		seed[i] = byte(i) // Yes, i will overrun the range of byte. That's fine...
	}
	entropy := bytes.NewReader(seed) // All zeros entropy

	plaintext := []byte("This is the consent record")
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"
	purpose := types.PulsePurposeEncryptConsentStructure
	chainId := uint32(1)
	consentNumber := uint32(2)

	// Get Alice's key from file (deterministic)
	alicePrivate, err := keyFromFile("alice_private.hex")
	if err != nil {
		t.Fatalf("Alice keyFromFile failed: %v", err)
	}
	expectedAlicePublic := "a2e2bc9316831a20238fb736714abb79925054823320ab12a4434422524d7da799b17678f7a2cc60280d08fc2b334357e1f7752666440e62125f943cf3e450d1d364e12684ab559da04baf7b8408c188691d596f934b08b0ba1e94a135a7a60b55994efba27095321526d975f5d92dabb33a60f85540c455b364826ed69508f716458cc0d9f121a699754061a747468fdf1a320a8841d28a3cd7281ecc65630d6c6123f7c3fcb994c903a79a447a57315f316a8a9c68972b481ad130b7b50401f8488c8dd64a6a7898471870061c63fc703d6e97486f0caef8f0278db4236bf6738f3cbea6919539819c9c590e0e09803504a771f2a65e5a7dcfe7682189005a879579522d11fa66534c9257b3af0828a9daf3cb5b8738b7bb462bd31208206b04c326ba788e0480c2a0f311cfa96c65843d29076e90f005d6294b0463cb159c41f610ada5d23bb2fa58dc8cb30f58983575555e172f540032e84a7530dc413624b75a38111e431a9a4b846c231a90e8072b05c9572c8648176ec62c612427b41239c71476588ef89b93f08c4edc3e51ca7303107cb3157069aa3e94982c942bb71f9a88a5baba446c203b592b354818fe03b0e1104c957590783b58ece1724630b1367a86721b77e4eac509b1626e738cc42a6ed6bccd897c3807b532b86c5c2c4410a3817045885c41e2610776168cab3bfd38a52bb5392c418f27c92218f0720bb272fe2401dcb09de2586802c20691ea22f3f82ede0b380a7bc0aef720a52a8db5aa7207c5476b083e7b040fe5f92121f707dd5cb06e840205eb0481d699a120ae4ce235ea6b5d9e380624652a5abc074f8ac5e1d3095f7743ea45cffa7b0478e105efcc6c47b399d63c451db72ac93c7b7b3aa0ed0b9d8b471c1b1331da4bc4d60a001bcaad6e1257118b6524d7baa4e5afbe92192abc40a6ec985e944997e114de7a82fdc73a16e3c9efec6d106b5ad7714e8c7a5e93e6384af4926eeb40fbdbbece398256c21698904a3934323d1498b32004513a6117b9ba785292e2c605a01b216785518d23a50a80a5418912d351ad8380af67401aa00c90b3d4c873b112855c22efd1c0d09940382c4de38cacedb75f263750f2d903f67687fe498475ca95c87524056784b2b5207fbbb47eb098da84657a4583e3b49b954465ea5b0e9119b2ebd14df817028466bd5f48ac007cacdd3b45e08acfb2ebaa5715775edb9ee0e30be9e680baa703be793b7df8528ac34c0500c04834020adc91e0cb3633b72d91fa93ba8babb1d91cdf8971173065b9530be00b08462b7e959c4b473489c2cc3a12a757cc14b7c923b0f7083d44972424a0a8c61408edd65fcef98bf3937a7d6541b2817027134fd6c715b5935ee988920a0544ce01c7fc3b23e4f093ff5b09bf837fedb195bd13201ba7c207d41ae8224e6a6c3fe7e8a64ffb66318188a0582b84816e0661466a61ccc022976ebaaf7be575bf489d422231167039c9950c0906238b11cad15a94338843ef776f72942005e31550b80480660ecc65a55efbb5cf04cffb4ac5d13cb0f205c60acaab4a508c4c69751f7886541297f8b7a137b23f61da0692717c1fd3959e389e209379512acbf8461903a842863877340e03d7eb46e5568ba4ec3e48c3805d96015ba4108b3118707b9f314b0aa6de"
	alicePublic := alicePrivate.Public().(*kyberKEM.PublicKey)
	apkPack := make([]byte, kyberKEM.PublicKeySize)
	alicePublic.Pack(apkPack)
	stringCompare(t, "Alice public key", expectedAlicePublic, textformat.FormatHex(apkPack))
	expectedAliceFingerprint := "01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd"
	fingerprintAlice := getPubKeyFingerprint(alicePublic)
	stringCompare(t, "Alice fingerprint", expectedAliceFingerprint, textformat.FormatHex(fingerprintAlice[:]))

	// Use Bob's key from file (deterministic as well)
	bobPrivate, err := keyFromFile("bob_private.hex")
	if err != nil {
		t.Fatalf("Bob keyFromFile failed: %v", err)
	}
	expectedBobPublic := "89a21b1d3283ad16478e535c81c89c00696ed5e8bc6113b970843055768a51569548c13a4174bd85ea4110462c6d4089e2e3c9c1bba21a1350f5e5308aea1d78cb7674c2013ed2919bb06d9e6420fb48a433a5961a15b672c9b4c07a0b2a7a8796869b8f94cca4e37fe11968aa23cd211248d355539e140ffa5a911bca07effc8cfb1cb162e883f84633bb9001da562abad08d39978d9f77595b0bce73c3162822c197784ba575890d8366b683aa2b05c6db0946f7020976f25ebd762158210eeea6986dc01d1c1965fbe98639b320c2d37b3d4a28397056e586cc9690976f3b9f50db1987735692c56944a3147c4a1e1ed18883d4339be5bd8eb4abc850af95670960ecc2dc4215781c9dee190e29a628f1315093f9aed9268a3ff8957018ac6b220f5f527277095f65f6aa6c49aa20553b954649b4da6d681974a0fb76fd35a36bd63f17fb571ef50c8b669bebd19f8a725649e772ccd5afd41aaaa69828db522e289a43908c8f86828317acb6e7fb2e981ace9df0a116cc8692807762094302813a5864ade7825715c4b14eecb526187be4e8748a85828677a6c1026281e03e07ac8c62e58713c38e57d22830a249d5acb2a0626afc13b61fe85d31b234833acc4577965430a2ab9cbefec843d04b13ac54487542c96ce97f0c16a107423acfccb40b5b5c37329b06117d29d0adf8d1a119acb7459bbccc777d98c0230c4035e2228f03651e5094425830575781562ea86fcc2a7b177494bf4a1d19718f24d71e13270006c4a02a7407e91bc88d137edc680eef58267ad0c3c32b71e3957654b29e1d029e8b9a1acc9bb3551170c650a61507983ef1381e656326228cf7ba9248399061b62b283474f2e095a2f2a108b48a601c8ac4f61c11a35586351ac048aa909c4ddf0466b8d9ca89a48eb2fa4a8915a9b1b98cd26310bf31b89549baefe587cc549d3bbc358e052918a371bf0cc1fa0442fa8a4e8c37979efb44d96941130823f083b396c17931609ab48c7b9dac0cc53a5e2f709cbcd14cc955cd4138884793b0b222b9dc51964589ab0215ab66286efa723caf3c298d6811e629425fc90114a7352123b7bd3c78b9f69f32042d1c1cce764a2136324595bab06263361a932e0ae53c755a00d9ca58e81a0f76fa8222b1a776f491352773499136679b6237a7601bb52a00c9a84418334db491e924877d7484a3304e504ba3c99a96347b1aeac2ba04009e885abc99a88b45e616fe86c98e549c6ea14aed32675ca09fbaa7529c55c043d8cf0617bf80981b40fb735777bccfe17026ea5294a9487dd95e41e53773c14de544923bfc4f6010435001b8b6f0a1caac02b1ec38b95b2d5414bec4bba01d9cbb417378381c8b34d87f3e01d0d2e676a3aa1560460f0080a685b54bdad871c32c38cc88b6f2ea3f08eac52596a1b23cc9788c9648a469c3b5c86d9821de763491abcace169f939935fe956f9d3567df7771fa48a08762a022c05d6005aecb6056b4230ac53b0f53bb0375c32d3f6aabb11b5551e453c3b27ee037a20b691758d779bd435614b730fbf4be1dc4c66994c553e566aef74acf8861aa273d9f18982ed9ba113c5bc5c9653844c7279bcf3b16851e1850cfc9ac1a7519e40e6349cb2b6841ca1d6e4576c9a576d4b4f2e1712d19ab57db195f32"
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)
	bpkPack := make([]byte, kyberKEM.PublicKeySize)
	bobPublic.Pack(bpkPack)
	stringCompare(t, "Bob public key", expectedBobPublic, textformat.FormatHex(bpkPack))
	expectedBobFingerprint := "70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"
	fingerprintBob := getPubKeyFingerprint(bobPublic)
	stringCompare(t, "Bob fingerprint", expectedBobFingerprint, textformat.FormatHex(fingerprintBob[:]))

	// Calculate expected intermediate values
	expectedRecipientIDString := "|pulse|group|v1|01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd|70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|"
	expectedRecipientIDHash := "9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922"
	expectedContextString := "|pulse|ctx|v1|chain=1|contract=0x0102030405060708090a0b0c0d0e0f1011121314|consentNumber=2"
	expectedContextHash := "7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"

	recipientIDString := getAllRecipientIDStringFromKeys([]*kyberKEM.PublicKey{bobPublic, alicePublic})
	stringCompare(t, "recipientIdString", expectedRecipientIDString, string(recipientIDString))
	recipientIDHash := getAllRecipientIDHashFromKeys([]*kyberKEM.PublicKey{bobPublic, alicePublic})
	stringCompare(t, "recipientIdHash", expectedRecipientIDHash, textformat.FormatHex(recipientIDHash))
	contextString := context.ContextString(chainId, contractAddress, consentNumber)
	stringCompare(t, "contextString", expectedContextString, string(contextString))
	contextHash := context.ContextHash(chainId, contractAddress, consentNumber)
	stringCompare(t, "contextHash", expectedContextHash, hex.EncodeToString(contextHash))

	// For dataAESKey and nonce, we need to know how they are generated in PulseSealWithNewKey
	// PulseSealWithNewKey(entropy, ...) calls randutil.Bytes(entropy, 32) then randutil.Bytes(entropy, 12)
	entropyClone := bytes.NewReader(seed)
	dataAESKeyGenerated, _ := randutil.Bytes(entropyClone, 32)
	nonceGenerated, _ := randutil.Bytes(entropyClone, 12)
	packedKey := packKey(dataAESKeyGenerated, nonceGenerated)

	result, err := EncryptPQ(entropy, plaintext, &contractAddress, []*kyberKEM.PublicKey{alicePublic, bobPublic}, purpose, chainId, consentNumber)
	if err != nil {
		t.Fatalf("EncryptPQ failed: %v", err)
	}

	// Verify all requested "known values"
	expectedDataAESKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	stringCompare(t, "dataAESKey", expectedDataAESKey, textformat.FormatHex(dataAESKeyGenerated))

	expectedNonce := "202122232425262728292a2b"
	stringCompare(t, "dataNonce", expectedNonce, textformat.FormatHex(nonceGenerated))

	expectedPackedKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
	stringCompare(t, "packedKey", expectedPackedKey, textformat.FormatHex(packedKey))

	expectedSealedData := "8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d69"
	if hex.EncodeToString(result.SealedData) != expectedSealedData {
		t.Errorf("SealedData mismatch: got %x, want %s", result.SealedData, expectedSealedData)
	}

	resultCBOR, err := result.CBOR()
	if err != nil {
		t.Fatalf("result.CBOR() failed: %v", err)
	}
	expectedResultCBOR := "82582a8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d698283582001b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd590440b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9583cb500e45683a54614d13c6c239dda4829089657ce965b5d28ab8920f3a87d96cf69bf85893de9c1a938caf63cf48ec3f0c29f30045b8ec1249f04681283582070e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde590440ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02583c4614dfed6eac84edbd00618bc1a681de48043dde02b187df803812427e59070ce716b3b3cf0033bab49cfb7568c9dbf5788b8b4f078cdd3fcb56ad76"
	stringCompare(t, "resultCBOR", expectedResultCBOR, textformat.FormatHex(resultCBOR))

	aliceKeys := result.Keys[0]
	bobKeys := result.Keys[1]
	stringCompare(t, "result.Alice.fingerprint", expectedAliceFingerprint, textformat.FormatHex(aliceKeys.KeyFingerPrint[:]))

	expectedEncapsulatedKey := "b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9"
	if hex.EncodeToString(result.Keys[0].EncapsulatedKeyKey) != expectedEncapsulatedKey {
		t.Errorf("EncapsulatedKeyKey mismatch: got %x, want %s", aliceKeys.EncapsulatedKeyKey, expectedEncapsulatedKey)
	}

	expectedEncapsulatedDataKey := "b500e45683a54614d13c6c239dda4829089657ce965b5d28ab8920f3a87d96cf69bf85893de9c1a938caf63cf48ec3f0c29f30045b8ec1249f046812"
	if hex.EncodeToString(result.Keys[0].EncapsulatedDataKey) != expectedEncapsulatedDataKey {
		t.Errorf("EncapsulatedDataKey mismatch: got %x, want %s", aliceKeys.EncapsulatedDataKey, expectedEncapsulatedDataKey)
	}

	stringCompare(t, "result.Bob.fingerprint", expectedBobFingerprint, textformat.FormatHex(bobKeys.KeyFingerPrint[:]))

	// Round-trip check
	decrypted, err := DecryptPQ(result, &contractAddress, bobPrivate, purpose, chainId, consentNumber)
	if err != nil {
		t.Fatalf("DecryptPQ failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}
