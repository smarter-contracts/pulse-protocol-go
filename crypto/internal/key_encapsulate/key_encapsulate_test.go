package key_encapsulate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	kyberKEM "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/context"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/hkdf"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/randutil"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/symmetric"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/internal/textformat"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/v2/purposes"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

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

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func stringCompare(t *testing.T, name, expected, actual string) {
	if expected != actual {
		t.Errorf("%s mismatch: got %s, want %s", name, actual, expected)
	}
}

// testDataDir returns the path to test data files (alice_private.hex, bob_private.hex)
// which are in the crypto package root directory.
func testDataDir() string {
	return "../../"
}

func TestPulsePQ_Encrypt_Success_WithRecipients(t *testing.T) {
	plainText := []byte("top secret pq data")
	contractAddress := helperContractAddressPQ()
	purpose := purposes.PulsePurposeEncryptConsentStructure
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

	fp1 := getPubKeyFingerprint(pk1)
	fp2 := getPubKeyFingerprint(pk2)

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
	fp1 := "01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd"
	fp2 := "70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"

	hash1 := getAllRecipientIDHashFromFingerPrints([]string{fp1, fp2})
	hash2 := getAllRecipientIDHashFromFingerPrints([]string{fp2, fp1})

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("getAllRecipientIDHashFromFingerPrints is not deterministic: %x != %x", hash1, hash2)
	}

	expectedHash := mustHexDecode("9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922")
	if !bytes.Equal(hash1, expectedHash) {
		t.Errorf("getAllRecipientIDHashFromFingerPrints mismatch: got %x, want %x", hash1, expectedHash)
	}
}

func TestEncapsulateKey_KnownValues(t *testing.T) {
	alicePrivate, err := keyFromFile(testDataDir() + "alice_private.hex")
	if err != nil {
		t.Fatalf("Alice keyFromFile failed: %v", err)
	}
	alicePublic := alicePrivate.Public().(*kyberKEM.PublicKey)

	bobPrivate, err := keyFromFile(testDataDir() + "bob_private.hex")
	if err != nil {
		t.Fatalf("Bob keyFromFile failed: %v", err)
	}
	bobPublic := bobPrivate.Public().(*kyberKEM.PublicKey)

	tests := []struct {
		name                 string
		seed                 []byte
		publicKey            *kyberKEM.PublicKey
		aesKeyPacked         []byte
		purpose              purposes.PulsePurpose
		contextHash          []byte
		expectedFingerPrint  string
		expectedSharedSecret string
		expectedEncapsulated string
		expectedKeyAESKey    string
		expectedKeyNonce     string
		expectedEncryptedKey string
		expectedResultCBOR   []byte
	}{
		{
			name:                 "Alice Isolation",
			seed:                 mustHexDecode("2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b"),
			publicKey:            alicePublic,
			aesKeyPacked:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"),
			purpose:              purposes.PulsePurposeEncryptConsentStructure,
			contextHash:          mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			expectedFingerPrint:  "01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd",
			expectedSharedSecret: "e2c21115bf6fb85c9d9c3ee9af7408ef5b249899338c5df3657196d3594ac59c",
			expectedEncapsulated: "d89942f8510774d48d74fa3b0307fc88268ddde463405ee56f2117161bd1ec71aabe923d9d772edfeee205e8417b2eeb2e94d54eaacfe148641bd27d0fd8f5dd9b35846a236359a881d043b2f3196116880a107c26263f94e05d43e6d77e0a966f302a326d0db13178fff2aec234784bce1dc2e98707bcde2814100069d3eb65cc7881ae9550c67642ff689ef6146de3207931b683097671196e92350debfe10abaf658e1a404069e724f74edcbd8a1fb9f009e1194b2ed8e4a4c06258ff52465e63483f374f6694caa90016905207b93bd028967baaa03dd1dab9f5a9a47890feab74e23c06afa0fa75b24d0e47552519df2eb224cfd7ec17a2a21790dc48cc6e4b00221c7e12659afddceb071d349e3c0279e0f8d3772920085748fb1c5c15cde4386db9a8afc5361542b260fef6aa246ec0266bfac64b8ca5bc65af0ac0239a45bd9063f3e071eb7023066eba71c8b619212336ea19524f03b5d416b82ffbc46492d22968bc3b32f6b550a6fb9ef8964bd0ec6a675e0a78c17d5fc24d3ca9591c462e5fec4fac6c2e62f290ad4f54b37be2a16c74c60c9efb584e13f4e2c127d303eccd6473e3a976cba1f1c4e2f16c618e102cac21d4ea6dd312630664dfd3332f884f7402e622b1a3b16e7126591895712a03d17bd85dd9d6e33c625a3ecfeac97e2f00499ef69ef12e59bda0eaf8b520c1ce3ececaeec6cd202e5f06b1db3bb7fcfaf1b011722078a7e69fd0ec0516a32c3b725acf257a26c991f28511cbbb4398d39b5aafa6ec26a1bfed830a616068ec577b0a996320270d681bec27c5b9659c53486113cdcce62c2e45fc11b4b6138f82ba25a2a4c7bc67d890551472685bdc48cc752a8f0d3474bb1c5e32a7abca10d5dc56e003b9ac3e89b1bae238c12f9668167c2b248bd1796e793bb6cd5646fa727d62dbc64f58547c95f124511cb49c9af6362a77ea08cdab4450c0bd213de8eefa59ae530e2d7bd611d3abfbc30670a73f538a52f2cc02d12595cd726248f7ea33941cd67f140c35980ead02be547e98e5ae5e90fe4f8ce0d1c000666d6d4d6c98fe3c2147be813624348defcefecc68e453f4dbac3fb16a66ba27d6beb5e27ca0a5382af0834fd8d6d1f7a9d5c265c94ed8146f37d577c5e288c1652df5ce62fd4d0261b6fc562589e32c91d0b53aa0961f8e33cde921450ff808daffaa8935f211603501d0e9d2c7cba92a6e71c94fc10672e8ea77c3762bc126854c9f0a96900f50540839496e3f5b71ebde553543d9171eeed94e2d8697b6d3e7d246146d5c33afcbaabe690173c0440085884197f6167b31feacb4719401339eacafdce8c02391566ea485ed7c891b1446714a4b80d32036d7f8ca71106e0cd60cf38b569758e76328a3785e9525e2fb5645bc45ecba15ba2b9db2dd8d3717b595c043994ba4dcf607b42829cf6eb4bcaca7051698a0333a53420225ceb3256edc857e1f53143b9392ca6ad9d67c375ec772ee621f480cf666e5b24f09281b799c81c873608b3ace2aec7f46ea48fc",
			expectedKeyAESKey:    "3e1bb5d938512dfb534ec4be1e1bb53b6fe4584327e5856405b3639823528b2d",
			expectedKeyNonce:     "9a20548d05e4563de6882c27",
			expectedEncryptedKey: "2604ee1385c64f0efec5cff47884c242eeeeb6ddc716f0157077eaaedf0bc41f0ae7a5bd30e15772fe848fc3e4ce8ef9929c9059d1027d34b2abf910",
			expectedResultCBOR:   mustHexDecode("83582001b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd590440d89942f8510774d48d74fa3b0307fc88268ddde463405ee56f2117161bd1ec71aabe923d9d772edfeee205e8417b2eeb2e94d54eaacfe148641bd27d0fd8f5dd9b35846a236359a881d043b2f3196116880a107c26263f94e05d43e6d77e0a966f302a326d0db13178fff2aec234784bce1dc2e98707bcde2814100069d3eb65cc7881ae9550c67642ff689ef6146de3207931b683097671196e92350debfe10abaf658e1a404069e724f74edcbd8a1fb9f009e1194b2ed8e4a4c06258ff52465e63483f374f6694caa90016905207b93bd028967baaa03dd1dab9f5a9a47890feab74e23c06afa0fa75b24d0e47552519df2eb224cfd7ec17a2a21790dc48cc6e4b00221c7e12659afddceb071d349e3c0279e0f8d3772920085748fb1c5c15cde4386db9a8afc5361542b260fef6aa246ec0266bfac64b8ca5bc65af0ac0239a45bd9063f3e071eb7023066eba71c8b619212336ea19524f03b5d416b82ffbc46492d22968bc3b32f6b550a6fb9ef8964bd0ec6a675e0a78c17d5fc24d3ca9591c462e5fec4fac6c2e62f290ad4f54b37be2a16c74c60c9efb584e13f4e2c127d303eccd6473e3a976cba1f1c4e2f16c618e102cac21d4ea6dd312630664dfd3332f884f7402e622b1a3b16e7126591895712a03d17bd85dd9d6e33c625a3ecfeac97e2f00499ef69ef12e59bda0eaf8b520c1ce3ececaeec6cd202e5f06b1db3bb7fcfaf1b011722078a7e69fd0ec0516a32c3b725acf257a26c991f28511cbbb4398d39b5aafa6ec26a1bfed830a616068ec577b0a996320270d681bec27c5b9659c53486113cdcce62c2e45fc11b4b6138f82ba25a2a4c7bc67d890551472685bdc48cc752a8f0d3474bb1c5e32a7abca10d5dc56e003b9ac3e89b1bae238c12f9668167c2b248bd1796e793bb6cd5646fa727d62dbc64f58547c95f124511cb49c9af6362a77ea08cdab4450c0bd213de8eefa59ae530e2d7bd611d3abfbc30670a73f538a52f2cc02d12595cd726248f7ea33941cd67f140c35980ead02be547e98e5ae5e90fe4f8ce0d1c000666d6d4d6c98fe3c2147be813624348defcefecc68e453f4dbac3fb16a66ba27d6beb5e27ca0a5382af0834fd8d6d1f7a9d5c265c94ed8146f37d577c5e288c1652df5ce62fd4d0261b6fc562589e32c91d0b53aa0961f8e33cde921450ff808daffaa8935f211603501d0e9d2c7cba92a6e71c94fc10672e8ea77c3762bc126854c9f0a96900f50540839496e3f5b71ebde553543d9171eeed94e2d8697b6d3e7d246146d5c33afcbaabe690173c0440085884197f6167b31feacb4719401339eacafdce8c02391566ea485ed7c891b1446714a4b80d32036d7f8ca71106e0cd60cf38b569758e76328a3785e9525e2fb5645bc45ecba15ba2b9db2dd8d3717b595c043994ba4dcf607b42829cf6eb4bcaca7051698a0333a53420225ceb3256edc857e1f53143b9392ca6ad9d67c375ec772ee621f480cf666e5b24f09281b799c81c873608b3ace2aec7f46ea48fc583c2604ee1385c64f0efec5cff47884c242eeeeb6ddc716f0157077eaaedf0bc41f0ae7a5bd30e15772fe848fc3e4ce8ef9929c9059d1027d34b2abf910"),
		},
		{
			name:                 "Bob Isolation",
			seed:                 mustHexDecode("4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b"),
			publicKey:            bobPublic,
			aesKeyPacked:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"),
			purpose:              purposes.PulsePurposeEncryptConsentStructure,
			contextHash:          mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			expectedFingerPrint:  "70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde",
			expectedSharedSecret: "c2c4cb244f66be5ac5c0a61d6cff01c5437ce1ac3c944a53ba42a6ac4691368a",
			expectedEncapsulated: "061e776e0c1be7d3436bde1a1ccf7777741bd6afb0c5a2733a9922c4fb127cf99a2c43affdf463cf7b2a398983e3d37f6b7217d8bb987f7fe8c35c67b767f9a8573fccc1eff02433fb329073ae9dcbf25823e00d1aab30b7d79157b643f7c3580c37784ccc99f4c240ed1b4711ac71cdc1a25bde8105c1a725c5b64b0519309a55282a3db8a5a244d61875801fcbe46660988a78aa3810686dae8ba881c2259ee4850412472a9975f122af8361b7a75b6287df08b4a1ef7aaffccc1e41a3aeb195007c8d829b49e126d7a8cc52ae187033cfb9f1aeea08827af9eee30a78b67f800432b7a4ea688ae03cbc0947bfa19029a75d9c4cd83ead8628ed76153b56d2b8604201d84d2fb8155b781050d6ab54d0bdce49dc2a9095c69b855fdf63020a254f4c420d514f4d3695414332cc1d9542e2287676b08cdded2ea1e74aa1d4b01ab880bfa652fe22aea876f812486bbbbbb7f83ee907f78e351f76aec3ac4952ae9a6cf8250103b9bd9001616059b4e412a34a05c94fb4fad14ee636afe2a86a8141594b56ed2e55331c00e2a212fdfcedfc8c30305dfc3d8b9de93d0d242688a9dfa093488c8dc879030ef23b1074257df5438307cbf73977d5abd8ec2d29caa7d81f3fbed2d60c206073f220c67f38dce0996cc5f1b18d3af42a443a49f79754dddc25e8614a66e09ee4ea15059f3ef9d0e1d38280a86b90cae0b028a9c203cb1c17d82ee31466f72883c68bb1962b539c71d7b54a350a2784f9494faa7ccf8ffda3c3ec793ad0dddbd9467178d91e0f20bc3d779b7c220b2f5cb508ce3ce7bb25fc6d50e28b2580f98364e07bf42e1b4322fb964107d61bf6f721a9a2eabe03d4db6c6e3d25dd1e5cd62ea0b80bc48cac30846210a313b7a16a74ca6183b1a4396b6b37cd03ef38d508522b423d88f51c51d04b1a3b7152e39b26dbc06383b5a6ec1e071d29601e0ca6419435143f2c03459868095edba830ad1f38d84f7d4482ab94cfb09eaf86b8eb95a67544b8a082f4e213435282c4ab7f781cb73635f1d575dcb065ca7d220abdcba67afed5249264bee3a1c5aff27b5f49a867a32973720e6f968bb640722521295e676c27ecfef9068126210951591880da131770b0ca4c25f8e980e8f403045d7ef64903792d2a48e6ce2f29942afcad4086885b63a4534d9c242294f205f7f53af45ce2aa8698f9b0ef5fb99111ca4544bc4a18961d1bb9f0702b07ac9f643cc0bdae32c49d5b36d7709e266551d284b253e291ca9101c97cc0a196bc8f362ff5ec0184f3762b231695680231601a7fa941649738eb282a57a81b0bbeb452174c7fabdad6acb0a475c45a6013d7726df281a8aa214d9434e624690cec1be8e97f64101156173de0c7364389da82a34869fc37c0bed2be4e1f1d881fce1e365de74cd043b1982dfd1f90f7c9fb901739f46f4ff76163fc1a7032411cddc5d292d0c2fd7c1334e043a30182c5337a63783594f6b44944e269dc3c83dd9dd17c03f6f4605e4e28409dbd3250343d4ba8d9d619ea75",
			expectedKeyAESKey:    "8c44be381a0d668ad6f859ca56e1a5553ff79a404b6c82c4813a6e26198c1ec3",
			expectedKeyNonce:     "ccde5a1a469ed7bba0cd9fba",
			expectedEncryptedKey: "3d338bca59f5e1f1f84ac9e113a13fde4d98b8483a3f51ab707ccc2efbeeaf3528ab13bf328894a8298532c05d8b57c1c0d42d596ec9e35ffe95f6ce",
			expectedResultCBOR:   mustHexDecode("83582070e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde590440061e776e0c1be7d3436bde1a1ccf7777741bd6afb0c5a2733a9922c4fb127cf99a2c43affdf463cf7b2a398983e3d37f6b7217d8bb987f7fe8c35c67b767f9a8573fccc1eff02433fb329073ae9dcbf25823e00d1aab30b7d79157b643f7c3580c37784ccc99f4c240ed1b4711ac71cdc1a25bde8105c1a725c5b64b0519309a55282a3db8a5a244d61875801fcbe46660988a78aa3810686dae8ba881c2259ee4850412472a9975f122af8361b7a75b6287df08b4a1ef7aaffccc1e41a3aeb195007c8d829b49e126d7a8cc52ae187033cfb9f1aeea08827af9eee30a78b67f800432b7a4ea688ae03cbc0947bfa19029a75d9c4cd83ead8628ed76153b56d2b8604201d84d2fb8155b781050d6ab54d0bdce49dc2a9095c69b855fdf63020a254f4c420d514f4d3695414332cc1d9542e2287676b08cdded2ea1e74aa1d4b01ab880bfa652fe22aea876f812486bbbbbb7f83ee907f78e351f76aec3ac4952ae9a6cf8250103b9bd9001616059b4e412a34a05c94fb4fad14ee636afe2a86a8141594b56ed2e55331c00e2a212fdfcedfc8c30305dfc3d8b9de93d0d242688a9dfa093488c8dc879030ef23b1074257df5438307cbf73977d5abd8ec2d29caa7d81f3fbed2d60c206073f220c67f38dce0996cc5f1b18d3af42a443a49f79754dddc25e8614a66e09ee4ea15059f3ef9d0e1d38280a86b90cae0b028a9c203cb1c17d82ee31466f72883c68bb1962b539c71d7b54a350a2784f9494faa7ccf8ffda3c3ec793ad0dddbd9467178d91e0f20bc3d779b7c220b2f5cb508ce3ce7bb25fc6d50e28b2580f98364e07bf42e1b4322fb964107d61bf6f721a9a2eabe03d4db6c6e3d25dd1e5cd62ea0b80bc48cac30846210a313b7a16a74ca6183b1a4396b6b37cd03ef38d508522b423d88f51c51d04b1a3b7152e39b26dbc06383b5a6ec1e071d29601e0ca6419435143f2c03459868095edba830ad1f38d84f7d4482ab94cfb09eaf86b8eb95a67544b8a082f4e213435282c4ab7f781cb73635f1d575dcb065ca7d220abdcba67afed5249264bee3a1c5aff27b5f49a867a32973720e6f968bb640722521295e676c27ecfef9068126210951591880da131770b0ca4c25f8e980e8f403045d7ef64903792d2a48e6ce2f29942afcad4086885b63a4534d9c242294f205f7f53af45ce2aa8698f9b0ef5fb99111ca4544bc4a18961d1bb9f0702b07ac9f643cc0bdae32c49d5b36d7709e266551d284b253e291ca9101c97cc0a196bc8f362ff5ec0184f3762b231695680231601a7fa941649738eb282a57a81b0bbeb452174c7fabdad6acb0a475c45a6013d7726df281a8aa214d9434e624690cec1be8e97f64101156173de0c7364389da82a34869fc37c0bed2be4e1f1d881fce1e365de74cd043b1982dfd1f90f7c9fb901739f46f4ff76163fc1a7032411cddc5d292d0c2fd7c1334e043a30182c5337a63783594f6b44944e269dc3c83dd9dd17c03f6f4605e4e28409dbd3250343d4ba8d9d619ea75583c3d338bca59f5e1f1f84ac9e113a13fde4d98b8483a3f51ab707ccc2efbeeaf3528ab13bf328894a8298532c05d8b57c1c0d42d596ec9e35ffe95f6ce"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := bytes.NewReader(tt.seed)

			res, err := encapsulateKey(entropy, tt.publicKey, tt.aesKeyPacked, tt.purpose, tt.contextHash)
			if err != nil {
				t.Fatalf("encapsulateKey failed: %v", err)
			}

			stringCompare(t, tt.name+" fingerPrint", tt.expectedFingerPrint, textformat.FormatHex(res.KeyFingerPrint[:]))
			stringCompare(t, tt.name+" encapsulatedSecret", tt.expectedEncapsulated, textformat.FormatHex(res.EncapsulatedKeyKey))
			stringCompare(t, tt.name+" encryptedKey", tt.expectedEncryptedKey, textformat.FormatHex(res.EncapsulatedDataKey))

			scheme := kyberKEM.Scheme()
			entropyClone := bytes.NewReader(tt.seed)
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
		})
	}
}

func TestEncryptPQ_KnownValues(t *testing.T) {
	seed := make([]byte, 1024)
	for i := range seed {
		seed[i] = byte(i)
	}
	entropy := bytes.NewReader(seed)

	plaintext := []byte("This is the consent record")
	contractAddress := "0x0102030405060708090a0b0c0d0e0f1011121314"
	purpose := purposes.PulsePurposeEncryptConsentStructure
	chainId := uint32(1)
	consentNumber := uint32(2)

	alicePrivate, err := keyFromFile(testDataDir() + "alice_private.hex")
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

	bobPrivate, err := keyFromFile(testDataDir() + "bob_private.hex")
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

	entropyClone := bytes.NewReader(seed)
	dataAESKeyGenerated, _ := randutil.Bytes(entropyClone, 32)
	nonceGenerated, _ := randutil.Bytes(entropyClone, 12)
	packedKey := packKey(dataAESKeyGenerated, nonceGenerated)

	result, err := EncryptPQ(entropy, plaintext, &contractAddress, []*kyberKEM.PublicKey{alicePublic, bobPublic}, purpose, chainId, consentNumber)
	if err != nil {
		t.Fatalf("EncryptPQ failed: %v", err)
	}

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

	resultCBOR, err := ipfs.MarshalConsentPQ(result)
	if err != nil {
		t.Fatalf("result.CBOR() failed: %v", err)
	}
	expectedResultCBOR := "a46174627071617601627364582a8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d69646b65797382a3626670582001b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd6365646b583c2604ee1385c64f0efec5cff47884c242eeeeb6ddc716f0157077eaaedf0bc41f0ae7a5bd30e15772fe848fc3e4ce8ef9929c9059d1027d34b2abf91063656b6b590440d89942f8510774d48d74fa3b0307fc88268ddde463405ee56f2117161bd1ec71aabe923d9d772edfeee205e8417b2eeb2e94d54eaacfe148641bd27d0fd8f5dd9b35846a236359a881d043b2f3196116880a107c26263f94e05d43e6d77e0a966f302a326d0db13178fff2aec234784bce1dc2e98707bcde2814100069d3eb65cc7881ae9550c67642ff689ef6146de3207931b683097671196e92350debfe10abaf658e1a404069e724f74edcbd8a1fb9f009e1194b2ed8e4a4c06258ff52465e63483f374f6694caa90016905207b93bd028967baaa03dd1dab9f5a9a47890feab74e23c06afa0fa75b24d0e47552519df2eb224cfd7ec17a2a21790dc48cc6e4b00221c7e12659afddceb071d349e3c0279e0f8d3772920085748fb1c5c15cde4386db9a8afc5361542b260fef6aa246ec0266bfac64b8ca5bc65af0ac0239a45bd9063f3e071eb7023066eba71c8b619212336ea19524f03b5d416b82ffbc46492d22968bc3b32f6b550a6fb9ef8964bd0ec6a675e0a78c17d5fc24d3ca9591c462e5fec4fac6c2e62f290ad4f54b37be2a16c74c60c9efb584e13f4e2c127d303eccd6473e3a976cba1f1c4e2f16c618e102cac21d4ea6dd312630664dfd3332f884f7402e622b1a3b16e7126591895712a03d17bd85dd9d6e33c625a3ecfeac97e2f00499ef69ef12e59bda0eaf8b520c1ce3ececaeec6cd202e5f06b1db3bb7fcfaf1b011722078a7e69fd0ec0516a32c3b725acf257a26c991f28511cbbb4398d39b5aafa6ec26a1bfed830a616068ec577b0a996320270d681bec27c5b9659c53486113cdcce62c2e45fc11b4b6138f82ba25a2a4c7bc67d890551472685bdc48cc752a8f0d3474bb1c5e32a7abca10d5dc56e003b9ac3e89b1bae238c12f9668167c2b248bd1796e793bb6cd5646fa727d62dbc64f58547c95f124511cb49c9af6362a77ea08cdab4450c0bd213de8eefa59ae530e2d7bd611d3abfbc30670a73f538a52f2cc02d12595cd726248f7ea33941cd67f140c35980ead02be547e98e5ae5e90fe4f8ce0d1c000666d6d4d6c98fe3c2147be813624348defcefecc68e453f4dbac3fb16a66ba27d6beb5e27ca0a5382af0834fd8d6d1f7a9d5c265c94ed8146f37d577c5e288c1652df5ce62fd4d0261b6fc562589e32c91d0b53aa0961f8e33cde921450ff808daffaa8935f211603501d0e9d2c7cba92a6e71c94fc10672e8ea77c3762bc126854c9f0a96900f50540839496e3f5b71ebde553543d9171eeed94e2d8697b6d3e7d246146d5c33afcbaabe690173c0440085884197f6167b31feacb4719401339eacafdce8c02391566ea485ed7c891b1446714a4b80d32036d7f8ca71106e0cd60cf38b569758e76328a3785e9525e2fb5645bc45ecba15ba2b9db2dd8d3717b595c043994ba4dcf607b42829cf6eb4bcaca7051698a0333a53420225ceb3256edc857e1f53143b9392ca6ad9d67c375ec772ee621f480cf666e5b24f09281b799c81c873608b3ace2aec7f46ea48fca3626670582070e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde6365646b583c3d338bca59f5e1f1f84ac9e113a13fde4d98b8483a3f51ab707ccc2efbeeaf3528ab13bf328894a8298532c05d8b57c1c0d42d596ec9e35ffe95f6ce63656b6b590440061e776e0c1be7d3436bde1a1ccf7777741bd6afb0c5a2733a9922c4fb127cf99a2c43affdf463cf7b2a398983e3d37f6b7217d8bb987f7fe8c35c67b767f9a8573fccc1eff02433fb329073ae9dcbf25823e00d1aab30b7d79157b643f7c3580c37784ccc99f4c240ed1b4711ac71cdc1a25bde8105c1a725c5b64b0519309a55282a3db8a5a244d61875801fcbe46660988a78aa3810686dae8ba881c2259ee4850412472a9975f122af8361b7a75b6287df08b4a1ef7aaffccc1e41a3aeb195007c8d829b49e126d7a8cc52ae187033cfb9f1aeea08827af9eee30a78b67f800432b7a4ea688ae03cbc0947bfa19029a75d9c4cd83ead8628ed76153b56d2b8604201d84d2fb8155b781050d6ab54d0bdce49dc2a9095c69b855fdf63020a254f4c420d514f4d3695414332cc1d9542e2287676b08cdded2ea1e74aa1d4b01ab880bfa652fe22aea876f812486bbbbbb7f83ee907f78e351f76aec3ac4952ae9a6cf8250103b9bd9001616059b4e412a34a05c94fb4fad14ee636afe2a86a8141594b56ed2e55331c00e2a212fdfcedfc8c30305dfc3d8b9de93d0d242688a9dfa093488c8dc879030ef23b1074257df5438307cbf73977d5abd8ec2d29caa7d81f3fbed2d60c206073f220c67f38dce0996cc5f1b18d3af42a443a49f79754dddc25e8614a66e09ee4ea15059f3ef9d0e1d38280a86b90cae0b028a9c203cb1c17d82ee31466f72883c68bb1962b539c71d7b54a350a2784f9494faa7ccf8ffda3c3ec793ad0dddbd9467178d91e0f20bc3d779b7c220b2f5cb508ce3ce7bb25fc6d50e28b2580f98364e07bf42e1b4322fb964107d61bf6f721a9a2eabe03d4db6c6e3d25dd1e5cd62ea0b80bc48cac30846210a313b7a16a74ca6183b1a4396b6b37cd03ef38d508522b423d88f51c51d04b1a3b7152e39b26dbc06383b5a6ec1e071d29601e0ca6419435143f2c03459868095edba830ad1f38d84f7d4482ab94cfb09eaf86b8eb95a67544b8a082f4e213435282c4ab7f781cb73635f1d575dcb065ca7d220abdcba67afed5249264bee3a1c5aff27b5f49a867a32973720e6f968bb640722521295e676c27ecfef9068126210951591880da131770b0ca4c25f8e980e8f403045d7ef64903792d2a48e6ce2f29942afcad4086885b63a4534d9c242294f205f7f53af45ce2aa8698f9b0ef5fb99111ca4544bc4a18961d1bb9f0702b07ac9f643cc0bdae32c49d5b36d7709e266551d284b253e291ca9101c97cc0a196bc8f362ff5ec0184f3762b231695680231601a7fa941649738eb282a57a81b0bbeb452174c7fabdad6acb0a475c45a6013d7726df281a8aa214d9434e624690cec1be8e97f64101156173de0c7364389da82a34869fc37c0bed2be4e1f1d881fce1e365de74cd043b1982dfd1f90f7c9fb901739f46f4ff76163fc1a7032411cddc5d292d0c2fd7c1334e043a30182c5337a63783594f6b44944e269dc3c83dd9dd17c03f6f4605e4e28409dbd3250343d4ba8d9d619ea75"
	stringCompare(t, "resultCBOR", expectedResultCBOR, textformat.FormatHex(resultCBOR))

	aliceKeys := result.Keys[0]
	bobKeys := result.Keys[1]
	stringCompare(t, "result.Alice.fingerprint", expectedAliceFingerprint, textformat.FormatHex(aliceKeys.KeyFingerPrint[:]))

	expectedEncapsulatedKey := "d89942f8510774d48d74fa3b0307fc88268ddde463405ee56f2117161bd1ec71aabe923d9d772edfeee205e8417b2eeb2e94d54eaacfe148641bd27d0fd8f5dd9b35846a236359a881d043b2f3196116880a107c26263f94e05d43e6d77e0a966f302a326d0db13178fff2aec234784bce1dc2e98707bcde2814100069d3eb65cc7881ae9550c67642ff689ef6146de3207931b683097671196e92350debfe10abaf658e1a404069e724f74edcbd8a1fb9f009e1194b2ed8e4a4c06258ff52465e63483f374f6694caa90016905207b93bd028967baaa03dd1dab9f5a9a47890feab74e23c06afa0fa75b24d0e47552519df2eb224cfd7ec17a2a21790dc48cc6e4b00221c7e12659afddceb071d349e3c0279e0f8d3772920085748fb1c5c15cde4386db9a8afc5361542b260fef6aa246ec0266bfac64b8ca5bc65af0ac0239a45bd9063f3e071eb7023066eba71c8b619212336ea19524f03b5d416b82ffbc46492d22968bc3b32f6b550a6fb9ef8964bd0ec6a675e0a78c17d5fc24d3ca9591c462e5fec4fac6c2e62f290ad4f54b37be2a16c74c60c9efb584e13f4e2c127d303eccd6473e3a976cba1f1c4e2f16c618e102cac21d4ea6dd312630664dfd3332f884f7402e622b1a3b16e7126591895712a03d17bd85dd9d6e33c625a3ecfeac97e2f00499ef69ef12e59bda0eaf8b520c1ce3ececaeec6cd202e5f06b1db3bb7fcfaf1b011722078a7e69fd0ec0516a32c3b725acf257a26c991f28511cbbb4398d39b5aafa6ec26a1bfed830a616068ec577b0a996320270d681bec27c5b9659c53486113cdcce62c2e45fc11b4b6138f82ba25a2a4c7bc67d890551472685bdc48cc752a8f0d3474bb1c5e32a7abca10d5dc56e003b9ac3e89b1bae238c12f9668167c2b248bd1796e793bb6cd5646fa727d62dbc64f58547c95f124511cb49c9af6362a77ea08cdab4450c0bd213de8eefa59ae530e2d7bd611d3abfbc30670a73f538a52f2cc02d12595cd726248f7ea33941cd67f140c35980ead02be547e98e5ae5e90fe4f8ce0d1c000666d6d4d6c98fe3c2147be813624348defcefecc68e453f4dbac3fb16a66ba27d6beb5e27ca0a5382af0834fd8d6d1f7a9d5c265c94ed8146f37d577c5e288c1652df5ce62fd4d0261b6fc562589e32c91d0b53aa0961f8e33cde921450ff808daffaa8935f211603501d0e9d2c7cba92a6e71c94fc10672e8ea77c3762bc126854c9f0a96900f50540839496e3f5b71ebde553543d9171eeed94e2d8697b6d3e7d246146d5c33afcbaabe690173c0440085884197f6167b31feacb4719401339eacafdce8c02391566ea485ed7c891b1446714a4b80d32036d7f8ca71106e0cd60cf38b569758e76328a3785e9525e2fb5645bc45ecba15ba2b9db2dd8d3717b595c043994ba4dcf607b42829cf6eb4bcaca7051698a0333a53420225ceb3256edc857e1f53143b9392ca6ad9d67c375ec772ee621f480cf666e5b24f09281b799c81c873608b3ace2aec7f46ea48fc"
	if hex.EncodeToString(result.Keys[0].EncapsulatedKeyKey) != expectedEncapsulatedKey {
		t.Errorf("EncapsulatedKeyKey mismatch: got %x, want %s", aliceKeys.EncapsulatedKeyKey, expectedEncapsulatedKey)
	}

	expectedEncapsulatedDataKey := "2604ee1385c64f0efec5cff47884c242eeeeb6ddc716f0157077eaaedf0bc41f0ae7a5bd30e15772fe848fc3e4ce8ef9929c9059d1027d34b2abf910"
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

// ── Tests merged from crypto/key_encapsulation_test.go ───────────────────────

func TestEncryptPQ_RoundTrip_FromFile(t *testing.T) {
	plainText := []byte("pulse text")
	contractAddress := helperContractAddressPQ()
	purpose := purposes.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)

	bobPrivate, err := keyFromFile(testDataDir() + "alice_private.hex")
	if err != nil {
		t.Skipf("skipping: key file not found: %v", err)
	}
	_ = bobPrivate
	bobPrivate2, err := keyFromFile(testDataDir() + "bob_private.hex")
	if err != nil {
		t.Skipf("skipping: key file not found: %v", err)
	}
	bobPublic := bobPrivate2.Public().(*kyberKEM.PublicKey)

	result, err := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{bobPublic}, purpose, chainId, 0)
	if err != nil {
		t.Fatalf("EncryptPQ: %v", err)
	}

	decrypted, err := DecryptPQ(result, contractAddress, bobPrivate2, purpose, chainId, 0)
	if err != nil {
		t.Fatalf("DecryptPQ: %v", err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", decrypted, plainText)
	}
}

func TestDecryptPQ_WrongKey(t *testing.T) {
	plainText := []byte("data")
	contractAddress := helperContractAddressPQ()
	purpose := purposes.PulsePurposeEncryptConsentStructure
	chainId := uint32(0x01)
	pk, _, _ := kyberKEM.GenerateKeyPair(rand.Reader)

	result, _ := EncryptPQ(nil, plainText, contractAddress, []*kyberKEM.PublicKey{pk}, purpose, chainId, 0)

	// Decrypt with wrong private key
	_, wrongSK, _ := kyberKEM.GenerateKeyPair(rand.Reader)
	_, err := DecryptPQ(result, contractAddress, wrongSK, purpose, chainId, 0)
	if err == nil || err.Error() != "no key found for this party" {
		t.Fatalf("expected 'no key found for this party', got %v", err)
	}
}
