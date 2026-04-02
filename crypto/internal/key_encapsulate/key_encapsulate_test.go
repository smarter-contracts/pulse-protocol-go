package key_encapsulate

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
	"github.com/smarter-contracts/pulse-protocol-go/crypto/purposes"
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
			purpose:              purposes.PulsePurposeEncryptConsentStructure,
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
	expectedResultCBOR := "a46174627071617601627364582a8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d69646b65797382a3626670582001b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd6365646b583cb500e45683a54614d13c6c239dda4829089657ce965b5d28ab8920f3a87d96cf69bf85893de9c1a938caf63cf48ec3f0c29f30045b8ec1249f04681263656b6b590440b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9a3626670582070e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde6365646b583c4614dfed6eac84edbd00618bc1a681de48043dde02b187df803812427e59070ce716b3b3cf0033bab49cfb7568c9dbf5788b8b4f078cdd3fcb56ad7663656b6b590440ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02"
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
