package symmetric

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/hash"
	"github.com/smarter-contracts/pulse-protocol-go/crypto/internal/textformat"
)

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSymmetric_KnownValues(t *testing.T) {
	tests := []struct {
		name           string
		plaintext      []byte
		aesKey         []byte
		nonce          []byte
		purpose        PulseSymmetricPurpose
		cipherSuite    string
		recipientHash  []byte
		contextHash    []byte
		transcriptHash []byte
		expectedAAD    string
		expectedCipher []byte
	}{
		{
			name:           "Key Exchange Known Values",
			plaintext:      []byte("This is the consent record"),
			aesKey:         mustHexDecode("cee5d3c958a8be9fdea4e4dca39cf4bf52ca824a1f71d026319e350a6b0ef67a"),
			nonce:          mustHexDecode("3298b5b0da18ab57667cf999"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "ecdh-secp256k1+hkdf-keccak256+aes-gcm-256",
			recipientHash:  mustHexDecode(""),
			contextHash:    mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			transcriptHash: mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4"),
			expectedAAD:    "|pulse|consent|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|nonce=3298b5b0da18ab57667cf999|",
			expectedCipher: mustHexDecode("36dae43a0870c0f96bea88d074d8136e0cda62a5d5a67bc0bd8ccf2eee27618951ce1cb2391d2688da0a"),
		},
		{
			name:           "Key Encapsulation Known Values Data",
			plaintext:      []byte("This is the consent record"),
			aesKey:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			nonce:          mustHexDecode("202122232425262728292a2b"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "rng+aes-gcm-256",
			recipientHash:  mustHexDecode("9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922"),
			contextHash:    mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			transcriptHash: hash.PulseHashBytes(mustHexDecode("202122232425262728292a2b")),
			expectedAAD:    "|pulse|consent|v1|rng+aes-gcm-256|rid=9674817700045e99280b08deebeb495374fd63823ed53130b16e84c3fc558922|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=08cbbdefe5c86347efb3a00eda9ac05c0e8b8da6d0443410f229ad7bd0a82253|nonce=202122232425262728292a2b|",
			expectedCipher: mustHexDecode("8652cf034cf1692e6e1427eea2779a8ab52798bcf5e500811e92c70cc2d6433e08b09e086a5989071d69"),
		},
		{
			name:           "Key Encapsulation Known Values Alice Key",
			plaintext:      mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"),
			aesKey:         mustHexDecode("fdc47c91d9783d3904ea193f5cab4245d1c6cc1363a1925bc1a996db3fd9e39f"),
			nonce:          mustHexDecode("3a46a68f32164320ed05f220"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "kyber768+hkdf-keccak256+aes-gcm-256",
			recipientHash:  mustHexDecode("01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd"),
			contextHash:    mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			transcriptHash: hash.PulseHashBytes(mustHexDecode("b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9")),
			expectedAAD:    "|pulse|consent|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=a0194d43f581fef367cf0b3d70020f48d742884e80fff1f7e952e0bb9a4ee58a|nonce=3a46a68f32164320ed05f220|",
			expectedCipher: mustHexDecode("59bbc6964a9e2b6dc51e07eaa9d5aeb08f5bba50d917fc01c27f290e4e49a5c47212739eae2cdc9e8d5b66d5f35706bb6d3ab7dad4aa78eb5b5e3ec2"),
		},
		{
			name:           "Key Encapsulation Known Values Bob Key",
			plaintext:      mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"),
			aesKey:         mustHexDecode("9db3027d1cd914e597f8adcae7e546f3f0495eafc8ed4a1e32bbfc94d625e706"),
			nonce:          mustHexDecode("c7439399def2cc23269f3943"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "kyber768+hkdf-keccak256+aes-gcm-256",
			recipientHash:  mustHexDecode("70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"),
			contextHash:    mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			transcriptHash: hash.PulseHashBytes(mustHexDecode("ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02")),
			expectedAAD:    "|pulse|consent|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3|th=67fbdbe0e5a5f06ea9c3b36d60a876d63f7e318061d0dd57216d6702e85c552e|nonce=c7439399def2cc23269f3943|",
			expectedCipher: mustHexDecode("6551657fa1a2a0607ce5f5f3ba481da211ef4e16959d10702e27e868abb5a276e005b8b43e4403ae630332284f2ece00298c4a1c67a8465d0e05c40d"),
		},
		{
			name:           "Symmetric Known Values 1",
			plaintext:      []byte("pulse test"),
			aesKey:         mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			nonce:          mustHexDecode("000102030405060708090a0b"),
			purpose:        PulseSymmetricConsent,
			cipherSuite:    "aes-gcm-256",
			recipientHash:  mustHexDecode("0102030405060708090a0b0c0d0e0f1011121314"),
			contextHash:    mustHexDecode("212223"), // This isn't really a hash but we use it for testing
			transcriptHash: mustHexDecode("313233"),
			expectedAAD:    "|pulse|consent|v1|aes-gcm-256|rid=0102030405060708090a0b0c0d0e0f1011121314|ctx=212223|th=313233|nonce=000102030405060708090a0b|",
			expectedCipher: mustHexDecode("3777ba68a0c5b67efe35cfa9a692dd1bd440590a55ab87a1ca4f"),
		},
		{
			name:           "Symmetric Known Values 2 (KeyWrap)",
			plaintext:      mustHexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f11223344556677889900aabbccddeeff"), // AES Key + Nonce
			aesKey:         mustHexDecode("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"),
			nonce:          mustHexDecode("1112131415161718191a1b1c"),
			purpose:        PulseSymmetricKeyWrap,
			cipherSuite:    "kyber768+hkdf-keccak256+aes-gcm-256",
			recipientHash:  mustHexDecode("70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"),
			contextHash:    mustHexDecode("6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea"),
			transcriptHash: mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4"),
			expectedAAD:    "|pulse|keywrap|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|ctx=6d7aace2b827d9377fc9bfb261f50b2ab4dbf041500a2ac837d8dcba19e54aea|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|nonce=1112131415161718191a1b1c|",
			expectedCipher: mustHexDecode("f6058785d4fea6790470dfce54417e1cef02f62ef7351ee5fea187865ad407a864c428eb25e17f764f0be39541f2550a1fb69b7ccd6cee56bedf691d0cdc3ca8"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aad := buildAAD(tt.purpose, tt.cipherSuite, tt.recipientHash, tt.nonce, tt.contextHash, tt.transcriptHash)
			if string(aad) != tt.expectedAAD {
				t.Errorf("AAD mismatch:\nGot:  %s\nWant: %s", string(aad), tt.expectedAAD)
			}

			ciphertext, err := PulseSeal(tt.plaintext, tt.aesKey, tt.nonce, tt.purpose, tt.cipherSuite, tt.recipientHash, tt.contextHash, tt.transcriptHash)
			if err != nil {
				t.Fatalf("PulseSeal failed: %v", err)
			}

			if !bytes.Equal(ciphertext, tt.expectedCipher) {
				t.Errorf("Ciphertext mismatch:\nGot:  %x\nWant: %x", ciphertext, tt.expectedCipher)
			}

			decrypted, err := PulseOpen(ciphertext, tt.aesKey, tt.nonce, tt.purpose, tt.cipherSuite, tt.recipientHash, tt.contextHash, tt.transcriptHash)
			if err != nil {
				t.Fatalf("PulseOpen failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("Decrypted plaintext mismatch:\nGot:  %s\nWant: %s", string(decrypted), string(tt.plaintext))
			}
		})
	}
}

/*
 * Test values for Symmetric encryption.
 *
 * EncryptionKey = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ( 32 bytes )
 * Nonce = 0x000102030405060708090a0b ( 12 bytes )
 * Purpose = 1 ( PulseSymmetricConsent )
 * Recipient = 0x0102030405060708090a0b0c0d0e0f1011121314 ( 20 bytes )
 * Context = 0x212223 ( "!"# )
 * Plaintext = "pulse test"
 */

func getTestKey() []byte {
	key := make([]byte, AESGCMKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func getTestNonce() []byte {
	nonce := make([]byte, AESGCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

func getTestRecipient() []byte {
	recipient := make([]byte, 20)
	for i := range recipient {
		recipient[i] = byte(i + 1)
	}
	return recipient
}

func TestPulseSeal_PulseOpen_RoundTrip(t *testing.T) {
	plaintext := []byte("pulse test")
	key := getTestKey()
	nonce := getTestNonce()
	recipient := getTestRecipient()
	purpose := PulseSymmetricConsent
	context := []byte("context")
	suite := "test-suite"
	transcript := []byte("test transcript")

	ciphertext, err := PulseSeal(plaintext, key, nonce, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseSeal failed: %v", err)
	}

	decrypted, err := PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseOpen failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestPulseSealWithNewKey_RoundTrip(t *testing.T) {
	plaintext := []byte("pulse test with new key")
	recipient := getTestRecipient()
	purpose := PulseSymmetricUpdate
	context := []byte("another context")
	suite := "test-suite"

	ciphertext, key, nonce, err := PulseSealWithNewKey(nil, plaintext, purpose, suite, recipient, context)
	if err != nil {
		t.Fatalf("PulseSealWithNewKey failed: %v", err)
	}

	if len(key) != AESGCMKeySize {
		t.Errorf("Generated key size mismatch: got %d, want %d", len(key), AESGCMKeySize)
	}
	if len(nonce) != AESGCMNonceSize {
		t.Errorf("Generated nonce size mismatch: got %d, want %d", len(nonce), AESGCMNonceSize)
	}

	// PulseSealWithNewKey uses Keccak256(nonce) as transcriptHash
	transcriptHash := hash.PulseHashBytes(nonce)

	decrypted, err := PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, context, transcriptHash)
	if err != nil {
		t.Fatalf("PulseOpen failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestPulseOpen_AuthenticationFailure(t *testing.T) {
	plaintext := []byte("pulse test")
	key := getTestKey()
	nonce := getTestNonce()
	recipient := getTestRecipient()
	purpose := PulseSymmetricConsent
	context := []byte("context")
	suite := "test-suite"
	transcript := []byte("transcript")

	ciphertext, err := PulseSeal(plaintext, key, nonce, purpose, suite, recipient, context, transcript)
	if err != nil {
		t.Fatalf("PulseSeal failed: %v", err)
	}

	// Test with wrong key
	wrongKey := make([]byte, AESGCMKeySize)
	copy(wrongKey, key)
	wrongKey[0] ^= 0xFF
	_, err = PulseOpen(ciphertext, wrongKey, nonce, purpose, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong key")
	}

	// Test with wrong nonce
	wrongNonce := make([]byte, AESGCMNonceSize)
	copy(wrongNonce, nonce)
	wrongNonce[0] ^= 0xFF
	_, err = PulseOpen(ciphertext, key, wrongNonce, purpose, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong nonce")
	}

	// Test with wrong purpose
	_, err = PulseOpen(ciphertext, key, nonce, PulseSymmetricRevoke, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong purpose")
	}

	// Test with wrong recipient
	wrongRecipient := make([]byte, 20)
	copy(wrongRecipient, recipient)
	wrongRecipient[0] ^= 0xFF
	_, err = PulseOpen(ciphertext, key, nonce, purpose, suite, wrongRecipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong recipient")
	}

	// Test with wrong context
	_, err = PulseOpen(ciphertext, key, nonce, purpose, suite, recipient, []byte("wrong context"), transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with wrong context")
	}

	// Test with modified ciphertext
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF
	_, err = PulseOpen(corruptedCiphertext, key, nonce, purpose, suite, recipient, context, transcript)
	if err == nil {
		t.Error("PulseOpen should have failed with corrupted ciphertext")
	}
}

func TestBuildAAD(t *testing.T) {
	purpose := PulseSymmetricConsent
	cipherSuite := "aes-gcm"
	recipient := getTestRecipient()
	nonce := getTestNonce()
	context := []byte("context")
	transcript := []byte("transcript")

	aad := buildAAD(purpose, cipherSuite, recipient, nonce, context, transcript)

	// Verify that AAD contains expected components
	if !bytes.Contains(aad, []byte("pulse|")) {
		t.Error("AAD missing 'pulse|' prefix")
	}
	if !bytes.Contains(aad, []byte("consent|")) {
		t.Error("AAD missing purpose string")
	}
	if !bytes.Contains(aad, []byte("v1|")) {
		t.Error("AAD missing version string")
	}
	if !bytes.Contains(aad, []byte(cipherSuite)) {
		t.Error("AAD missing cipher suite")
	}
	if !bytes.Contains(aad, []byte("rid="+textformat.FormatHex(recipient))) {
		t.Error("AAD missing recipient hex")
	}
	if !bytes.Contains(aad, []byte("nonce="+textformat.FormatHex(nonce))) {
		t.Error("AAD missing nonce hex")
	}
	if !bytes.Contains(aad, []byte("ctx=")) {
		t.Error("AAD missing context prefix 'ctx='")
	}
	if !bytes.Contains(aad, []byte("th=")) {
		t.Error("AAD missing transcript prefix 'th='")
	}
}

func TestPulseSymmetricPurposes(t *testing.T) {
	tests := []struct {
		purpose PulseSymmetricPurpose
		want    string
	}{
		{PulseSymmetricConsent, "consent"},
		{PulseSymmetricRevoke, "revoke"},
		{PulseSymmetricUpdate, "update"},
		{PulseSymmetricKeyWrap, "keywrap"},
	}

	recipient := getTestRecipient()
	nonce := getTestNonce()
	context := []byte("ctx")
	transcript := []byte("transcript")

	for _, tt := range tests {
		aad := buildAAD(tt.purpose, "test", recipient, nonce, context, transcript)
		if !bytes.Contains(aad, []byte(tt.want)) {
			t.Errorf("buildAAD for purpose %v: expected to contain %q, got %q", tt.purpose, tt.want, string(aad))
		}
	}
}
