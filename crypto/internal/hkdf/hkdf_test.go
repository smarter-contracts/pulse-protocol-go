package hkdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPulseHKDF_KnownValues(t *testing.T) {
	tests := []struct {
		name         string
		mode         string // "ECDH" or "Kyber"
		sharedSecret []byte
		transcript   []byte
		recipientId  []byte
		context      []byte
		// Expected outputs
		expectedSaltString      string
		expectedSalt            []byte
		expectedPrk             []byte
		expectedInfoStringAES   string
		expectedInfoStringNonce string
		expectedAESKey          []byte
		expectedAESNonce        []byte
	}{
		{
			name:         "ECDH call",
			mode:         "ECDH",
			sharedSecret: mustHexDecode("3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e"),
			transcript:   mustHexDecode("1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4"),
			recipientId:  nil,
			context:      mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			// Expected values
			expectedSaltString:      "|pulse|kdf|v1|salt|secp256k1|1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4|",
			expectedSalt:            mustHexDecode("6eb7673063d3bc573bf040c9656a83e73d10276770f23f15db25bfc8edbeb6e7"),
			expectedPrk:             mustHexDecode("b37289fa18c1c6b48da35bde046425f1fe31eb2ff1bc0c96ba133d6916f7aeab"),
			expectedInfoStringAES:   "|pulse|kdf|v1|aead:channel:key|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedInfoStringNonce: "|pulse|kdf|v1|aead:channel:nonce|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedAESKey:          mustHexDecode("e52121ff74c5fc185d5aa165c47283889378492f64a53fbf5d53f3e5dc5e4e82"),
			expectedAESNonce:        mustHexDecode("9b6585bef61692965127d170"),
		},
		{
			name:         "Alice Kyber Encapsulate",
			mode:         "Kyber",
			sharedSecret: mustHexDecode("5c1db08a4db86a2f26964f53c2911e8ab029f0087732e76bd5e1842dbac50777"),
			transcript:   mustHexDecode("b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9"),
			recipientId:  mustHexDecode("01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd"),
			context:      mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			// Expected values
			expectedSaltString:      "|pulse|kdf|v1|salt|kyber768|b236c30d44fa247895e19d4b249ef8a07db4f15b5280f8fca53587093884b182e34e5af87163402b51ece1c1945532fa297b3307a42e37aca5f93de09e53af17564b16c073c80d928ac7e21d11876789c3060498ace470a431e8fe13b67a856e641dcce741229193766a2b9b9533e5b47e328a9aa1f930a51581c11d79815a270f82ce3b78d4c0235746004a480f6101ac77eeea0ce879c354f0c18a0afa230a880f97f443ddf0a63027529ee452b311510baa59d89e0d8e8f20478ba95c19b006a8d22313e6f648f9c6f9c6c2af67bc76be832dc49feda76afcceb41dc56dfe81db2238b50883ef2e9bc3df0cc0af57b7cc02e87e6b3cd24d82f0bc563f5aef7eb29facef912c96fe7f0b0dba53497a0f992ad3b0f43346678851ee99b36cbd2b8e7012bcfddc5e01ecdd7a8c59030ae908ade990d2471acf4541b283b2c2c68d39c3ea75c3df3e9748b7796cd8a5e9cbc22752c3ff487debbebe342edf19057bec457047c6172d954df1abf57b3be492a35a4e8f778aba2ad1b3b56a2aef2841e348cf5bb475620622030c255f3b32ee59c0676149be0725024d0aa64923f329b03bffc424b2040ac5cc9f1c976fdfec41b65e66e0c9cd6bd68d1e66978197cd4f1e3f5a991ca95445f75caa19cc3ce4b433d53a3ffb25039fd312ea40975a7065ef32edd08335ef8a71ce6c7697eab7c37f37594665ee62d4a82005df15660fcd92fe710e85cef0d57631801fc878245c4ee96c2cebf537c3f628ef777a8b4a54f1d5b72fa4953cff152cb35e188eaa2b14ad749d5350abfdfcb2ad73d64362f8379ed034c37865d2c0a0c38226bffd80a4b5981afbd84ce8f4f89c757e902b5ea441d74783352d3a60aa6447420e27cf6992d5d0b1dfbcd237d7e39dd080b2e629795ec30603a4562fb9b46d33b6a9692d59f7e032d8d0420d42a3a492c61189f1357a7a1b1c49e3622246137d0b5d4a5bc589ee29be1e10b9346c148f41e1403491f4d599436f5929760ceaee077b496a1a1bb095b1f7bb20b80e626a2ef7b83631c650074c56b9a2dfc08cae48b65255e7571a4928266a4f9c5ecaa9a546447f350c34ccccc22b8748ed323d19e712e5d41c6726a87a4bcb9b26f7f12ea5bf42ce66dcadfb16b143238d193499b56141a87e1168483f59fc1156d7f26b03b1f48d3553fa828bc3c87885a6c7942be3886209117151d3e59ff0610ef6e40e7e05c72e0a16fa80ae401c8fb1738a214bae41a9a3601951bf61c49227909d91f65aad5183d6adfefc48a2bd3c4ee3c2a013aac269eb709f2499c724f445feb750e48db19f33e6303be50d614029a3c27ec3191a51e0fcf6183f82ecbc44a96892d971e4bdc346634170ed1b6635aa7660143a6e2aae92fb5c128cad73a1bf9c450c22accebbdd099fe8b8e82915acf09364edb6e16fc245baa8e8c684400e5dac29c9fce2a5ba9dcbd66aaaf087c2effe80ccb2a750579479ff16ca6fc472dea7d2120bf672df3d4050ef69ebe9e5dffe73395da4a09a8ed157bb2c63f9d9|",
			expectedSalt:            mustHexDecode("3acf0f1b25cafa0b47d1fcb1907a1677714f31ce1ca950aa447284f7c90a9d86"),
			expectedPrk:             mustHexDecode("2f4a315fcec8ef3577086f3f47f6f0564a6bb04c5bbf7012737de543a99dec02"),
			expectedInfoStringAES:   "|pulse|kdf|v1|keywrap-aeskey|kyber768+hkdf-keccak256|rid=01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedInfoStringNonce: "|pulse|kdf|v1|keywrap-aesnonce|kyber768+hkdf-keccak256|rid=01b4f1d38c1f547fa0d533118f43a523ae60171156ad380f01a724511ebe78cd|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedAESKey:          mustHexDecode("8c00e2528428927b81befef1022cf7de7aae639b8f714a90c1c6106237000822"),
			expectedAESNonce:        mustHexDecode("504f2d28709e2db670a59cc4"),
		},
		{
			name:         "Bob Kyber Encapsulate",
			mode:         "Kyber",
			sharedSecret: mustHexDecode("49666a8941873a339c07299b0aea6941ad420dd0df8ebd9fc5160154153caea3"),
			transcript:   mustHexDecode("ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02"),
			recipientId:  mustHexDecode("70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde"),
			context:      mustHexDecode("7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3"),
			// Expected values
			expectedSaltString:      "|pulse|kdf|v1|salt|kyber768|ba3ba03f50569012f826140c5badce912aae42495114db4c623c914e9c292ab6ba0feb2ff2c3a733113d796c6f2fffe7e35ba57744a11d7cac31a1897ef0dd4c7fbe9f94408ef7b1273c374c628feaf0f497a18429b1cc6960a9ba5be6a1767539dafa10ab40591dfe8efd05b804ccaa2b4351270a281e8addc7e0f5dcc48bd266836221996a2e5b0b6854f51234991596914563a8b1f600c923f8e6dfb3ef8d6f2f819e8ca03e37d8caee541a910ab1ec6c19e4bc3428c4cbe706f17c0fa477a0035152d01bb811ff82b667b44b18fa18e6ea85ec4d4382e1ff6dc5a80d11db6bfed4f4290a15f6c4fba54195dad9672ad06453ed6bdf2f04832bc2b953502ffc79c5f023776fed991f4e3784f00ef702eb81fa08afe2957a06f83d87b9729a2f8e3f7f5567f167cb425a0bcbe7858c5dcc405855ab14600a0798c41dc1feeff8959b2bca0680f3edea4df3ba2947180a0c762709174de56aed62e8e40ae3b128bbc724e8491d8366f8072f5194ff904acf5b278fc3dd5574128c8b29acd7111fbe1ea4b57f693ae82781497d57eeb8a6949208c8139e675a0d8afcdb20c00241138d64b6e18ac32368956985230a05ddd8eb9746f8acec8974dd38c65bfea5defc0c9647c60beae3d1a1f4deb26c0290774b9235eea6a971af18e9710eb5084eb02cee51f3fabf6e5cd3fd486224512c78b6a0e4b166e5196d8ebb36387922e697719cf7d9e0639990e6d993fe3d63820daf337d037a57aa4620748fd23c6a3cab5712bf1f709f55949831acbc1e700edd2d67efa8598fcafc3d659bc2f3b42078601910087077f47f467273032ed203151c2c276be3f18b7f253e9e6bbd028b053dd42a58572bb7b1d923360cbbcf04816c74322804c14ea01400a303f9d7dd66caa727b39a5be6f18d0f1d37f4323fbb1b5937cf23e1777147b37406f73d64984f79444b121f5ad43280ac3aecc5181dfd370361b9bbdbb791774e9b634f4a045856dd29574651a7eb1d5afb49e8e46237aef5eb6c3d2c24a172f512e9b5f0f62a41894432def40f97b77f1dbe0de804f2eb4241f9fe8de10947829c0de94e98c1c0162a73c07f1f77ff584584000128490c332fa1347278665e23c6e0b2bac7ab0cecbd3a2c5992881eca436f44c4b3c24f1ddf4e392d06b2bb41ba99e6b394d26f26f01d6ac8b5762e9904f38823ea0c45fef94a7420011eb090951228b19f8ec36a1cf3f70e311b8c9fa5237f445cf9543edf8acfe215437d3046327c7b4e38641d18764ad83692caa56de62a8bd63ce6380e885322a8dc6f7518188c364d05fd613b87e62278f3e661b6858c7db09164a4e44d22940dbe2d8b46c61478fb16588efbb849e0d7b22e7a3aa4ff9fc388c9294cbbc2b5b9b0fa3ed91f39e17bf10e7288f4901b946a3c011fa3865f3377a0b2e35967ab62ea733cd92f08ff575fe935d3123b4beae21a222f0111b34ae5fcf86811d2ec0baf98bca4111d0fd665d7b4dac3669d2de1896fbecc854b792c5d1fa067dee802bc1fe2559e02|",
			expectedSalt:            mustHexDecode("5d597a0aa15335dbdf60d14d86046769e67e5dba20fb165232af63aa4529bca5"),
			expectedPrk:             mustHexDecode("1503189557488c6c5c36f98fa6d704e10774b49394e88f45a397b71206f361f4"),
			expectedInfoStringAES:   "|pulse|kdf|v1|keywrap-aeskey|kyber768+hkdf-keccak256|rid=70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedInfoStringNonce: "|pulse|kdf|v1|keywrap-aesnonce|kyber768+hkdf-keccak256|rid=70e2c14612b36ffcf09fe5ca28564270a7513ff0c84ac000cbff35292b35fdde|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862|",
			expectedAESKey:          mustHexDecode("ec144bc3e77f9d68782131775750e9e53d76ccc8186e1846a146d5e37c48f3ca"),
			expectedAESNonce:        mustHexDecode("2e00a1a119f54375f5a75416"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 1. Test Salt String and Salt Value
			parentAlgo, purpose, suite := getSettings(tt.mode)

			saltString := createSaltString(parentAlgo, tt.transcript)
			if saltString != tt.expectedSaltString {
				t.Errorf("saltString mismatch: got %q, want %q", saltString, tt.expectedSaltString)
			}
			salt := createSalt(parentAlgo, tt.transcript)
			if !bytes.Equal(salt, tt.expectedSalt) {
				t.Errorf("salt mismatch: got %x, want %x", salt, tt.expectedSalt)
			}

			infoKey := createInfo(purpose, false, suite, tt.recipientId, tt.context)
			if string(infoKey) != tt.expectedInfoStringAES {
				t.Errorf("infoKeyString mismatch: got %q, want %q", string(infoKey), tt.expectedInfoStringAES)
			}

			infoNonce := createInfo(purpose, true, suite, tt.recipientId, tt.context)
			if string(infoNonce) != tt.expectedInfoStringNonce {
				t.Errorf("infoNonceString mismatch: got %q, want %q", string(infoNonce), tt.expectedInfoStringNonce)
			}

			// 3. Test PRK, AES Key and AES Nonce
			prkExtracted := pulseExtract(tt.sharedSecret, parentAlgo, tt.transcript)
			if !bytes.Equal(prkExtracted, tt.expectedPrk) {
				t.Errorf("PRK mismatch: got %x, want %x", prkExtracted, tt.expectedPrk)
			}

			var key, nonce []byte
			var err error
			if tt.mode == "ECDH" {
				key, nonce, err = PulseHKDFECDH(tt.sharedSecret, tt.transcript, tt.recipientId, tt.context)
			} else {
				key, nonce, err = PulseHKDFKyber(tt.sharedSecret, tt.transcript, tt.recipientId, tt.context)
			}

			if err != nil {
				t.Fatalf("HKDF failed: %v", err)
			}

			if !bytes.Equal(prkExtracted, tt.expectedPrk) {
				t.Errorf("PRK mismatch (from HKDF call): got %x, want %x", prkExtracted, tt.expectedPrk)
			}

			if !bytes.Equal(key, tt.expectedAESKey) {
				t.Errorf("AES key mismatch: got %x, want %x", key, tt.expectedAESKey)
			}
			if !bytes.Equal(nonce, tt.expectedAESNonce) {
				t.Errorf("AES nonce mismatch: got %x, want %x", nonce, tt.expectedAESNonce)
			}
		})
	}
}
