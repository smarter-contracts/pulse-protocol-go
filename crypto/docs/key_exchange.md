# Key Exchange - Protocol and Worked example

## Intro

Key Exchange is the method of encrypting pulse consent data using Elliptic Curve Diffie-Hellman (ECDH) and the secp256k1
curve to create a shared secret and thus encryption key. 
This is distinct from the "Key Encapsulation" method that uses Kyber768 to create receipient-specific keys
for encrypting the consent data, and documented elsewhere.

The protocol uses the following building cryptographic building blocks:
 - Diffie-Hellman over the Secp256k1 elliptic curve (Key generation)
 - AES-GCM ( symmetric cipher )
 - Keccak-256 ( hash function )
 - RFC 5869 HKDF ( key derivation function )

At a high level, encryption and decryption work as follows:
  
 - **Encryption** ( needs consent data, my "Alice" private key and the public key of the recipient "Bob"):
   1. ECDH key exchange using Alice's private key and Bob's public key to generate a shared secret.
   2. Use the HKDF to derive an AES key and nonce from the shared secret.
   3. Encrypt the consent data using AES-GCM and the derived AES key.
   4. Put the encrypted data and the secp256k1 public keys into the result structure.

 - **Decryption** ( needs the encrypted consent and my private key):
   1. Get my public key from my private key.
   2. Identify which key in the result structure matches my public key, and which is the "other public key"
   3. ECDH exchange using my private key and the "other public key" to recover the shared secret.
   4. Use the HKDF to derive the AES key and nonce from the shared secret.
   5. Decrypt the encrypted consent data using AES-GCM and the derived AES key.


We also need to populate the AAD (additional authenticated data) for the AES-GCM encryption, along with the Salt and 
Info parameters for the HKDF key derivation. These fields use a combination of external context data, such as the 
smart contract address, and internal interim results.

## Formal Definition

### Encrypted Data Structures

```
type PulseECEncryptionResult struct {
	SealedData []byte   `json:"sealedData" cbor:"0,keyasint"` // Encrypted data
	Key1       []byte   `json:"key1"       cbor:"1,keyasint"` // My public key, 33-byte compressed format
	Key2       []byte   `json:"key2"       cbor:"2,keyasint"` // Public key of the other party, 33-byte compressed format
}
```
This structure can be serialized to both CBOR and JSON format. CBOR is preferred for storage and transmission, as it is more
compact and has stronger structural/ordering guarantees.

### Helper Functions

All functions are named in UPPERCASE. Variables are not.

```H(byte_data) -> byte[32]```   // Keccak-256 hash function, input is a stream of bytes. output is 32 bytes/256 bit binary value.

```HEX(byte[]) -> string```  /// Convert a byte array to a hex string.
   
Notes: 
* Each input byte is represented by two hex characters (0-9, a-f). Always lowercase letters, no uppercase.
* No leading '0x'
* Output string length is always exactly 2 * input byte.length.

```EXTRACT(shared_secret, salt) -> prk```  /// HKDF extract function, computes a pseudorandom key from input keying 
    material and a salt.

   Notes:
* Uses HMAC with Keccak-256 as the underlying hash function.
* prk length is 32 bytes.

```EXPAND(prk, info, L) -> okm```  /// HKDF expand function, computes output keying material from pseudorandom key, info, and desired length.

   Notes:
* Uses HMAC with Keccak-256 as the underlying hash function.
* okm length is L bytes.

```
   AES_SEAL(plaintext, key, nonce, AAD) -> ciphertext  // AES Encryption with Authenticated Encryption
   AES_OPEN(ciphertext, key, nonce, AAD) -> plaintext  // AES Decryption with Authenticated Encryption
   ``` 

Notes:
* Uses AES-256 in GCM mode.
* ciphertext length is exactly plaintext.length bytes.
* nonce length is 12 bytes. key length is 32 bytes.`

```ECDH(myPrivateKey, otherPublicKey) -> sharedSecret```  /// ECDH key exchange function to get a shared secret

```PUBKEY(privateKey) -> publicKey```  /// Gets the public key from a private key. For ECDH this is G^<privateKey> mod P.

```SPRINTF(format, args...) -> string``` /// String formatting function, similar to fmt.Sprintf in Go or sprintf in C.

```SERIALISE(publicKey) -> string``` /// Serializes a public key to a hex string. We use the compressed format for the 
keys.

### Common Inputs - Contextual

These are common and used for both Encryption and Decryption in Pulse. These are used in the HKDF and AAD contstruction
to ensure that keys cannot be reused across different consent transactions and environments.

*  ```smartContractAddress string``` // Address of the smart contract that generated the consent transaction. Should be 40 hex characters.
*  ```consentNumber int32``` // Unique number assigned to the consent transaction. This number starts at 1 for the first
    consent between these parties, and increments by 1 for each subsequent consent.
*  ```chainId int32``` // Chain number of the key used. This is always 1.
*  ```purpose byte```  // Indicates the type of underyling plaintext:


| Value | Purpose                                          | String Value |
|-------|--------------------------------------------------|--------------|
| 0     | No defined purpose                               |
| 1     | Consent data                                     | consent      |
| 2     | Revocation record for a prior consent.           | revoke       |
| 3     | Update record for modifying an existing consent. | update       |
| 255   | Wrapping a key                                   | keywrap      |

### Encryption Inputs - Cryptographic

*  ```plaintext byte[]``` // Consent record to be encrypted.
*  ```otherPublicKey secp256k1.publicKey```  /// Public keys of other participant
*  ```myPrivateKey secp256k1.privateKey``` // My private key.

### Encryption Algorithm

```
myPublicKey := PUBKEY(myPrivateKey)

contextString := SPRINTF("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d", chainId, smartContractAddress, consentNumber)
contextHash := H(contextString)

keys = [ SERIALISE(myPublicKey), SERIALISE(otherPublicKey) ]
SORT(keys)
transcriptString := SPRINTF("|pulse|group|v1|%s|%s|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|", keys[0], keys[1])
transcriptHash := H(transcriptString)

sharedSecret := ECDH(myPrivateKey, otherPublicKey)

saltString := SPRINTF("pulse|kdf|v1|salt|secp256k1|%s", HEX(transcriptHash)
salt := H(saltString)
prk := EXTRACT(sharedSecret, salt)

infoKeyString := SPRINTF("pulse|kdf|v1|aead:channel:key|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=%s", HEX(contextHash))
aesKey := EXPAND(prk, infoKeyString, 32)   // Derive AES key for encrypting the data.
infoNonceString := SPRINTF("pulse|kdf|v1|aead:channel:nonce|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=%s", HEX(contextHash))
aesNonce := EXPAND(prk, infoNonceString, 12)  // Derive nonce for encrypting the data.

aad := SPRINTF("|pulse|%s|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=%s|th=%s|nonce=%s|", purpose.STRING(), HEX(contextHash), HEX(transcriptHash), HEX(aesNonce),

encryptedData := AES_SEAL(plaintext, aesKey, aesNonce, aad)

encryptionResult := PulseECEncryptionResult {
    SealedData: encryptedData,
    Key1: SERIALISE(myPublicKey),
    Key2: SERIALISE(otherPublicKey)
}
```

### Decryption Inputs - Cryptographic

*  ```encryptedData PulseECEncryptionResult``` // Encrypted data to be decrypted.
*  ```privateKey secp256k1.PrivateKey``` // My private key.

### Decryption Algorithm

```
myPublicKey := PUBKEY(myPrivateKey)
otherPublicKey := (encrptedData.Key1 == myPublicKey) ? encryptedData.Key2 : encryptedData.Key1

contextString := SPRINTF("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d", chainId, smartContractAddress, consentNumber)
contextHash := H(contextString)

keys = [ encryptedData.Key1, encyptedData.Key2 ]
SORT(keys)
transcriptString := SPRINTF("|pulse|group|v1|%s|%s|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|", keys[0], keys[1])
transcriptHash := H(transcriptString)

sharedSecret := ECDH(myPrivateKey, otherPublicKey)

saltString := SPRINTF("pulse|kdf|v1|salt|secp256k1|%s", HEX(transcriptHash)
salt := H(saltString)
prk := EXTRACT(sharedSecret, salt)

infoKeyString := SPRINTF("pulse|kdf|v1|aead:channel:key|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=%s", HEX(contextHash))
aesKey := EXPAND(prk, infoKeyString, 32)   // Derive AES key for encrypting the data.
infoNonceString := SPRINTF("pulse|kdf|v1|aead:channel:nonce|ecdh-secp256k1+hkdf-keccak256|rid=|ctx=%s", HEX(contextHash))
aesNonce := EXPAND(prk, infoNonceString, 12)  // Derive nonce for encrypting the data.

aad := SPRINTF("|pulse|%s|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=%s|th=%s|nonce=%s|", purpose.STRING(), HEX(contextHash), HEX(transcriptHash), HEX(aesNonce),

plaintext := AES_OPEN(encryptedData.SealedData, aesKey, aesNonce, aad)

```
## Known Values for Testing

We provide a single set of known values for testing both Encryption and Decryption, as many of the values between
the two algorithms are the same. 

Binary values are presented in hexadecimal format, so they can be easily viewed here and pasted into test code.

Strings are written inside double quotes: "string value"

### External Input Values

| Name               | Comment                                                                    | Value                                                            |
|--------------------|----------------------------------------------------------------------------|------------------------------------------------------------------|
| PrivateKey (Alice) | Private key for first participant                                          | 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 
| PrivateKey (Bob)   | Private key for second participant                                         | 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e20 
| ChainId            | Chain number                                                               | 1 (0x00000001)                                                   |
| SmartContractAddress | Address of the smart contract, as a string                                 | "0x0102030405060708091011121314"                                  |
| ConsentNumber       | Unique number (for these participants) assigned to the consent transaction | 2                                                                |
| Purpose             | Purpose of the consent transaction                                         | 1 (consent)                                                      |
| Plaintext           | Consent record to be encrypted                                             | "This is the consent record"                                     |

### Derived Values

| Name                    | Calculation                                                   | Value                                                                                                                                                                                                                                                |
|-------------------------|---------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| publicKeyAlice          | PUBKEY(PrivateKeyAlice)                                       | 036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2                                                                                                                                                                                   |
| publicKeyBob            | PUBKEY(PrivateKeyBob)                                         | 03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc                                                                                                                                                                                   |
| contextString           | SPRINTF(contextFormat, values... )                            | "\|pulse\|ctx\|v1\|chain=1\|contract=0x0102030405060708090a0b0c0d0e0f1011121314\|consentNumber=2"                                                                                                                                                    |   
| contextHash             | H(contextString)                                              | 7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3                                                                                                                                                                                     |
| keys                    | [ publicKeyAlice, publicKeyBob ] (order not important)        | [ "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e", "03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc" ]                                                                                                        |                                                         |
| transcriptString        | SPRINTF(transcriptFormat, keys, suite )                       | "\|pulse\|group\|v1\|03131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc\|036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2\|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256\|"                                            |
| transcriptHash          | H(transcriptString)                                           | 1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4                                                                                                                                                                                     |
| sharedSecret            | ECDH(alicePrivate,BobPublic) OR ECDH(bobPrivate, AlicePublic) | 3872a1eb53189a568a797a14a2765e22811f2bd293bef8ecea81a17dab95998e                                                                                                                                                                                     |
| saltString              | SPRINTF(saltformat, args..)                                   | "pulse\|kdf\|v1\|salt\|secp256k1\|1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4\|"                                                                                                                                                |
| salt                    | H(saltString)                                                 | 1ec80f02e80bc5f74a6b4975477a579545067042088d26149950b288562693af                                                                                                                                                                                     |
| prk                     | EXPAND(sharedSecret,salt)                                     | f7c1f084075cb16f0a7fa816e6dabf354af548e802585216bd7b3c3d7b5b5f69                                                                                                                                                                                     |
| infoKeyString           | SPRINTF(infoKeyFormat,args...)                                | "\|pulse\|kdf\|v1\|aead:channel:key\|ecdh-secp256k1+hkdf-keccak256\|rid=\|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862\|"                                                                                                    |
| infoNonceString         | SPRINTF(infoKeyFormat,args...)                                | "\|pulse\|kdf\|v1\|aead:channel:nonce\|ecdh-secp256k1+hkdf-keccak256\|rid=\|ctx=4cdac3f08f1d9b30e13c4bee9d3fbbaccb1717f4467778c0c0dfbe8b41f46862\|"                                                                                                  |             
| aesKey                  | EXPAND(prk,infoKeyString,32)                                  | cee5d3c958a8be9fdea4e4dca39cf4bf52ca824a1f71d026319e350a6b0ef67a                                                                                                                                                                                     |
| aesNonce                | EXPAND(prk,infoNonceString,12)                                | 3298b5b0da18ab57667cf999                                                                                                                                                                                                                             |
| aad                     | SPRINTF(aadFormat, args...)                                   | "\|pulse\|consent\|v1\|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256\|rid=\|ctx=7a3770b999386d8d7c0464f12cf647e91e91769fda2d399847d461b594e3c2f3\|th=1e3896ba915877689883ed502ee8d3a2629bdf8ddbc03d1a441cbbe7af335fa4\|nonce=3298b5b0da18ab57667cf999\|" |
| encryptedData           | AES_SEAL(Plaintext,aesKey,aesNonce,aad)                       | 36dae43a0870c0f96bea88d074d8136e0cda62a5d5a67bc0bd8ccf2eee27618951ce1cb2391d2688da0a                                                                                                                                                                                                                                                     |
| encrpytionResult (CBOR) | CBOR.MARSHALL(encryptionResult)                               | 83582a36dae43a0870c0f96bea88d074d8136e0cda62a5d5a67bc0bd8ccf2eee27618951ce1cb2391d2688da0a5821036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2582103131341eb2154dded12e38e0bce03f906802fb10690ec1b2b27303a4a9fba88bc                                                                                                                                                                                                                                                    |
| encrpytionResult (JSON) | JSON.MARSHALL(encryptionResult)                               | {"sealedData":"NtrkOghwwPlr6ojQdNgTbgzaYqXVpnvAvYzPLu4nYYlRzhyyOR0miNoK","key1":"A21sqsJIr5b2r6f5BPVQJToPPvP1qi/mg4qVshZpFGji","key2":"AxMTQeshVN3tEuOOC84D+QaAL7EGkOwbKycwOkqfuoi8"}                                                                                                                                                                                                                                                    |
