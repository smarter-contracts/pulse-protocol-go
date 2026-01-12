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

aad := SPRINTF("pulse|%s|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=%s|th=%s|nonce=%s", purpose.STRING(), HEX(contextHash), HEX(transcriptHash), HEX(aesNonce),

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

aad := SPRINTF("pulse|%s|v1|ecdh-secp256k1+hkdf-keccak256+aes-gcm-256|rid=|ctx=%s|th=%s|nonce=%s", purpose.STRING(), HEX(contextHash), HEX(transcriptHash), HEX(aesNonce),

plaintext := AES_OPEN(encryptedData.SealedData, aesKey, aesNonce, aad)

```
