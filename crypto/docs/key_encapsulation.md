# Key Encapsulation - Protocol and Worked example

## Intro

Key Encapsulation is the method of encrypting pulse consent data using a Kyber768 cipher suite. 
This is distinct from the "Key Exchange" method that uses a ECDH (secp256k1) key exchange to derive a symmetric key 
for encrypting the conset data, and documented elsewhere.

The protocol uses the following building cryptographic building blocks:
 - Kyber768 ( Key encapsulation mechanism )
 - AES-GCM ( symmetric cipher )
 - Keccak-256 ( hash function )
 - RFC 5869 HKDF ( key derivation function )

At a high level, encryption and decryption work as follows:
  
 - **Encryption** ( needs consent data and a list of Public Keys):
   1. Generate a random symmetric key (32 bytes) and nonce (12 bytes) "AESDataKey"
   2. Encrypt the consent data/plaintext using AES-GCM with the symmetric key.
   3. For each recipient's public key (including the sender!)
      - Create a fingerprint of the public key by Hashing it.
      - Use Kyber768 and the Public Key to create and encapsulate a shared secret"
      - Use HKDF to derive and AES key and nonce from the shared secret "AESKeyKey"
      - Encrypt the AESDataKey with the AESKeyKey using AES-GCM
      - Package the encapsulated shared secret, fingerprint, and encrypted data key into a `PulsePQEncryptionKey`.
   4. Package the ciphertext and list of `PulsePQEncryptionKey` into a `PulsePQEncryptionResult`.

 - **Decryption** ( needs a PulsePQEncryptionResult and my Private Key/Public Key):
   1. Identify the recipient's PulsePQEncryptionKey record using the fingerprint of their public key.
   2. Use Kyber768 to decapsulate the encapsulated key, recovering the shared secret.
   3. Use HKDF to derive the AESKeyKey and nonce from the shared secret.
   4. Decrypt the encrypted data key using AES-GCM with the AESKeyKey to recover the AESDataKey.
   5. Decrypt the ciphertext using AES-GCM with the AESDataKey.

We also need to populate the AAD (additional authenticated data) for the AES-GCM encryption, along with the Salt and 
Info parameters for the HKDF key derivation. These fields use a combination of external context data, such as the 
smart contract address, and internal interim results.

## Formal Definition

### Encrypted Data Structures

```
type PulsePQEncryptionResult struct {
	SealedData []byte                  `json:"sealedData" cbor:"0,keyasint"` // Encrypted data
	Keys       []*PulsePQEncryptionKey `json:"keys"       cbor:"1,keyasint"` // Public keys of parties that may be able to decrypt the data
}

type PulsePQEncryptionKey struct {
	KeyFingerPrint      [32]byte `json:"keyFingerPrint"  cbor:"0,keyasint"`     // Hash of public key
	EncapsulatedKeyKey  []byte   `json:"encapsulatedKeyKey" cbor:"1,keyasint"`  // Encapsulated/Encrypted AES EncryptionKey
	EncapsulatedDataKey []byte   `json:"encapsulatedDataKey" cbor:"2,keyasint"` // Encapsulated/Encrypted AES Ciphertext
}
```
Both types can be serialized to both CBOR and JSON format. CBOR is preferred for storage and transmission, as it is more
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

```ENCAPSULATE(publicKey) -> (sharedSecret,encapsulatedSecret)```  /// Kyber768 encapsulation function. Generates a 
random shared secret, and encapsulates it so that only someone with the associated private key can retrieve ```sharedSecret``` 
from ```encapsulatedSecret```

```DECAPSULATE(privateKey, encapsulatedSecret) -> sharedSecret```  /// Kyber768 decapsulation function. Reverses the
ENCAPSULATE function.

```PUBKEY(privateKey) -> publicKey```  /// Gets the public key from a private key. For Kyber, this is usually pre-stored
inside the private key.

```RNG(n) -> byte[n]```  /// Cryptographically secure random number generator, returns n random bytes.

```PACK(Kyber Public Key) -> byte[1184]```  /// Packs a Kyber public key into a 1184 byte array. Canonical representation.```

```SPRINTF(format, args...) -> string``` /// String formatting function, similar to fmt.Sprintf in Go or sprintf in C.

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
*  ```publicKeys kyber.PublicKey[]```  /// Public keys of all participants to the consent transaction.

### Encryption Algorithm

```
FINGERPRINT(publicKey) -> byte[32] = H(PACK(publicKey))

fingerPrints := [ for pk in publicKeys: HEX(FINGERPRINT(pk)) ]
fingerPrints.SORT()     // Lexical/Alphabetical order

recipientString := "|pulse|group|v1|" + [ for fp in fingerPrints: fp + "|" ]
receipientStringHash := H(recipientString)

contextString := SPRINTF("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d", chainId, smartContractAddress, consentNumber)
context := H(contextString)

AESDataKey := RNG(32)
AESDataNonce := RNG(12)

dataAAD := SPRINTF("pulse|%s|v1|rng+aes-gcm-256|rid=%s|ctx=%s|th=%s|nonce=%s", purpose.STRING(), HEX(recipientStringHash), HEX(contextHash), HEX(H(AESDataNonce)), HEX(AESDataNonce),

encryptedData := AES_SEAL(plaintext, AESDataKey, AESDataNonce, dataAAD)

packedKey := AESDataKey + AESDataNonce  // Concatenate the AESDataKey and AESDataNonce into a single byte array.

foreach pubkey in publicKeys:
    sharedSecret, encapsulatedSecret := ENCAPSULATE(pubkey)
   
    saltString = SPRINTF("pulse|kdf|v1|salt|kyber768|%s", HEX(encapsulatedSecret))
    salt := H(saltString)
    prk := EXTRACT(sharedSecret, salt)

    infoKeyString = SPRINTF("pulse|kdf|v1|keywrap-aeskey|kyber768+hkdf-keccak256|rid=%s|ctx=%s", HEX(FINGERPRINT(pubkey)), HEX(context))
    aesKeyKey := EXPAND(prk, infoKeyString, 32)   // Derive AES key for encrypting the data key.
    infoKeyNonce := SPRINTF("pulse|kdf|v1|keywrap-aesnonce|kyber768+hkdf-keccak256|rid=%s|ctx=%s", HEX(FINGERPRINT(pubkey)), HEX(context))
    aesKeyNonce := EXPAND(prk, infoKeyNonce, 12)  // Derive nonce for encrypting the data key.

    keyAAD := SPRINTF("pulse|%s|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=%s|ctx=%s|th=%s|nonce=%s", purpose.STRING(), HEX(FINGERPRINT(pubkey), HEX(context), HEX(H(encapsulatedSecret)), HEX(AESKeyNonce))

    encryptedKey := AES_SEAL(packedKey, AESKeyKey, AESKeyNonce, keyAAD)

    store PulsePQEncryptionKey {
        Fingerprint: FINGERPRINT(pubkey),
        EncapsulatedKey: encapsulatedKey,
        EncryptedDataKey: encryptedPackedKey
    }

encryptionResult := PulsePQEncryptionResult {
    Ciphertext: encryptedData,
    Keys: [ all stored PulsePQEncryptionKey records ]
}
```

### Decryption Inputs - Cryptographic

*  ```encryptedData PulsePQEncryptionResult``` // Encrypted data to be decrypted.
*  ```privateKey kyber.PrivateKey``` // My private key.

### Decryption Algorithm

```
contextString := SPRINTF("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d", chainId, smartContractAddress, consentNumber)
context := H(contextString)

publicKey := PUBKEY(privateKey)
fingerPrint := FINGERPRINT(publicKey)

cipherText := encryptedData.Ciphertext
keys := encryptedData.Keys

foreach key in keys:
    if key.Fingerprint == fingerPrint:
        myKey := key
        fingerPrints := fingerPrints.append(key.Fingerprint)
// Error if no key founcd for the recipient's public key.
fingerPrints.SORT()     // Lexical/Alphabetical order

recipientString := "|pulse|group|v1|" + [ for fp in fingerPrints: fp + "|" ]
receipientStringHash := H(recipientString)

sharedSecret := DECAPSULATE(privateKey, key.EncapsulatedKey)

// Build Salt and Info same as Encryption Algorithm
saltString = SPRINTF("pulse|kdf|v1|salt|kyber768|%s", HEX(key.EncapsulatedKeyKey))
salt := H(saltString)
prk := EXTRACT(sharedSecret, salt)

infoKeyString = SPRINTF("pulse|kdf|v1|keywrap-aeskey|kyber768+hkdf-keccak256|rid=%s|ctx=%s", HEX(fingerPrint), HEX(context))
aesKeyKey := EXPAND(prk, infoKeyString, 32)   // Derive AES key for encrypting the data key.
infoKeyNonce := SPRINTF("pulse|kdf|v1|keywrap-aesnonce|kyber768+hkdf-keccak256|rid=%s|ctx=%s", HEX(fingerPrint), HEX(context))
aesKeyNonce := EXPAND(prk, infoKeyNonce, 12)  // Derive nonce for encrypting the data key.

keyAAD := SPRINTF("pulse|%s|v1|kyber768+hkdf-keccak256+aes-gcm-256|rid=%s|ctx=%s|th=%s|nonce=%s", purpose.STRING(), HEX(fingerPrint), HEX(context), HEX(H(myKey.EncapsulatedKeyKey)), HEX(aesKeyNonce))

decryptedKey := AES_OPEN(myKey.EncryptedDataKey, aesKeyKey, aesKeyNonce, keyAAD)

aesDataKey := decryptedKey[0:32]
aesDataNonce := decryptedKey[32:44]

dataAAD := SPRINTF("pulse|%s|v1|rng+aes-gcm-256|rid=%s|ctx=%s|th=%s|nonce=%s", purpose.STRING(), HEX(recipientStringHash), HEX(contextHash), HEX(H(AESDataNonce)), HEX(AESDataNonce))
plaintext := AES_OPEN(cipherText, aesDataKey, aesDataNonce, dataAAD)

```
