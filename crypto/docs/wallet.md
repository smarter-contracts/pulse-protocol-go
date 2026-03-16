# HD Wallet Derivation - Protocol and Formal Definition

## Intro

The Pulse Protocol uses BIP-32 Hierarchical Deterministic (HD) wallets to derive all cryptographic keys from a
single master seed. This provides deterministic key generation, meaning that any party who knows the master key
and the derivation parameters can independently reproduce the same keys.

The HD wallet serves two purposes:
1. **EC key derivation**: Deriving secp256k1 private keys for ECDSA signing and ECDH key exchange.
2. **PQ key derivation**: Deriving ML-KEM-768 (Kyber768) key pairs for post-quantum key encapsulation, via an
   intermediate HKDF seed expansion step.

The derivation path follows BIP-43 conventions with a Pulse-specific protocol identifier. Each level of the
path binds the key to a specific context: the other party, the blockchain, the consent number, and the intended
purpose.

## HD Derivation Path

All Pulse keys are derived from a BIP-32 master key using the following path:

```
m / 4410704' / otherParty / chainId / consentNumber / purpose
```

| Level         | Range            | Hardened | Description                                         |
|---------------|------------------|----------|-----------------------------------------------------|
| Protocol      | 4410704 (fixed)  | Yes      | BIP-43 identifier for Pulse Protocol (0x434d50 = 'CMP' in ASCII). Stored as 0x80434d50 (with hardening bit). |
| OtherParty    | 0 – 0x7FFFFFFF   | No       | Numeric identifier for the counterparty.            |
| ChainId       | 1 – 0x7FFFFFFF   | No       | Blockchain network identifier (1 = Polygon).        |
| ConsentNumber | 0 – 0x7FFFFFFF   | No       | Sequential consent number for this pair of parties.  |
| Purpose       | See table below  | No       | Intended use of the derived key.                    |

### Purpose Values

| Value | Constant Name                        | String Value                 | Key Type | Used For                                               |
|-------|--------------------------------------|------------------------------|----------|--------------------------------------------------------|
| 1     | PulsePurposeSignTx                   | signtx                       | EC       | EIP-191 signing of consent and revoke transactions     |
| 2     | PulsePurposeEncryptConsentNotaryBlock| encrypt-consent-notary-block | EC       | ECDH encryption of consent notary blocks               |
| 3     | PulsePurposeEncryptConsentStructure  | consent                      | EC       | ECDH encryption of consent data                        |
| 4     | PulsePurposeEncryptRevokeNotaryBlock | encrypt-revoke-notary-block  | EC       | ECDH encryption of revoke notary blocks                |
| 5     | PulsePurposeEncryptRevokeStructure   | revoke                       | EC       | ECDH encryption of revoke data                         |
| 9     | PulsePurposePQDeriveConsent          | pq-derive-consent            | PQ       | Deriving ML-KEM-768 key pair for consent encryption    |
| 10    | PulsePurposePQDeriveRevoke           | pq-derive-revoke             | PQ       | Deriving ML-KEM-768 key pair for revoke encryption     |

Purposes 1–5 produce secp256k1 private keys that are used directly.
Purposes 9 and 10 produce secp256k1 node keys that are then expanded into ML-KEM-768 key pairs via HKDF.

Note: the symmetric encryption purposes (6=consent, 7=revoke, 255=keywrap) are not HD wallet derivation purposes.
They are passed to the encryption layer (see key_exchange.md and key_encapsulation.md) to label the type of
plaintext being encrypted.

## Formal Definition

### Helper Functions

All functions are named in UPPERCASE. Variables are not.

```H(byte_data) -> byte[32]```   // Keccak-256 hash function, input is a stream of bytes. Output is 32 bytes/256 bit binary value.

```HEX(byte[]) -> string```  /// Convert a byte array to a hex string.

Notes:
* Each input byte is represented by two hex characters (0-9, a-f). Always lowercase letters, no uppercase.
* No leading '0x'
* Output string length is always exactly 2 * input byte.length.

```DERIVE(parentKey, index) -> childKey```  /// BIP-32 child key derivation. If index >= 0x80000000, the derivation
is hardened (private key required). Otherwise it is normal (public key sufficient).

```EXTRACT(ikm, salt) -> prk```  /// HKDF extract function, computes a pseudorandom key from input keying
    material and a salt.

   Notes:
* Uses HMAC with Keccak-256 as the underlying hash function.
* prk length is 32 bytes.

```EXPAND(prk, info, L) -> okm```  /// HKDF expand function, computes output keying material from a pseudorandom key, info, and desired length.

   Notes:
* Uses HMAC with Keccak-256 as the underlying hash function.
* okm length is L bytes.

```PUBKEY(privateKey) -> publicKey```  /// Gets the secp256k1 public key from a private key.

```COMPRESS(publicKey) -> byte[33]```  /// Serialises a secp256k1 public key to 33-byte compressed format.

```SPRINTF(format, args...) -> string``` /// String formatting function, similar to fmt.Sprintf in Go or sprintf in C.

```KYBER_DERIVE(seed byte[64]) -> (privateKey, publicKey)```  /// Deterministically derives an ML-KEM-768
key pair from a 64-byte seed using the scheme's DeriveKeyPair function.

### EC Key Derivation

For purposes 1–5, the HD wallet produces a secp256k1 private key that is used directly for signing (purpose 1)
or ECDH key exchange (purposes 2–5).

#### Inputs

*  ```masterKey``` BIP-32 master key (derived from a mnemonic via BIP-39).
*  ```otherParty uint32``` Numeric identifier for the counterparty.
*  ```chainId uint32``` Blockchain network identifier.
*  ```consentNumber uint32``` Sequential consent number.
*  ```purpose uint32``` One of 1, 2, 3, 4, or 5.

#### Algorithm

```
// Derive the full HD path: m/4410704'/otherParty/chainId/consentNumber/purpose
protocolKey := DERIVE(masterKey, 0x80434d50)        // Hardened: protocol identifier
otherPartyKey := DERIVE(protocolKey, otherParty)     // Normal: counterparty
chainKey := DERIVE(otherPartyKey, chainId)           // Normal: blockchain
consentKey := DERIVE(chainKey, consentNumber)        // Normal: consent number
purposeKey := DERIVE(consentKey, purpose)            // Normal: purpose

privateKey := purposeKey.PrivateKeyBytes()           // 32-byte secp256k1 private key
publicKey := PUBKEY(privateKey)                      // secp256k1 public key
```

The resulting `privateKey` is used as follows:
- **Purpose 1 (SignTx)**: Passed to the ECDSA signing algorithm (see [signing.md](signing.md)).
- **Purposes 2–5 (Encrypt)**: Passed to the ECDH key exchange algorithm (see [key_exchange.md](key_exchange.md)).

#### Public Key Derivation (Without Private Key)

For ECDH encryption, Alice needs Bob's public key for a specific (chainId, consentNumber, purpose). If Alice
has Bob's extended public key at the `m/4410704'/otherParty` level (the "other party generator"), she can derive
Bob's public key without ever seeing his private key, because the remaining path levels are all non-hardened:

```
// Given: otherPartyGeneratorPubKey (extended public key at m/4410704'/otherParty)
chainKey := DERIVE(otherPartyGeneratorPubKey, chainId)
consentKey := DERIVE(chainKey, consentNumber)
purposeKey := DERIVE(consentKey, purpose)

publicKey := purposeKey.PublicKeyBytes()             // 33-byte compressed secp256k1 public key
```

This only works for purposes 1–5. PQ key derivation (purposes 9, 10) always requires the private key.

### PQ Key Derivation (ML-KEM-768)

For purposes 9 and 10, the HD wallet first derives a secp256k1 node key (same as EC derivation), then expands
the node's private key into a 64-byte seed for ML-KEM-768 key pair generation using HKDF.

This two-step approach means:
- The BIP-32 HD wallet provides deterministic, path-bound key material.
- The HKDF expansion converts 32 bytes of secp256k1 key material into the 64 bytes needed by ML-KEM-768.
- Domain separation ensures consent and revoke PQ keys are independent (different purpose in the HD path).

#### Inputs

*  ```masterKey``` BIP-32 master key.
*  ```otherParty uint32``` Numeric identifier for the counterparty.
*  ```chainId uint32``` Blockchain network identifier.
*  ```consentNumber uint32``` Sequential consent number.
*  ```purpose uint32``` Either 9 (PQ consent) or 10 (PQ revoke).

#### Algorithm

```
// Step 1: Derive the secp256k1 node key at the HD path
protocolKey := DERIVE(masterKey, 0x80434d50)
otherPartyKey := DERIVE(protocolKey, otherParty)
chainKey := DERIVE(otherPartyKey, chainId)
consentKey := DERIVE(chainKey, consentNumber)
purposeKey := DERIVE(consentKey, purpose)

nodePrivateKey := purposeKey.PrivateKeyBytes()       // 32-byte secp256k1 private key (IKM for HKDF)
nodePublicKey := COMPRESS(PUBKEY(nodePrivateKey))     // 33-byte compressed public key (transcript for HKDF)

// Step 2: Build HKDF parameters
// The context binds the seed to the specific (chainId, consentNumber) tuple.
// Note: contractAddress is empty for seed derivation (not known at key generation time).
contextString := SPRINTF("|pulse|ctx|v1|chain=%d|contract=|consentNumber=%d", chainId, consentNumber)
contextHash := H(contextString)

// Note: the HKDF info string double-hashes the context — H(contextHash) not contextHash.
hkdfContextHash := H(contextHash)

recipientIdStr := SPRINTF("%d", otherParty)

// Salt: binds to the node's public key for domain separation
saltString := SPRINTF("|pulse|seed|v1|salt|kyber768|%s|", HEX(nodePublicKey))
salt := H(saltString)

// Extract
prk := EXTRACT(nodePrivateKey, salt)

// Expand: single 64-byte output (no separate key/nonce)
infoString := SPRINTF("|pulse|seed|v1|kyber-keygen|kyber768+hkdf-keccak256|rid=%s|ctx=%s|", recipientIdStr, HEX(hkdfContextHash))
seed := EXPAND(prk, infoString, 64)

// Step 3: Derive the ML-KEM-768 key pair from the 64-byte seed
kyberPrivateKey, kyberPublicKey := KYBER_DERIVE(seed)
```

The resulting `kyberPublicKey` is shared with other parties. The `kyberPrivateKey` is kept secret and used
for decapsulation.

#### HKDF Parameter Summary

| Parameter   | Value                                                                       |
|-------------|-----------------------------------------------------------------------------|
| Hash        | Keccak-256                                                                  |
| IKM         | 32-byte secp256k1 node private key                                          |
| Salt        | H("\|pulse\|seed\|v1\|salt\|kyber768\|{compressed node public key}\|")      |
| Info        | "\|pulse\|seed\|v1\|kyber-keygen\|kyber768+hkdf-keccak256\|rid={otherParty}\|ctx={H(contextHash)}\|" |
| Output size | 64 bytes                                                                    |

## Key Usage Summary

The following table shows how each purpose maps to a key type and its downstream use:

| Purpose | HD Path Suffix | Key Produced         | Used By                     | Symmetric Purpose |
|---------|----------------|----------------------|-----------------------------|-------------------|
| 1       | .../1          | secp256k1 private    | signing.md (ECDSA)          | N/A               |
| 2       | .../2          | secp256k1 private    | key_exchange.md (ECDH)      | 2                 |
| 3       | .../3          | secp256k1 private    | key_exchange.md (ECDH)      | 3                 |
| 4       | .../4          | secp256k1 private    | key_exchange.md (ECDH)      | 4                 |
| 5       | .../5          | secp256k1 private    | key_exchange.md (ECDH)      | 5                 |
| 9       | .../9          | ML-KEM-768 key pair  | key_encapsulation.md (KEM)  | 6 (consent)       |
| 10      | .../10         | ML-KEM-768 key pair  | key_encapsulation.md (KEM)  | 7 (revoke)        |
