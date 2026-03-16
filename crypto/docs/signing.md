# Consent Signing - Protocol and Worked example

## Intro

This document describes the protocol for signing consent and revoke requests using the Pulse protocol.

The signatures that are generated are designed to be used by the Pulse Smart Contract, which will use signatures
on a transaction to recover the Ethereum/Polygon address of the signer. This makes use of the ECDSA Recover operation,
rather than the usual Validate operation on Digital Signatures. We need to conform
to the [EIP-191](https://eips.ethereum.org/EIPS/eip-191) standard for signing messages otherwise they will not work
correctly at the smart contract level.

The signatures are generated using an Elliptic Curve Digital Signature Algorithm (ECDSA) with the secp256k1 curve.

The signing key is derived from a BIP-32 HD wallet using the Pulse derivation path at purpose 1 (SignTx).
See [wallet.md](wallet.md) for full details on the HD wallet derivation.

The message for a signature is created in three steps:
1. Parse the Smart Contract Address from a hex string into a 20-byte binary address.
2. Pack the binary contract address, plus one (consent) or two (revoke) CID values into a byte array, then hash it
using Keccak256.
3. Create an EIP-191 compatible message as ```"\x19Ethereum Signed Message:\n" + <length of message>(0x20) " + <message>(result of step 2)```
Hash the result using Keccak256

The resulting signature is 65 bytes long, with 32 bytes of R and 32 bytes of S plus a recovery ID byte. The recoveryID
byte will be used, but EIP-191 expects the recovery ID to be 27 or 28. Signing libraries will often return 0 or 1 for
the recovery ID, so we need to convert these to 27 or 28 by adding 27 to the result.

## Formal Definition

### Encrypted Data Structures

```
type PulseSignature byte[65]
```

bytes 0-31 are the R value of the signature.
bytes 32-63 are the S value of the signature.
byte 64 is the recovery ID.

As a byte array, the result can easily be converted to a hex string (only use lowercase letters, no preceding 0x) or 
base64 encoding.

### Helper Functions

All functions are named in UPPERCASE. Variables are not.

```H(byte_data) -> byte[32]```   // Keccak-256 hash function, input is a stream of bytes. output is 32 bytes/256 bit binary value.

```HEX(byte[]) -> string```  /// Convert a byte array to a hex string.
   
Notes: 
* Each input byte is represented by two hex characters (0-9, a-f). Always lowercase letters, no uppercase.
* No leading '0x'
* Output string length is always exactly 2 * input byte.length.

```PUBKEY(privateKey secp256k1.PrivateKey) -> secp256k1.PublicKey``` // Get the public key from a private key.

```ECDSA(message byte[], privateKey secp256k1.PrivateKey) -> PulseSignature``` // Sign a message using a private key,
using Elliptic Curve Digital Signature Algorithm (ECDSA) with the secp256k1 curve.

```RECOVER(message byte[], signature PulseSignature) -> PublicKey``` // Recover the public key from a signature and message```

```PARSEHEX(hexString) -> byte[]``` // Parse a hex string into a byte array. Strips any leading "0x" prefix.

```PACK(arguments...) -> byte[]``` // Pack a sequence of arguments into a byte array in the order they are specified.```

```ADDRESS(publicKey secp256k1.PublicKey) -> string``` // Convert a public key to a 20 byte Ethereum address.```

### Signing Inputs

*  ```contractAddress``` String with the contract address (hex, with or without "0x" prefix).
*  ```cid``` IPFS content cid of the consent record we are using
*  ```rcid``` IPFS cid of the revocation record we are using (if revoking)
*  ```privateKey secp256k1.PrivateKey``` // Private key for the signing account.```

### Signing Algorithm

```
contract := PARSEHEX(contractAddress)    // 20-byte binary address
switch( purpose ) {
    case CONSENT:
        message = PACK(contract, cid)
    case REVOKE:
        message = PACK(contract, cid, rcid)
}

hMessage := H(message)
eip191Message := SPRINTF("\x19Ethereum Signed Message:\n32%s", hMessage)
sMessage := H(eip191Message)
signature := ECDSA(sMessage, privateKey)

// Only if the recovery ID is in the 0/1 range:
signature[64] := signature[64] + 27,
```

### Recovery Inputs

*  ```contractAddress``` String with the contract address (hex, with or without "0x" prefix).
*  ```cid``` IPFS content cid of the consent record we are using
*  ```rcid``` IPFS cid of the revocation record we are using (if revoking)
*  ```signature bytes[65]``` // Signature of the message.```

### Recovery Algorithm

```
contract := PARSEHEX(contractAddress)    // 20-byte binary address
switch( purpose ) {
    case CONSENT:
        message = PACK(contract, cid)
    case REVOKE:
        message = PACK(contract, cid, rcid)
}

hMessage := H(message)
eip191Message := SPRINTF("\x19Ethereum Signed Message:\n32%s", hMessage)
sMessage := H(eip191Message)

publicKey := RECOVER(sMessage, signature)
address := ADDRESS(publicKey)
```
## Known Values for Testing

We provide a single set of known values for testing both Signing and Recovery, as many of the values between
the two algorithms are the same. 

Binary values are presented in hexadecimal format, so they can be easily viewed here and pasted into test code.

Strings are written inside double quotes: "string value"

### Input Values

| Name | Value |
|---|----|
| ContractAddress | "0x9b980288ae5F7a1aca113faec133e765879a5fab" |
| privateKeyAlice | 89b58da1002bdd02ea9972c3c64c050f9a5236e430e030c18406035ca2be1856 |
| privateKeyBob | da4782769625a2cfe4c5ab998f71e19892d0769ed42c0551b2efab5eceae884c |
| cid | "bafyreialkztkqka6ki4arwlrryrhpamzaa3otihmegainx4puyyiq7yspm" |
| rcid | "bafyreidxxmeu4hn46zhbwclzwykj7vdbixj5boduhql7ihm4i2djqt4dmq" |

### Derived Values

| Name                    | Calculation                                                 | Value                                                                                                                                                                                                                                                |
|-------------------------|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| publicKeyAlice          | PUBKEY(PrivateKeyAlice)                                     | 04badd8074a5f44f7311552f5709e49c438d5940f7d8bb8be578c187caf40ff669e8b2d2ec4d2459c928c586dd3f62dc3b441431235eb06b646a359731032c9cb6                                                                                                                                                                                   |
| publicKeyBob            | PUBKEY(PrivateKeyBob)                                       | 04cadc6350aae69f23b9807a3462e72602914cebdd39dfa1b22d585730ca69c617d0c6e3644605da370694bb30172a9838fd1cb6c2e4d446021cc9bfaf982e7f11                                                                                                                                                                                   |
| addressAlice            | ADDRESS(PublicKeyAlice)                                     | fc3a23dade5b5a5c6b1790f9ac4256aed8ee8993 |
| addressBob              | ADDRESS(PublicKeyBob)                                       | 33a1debbe882df214f96a2b92b4062ee8fbb9c2f |
| consentMessage          | PACK(contract, cid )                                        | 9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d |
| hMessage(consent)       | H(consentMessage)                                           | e70594616cdcabad2c33930134d92dd152d138de679cb4f21fcadf0db30d07b2 | 
| sMessage(consent)       | H("\019Ethereum Signed Message\n\040" + hMessage(consent) ) | a30638332e2051a57faa61224ef3920ed2cdb216c4c7b3b38b02a05a391c6140 |
| consentSignature(Alice) | ECDSA(sMessage(Consent), privateKeyAlice)                   | b60d499d54b1a73eb9bb69c7289d5dcdd32e9893bc7e4f72df32fa75f395a1800cfa4eb49bf3a87bad7fc69b476ef5d5bea56883d2b9d0348963fcad34e5542e1b |
| consentSignaure(Bob)    | ECDSA(sMessage(consent), privateKeyBob )                    | 83dc442a0a67d27cccf8c57357f06b35b6f5b33082a81616fa0b0c4d144d572a0ca95431fe5262a41c83a04473b13c0cd5611bf6b5f1b560283ebceb88a295ff1b |
| revokeMessage           | PACK(contract, cid, rcid )                                  | 9b980288ae5f7a1aca113faec133e765879a5fab62616679726569616c6b7a746b716b61366b69346172776c727279726870616d7a6161336f7469686d656761696e7834707579796971377973706d626166797265696478786d657534686e34367a686277636c7a77796b6a3776646269786a35626f647568716c3769686d346932646a717434646d71 |
| hMessage(revoke)        | H(revokeMessage)                                            | cc506c53243fe75efed2a8407f9507d9741435ce35ba038c8dc7fcf7ded772d2 | 
| sMessage(revoke)        | H("\019Ethereum Signed Message\n\040" + hMessage(revoke) )  | 268c86604e8c4b1925b4ab12fc9c6ac5d0a974c0e8b70466678319a69ab76b88 |
| revokeSignature(Alice)  | ECDSA(sMessage(revoke), privateKeyAlice)                    | 380309be5b333ee98a842eba5243d6ea12df1460242b945852b80066dd14f3b06dadac3afe2acdfcc5762ef8fa6eff0df71cbc17eee4e83ed8911e8a577162721b |
| revokeSignaure(Bob)     | ECDSA(sMessage(revoke), privateKeyBob )                     | 07c1b03984ca30b557638a808768de4a992fc0a82290d2d8a9af8130ae3e4ec1365d0952bea16f671a71a8b8b0ff9c65370761a44b1a53518d66ac78e493e4d61c |
