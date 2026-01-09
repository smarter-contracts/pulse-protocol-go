package textformat

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// textformat contains common functions for formatting components of AES AAD, HKDF Info and Salt strings.
//
// We want the strings to be human readable, so the general approach is:
//
//  -- Long blocks of data are hashed ( with Keccak ) to shorten down to 32 bytes of data
//  -- All binary data is hex encoded using no 0x, and all lowercase letters.
//
// Yes, hex encoding binary data is not the most space efficient approach, but it is easier to read/debug,
// and we shouldn't be sending any of these strings over the wire...

func FormatHex(b []byte) string {
	return hex.EncodeToString(b)
}

func ContextString(chainId int32,
	contractAddress string,
	consentNumber int32,
) string {
	return fmt.Sprintf("|pulse|ctx|v1|chain=%d|contract=%s|consentNumber=%d",
		chainId, contractAddress, consentNumber)
}

func ContextHash(chainId int32,
	contractAddress string,
	consentNumber int32,
) []byte {

	hash := sha3.NewLegacyKeccak256()
	return hash.Sum([]byte(ContextString(chainId, contractAddress, consentNumber)))
}
